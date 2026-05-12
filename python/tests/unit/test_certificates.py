# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Unit tests for ``arsia_protocol.certificates``.

Self-signed Ed25519 certificates are generated in-memory via
``cryptography.x509.CertificateBuilder``. Nothing is shipped in
``shared/`` — these certs are dev-facing test fixtures, not canonical
test vectors.

Spec: ARSIA-Identity.md §6.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtensionOID, NameOID

from arsia_protocol.identity.certificates import (
    QC_STATEMENTS_OID,
    CertificateVerificationResult,
    compute_trust_level,
    extract_public_key_from_cert,
    has_qc_statements,
    is_certificate_chain_expired,
    verify_certificate_chain,
)


# ----------------------------------------------------------------------
# Cert factory
# ----------------------------------------------------------------------


def _build_cert(
    *,
    agent_id: str = "agent:acme.bot",
    subject_name: str = "Acme Corp",
    private_key: Ed25519PrivateKey | None = None,
    issuer_private_key: Ed25519PrivateKey | None = None,
    issuer_name: str | None = None,
    not_before: _dt.datetime | None = None,
    not_after: _dt.datetime | None = None,
    san_uri: str | None = None,
    include_san: bool = True,
    ca_false: bool = True,
    digital_signature: bool = True,
    with_qc_statements: bool = False,
) -> tuple[x509.Certificate, Ed25519PrivateKey]:
    """Generate a self-signed or CA-issued Ed25519 certificate.

    Returns the certificate and the private key used for its
    subject (so tests can sign data with it). When ``issuer_private_key``
    is ``None``, the cert is self-signed with ``private_key``.
    """
    if private_key is None:
        private_key = ed25519.Ed25519PrivateKey.generate()

    signer = issuer_private_key or private_key
    issuer = issuer_name if issuer_name is not None else subject_name

    if not_before is None:
        not_before = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=1)
    if not_after is None:
        not_after = _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=365)

    builder = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_name)])
        )
        .issuer_name(
            x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer)])
        )
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    if include_san:
        san_value = san_uri if san_uri is not None else agent_id
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier(san_value)]
            ),
            critical=False,
        )

    builder = builder.add_extension(
        x509.BasicConstraints(ca=not ca_false, path_length=None),
        critical=True,
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=digital_signature,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )

    if with_qc_statements:
        # Minimal ASN.1 DER payload for the QcStatements extension.
        # Structure: SEQUENCE { SEQUENCE { OID id-etsi-qcs-QcCompliance } }
        # DER bytes: 30 0b 30 09 06 07 2a 8a 22 07 01 01
        qc_payload = bytes.fromhex("300b300906072a8a22070101")
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier(QC_STATEMENTS_OID),
                qc_payload,
            ),
            critical=False,
        )

    cert = builder.sign(private_key=signer, algorithm=None)
    return cert, private_key


def _cert_to_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


@pytest.fixture
def valid_self_signed() -> dict[str, Any]:
    """A valid L2-shape self-signed cert meeting all §6.2 requirements."""
    cert, pk = _build_cert(agent_id="agent:acme.bot")
    return {
        "cert": cert,
        "pem": _cert_to_pem(cert),
        "private_key": pk,
        "public_key_bytes": pk.public_key().public_bytes_raw(),
        "agent_id": "agent:acme.bot",
    }


@pytest.fixture
def qc_statements_cert() -> dict[str, Any]:
    """A cert bearing the QcStatements extension → L3 claim."""
    cert, pk = _build_cert(
        agent_id="agent:arsialabs.qualified",
        with_qc_statements=True,
    )
    return {
        "cert": cert,
        "pem": _cert_to_pem(cert),
        "private_key": pk,
        "public_key_bytes": pk.public_key().public_bytes_raw(),
        "agent_id": "agent:arsialabs.qualified",
    }


# ----------------------------------------------------------------------
# Trust level classification
# ----------------------------------------------------------------------


def test_trust_level_l1_no_chain() -> None:
    """A record with no ``certificate_chain`` field claims L1.

    Spec: ARSIA-Identity.md §6.5.2 first row.
    """
    assert compute_trust_level({"agent_id": "agent:acme.bot"}) == "L1"


def test_trust_level_l1_empty_chain() -> None:
    """A record with an empty ``certificate_chain`` list claims L1.

    Spec: ARSIA-Identity.md §6.5.2 first row.
    """
    assert compute_trust_level({"certificate_chain": []}) == "L1"


def test_trust_level_l2_valid_chain(valid_self_signed: dict[str, Any]) -> None:
    """A record whose leaf has no QcStatements claims L2.

    Spec: ARSIA-Identity.md §6.5.2 second row.
    """
    record = {"certificate_chain": [valid_self_signed["pem"]]}
    assert compute_trust_level(record) == "L2"


def test_trust_level_l3_qc_statements(qc_statements_cert: dict[str, Any]) -> None:
    """A record whose leaf carries QcStatements claims L3.

    Spec: ARSIA-Identity.md §6.5.2 third row.
    """
    record = {"certificate_chain": [qc_statements_cert["pem"]]}
    assert compute_trust_level(record) == "L3"


def test_trust_level_l1_fallback_on_malformed_pem() -> None:
    """Unparseable PEM degrades the claim to L1 per module docstring.

    :func:`compute_trust_level` is a permissive classifier — full
    rejection is the job of :func:`verify_certificate_chain`.
    """
    record = {"certificate_chain": ["-----BEGIN CERTIFICATE-----\nnot valid\n-----END CERTIFICATE-----"]}
    assert compute_trust_level(record) == "L1"


def test_trust_level_l1_when_chain_entry_not_string() -> None:
    """Non-string chain entry degrades the claim to L1."""
    record: dict[str, Any] = {"certificate_chain": [123]}
    assert compute_trust_level(record) == "L1"


# ----------------------------------------------------------------------
# has_qc_statements / extract_public_key_from_cert
# ----------------------------------------------------------------------


def test_has_qc_statements_present(qc_statements_cert: dict[str, Any]) -> None:
    """Cert with QcStatements extension is detected.

    Spec: ARSIA-Identity.md §6.3.
    """
    assert has_qc_statements(qc_statements_cert["pem"]) is True


def test_has_qc_statements_absent(valid_self_signed: dict[str, Any]) -> None:
    """Normal L2 cert has no QcStatements.

    Spec: ARSIA-Identity.md §6.2.
    """
    assert has_qc_statements(valid_self_signed["pem"]) is False


def test_has_qc_statements_malformed_raises() -> None:
    """Malformed PEM raises ``ValueError``."""
    with pytest.raises(ValueError, match="malformed"):
        has_qc_statements("not a cert")


def test_extract_public_key_from_ed25519_cert(
    valid_self_signed: dict[str, Any],
) -> None:
    """Raw public key is recovered from an Ed25519 cert.

    Spec: ARSIA-Identity.md §6.2 (pubkey consistency).
    """
    raw = extract_public_key_from_cert(valid_self_signed["pem"])
    assert raw == valid_self_signed["public_key_bytes"]
    assert len(raw) == 32


def test_extract_public_key_from_non_ed25519_cert_raises() -> None:
    """RSA cert causes :func:`extract_public_key_from_cert` to raise.

    Spec: ARSIA-Identity.md §6.2 (Ed25519 only).
    """
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "X")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "X")]))
        .public_key(rsa_key.public_key())
        .serial_number(1)
        .not_valid_before(now - _dt.timedelta(days=1))
        .not_valid_after(now + _dt.timedelta(days=30))
        .sign(
            private_key=rsa_key,
            algorithm=__import__(
                "cryptography.hazmat.primitives.hashes",
                fromlist=["SHA256"],
            ).SHA256(),
        )
    )
    pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    with pytest.raises(ValueError, match="Ed25519"):
        extract_public_key_from_cert(pem)


def test_extract_public_key_malformed_raises() -> None:
    """Malformed PEM causes :func:`extract_public_key_from_cert` to raise."""
    with pytest.raises(ValueError, match="malformed"):
        extract_public_key_from_cert("-----BEGIN CERTIFICATE-----\ngarbage\n-----END CERTIFICATE-----")


# ----------------------------------------------------------------------
# verify_certificate_chain — success paths
# ----------------------------------------------------------------------


def test_verify_empty_chain_is_valid_l1() -> None:
    """Empty chain → ``is_valid=True``, ``trust_level="L1"``.

    Spec: ARSIA-Identity.md §6.4.1 step 3.
    """
    result = verify_certificate_chain([], "agent:acme.bot", b"\x00" * 32)
    assert result.is_valid is True
    assert result.trust_level == "L1"
    assert result.errors == ()
    assert result.leaf_subject is None
    assert result.expires_at is None


def test_verify_self_signed_l2_passes(valid_self_signed: dict[str, Any]) -> None:
    """Self-signed L2 cert with correct SAN + pubkey → L2.

    Spec: ARSIA-Identity.md §6.4.1 steps 4a–4f.
    """
    result = verify_certificate_chain(
        [valid_self_signed["pem"]],
        valid_self_signed["agent_id"],
        valid_self_signed["public_key_bytes"],
    )
    assert result.is_valid is True, result.errors
    assert result.trust_level == "L2"
    assert result.errors == ()


def test_verify_self_signed_l3_when_qc_statements_present(
    qc_statements_cert: dict[str, Any],
) -> None:
    """QcStatements on the leaf upgrades trust level to L3.

    Spec: ARSIA-Identity.md §6.4.1 step 4g.
    """
    result = verify_certificate_chain(
        [qc_statements_cert["pem"]],
        qc_statements_cert["agent_id"],
        qc_statements_cert["public_key_bytes"],
    )
    assert result.is_valid is True, result.errors
    assert result.trust_level == "L3"


def test_verify_result_exposes_leaf_subject_and_expiry(
    valid_self_signed: dict[str, Any],
) -> None:
    """Verification result carries the leaf's display name and expiry.

    Spec: ARSIA-Identity.md §6.5.2 — metadata exposed by verifier.
    """
    result = verify_certificate_chain(
        [valid_self_signed["pem"]],
        valid_self_signed["agent_id"],
        valid_self_signed["public_key_bytes"],
    )
    assert result.leaf_subject == "Acme Corp"
    assert isinstance(result.expires_at, str)
    assert result.expires_at.endswith("Z")


# ----------------------------------------------------------------------
# verify_certificate_chain — failure paths
# ----------------------------------------------------------------------


def test_verify_rejects_san_mismatch() -> None:
    """Leaf SAN that does not contain ``agent_id`` is rejected.

    Spec: ARSIA-Identity.md §6.4.1 step 4e
    (``details.reason=agent_id_not_in_san``).
    """
    cert, pk = _build_cert(agent_id="agent:acme.bot", san_uri="agent:other.bot")
    pem = _cert_to_pem(cert)
    result = verify_certificate_chain(
        [pem], "agent:acme.bot", pk.public_key().public_bytes_raw()
    )
    assert result.is_valid is False
    assert any(e.code == "agent_id_not_in_san" for e in result.errors)
    assert result.trust_level == "L1"


def test_verify_rejects_missing_san() -> None:
    """Leaf with no SAN extension is rejected.

    Spec: ARSIA-Identity.md §6.4.1 step 4e.
    """
    cert, pk = _build_cert(agent_id="agent:acme.bot", include_san=False)
    pem = _cert_to_pem(cert)
    result = verify_certificate_chain(
        [pem], "agent:acme.bot", pk.public_key().public_bytes_raw()
    )
    assert result.is_valid is False
    assert any(e.code == "agent_id_not_in_san" for e in result.errors)


def test_verify_rejects_pubkey_mismatch(
    valid_self_signed: dict[str, Any],
) -> None:
    """Pubkey in cert differs from JWKS key → ``key_mismatch`` rejection.

    Spec: ARSIA-Identity.md §6.4.1 step 4d.
    """
    other_key = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    result = verify_certificate_chain(
        [valid_self_signed["pem"]],
        valid_self_signed["agent_id"],
        other_key,
    )
    assert result.is_valid is False
    assert any(e.code == "key_mismatch" for e in result.errors)


def test_verify_rejects_expired_cert() -> None:
    """Expired leaf certificate is rejected via ``certificate_expired``.

    Spec: ARSIA-Identity.md §6.4.1 step 4c.
    """
    now = _dt.datetime.now(_dt.timezone.utc)
    cert, pk = _build_cert(
        agent_id="agent:acme.bot",
        not_before=now - _dt.timedelta(days=400),
        not_after=now - _dt.timedelta(days=30),
    )
    pem = _cert_to_pem(cert)
    result = verify_certificate_chain(
        [pem], "agent:acme.bot", pk.public_key().public_bytes_raw()
    )
    assert result.is_valid is False
    assert any(e.code == "certificate_expired" for e in result.errors)


def test_verify_rejects_not_yet_valid_cert() -> None:
    """Cert with ``notBefore`` in the future is rejected.

    Spec: ARSIA-Identity.md §6.4.1 step 4c.
    """
    now = _dt.datetime.now(_dt.timezone.utc)
    cert, pk = _build_cert(
        agent_id="agent:acme.bot",
        not_before=now + _dt.timedelta(days=10),
        not_after=now + _dt.timedelta(days=100),
    )
    pem = _cert_to_pem(cert)
    result = verify_certificate_chain(
        [pem], "agent:acme.bot", pk.public_key().public_bytes_raw()
    )
    assert result.is_valid is False
    assert any("not yet valid" in str(e) for e in result.errors)


def test_verify_now_override_is_honoured(
    valid_self_signed: dict[str, Any],
) -> None:
    """Passing a future ``now`` makes a currently-valid cert look expired.

    This is the deterministic hook tests rely on so they don't have to
    manipulate wall-clock time.
    """
    future = _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=3650)
    result = verify_certificate_chain(
        [valid_self_signed["pem"]],
        valid_self_signed["agent_id"],
        valid_self_signed["public_key_bytes"],
        now=future,
    )
    assert result.is_valid is False
    assert any(e.code == "certificate_expired" for e in result.errors)


def test_verify_rejects_ca_true_leaf() -> None:
    """Leaf with ``CA:TRUE`` is rejected per §6.2 structural requirements.

    Spec: ARSIA-Identity.md §6.2 (Basic Constraints CA:FALSE).
    """
    cert, pk = _build_cert(agent_id="agent:acme.bot", ca_false=False)
    pem = _cert_to_pem(cert)
    result = verify_certificate_chain(
        [pem], "agent:acme.bot", pk.public_key().public_bytes_raw()
    )
    assert result.is_valid is False
    assert any("Basic Constraints" in str(e) for e in result.errors)


def test_verify_rejects_missing_digital_signature() -> None:
    """Leaf without ``digitalSignature`` key usage is rejected.

    Spec: ARSIA-Identity.md §6.2.
    """
    cert, pk = _build_cert(agent_id="agent:acme.bot", digital_signature=False)
    pem = _cert_to_pem(cert)
    result = verify_certificate_chain(
        [pem], "agent:acme.bot", pk.public_key().public_bytes_raw()
    )
    assert result.is_valid is False
    assert any("digitalSignature" in str(e) for e in result.errors)


def test_verify_rejects_malformed_pem() -> None:
    """Malformed PEM in the chain produces parse errors.

    Spec: ARSIA-Identity.md §6.4.1 step 4a.
    """
    result = verify_certificate_chain(
        ["-----BEGIN CERTIFICATE-----\nbroken\n-----END CERTIFICATE-----"],
        "agent:acme.bot",
        b"\x00" * 32,
    )
    assert result.is_valid is False
    assert any("malformed" in str(e) for e in result.errors)
    assert result.trust_level == "L1"


def test_verify_rejects_non_string_chain_entry() -> None:
    """Non-string chain entry produces a parse error."""
    result = verify_certificate_chain(
        [123],  # type: ignore[list-item]
        "agent:acme.bot",
        b"\x00" * 32,
    )
    assert result.is_valid is False
    assert any("not a string" in str(e) for e in result.errors)


def test_verify_two_cert_chain_with_valid_ca() -> None:
    """Two-cert chain where leaf is signed by a self-signed Ed25519 CA.

    Exercises the §6.4.1 step 4b path where each cert must verify
    against the next.
    """
    ca_key = ed25519.Ed25519PrivateKey.generate()
    ca_cert, _ = _build_cert(
        agent_id="agent:acme.ca",
        subject_name="Acme CA",
        private_key=ca_key,
        include_san=False,
        ca_false=False,
    )

    leaf_key = ed25519.Ed25519PrivateKey.generate()
    leaf_cert, _ = _build_cert(
        agent_id="agent:acme.bot",
        subject_name="Acme Bot",
        private_key=leaf_key,
        issuer_private_key=ca_key,
        issuer_name="Acme CA",
    )

    chain = [_cert_to_pem(leaf_cert), _cert_to_pem(ca_cert)]
    result = verify_certificate_chain(
        chain, "agent:acme.bot", leaf_key.public_key().public_bytes_raw()
    )
    assert result.is_valid is True, result.errors
    assert result.trust_level == "L2"


def test_verify_two_cert_chain_with_broken_signature() -> None:
    """Leaf signed by a key that isn't the next cert in the chain → fail.

    Spec: ARSIA-Identity.md §6.4.1 step 4b.
    """
    # CA cert claims to be the issuer but leaf is signed by a different key.
    ca_key = ed25519.Ed25519PrivateKey.generate()
    ca_cert, _ = _build_cert(
        agent_id="agent:acme.ca",
        subject_name="Acme CA",
        private_key=ca_key,
        include_san=False,
        ca_false=False,
    )

    wrong_issuer = ed25519.Ed25519PrivateKey.generate()
    leaf_key = ed25519.Ed25519PrivateKey.generate()
    leaf_cert, _ = _build_cert(
        agent_id="agent:acme.bot",
        subject_name="Acme Bot",
        private_key=leaf_key,
        issuer_private_key=wrong_issuer,
        issuer_name="Acme CA",
    )

    chain = [_cert_to_pem(leaf_cert), _cert_to_pem(ca_cert)]
    result = verify_certificate_chain(
        chain, "agent:acme.bot", leaf_key.public_key().public_bytes_raw()
    )
    assert result.is_valid is False
    assert any("signature does not verify" in str(e) for e in result.errors)


def test_verify_trust_store_accepts_anchor() -> None:
    """Explicit ``trust_store`` lets a chain anchor to an external CA.

    Spec: ARSIA-Identity.md §6.4.2.
    """
    ca_key = ed25519.Ed25519PrivateKey.generate()
    ca_cert, _ = _build_cert(
        agent_id="agent:acme.ca",
        subject_name="External CA",
        private_key=ca_key,
        include_san=False,
        ca_false=False,
    )
    leaf_key = ed25519.Ed25519PrivateKey.generate()
    leaf_cert, _ = _build_cert(
        agent_id="agent:acme.bot",
        subject_name="Acme Bot",
        private_key=leaf_key,
        issuer_private_key=ca_key,
        issuer_name="External CA",
    )
    # Chain ONLY has the leaf — the CA lives in trust_store.
    result = verify_certificate_chain(
        [_cert_to_pem(leaf_cert)],
        "agent:acme.bot",
        leaf_key.public_key().public_bytes_raw(),
        trust_store=[ca_cert],
    )
    assert result.is_valid is True, result.errors
    assert result.trust_level == "L2"


def test_verify_result_structure_is_frozen(
    valid_self_signed: dict[str, Any],
) -> None:
    """Result object is a frozen dataclass with the documented fields."""
    result = verify_certificate_chain(
        [valid_self_signed["pem"]],
        valid_self_signed["agent_id"],
        valid_self_signed["public_key_bytes"],
    )
    assert isinstance(result, CertificateVerificationResult)
    assert isinstance(result.errors, tuple)
    with pytest.raises(Exception):
        result.trust_level = "L1"  # type: ignore[misc]


def test_verify_result_errors_preserved_on_partial_failure(
    valid_self_signed: dict[str, Any],
) -> None:
    """Multiple failures are all reported in ``errors``.

    Exercises the "accumulate, don't short-circuit" property.
    """
    wrong_key = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    result = verify_certificate_chain(
        [valid_self_signed["pem"]],
        "agent:other.bot",  # SAN mismatch
        wrong_key,  # pubkey mismatch
    )
    assert result.is_valid is False
    assert len(result.errors) >= 2
    assert any(e.code == "key_mismatch" for e in result.errors)
    assert any(e.code == "agent_id_not_in_san" for e in result.errors)


# ----------------------------------------------------------------------
# compute_trust_level on full record shape
# ----------------------------------------------------------------------


def test_compute_trust_level_from_full_identity_record(
    valid_self_signed: dict[str, Any],
) -> None:
    """Accepts a full IdentityRecord-shaped dict.

    Spec: ARSIA-Identity.md §1.2 + §6.5.1.
    """
    record = {
        "agent_id": "agent:acme.bot",
        "owner_id": "PT501234567",
        "owner_name": "Acme Corp",
        "jurisdiction": "PT",
        "ai_system_classification": "minimal-risk",
        "created_at": "2026-03-24T10:00:00.000Z",
        "certificate_chain": [valid_self_signed["pem"]],
    }
    assert compute_trust_level(record) == "L2"


# ----------------------------------------------------------------------
# Sanity: the cert factory actually produced a QcStatements cert the
# cryptography library can parse back. Protects against a silent change
# in the hand-crafted DER payload.
# ----------------------------------------------------------------------


def test_qc_statements_factory_cert_round_trips(
    qc_statements_cert: dict[str, Any],
) -> None:
    """Regenerated cert round-trips through ``x509.load_pem_x509_certificate``."""
    cert = x509.load_pem_x509_certificate(qc_statements_cert["pem"].encode("ascii"))
    ext = cert.extensions.get_extension_for_oid(
        x509.ObjectIdentifier(QC_STATEMENTS_OID)
    )
    assert ext is not None
    # SAN also survives round-trip
    san = cert.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    ).value
    assert isinstance(san, x509.SubjectAlternativeName)


# ----------------------------------------------------------------------
# is_certificate_chain_expired (pre-serve check, §6.5.1 / §6.5.3)
# ----------------------------------------------------------------------


def test_chain_expired_returns_false_for_empty_chain() -> None:
    """Spec: §6.5.1 — empty chain is L1 self-signed; not expired."""
    assert is_certificate_chain_expired([]) is False
    assert is_certificate_chain_expired(None) is False


def test_chain_expired_returns_false_when_all_certs_valid() -> None:
    """Spec: §6.5.1 — every cert still within validity window."""
    cert, _ = _build_cert(agent_id="agent:acme.bot")
    pem = _cert_to_pem(cert)
    assert is_certificate_chain_expired([pem]) is False


def test_chain_expired_returns_true_when_any_cert_expired() -> None:
    """Spec: §6.5.1 — agent MUST NOT serve record with expired cert."""
    expired_cert, _ = _build_cert(
        agent_id="agent:acme.bot",
        not_before=_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=400),
        not_after=_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=10),
    )
    pem = _cert_to_pem(expired_cert)
    assert is_certificate_chain_expired([pem]) is True


def test_chain_expired_detects_expired_intermediate() -> None:
    """Any cert in the chain — not only the leaf — triggers True.

    Spec: §6.5.1 ("All certificates in the chain MUST be valid").
    """
    valid_leaf, _ = _build_cert(agent_id="agent:acme.bot")
    expired_intermediate, _ = _build_cert(
        agent_id="agent:acme.bot",
        not_before=_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=400),
        not_after=_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=10),
    )
    chain = [_cert_to_pem(valid_leaf), _cert_to_pem(expired_intermediate)]
    assert is_certificate_chain_expired(chain) is True


def test_chain_expired_with_injected_now() -> None:
    """The reference instant is injectable for deterministic tests."""
    cert, _ = _build_cert(
        agent_id="agent:acme.bot",
        not_before=_dt.datetime(2026, 1, 1, tzinfo=_dt.timezone.utc),
        not_after=_dt.datetime(2027, 1, 1, tzinfo=_dt.timezone.utc),
    )
    pem = _cert_to_pem(cert)
    # Before notAfter → not expired.
    assert (
        is_certificate_chain_expired(
            [pem], now=_dt.datetime(2026, 6, 1, tzinfo=_dt.timezone.utc)
        )
        is False
    )
    # After notAfter → expired.
    assert (
        is_certificate_chain_expired(
            [pem], now=_dt.datetime(2028, 1, 1, tzinfo=_dt.timezone.utc)
        )
        is True
    )


def test_chain_expired_treats_unparseable_pem_as_expired() -> None:
    """Broken PEM never gets served — treated as expired.

    Spec: §6.5.1 (defense-in-depth on serve side).
    """
    assert is_certificate_chain_expired(["not-a-cert"]) is True


# ----------------------------------------------------------------------
# §6.4.2 Trust-level acceptance defaults (req:e3ffe67a, req:6bc46c4f)
# ----------------------------------------------------------------------


def test_trust_level_1_message_accepted_by_default() -> None:
    """An agent MUST NOT reject messages solely because trust_level is 1.

    verify_certificate_chain with an empty chain (Level 1) returns
    is_valid=True — the message is accepted.

    Spec: ARSIA-Identity.md §6.4.2.
    """
    result = verify_certificate_chain(
        certificate_chain=[],
        agent_id="agent:acme.bot",
        public_key_bytes=b"\x00" * 32,
    )
    assert result.is_valid is True
    assert result.trust_level == "L1"
    assert result.errors == ()


def test_default_accepts_all_trust_levels() -> None:
    """Default behaviour MUST accept messages at all trust levels.

    Level 1 (empty chain), Level 2 (valid chain, no QcStatements), and
    Level 3 (valid chain + QcStatements) all return is_valid=True when
    the certificates are structurally correct.

    Spec: ARSIA-Identity.md §6.4.2.
    """
    # Level 1 — no chain
    r1 = verify_certificate_chain([], "agent:acme.bot", b"\x00" * 32)
    assert r1.is_valid is True
    assert r1.trust_level == "L1"

    # Level 2 — valid chain without QcStatements
    private_key = Ed25519PrivateKey.generate()
    pub_bytes = private_key.public_key().public_bytes_raw()
    now = _dt.datetime.now(_dt.timezone.utc)
    cert, _ = _build_cert(
        agent_id="agent:acme.bot",
        private_key=private_key,
        not_before=now - _dt.timedelta(hours=1),
        not_after=now + _dt.timedelta(days=365),
    )
    pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    r2 = verify_certificate_chain(
        [pem],
        "agent:acme.bot",
        pub_bytes,
        now=now,
    )
    assert r2.is_valid is True
    assert r2.trust_level == "L2"


def test_no_trust_level_only_rejection_in_default_config() -> None:
    """The verification pipeline has no min_trust_level gate.

    Even a degraded (failed verification) chain result never rejects
    *because* of trust level — it rejects because of certificate errors.
    A Level 1 record with no chain is always valid.

    Spec: ARSIA-Identity.md §6.4.2 (req:e3ffe67a).
    """
    result = verify_certificate_chain(
        certificate_chain=[],
        agent_id="agent:test.minimal",
        public_key_bytes=Ed25519PrivateKey.generate().public_key().public_bytes_raw(),
    )
    assert result.is_valid is True
    assert result.trust_level == "L1"
    assert "trust" not in " ".join(result.errors).lower()


# ----------------------------------------------------------------------
# Subject O vs IdentityRecord owner_name — §6.2
# ----------------------------------------------------------------------


def test_verify_chain_subject_o_matches_owner_name_passes() -> None:
    """Subject O matching owner_name produces no error.

    Spec: ARSIA-Identity.md §6.2 (IDENT-§6.2-03).
    """
    agent_id = "agent:acme.bot"
    cert, key = _build_cert(agent_id=agent_id, subject_name="Acme Corp")
    pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    pub_bytes = key.public_key().public_bytes_raw()
    identity_record = {"owner_name": "Acme Corp"}
    result = verify_certificate_chain(
        certificate_chain=[pem],
        agent_id=agent_id,
        public_key_bytes=pub_bytes,
        identity_record=identity_record,
    )
    assert result.is_valid is True
    error_codes = [e.code for e in result.errors]
    assert "subject_organization_mismatch" not in error_codes


def test_verify_chain_subject_o_mismatch_returns_error() -> None:
    """Subject O not matching owner_name produces an error.

    Spec: ARSIA-Identity.md §6.2 (IDENT-§6.2-03).
    """
    agent_id = "agent:acme.bot"
    cert, key = _build_cert(agent_id=agent_id, subject_name="Acme Corp")
    pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    pub_bytes = key.public_key().public_bytes_raw()
    identity_record = {"owner_name": "Different Corp"}
    result = verify_certificate_chain(
        certificate_chain=[pem],
        agent_id=agent_id,
        public_key_bytes=pub_bytes,
        identity_record=identity_record,
    )
    assert result.is_valid is False
    error_codes = [e.code for e in result.errors]
    assert "subject_organization_mismatch" in error_codes


def test_verify_chain_no_identity_record_skips_subject_o_check() -> None:
    """Without identity_record, Subject O check is skipped.

    Spec: ARSIA-Identity.md §6.2 — backward compatible.
    """
    agent_id = "agent:acme.bot"
    cert, key = _build_cert(agent_id=agent_id, subject_name="Acme Corp")
    pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    pub_bytes = key.public_key().public_bytes_raw()
    result = verify_certificate_chain(
        certificate_chain=[pem],
        agent_id=agent_id,
        public_key_bytes=pub_bytes,
    )
    assert result.is_valid is True
    error_codes = [e.code for e in result.errors]
    assert "subject_organization_mismatch" not in error_codes
