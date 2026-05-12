# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Certificate trust levels and chain verification for ARSIA agents.

This module is Layer 4 in the SDK dependency graph. It implements
ARSIA-Identity.md §6 — the three-tier trust model on top of the base
EdDSA identity layer:

- **Level 1 — Self-signed (default).** The agent's IdentityRecord has
  no ``certificate_chain`` field, or the field is empty. Trust derives
  entirely from the EdDSA signature.
- **Level 2 — CA-signed.** A conventional X.509 chain issued by an
  enterprise / consortium / sandbox CA vouches for the binding between
  ``agent_id``, the legal entity, and the public key.
- **Level 3 — Qualified certificate (eIDAS).** A Level 2 chain whose
  leaf certificate carries the ``QcStatements`` extension from a QTSP
  on an EU Member State Trusted List.

Two entry points matter:

- :func:`compute_trust_level` is a *claim* classifier. It inspects the
  IdentityRecord as-is and answers "what level does this record claim?"
  without performing full chain validation. A broken chain degrades
  silently to ``"L1"`` because unparseable certificates cannot claim
  anything.
- :func:`verify_certificate_chain` is the *verifier*. It executes
  ARSIA-Identity.md §6.4.1 steps 4a–4g and returns a structured
  :class:`CertificateVerificationResult` with ``is_valid``, the
  computed ``trust_level``, and a list of failure reasons.

**Dependency boundary.** This module imports *only* from stdlib and the
``cryptography`` package. It does not import from
:mod:`arsia_protocol.types`, :mod:`arsia_protocol.identity`, or any
other SDK module. The input to the public entry points is always a
plain :class:`dict` (the IdentityRecord) or raw PEM strings — never a
Pydantic model — so the module can be consumed independently of the
types subpackage.

**What this module does NOT do:**

- **Revocation (OCSP / CRL).** §6.4.1 step 4h requires an OCSP or CRL
  check for Level 3. The SDK does not perform network I/O, so
  revocation is out of scope. Callers that need revocation checks
  must layer them on top of :func:`verify_certificate_chain`.
- **Full ETSI EN 319 412-5 QcStatements parsing.** The
  :func:`has_qc_statements` discriminator only checks for the presence
  of the ``QcStatements`` OID (1.3.6.1.5.5.7.1.3). Parsing the ASN.1
  ``QcStatements`` structure, verifying ``id-etsi-qcs-QcCompliance``,
  and cross-checking with a Member State Trusted List is out of scope
  and MUST be performed by the deploying integration.
- **Trust store discovery.** §6.4.2 says trust store configuration is
  operational. Callers may pass an explicit ``trust_store`` kwarg to
  :func:`verify_certificate_chain`; if omitted, the last certificate
  in the supplied chain is treated as the anchor (self-signed root
  MUST verify its own signature).

Spec: ARSIA-Identity.md §6.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal

from arsia_protocol._errors import ValidationError

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.x509.oid import ExtensionOID

TrustLevel = Literal["L1", "L2", "L3"]
"""Claimed or verified trust level for an ARSIA agent (Identity §6)."""

QC_STATEMENTS_OID = "1.3.6.1.5.5.7.1.3"
"""OID for the QcStatements extension, ETSI EN 319 412-5 / RFC 3739.

Presence of this OID on the leaf certificate is the L2→L3
discriminator. Full parsing of the QcStatements structure
(``id-etsi-qcs-QcCompliance`` etc.) is intentionally out of scope;
this module only checks extension presence.
"""


@dataclass(frozen=True)
class CertificateVerificationResult:
    """Outcome of :func:`verify_certificate_chain`.

    A frozen dataclass so callers can hash/share results safely.

    Attributes:
        trust_level: ``"L1"`` when the chain is empty or verification
            failed; ``"L2"`` when a valid chain with no QcStatements
            extension was found; ``"L3"`` when the leaf carries
            QcStatements and all L2 checks pass.
        is_valid: ``True`` if every check in §6.4.1 step 4 passed.
            ``False`` if any check failed (``errors`` will be
            non-empty).
        errors: Tuple of human-readable failure reasons. Empty when
            ``is_valid`` is ``True``. Frozen so that stored results
            cannot be mutated.
        leaf_subject: Best-effort display string for the leaf
            certificate's Subject. Prefers ``commonName`` then
            ``organizationName``. ``None`` when the chain is empty
            or the leaf could not be parsed.
        expires_at: ISO-8601 (with ``Z`` suffix) string of the leaf
            certificate's ``notAfter``. ``None`` when unavailable.

    Spec: ARSIA-Identity.md §6.4.1, §6.5.2.
    """

    trust_level: TrustLevel
    is_valid: bool
    errors: tuple[ValidationError, ...]
    leaf_subject: str | None
    expires_at: str | None


# ----------------------------------------------------------------------
# Trust-level classification (claim-based, no verification)
# ----------------------------------------------------------------------


def compute_trust_level(identity_record: dict[str, object]) -> TrustLevel:
    """Return the trust level *claimed* by an IdentityRecord.

    This is a lightweight classifier that inspects the record without
    performing full chain validation. It implements the table in
    ARSIA-Identity.md §6.5.2:

    =============================================================  ============
    Condition                                                      Trust Level
    =============================================================  ============
    ``certificate_chain`` absent or empty                          ``"L1"``
    chain parses and leaf has ``QcStatements``                     ``"L3"``
    chain parses and leaf has no ``QcStatements``                  ``"L2"``
    chain present but unparseable                                  ``"L1"`` *
    =============================================================  ============

    *The spec's §6.4.1 verification procedure rejects unparseable
    chains outright with ``certificate_invalid``. :func:`compute_trust_level`
    is intentionally permissive — it is a *classifier*, not a
    verifier. Consumers that must enforce §6.4.1 MUST call
    :func:`verify_certificate_chain` instead of relying on this
    function alone.

    Args:
        identity_record: Parsed IdentityRecord as a plain dict (as
            returned by ``json.loads`` or the output of Pydantic's
            ``model_dump``). Pydantic models are not accepted to keep
            this module free of a ``types`` dependency.

    Returns:
        The claimed trust level.

    Spec: ARSIA-Identity.md §6.5.2.
    """
    chain = identity_record.get("certificate_chain")
    if not isinstance(chain, list) or not chain:
        return "L1"
    leaf_pem = chain[0]
    if not isinstance(leaf_pem, str):
        return "L1"
    try:
        if has_qc_statements(leaf_pem):
            return "L3"
        return "L2"
    except ValueError:
        # Unparseable PEM — fall back to a claim of Level 1 rather
        # than propagating. Verification is the caller's job.
        return "L1"


# ----------------------------------------------------------------------
# Low-level helpers
# ----------------------------------------------------------------------


def _parse_cert(pem: str) -> x509.Certificate:
    """Parse a single PEM-encoded certificate or raise ``ValueError``."""
    try:
        return x509.load_pem_x509_certificate(pem.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError(f"malformed PEM certificate: {exc}") from exc


def extract_public_key_from_cert(cert_pem: str) -> bytes:
    """Return the raw 32-byte Ed25519 public key embedded in ``cert_pem``.

    Args:
        cert_pem: A single PEM-encoded X.509 certificate.

    Returns:
        The 32-byte raw Ed25519 public key.

    Raises:
        ValueError: if ``cert_pem`` is malformed or the certificate's
            public key is not Ed25519.

    Spec: ARSIA-Identity.md §6.2 (public key in cert must match JWKS).
    """
    cert = _parse_cert(cert_pem)
    pub = cert.public_key()
    if not isinstance(pub, ed25519.Ed25519PublicKey):
        raise ValueError(
            "certificate public key is not Ed25519 — ARSIA requires "
            "Ed25519 for agent certificates (Identity §6.2)"
        )
    return pub.public_bytes_raw()


def has_qc_statements(cert_pem: str) -> bool:
    """Return ``True`` when the certificate carries the QcStatements OID.

    This is the L2→L3 discriminator. The check is intentionally shallow:
    it only detects presence of the ``1.3.6.1.5.5.7.1.3`` extension OID.
    Full ETSI EN 319 412-5 parsing (verifying that the QcStatements
    structure actually contains ``id-etsi-qcs-QcCompliance`` and related
    statements) is out of scope — production Level 3 verification MUST
    layer additional validation on top of this check.

    Args:
        cert_pem: A single PEM-encoded X.509 certificate.

    Returns:
        ``True`` if the QcStatements OID is present as an extension,
        ``False`` otherwise.

    Raises:
        ValueError: if ``cert_pem`` is malformed.

    Spec: ARSIA-Identity.md §6.3 (Level 3 QcStatements), RFC 3739 §3.2.
    """
    cert = _parse_cert(cert_pem)
    target_oid = x509.ObjectIdentifier(QC_STATEMENTS_OID)
    for ext in cert.extensions:
        if ext.oid == target_oid:
            return True
    return False


def _leaf_subject_display(cert: x509.Certificate) -> str | None:
    """Best-effort display string for the leaf certificate Subject."""
    try:
        cn_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if cn_attrs:
            value = cn_attrs[0].value
            return value if isinstance(value, str) else value.decode("utf-8")
        org_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
        if org_attrs:
            value = org_attrs[0].value
            return value if isinstance(value, str) else value.decode("utf-8")
    except (ValueError, AttributeError):  # pragma: no cover - defensive
        return None
    return None


def _format_not_after(cert: x509.Certificate) -> str:
    """Format ``notAfter`` as an ISO-8601 string with ``Z`` suffix."""
    dt = cert.not_valid_after_utc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + (
        f"{dt.microsecond // 1000:03d}Z"
    )


def _verify_cert_signature(child: x509.Certificate, parent: x509.Certificate) -> bool:
    """Verify that ``child`` was signed by ``parent``'s public key.

    Dispatches on the parent's key type so we can handle Ed25519 root
    CAs, conventional RSA / ECDSA CAs (common in enterprise trust
    stores), and fall back to ``False`` for unsupported algorithms.
    """
    parent_key = parent.public_key()
    try:
        if isinstance(parent_key, ed25519.Ed25519PublicKey):
            parent_key.verify(child.signature, child.tbs_certificate_bytes)
            return True
        if isinstance(parent_key, rsa.RSAPublicKey):
            hash_alg = child.signature_hash_algorithm
            if hash_alg is None:
                return False
            parent_key.verify(
                child.signature,
                child.tbs_certificate_bytes,
                asym_padding.PKCS1v15(),
                hash_alg,
            )
            return True
        if isinstance(parent_key, ec.EllipticCurvePublicKey):
            hash_alg = child.signature_hash_algorithm
            if hash_alg is None:
                return False
            parent_key.verify(
                child.signature,
                child.tbs_certificate_bytes,
                ec.ECDSA(hash_alg),
            )
            return True
    except InvalidSignature:
        return False
    return False


def _extract_subject_organization(cert: x509.Certificate) -> str | None:
    """Extract the Subject Organization (O) attribute from a certificate."""
    try:
        org_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
        if org_attrs:
            value = org_attrs[0].value
            return value if isinstance(value, str) else value.decode("utf-8")
    except (ValueError, AttributeError):
        return None
    return None


def _san_contains_agent_id(cert: x509.Certificate, agent_id: str) -> bool:
    """Return ``True`` if the SAN extension contains ``agent_id`` as URI."""
    try:
        san_ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
    except x509.ExtensionNotFound:
        return False
    san = san_ext.value
    if not isinstance(san, x509.SubjectAlternativeName):  # pragma: no cover
        return False
    for uri in san.get_values_for_type(x509.UniformResourceIdentifier):
        if uri == agent_id:
            return True
    return False


def _basic_constraints_ca_false(cert: x509.Certificate) -> bool:
    """Return ``True`` when Basic Constraints declares ``CA:FALSE``."""
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
    except x509.ExtensionNotFound:
        return False
    bc = ext.value
    if not isinstance(bc, x509.BasicConstraints):  # pragma: no cover
        return False
    return bc.ca is False


def _key_usage_has_digital_signature(cert: x509.Certificate) -> bool:
    """Return ``True`` when Key Usage has the ``digitalSignature`` bit set."""
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
    except x509.ExtensionNotFound:
        return False
    ku = ext.value
    if not isinstance(ku, x509.KeyUsage):  # pragma: no cover
        return False
    return ku.digital_signature is True


def _key_usage_has_key_cert_sign(cert: x509.Certificate) -> bool:
    """Return ``True`` when Key Usage has the ``keyCertSign`` bit set."""
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
    except x509.ExtensionNotFound:
        return False
    ku = ext.value
    if not isinstance(ku, x509.KeyUsage):  # pragma: no cover
        return False
    return ku.key_cert_sign is True


# ----------------------------------------------------------------------
# Full chain verification (§6.4.1 step 4)
# ----------------------------------------------------------------------


def verify_certificate_chain(
    certificate_chain: list[str],
    agent_id: str,
    public_key_bytes: bytes,
    *,
    trust_store: list[x509.Certificate] | None = None,
    now: datetime | None = None,
    identity_record: dict[str, Any] | None = None,
) -> CertificateVerificationResult:
    """Execute ARSIA-Identity.md §6.4.1 step 4 against a candidate chain.

    Performs the following checks in order:

    1. Parse every PEM in the chain (step 4a).
    2. Verify each certificate is signed by the next one in the chain;
       the last certificate must either be self-signed or signed by a
       certificate in ``trust_store`` (step 4b).
    3. Check the leaf's ``notBefore`` / ``notAfter`` window against
       ``now`` (step 4c).
    4. Compare the leaf's raw Ed25519 public key to ``public_key_bytes``
       (step 4d).
    5. Look for ``agent_id`` as a URI in the leaf's Subject Alternative
       Name extension (step 4e).
    6. Check Subject O matches IdentityRecord ``owner_name`` (§6.2).
    7. Check Basic Constraints declares ``CA:FALSE`` and Key Usage has
       the ``digitalSignature`` bit (§6.2 requirements).
    8. Detect ``QcStatements`` on the leaf to upgrade to Level 3
       (step 4g).

    Revocation (OCSP / CRL — step 4h) is **not** performed. Callers
    that need revocation checks MUST layer them on top.

    Args:
        certificate_chain: Ordered list of PEM-encoded certificates.
            Leaf first, root last. May be empty, in which case the
            result is ``is_valid=True`` with ``trust_level="L1"``.
        agent_id: The agent identifier the SAN must contain.
        public_key_bytes: The 32-byte raw Ed25519 public key published
            in the agent's JWKS — must match the leaf certificate's
            embedded public key.
        trust_store: Optional list of trust anchor ``x509.Certificate``
            objects. When provided, the root of ``certificate_chain``
            may be signed by one of these anchors. When omitted, the
            last certificate in the chain must be self-signed.
        now: Optional override for "current time" — defaults to
            ``datetime.now(timezone.utc)``. Parametrising this keeps
            the tests for expiry / not-yet-valid deterministic.
        identity_record: Optional IdentityRecord dict. When provided,
            the leaf certificate's Subject Organization (O) is compared
            against the ``owner_name`` field (§6.2). When omitted, the
            Subject O check is skipped.

    Returns:
        A :class:`CertificateVerificationResult`. When any check
        fails, ``is_valid`` is ``False``, ``errors`` lists every
        failure reason, and ``trust_level`` drops to ``"L1"`` (the
        safe default per §6.4.1 rejection semantics).

    Spec: ARSIA-Identity.md §6.4.1 step 4, §6.2, §6.5.2.
    """
    errors: list[ValidationError] = []

    # --- empty / absent chain → Level 1 is valid ------------------
    if not certificate_chain:
        return CertificateVerificationResult(
            trust_level="L1",
            is_valid=True,
            errors=(),
            leaf_subject=None,
            expires_at=None,
        )

    # --- step 4a: parse every PEM ---------------------------------
    parsed: list[x509.Certificate] = []
    for i, pem in enumerate(certificate_chain):
        if not isinstance(pem, str):
            errors.append(
                ValidationError(
                    code="cert_chain_not_string",
                    message=f"chain[{i}]: entry is not a string",
                    details={"index": i},
                    spec_ref="Identity §6.4.1 step 4a",
                )
            )
            continue
        try:
            parsed.append(_parse_cert(pem))
        except ValueError as exc:
            errors.append(
                ValidationError(
                    code="cert_chain_parse_error",
                    message=f"chain[{i}]: {exc}",
                    details={"index": i},
                    spec_ref="Identity §6.4.1 step 4a",
                )
            )

    if not parsed or len(parsed) != len(certificate_chain):
        # Cannot continue meaningfully if any parse failed.
        return CertificateVerificationResult(
            trust_level="L1",
            is_valid=False,
            errors=tuple(errors),
            leaf_subject=None,
            expires_at=None,
        )

    leaf = parsed[0]
    leaf_subject = _leaf_subject_display(leaf)
    expires_at: str | None = None
    try:
        expires_at = _format_not_after(leaf)
    except (ValueError, AttributeError):  # pragma: no cover - defensive
        expires_at = None

    # --- step 4b: chain signatures --------------------------------
    for i in range(len(parsed) - 1):
        child = parsed[i]
        parent = parsed[i + 1]
        if not _verify_cert_signature(child, parent):
            errors.append(
                ValidationError(
                    code="cert_signature_invalid",
                    message=f"chain[{i}]: signature does not verify under chain[{i + 1}]",
                    details={"child_index": i, "parent_index": i + 1},
                    spec_ref="Identity §6.4.1 step 4b",
                )
            )

    # Anchor: last cert must be self-signed OR signed by a trust_store entry.
    anchor = parsed[-1]
    if trust_store:
        anchor_ok = False
        for trusted in trust_store:
            if _verify_cert_signature(anchor, trusted):
                anchor_ok = True
                break
        if not anchor_ok and not _verify_cert_signature(anchor, anchor):
            errors.append(
                ValidationError(
                    code="cert_anchor_untrusted",
                    message="chain anchor is not signed by any trust_store entry and is not self-signed",
                    spec_ref="Identity §6.4.1 step 4b",
                )
            )
    else:
        if not _verify_cert_signature(anchor, anchor):
            errors.append(
                ValidationError(
                    code="cert_root_not_self_signed",
                    message="chain root is not self-signed and no trust_store was provided",
                    spec_ref="Identity §6.4.1 step 4b, §6.4.2",
                )
            )

    # --- step 4c: validity period ---------------------------------
    current = now if now is not None else datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    not_before = leaf.not_valid_before_utc
    not_after = leaf.not_valid_after_utc
    if not_before.tzinfo is None:  # pragma: no cover - cryptography always sets tz
        not_before = not_before.replace(tzinfo=timezone.utc)
    if not_after.tzinfo is None:  # pragma: no cover
        not_after = not_after.replace(tzinfo=timezone.utc)
    if current < not_before:
        errors.append(
            ValidationError(
                code="cert_not_yet_valid",
                message=f"leaf certificate is not yet valid: notBefore={not_before.isoformat()}",
                details={"not_before": not_before.isoformat()},
                spec_ref="Identity §6.4.1 step 4c",
            )
        )
    if current > not_after:
        errors.append(
            ValidationError(
                code="certificate_expired",
                message=f"leaf certificate is expired: notAfter={not_after.isoformat()}",
                details={"not_after": not_after.isoformat()},
                spec_ref="Identity §6.4.1 step 4c",
            )
        )

    # --- step 4d: public key consistency --------------------------
    leaf_pub = leaf.public_key()
    if isinstance(leaf_pub, ed25519.Ed25519PublicKey):
        if leaf_pub.public_bytes_raw() != public_key_bytes:
            errors.append(
                ValidationError(
                    code="key_mismatch",
                    message="leaf certificate public key does not match the supplied JWKS key",
                    spec_ref="Identity §6.4.1 step 4d",
                )
            )
    else:
        errors.append(
            ValidationError(
                code="cert_key_not_ed25519",
                message="leaf certificate public key is not Ed25519",
                spec_ref="Identity §6.2",
            )
        )

    # --- step 4e: SAN contains agent_id ---------------------------
    if not _san_contains_agent_id(leaf, agent_id):
        errors.append(
            ValidationError(
                code="agent_id_not_in_san",
                message=f"leaf SAN does not contain URI {agent_id!r}",
                details={"agent_id": agent_id},
                spec_ref="Identity §6.4.1 step 4e",
            )
        )

    # --- step 4f: Subject O vs IdentityRecord owner_name -----------
    if identity_record is not None:
        owner_name = identity_record.get("owner_name")
        subject_o = _extract_subject_organization(leaf)
        if subject_o is not None and owner_name is not None and subject_o != owner_name:
            errors.append(
                ValidationError(
                    code="subject_organization_mismatch",
                    message=(
                        f"certificate Subject O {subject_o!r} does not match "
                        f"IdentityRecord owner_name {owner_name!r}"
                    ),
                    details={"subject_o": subject_o, "owner_name": owner_name},
                    spec_ref="Identity §6.2",
                )
            )

    # --- §6.2 structural checks -----------------------------------
    if not _basic_constraints_ca_false(leaf):
        errors.append(
            ValidationError(
                code="cert_basic_constraints_missing",
                message="leaf certificate missing Basic Constraints CA:FALSE",
                spec_ref="Identity §6.2",
            )
        )
    if not _key_usage_has_digital_signature(leaf):
        errors.append(
            ValidationError(
                code="cert_digital_signature_missing",
                message="leaf certificate missing Key Usage digitalSignature",
                spec_ref="Identity §6.2",
            )
        )
    if _key_usage_has_key_cert_sign(leaf):
        errors.append(
            ValidationError(
                code="cert_key_cert_sign_present",
                message="leaf certificate MUST NOT have keyCertSign Key Usage bit",
                spec_ref="Identity §6.2",
            )
        )

    # --- step 4g: Level 3 detection -------------------------------
    level_3 = False
    try:
        level_3 = has_qc_statements(
            leaf.public_bytes(serialization.Encoding.PEM).decode("ascii")
        )
    except ValueError:  # pragma: no cover - parsed leaf always re-encodes
        level_3 = False

    if errors:
        return CertificateVerificationResult(
            trust_level="L1",
            is_valid=False,
            errors=tuple(errors),
            leaf_subject=leaf_subject,
            expires_at=expires_at,
        )

    return CertificateVerificationResult(
        trust_level="L3" if level_3 else "L2",
        is_valid=True,
        errors=(),
        leaf_subject=leaf_subject,
        expires_at=expires_at,
    )


def is_certificate_chain_expired(
    chain: list[str] | None,
    *,
    now: datetime | None = None,
) -> bool:
    """Pre-serve check that any certificate in the chain has expired.

    ARSIA-Identity.md §6.5.1 prohibits agents from serving an
    IdentityRecord whose ``certificate_chain`` contains an expired
    certificate. Agents SHOULD call this helper before publishing
    their IdentityRecord and refresh / re-issue any expired entry.

    Unlike :func:`verify_certificate_chain`, this function does not
    inspect signatures, SAN bindings, or QcStatements — it only checks
    each certificate's ``notAfter`` against ``now``. It is intended as
    the cheap pre-flight gate for the *serve* side; the *verify* side
    still calls :func:`verify_certificate_chain` for the full §6.4.1
    procedure.

    Args:
        chain: Ordered list of PEM-encoded certificates, leaf first
            (the same shape as :func:`verify_certificate_chain`'s
            input). May be ``None`` or empty.
        now: Reference instant. Defaults to ``datetime.now(UTC)``;
            tests pass an explicit value for determinism.

    Returns:
        ``True`` iff *any* certificate in the chain has ``notAfter``
        earlier than ``now``. ``False`` for an empty/``None`` chain
        or when every certificate is still within its validity
        window. Unparseable PEM entries are treated as expired so
        that broken chains never get served.

    Spec: ARSIA-Identity.md §6.5.1, §6.5.3.
    """
    if not chain:
        return False
    current = now if now is not None else datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    for pem in chain:
        if not isinstance(pem, str):
            return True
        try:
            cert = _parse_cert(pem)
        except ValueError:
            return True
        not_after = cert.not_valid_after_utc
        if not_after.tzinfo is None:  # pragma: no cover
            not_after = not_after.replace(tzinfo=timezone.utc)
        if current > not_after:
            return True
    return False


__all__ = [
    "TrustLevel",
    "QC_STATEMENTS_OID",
    "CertificateVerificationResult",
    "compute_trust_level",
    "verify_certificate_chain",
    "extract_public_key_from_cert",
    "has_qc_statements",
    "is_certificate_chain_expired",
]
