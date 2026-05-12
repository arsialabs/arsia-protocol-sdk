# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Command-line interface for the ARSIA Protocol SDK.

Invoke via ``python -m arsia_protocol <command>`` or the ``arsia``
entry-point script installed from ``pyproject.toml``'s ``[project.scripts]``.

Commands
--------

* ``keygen``        — generate a fresh Ed25519 keypair (PEM, JSON, or JWK)
* ``verify``        — verify a signed envelope against a JWK
* ``canonicalize``  — emit the JCS-canonical bytes for a JSON document
* ``inspect``       — pretty-print an envelope with pipeline diagnostics
* ``schemas``       — list bundled JSON Schemas (``schemas show NAME``
                      prints a single schema)
* ``vectors``       — list bundled test vectors (``vectors run``
                      executes the bundled conformance suite)
* ``profiles``      — list bundled compliance profiles
* ``version``       — print SDK + protocol versions

The CLI is a thin wrapper around the public SDK API. It exists for
operator ergonomics (debugging wire bytes, generating keys during
bootstrap) and is NOT a configuration surface for production agents —
those should import the SDK directly.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

try:
    import click
except ImportError as exc:  # pragma: no cover - import guard
    raise ImportError(
        "arsia_protocol.__main__ requires the 'cli' extra. "
        "Install with: pip install 'arsia-protocol[cli]'"
    ) from exc

from arsia_protocol import _data_resolver
from arsia_protocol.core import version
from arsia_protocol.core.compliance import get_profile, get_profile_names
from arsia_protocol.hazmat.canonicalization import canonicalize as _canonicalize
from arsia_protocol.hazmat.primitives.ed25519 import (
    base64url_encode,
    generate_keypair,
    public_key_from_bytes,
    public_key_to_jwk_dict,
)
from arsia_protocol.core.message import verify_message


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_text(target: Path | None, data: str) -> None:
    if target is None:
        click.echo(data)
    else:
        target.write_text(data, encoding="utf-8")


@click.group(
    help=(
        "ARSIA Protocol SDK command-line utilities. Use a subcommand to "
        "generate keys, inspect envelopes, verify signatures, or enumerate "
        "bundled artifacts."
    )
)
@click.version_option(
    version.__version__, "-V", "--version", package_name="arsia-protocol"
)
def cli() -> None:
    """Top-level ``arsia`` command."""


# ---------------------------------------------------------------------------
# keygen
# ---------------------------------------------------------------------------


@cli.command("keygen")
@click.option(
    "--kid",
    default=None,
    help="Key identifier (e.g., 'agent:acme.bot#k1'). Required for 'json' "
    "and 'jwk' formats; ignored for 'pem'.",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["pem", "json", "jwk"]),
    default="pem",
    help="Output format. 'pem' (default) emits a PKCS#8 PEM-encoded "
    "Ed25519 private key — the format loadable by cryptography's "
    "``load_pem_private_key``. 'json' emits a JSON object with hex + "
    "base64url + JWK representations for advanced use. 'jwk' emits the "
    "public key as an RFC 8037 JWK dict, suitable for populating "
    "discovery JWKS endpoints (Core §7.3).",
)
@click.option(
    "--out",
    type=click.Path(dir_okay=False, writable=True, path_type=Path),
    default=None,
    help="Write output to FILE instead of stdout.",
)
def keygen(kid: str | None, fmt: str, out: Path | None) -> None:
    """Generate a fresh Ed25519 keypair."""
    from cryptography.hazmat.primitives import serialization

    priv, pub = generate_keypair()
    if fmt == "pem":
        pem_bytes = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        if out is None:
            sys.stdout.buffer.write(pem_bytes)
        else:
            out.write_bytes(pem_bytes)
        return

    if kid is None:
        raise click.ClickException(f"--kid is required when --format is '{fmt}'.")
    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = pub.public_bytes_raw()
    jwk = public_key_to_jwk_dict(pub, kid)
    if fmt == "jwk":
        body = json.dumps(jwk, indent=2)
    else:  # fmt == "json"
        body = json.dumps(
            {
                "private_hex": priv_raw.hex(),
                "public_hex": pub_raw.hex(),
                "public_b64url": base64url_encode(pub_raw),
                "jwk": jwk,
                "kid": kid,
            },
            indent=2,
        )
    _write_text(out, body)


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


@cli.command("verify")
@click.argument(
    "envelope_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--jwk",
    "jwk_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to the sender's JWK (JSON with 'x' base64url 32-byte key).",
)
def verify(envelope_path: Path, jwk_path: Path) -> None:
    """Verify the signature on an ARSIA envelope."""
    envelope = _load_json(envelope_path)
    jwk = _load_json(jwk_path)
    x = jwk.get("x") if isinstance(jwk, dict) else None
    if not isinstance(x, str):
        raise click.ClickException("JWK is missing a base64url 'x' field.")
    from arsia_protocol.hazmat.primitives.ed25519 import base64url_decode

    raw = base64url_decode(x)
    if len(raw) != 32:
        raise click.ClickException(f"JWK 'x' must decode to 32 bytes (got {len(raw)}).")
    public_key = public_key_from_bytes(raw)
    ok = verify_message(envelope, public_key)
    if ok:
        click.echo("VALID")
    else:
        click.echo("INVALID", err=True)
        sys.exit(1)


# ---------------------------------------------------------------------------
# canonicalize
# ---------------------------------------------------------------------------


@cli.command("canonicalize")
@click.argument(
    "json_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--out",
    type=click.Path(dir_okay=False, writable=True, path_type=Path),
    default=None,
    help="Write canonical bytes to FILE instead of stdout.",
)
def canonicalize(json_path: Path, out: Path | None) -> None:
    """Emit JCS-canonical bytes (RFC 8785) for a JSON document."""
    doc = _load_json(json_path)
    if not isinstance(doc, (dict, list)):
        raise click.ClickException(
            "JCS canonicalization requires a JSON object or array at the root."
        )
    body = _canonicalize(doc)
    if out is None:
        sys.stdout.buffer.write(body)
    else:
        out.write_bytes(body)


# ---------------------------------------------------------------------------
# inspect
# ---------------------------------------------------------------------------


@cli.command("inspect")
@click.argument(
    "envelope_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
def inspect(envelope_path: Path) -> None:
    """Pretty-print an envelope with basic diagnostics."""
    envelope = _load_json(envelope_path)
    if not isinstance(envelope, dict):
        raise click.ClickException("Envelope must be a JSON object.")
    from arsia_protocol.core.validation import validate_schema, validate_semantic

    summary: dict[str, Any] = {
        "v": envelope.get("v"),
        "id": envelope.get("id"),
        "from": envelope.get("from"),
        "to": envelope.get("to"),
        "intent": envelope.get("intent"),
        "payload_type": (envelope.get("payload") or {}).get("type"),
        "ts": envelope.get("ts"),
        "expires_at": envelope.get("expires_at"),
        "has_security": isinstance(envelope.get("security"), dict),
        "kid": (envelope.get("security") or {}).get("kid"),
    }
    l1 = validate_schema(envelope)
    l2 = validate_semantic(envelope) if not l1 else []
    click.echo(
        json.dumps(
            {"summary": summary, "l1_errors": l1, "l2_errors": l2},
            indent=2,
            default=str,
        )
    )


# ---------------------------------------------------------------------------
# schemas / vectors / profiles
# ---------------------------------------------------------------------------


def _list_schema_files() -> list[Path]:
    root = _data_resolver.schemas_dir()
    return sorted(root.rglob("*.json"))


def _schema_name_index() -> dict[str, Path]:
    """Map both bare names ('arsia-message') and file names to their path."""
    index: dict[str, Path] = {}
    for path in _list_schema_files():
        index[path.name] = path
        if path.name.endswith(".schema.json"):
            index[path.name[: -len(".schema.json")]] = path
    return index


@cli.group("schemas", invoke_without_command=True)
@click.pass_context
def schemas(ctx: click.Context) -> None:
    """List bundled JSON Schemas (default) or show one with ``show NAME``."""
    if ctx.invoked_subcommand is None:
        ctx.invoke(schemas_list)


@schemas.command("list")
def schemas_list() -> None:
    """List bundled JSON Schemas."""
    root = _data_resolver.schemas_dir()
    for path in _list_schema_files():
        click.echo(str(path.relative_to(root)))


@schemas.command("show")
@click.argument("name")
def schemas_show(name: str) -> None:
    """Print the JSON Schema named NAME (e.g., 'arsia-message')."""
    index = _schema_name_index()
    path = index.get(name)
    if path is None:
        click.echo(f"Unknown schema: {name!r}", err=True)
        click.echo("Available schemas:", err=True)
        for candidate in sorted({p.name for p in _list_schema_files()}):
            short = (
                candidate[: -len(".schema.json")]
                if candidate.endswith(".schema.json")
                else candidate
            )
            click.echo(f"  {short}", err=True)
        sys.exit(1)
    doc = _load_json(path)
    click.echo(json.dumps(doc, indent=2))


@cli.group("vectors", invoke_without_command=True)
@click.pass_context
def vectors(ctx: click.Context) -> None:
    """List bundled test vectors (default) or execute them with ``run``."""
    if ctx.invoked_subcommand is None:
        ctx.invoke(vectors_list)


@vectors.command("list")
def vectors_list() -> None:
    """List bundled test vector files."""
    root = _data_resolver.test_vectors_dir()
    for path in sorted(root.rglob("*.json")):
        click.echo(str(path.relative_to(root)))


# Partition of invalid vectors by the validator that owns the rule they
# violate. Mirrors python/tests/vectors/test_vectors.py — kept in sync
# manually since the CLI intentionally does not import test code.
_VECTORS_SLICE_1D_INVALID: dict[str, str] = {
    "INV-01": "from",
    "INV-02": "id",
    "INV-03": "ts",
    "INV-04": "from",
    "INV-05": "expires_at",
    "INV-06": "legal_basis",
    "INV-07": "profile",
    "INV-08": "retention_days",
    "INV-11": "kid",
}
_VECTORS_SLICE_4D_INVALID: dict[str, str] = {
    "INV-10": "capabilit",
}
_VECTORS_SLICE_6_INVALID: dict[str, str] = {
    "INV-09": "currency amount precision exceeds 2 decimal places",
    "INV-12": "reversal requires original transfer status completed",
}


def _run_schema_vector(vector: dict[str, Any]) -> tuple[bool, str]:
    """Validate a Format B (schema) vector against its named schema."""
    from arsia_protocol.core.validation import validate_schema

    data = vector.get("data") or vector.get("message")
    if data is None:
        return False, "vector has neither 'data' nor 'message' key"
    errors = validate_schema(data, vector["schema_ref"])
    want_valid = vector["expected"] == "valid"
    if want_valid:
        if errors:
            return False, f"L1 schema errors: {errors[0]}"
        return True, ""
    if not errors:
        return False, "expected schema rejection but data passed"
    return True, ""


def _run_valid_vector(vector: dict[str, Any]) -> tuple[bool, str]:
    """Reproduce canonicalization + signing + verification for a valid vector.

    Returns (ok, detail). ``detail`` is empty on success, or a short
    failure reason on error.
    """
    import copy

    from arsia_protocol.hazmat.primitives.ed25519 import (
        private_key_from_hex,
        public_key_from_hex,
        sign as raw_sign,
    )
    from arsia_protocol.core.validation import validate_schema

    crypto = vector.get("crypto")
    if not isinstance(crypto, dict):
        return False, "missing crypto block"
    alg = vector.get("message", {}).get("security", {}).get("alg", "EdDSA")
    if alg != "EdDSA":
        return True, f"skipped (algorithm {alg}, SDK supports EdDSA only)"
    unsigned = copy.deepcopy(vector["message"])
    unsigned.pop("security", None)
    produced = _canonicalize(unsigned)
    expected_bytes = bytes.fromhex(crypto["canonical_bytes_hex"])
    if produced != expected_bytes:
        return False, "canonical bytes mismatch"
    sk = private_key_from_hex(crypto["private_key_hex"])
    sig = raw_sign(sk, produced)
    if base64url_encode(sig) != crypto["signature_base64url"]:
        return False, "signature mismatch"
    pk = public_key_from_hex(crypto["public_key_hex"])
    if verify_message(vector["message"], pk) is not True:
        return False, "verify_message returned False"
    errors = validate_schema(vector["message"])
    if errors:
        return False, f"L1 schema errors: {errors[0]}"
    return True, ""


def _run_invalid_vector(vector: dict[str, Any]) -> tuple[bool, str]:
    """Confirm an invalid vector is rejected by the correct validator.

    Returns (ok, detail). ``ok`` is True when the vector is rejected
    with an error mentioning the expected keyword.
    """
    from arsia_protocol.core.validation import validate_envelope

    vid = vector["id"]
    message = vector["message"]
    if vid in _VECTORS_SLICE_1D_INVALID or vid in _VECTORS_SLICE_4D_INVALID:
        keyword = _VECTORS_SLICE_1D_INVALID.get(vid) or _VECTORS_SLICE_4D_INVALID[vid]
        errors = validate_envelope(message, strict=False)
        if not errors:
            return False, "validate_envelope accepted an invalid vector"
        if not any(keyword.lower() in str(e).lower() for e in errors):
            return False, f"no error mentioned {keyword!r}"
        return True, ""
    if vid in _VECTORS_SLICE_6_INVALID:
        from arsia_protocol._errors import ValidationError as _VE
        from arsia_protocol.assets.assets import (
            validate_reversal_precondition,
            validate_transfer_request,
            validate_transfer_reversal,
        )

        keyword = _VECTORS_SLICE_6_INVALID[vid]
        args = message["payload"]["args"]
        asset_errors: list[_VE]
        if vid == "INV-09":
            asset_errors = validate_transfer_request(args)
        else:  # INV-12
            asset_errors = validate_transfer_reversal(args)
            asset_errors.extend(
                validate_reversal_precondition(args, original_status="pending")
            )
        if not asset_errors:
            return False, "assets validator accepted an invalid vector"
        if not any(keyword.lower() in str(e).lower() for e in asset_errors):
            return False, f"no error mentioned {keyword!r}"
        return True, ""
    return False, f"unclassified invalid vector {vid!r}"


@vectors.command("run")
@click.option(
    "--output-format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format: 'text' (default) for human-readable, 'json' for machine-readable.",
)
def vectors_run(output_format: str) -> None:
    """Execute the bundled conformance test vectors and report PASS/FAIL."""
    vectors_path = _data_resolver.test_vectors_dir() / "arsia-test-vectors.json"
    doc = _load_json(vectors_path)
    entries = list(doc.get("vectors", []))
    results: list[dict[str, Any]] = []
    for entry in entries:
        vid = entry["id"]
        if "schema_ref" in entry:
            ok, detail = _run_schema_vector(entry)
            label = f"schema ({entry['expected']})"
        elif entry.get("valid"):
            ok, detail = _run_valid_vector(entry)
            label = "valid"
        else:
            ok, detail = _run_invalid_vector(entry)
            label = "invalid (correctly rejected)" if ok else "invalid"
        results.append(
            {
                "vector_id": vid,
                "status": "PASS" if ok else "FAIL",
                "label": label,
                "detail": detail if detail else None,
            }
        )
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")
    if output_format == "json":
        click.echo(json.dumps(results, indent=2))
    else:
        click.echo(f"Running {len(entries)} test vectors...")
        for r in results:
            line = f"  {r['vector_id']:<8} {r['label']:<30} {r['status']}"
            if r["status"] == "FAIL" and r["detail"]:
                line = f"{line} — {r['detail']}"
            click.echo(line)
        click.echo("")
        click.echo(f"{passed} passed, {failed} failed")
    if failed:
        sys.exit(1)


@cli.command("profiles")
@click.argument("name", required=False)
def profiles(name: str | None) -> None:
    """List bundled compliance profiles (or print one when NAME is given)."""
    if name is None:
        for n in get_profile_names():
            click.echo(n)
        return
    try:
        profile = get_profile(name)
    except KeyError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(json.dumps(profile, indent=2, default=str))


# ---------------------------------------------------------------------------
# version
# ---------------------------------------------------------------------------


@cli.command("version")
def version_cmd() -> None:
    """Print SDK package version and wire protocol version."""
    click.echo(
        json.dumps(
            {
                "sdk_version": version.__version__,
                "protocol_version": version.PROTOCOL_VERSION,
            },
            indent=2,
        )
    )


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    cli()
