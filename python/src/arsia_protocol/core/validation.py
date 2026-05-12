# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Two-layer envelope validation: L1 schema + L2 semantic rules.

This module is Layer 3 in the SDK dependency graph. It imports from
Layer 1 (``types``), Layer 0 (``identity``, ``_data_resolver``), and
Layer 2 (``compliance``). It must not import from ``message``,
``errors``, or ``hazmat``.

Validation proceeds in two layers:

- **L1 — Schema (structural).** The envelope is validated against the
  bundled JSON Schemas in ``shared/schemas/`` using
  ``jsonschema.Draft202012Validator``. L1 catches type errors,
  missing required fields, and bad patterns.
- **L2 — Semantic (behavioural).** The envelope is checked against
  the MUST / MUST NOT rules from ARSIA-Core.md §4 that cannot be
  expressed as a JSON Schema constraint: intent-conditional fields,
  ``expires_at > ts``, ``kid`` prefix ↔ ``from`` binding, and the
  compliance rules in §4.3.8.

:func:`validate_envelope` is the canonical entry point. It runs L1
first; if L1 reports any error, L2 is skipped (a structurally broken
envelope cannot be meaningfully checked for semantic rules).

The ``strict`` flag promotes SHOULD-level rules (e.g. unknown
compliance profile names) to errors. Use ``strict=True`` in
conformance test runs and ``strict=False`` in production.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema import ValidationError as JsonSchemaValidationError
import referencing.exceptions
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from arsia_protocol._data_resolver import schemas_dir
from arsia_protocol.core.compliance import validate_compliance
from arsia_protocol.identity.agent_id import is_valid_agent_id
from arsia_protocol.types.actions import CAPABILITY_PATTERN
from arsia_protocol.types.errors import ValidationError
from arsia_protocol.core.version import PROTOCOL_VERSION, parse_version

logger = logging.getLogger(__name__)

_SCHEMA_CACHE: dict[str, dict[str, Any]] = {}
"""Lazy cache of JSON Schema documents keyed by filename."""

_REGISTRY_CACHE: Registry[Any] | None = None
"""Lazy cache of the referencing.Registry built from all local schemas."""

_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
"""Base64url alphabet without padding (Core §5.1 Step 5, §5.2 Step 1)."""

_REGEX_HUMAN_READABLE: dict[str, str] = {
    "agent:": "must be in agent:org.name format (e.g., agent:acme.billing)",
    "]{8}-": "must be a UUID v4 (e.g., 550e8400-e29b-41d4-a716-446655440000)",
    "^\\d+\\.\\d+$": "must be a semver string (e.g., 1.0)",
    "[a-zA-Z][a-zA-Z0-9]*(\\.": (
        "must have ≥2 dot-separated segments (e.g., com.acme.billing.create-invoice)"
    ),
}

INTENT_CONTENT_FIELD: dict[str, str] = {
    "request": "args",
    "response": "result",
    "event": "data",
    "error": "error",
    "pending_approval": "args",
    "approval_decision": "result",
}
"""Intent → expected content field mapping per Core §4.4.7."""

_CONTENT_FIELDS = frozenset({"args", "result", "data", "error"})
"""The four mutually-exclusive payload content fields (Core §4.4.7)."""


class PayloadTypeRegistry:
    """Registry of recognised payload types (Core §4.4.1).

    Implementations MUST reject messages with payload types they do not
    recognise. This registry provides the ``is_recognized`` check that
    :func:`validate_semantic` uses when a registry is supplied.
    """

    def __init__(self) -> None:
        self._types: set[str] = set()

    def register(self, *payload_types: str) -> None:
        """Register one or more payload types as recognised."""
        self._types.update(payload_types)

    def is_recognized(self, payload_type: str) -> bool:
        """Return ``True`` if ``payload_type`` has been registered."""
        return payload_type in self._types

    def registered_types(self) -> frozenset[str]:
        """Return a frozen copy of the registered type set."""
        return frozenset(self._types)


def resolve_content_field(
    envelope: dict[str, Any],
) -> tuple[str, Any]:
    """Return the intent-matching content field name and value.

    Implements the §4.4.7 rule: MUST process the field corresponding to
    the message intent and MUST ignore the others. If multiple content
    fields are present, a warning is logged but no error is raised.

    Args:
        envelope: An ARSIA envelope dict.

    Returns:
        A ``(field_name, value)`` tuple. The value may be ``None`` if
        the expected field is absent from the payload.

    Raises:
        ValueError: If ``intent`` is missing or unrecognised, or if
            ``payload`` is not a dict.
    """
    intent = envelope.get("intent")
    if not isinstance(intent, str) or intent not in INTENT_CONTENT_FIELD:
        raise ValueError(f"Unknown or missing intent: {intent!r}")
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("payload must be a dict to resolve content fields")

    expected_field = INTENT_CONTENT_FIELD[intent]

    present = [f for f in _CONTENT_FIELDS if payload.get(f) is not None]
    if len(present) > 1:
        ignored = [f for f in present if f != expected_field]
        logger.warning(
            "Multiple content fields present in payload: %s; "
            "processing '%s' per intent='%s', ignoring %s (Core §4.4.7)",
            present,
            expected_field,
            intent,
            ignored,
        )

    return expected_field, payload.get(expected_field)


def _retrieve_local_schema(uri: str) -> Resource[Any]:
    filename = uri.rsplit("/", 1)[-1]
    path = schemas_dir() / filename
    if path.is_file():
        with path.open("r", encoding="utf-8") as fh:
            contents = json.load(fh)
        return Resource.from_contents(contents, default_specification=DRAFT202012)
    raise referencing.exceptions.NoSuchResource(ref=uri)  # type: ignore[call-arg]


def _get_schema_registry() -> Registry[Any]:
    global _REGISTRY_CACHE  # noqa: PLW0603
    if _REGISTRY_CACHE is not None:
        return _REGISTRY_CACHE
    pairs: list[tuple[str, Resource[Any]]] = []
    for path in sorted(schemas_dir().glob("*.json")):
        with path.open("r", encoding="utf-8") as fh:
            contents = json.load(fh)
        if "$id" in contents:
            resource = Resource.from_contents(
                contents, default_specification=DRAFT202012
            )
            pairs.append((contents["$id"], resource))
    _REGISTRY_CACHE = Registry(retrieve=_retrieve_local_schema).with_resources(pairs)  # type: ignore[call-arg]
    return _REGISTRY_CACHE


def _load_schema(name: str) -> dict[str, Any]:
    """Load and cache a JSON Schema by filename, with optional JSON Pointer.

    Args:
        name: Schema reference — either a plain filename
            (``"arsia-message.schema.json"``) or a filename with a
            JSON Pointer fragment
            (``"arsia-common.schema.json#/$defs/agent_id"``).

    Returns:
        The parsed schema document or the resolved sub-schema.

    Raises:
        FileNotFoundError: if the schema file does not exist.
        KeyError: if the JSON Pointer fragment does not resolve.
    """
    if name not in _SCHEMA_CACHE:
        filename, _, fragment = name.partition("#")
        path = schemas_dir() / filename
        with path.open("r", encoding="utf-8") as fh:
            schema = json.load(fh)
        if fragment:
            for part in fragment.strip("/").split("/"):
                schema = schema[part]
        _SCHEMA_CACHE[name] = schema
    return _SCHEMA_CACHE[name]


def _format_jsonschema_error(err: JsonSchemaValidationError) -> ValidationError:
    """Format a ``jsonschema`` validation error as a :class:`ValidationError`.

    Produces a structured error with ``code="schema_violation"`` and
    ``details`` carrying the JSON Pointer path and validator type.
    Pattern-mismatch errors are replaced with human-readable descriptions.
    """
    pointer = "/" + "/".join(str(p) for p in err.absolute_path)
    if pointer == "/":
        pointer = "<root>"
    msg = err.message
    if err.validator == "pattern" and isinstance(err.validator_value, str):
        for substring, description in _REGEX_HUMAN_READABLE.items():
            if substring in err.validator_value:
                msg = f"{err.instance!r} {description}"
                break
    return ValidationError(
        code="schema_violation",
        message=f"{pointer}: {msg}",
        details={"path": pointer, "validator": err.validator},
        spec_ref="Core §4",
    )


def validate_schema(
    envelope: dict[str, Any],
    schema_name: str = "arsia-message.schema.json",
) -> list[ValidationError]:
    """Run L1 (JSON Schema) validation against ``envelope``.

    Uses :class:`jsonschema.Draft202012Validator` directly rather than
    ``jsonschema.validate()`` because the top-level helper does not
    default to Draft 2020-12.

    Args:
        envelope: The envelope (or any JSON-compatible object) to
            validate.
        schema_name: Filename of the schema to use. Defaults to
            ``"arsia-message.schema.json"``.

    Returns:
        A list of :class:`ValidationError` with ``code="schema_violation"``.
        Empty means the envelope passes schema validation.

    Spec: ARSIA-Core.md §4; JSON Schema Draft 2020-12.
    """
    schema = _load_schema(schema_name)
    validator = Draft202012Validator(schema, registry=_get_schema_registry())
    errors: list[ValidationError] = []
    for err in sorted(validator.iter_errors(envelope), key=lambda e: e.path):
        errors.append(_format_jsonschema_error(err))
    return errors


def _parse_rfc3339_ms(value: str) -> datetime | None:
    """Parse an ARSIA RFC 3339 millisecond timestamp.

    Returns ``None`` when the string cannot be parsed as a timezone-aware
    datetime. L1 already rejects syntactically malformed timestamps;
    this helper is defensive.
    """
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def validate_semantic(
    envelope: dict[str, Any],
    *,
    strict: bool = False,
    payload_type_registry: PayloadTypeRegistry | None = None,
) -> list[ValidationError]:
    """Run L2 (semantic) validation against ``envelope``.

    Checks the MUST / MUST NOT rules from ARSIA-Core.md §4 that cannot
    be expressed as JSON Schema constraints:

    - ``from`` / ``to`` are valid ARSIA agent identifiers (§3.3).
    - Intent-conditional fields: ``capabilities`` + ``expires_at`` for
      ``request``, ``expires_at`` for ``pending_approval``,
      ``correlation_id`` for ``response`` / ``error`` /
      ``approval_decision``.
    - ``intent='error'`` implies a non-empty
      ``payload.error.{code,description}``.
    - ``capabilities`` is non-empty and has unique entries when
      present.
    - ``expires_at`` is strictly greater than ``ts`` (when both are
      present).
    - ``security.kid`` starts with ``from + "#"`` (§5.2 Step 6).
    - ``security.sig`` is a well-formed base64url string.
    - When ``payload_type_registry`` is provided, the ``payload.type``
      must be a recognised type (§4.4.1).
    - The compliance rules in §4.3.8 via
      :func:`arsia_protocol.compliance.validate_compliance`.

    Args:
        envelope: The envelope to validate.
        strict: When ``True``, SHOULD-level compliance rules (e.g.
            unknown profile names) are promoted to errors.
        payload_type_registry: Optional registry of recognised payload
            types. When provided, unrecognised types produce an error
            per §4.4.1.

    Returns:
        A list of :class:`ValidationError`. Empty means the envelope
        passes semantic validation.

    Spec: ARSIA-Core.md §4, §4.3.8, §5.2.
    """
    errors: list[ValidationError] = []

    # --- Agent identifiers ---------------------------------------------
    from_agent = envelope.get("from")
    if not isinstance(from_agent, str) or not is_valid_agent_id(from_agent):
        errors.append(
            ValidationError(
                code="invalid_from_agent_id",
                message=f"'from' is not a valid ARSIA agent identifier: {from_agent!r}",
                details={"field": "from"},
                spec_ref="Core §3.3",
            )
        )
    to_agent = envelope.get("to")
    if not isinstance(to_agent, str) or not is_valid_agent_id(to_agent):
        errors.append(
            ValidationError(
                code="invalid_to_agent_id",
                message=f"'to' is not a valid ARSIA agent identifier: {to_agent!r}",
                details={"field": "to"},
                spec_ref="Core §3.3",
            )
        )

    intent = envelope.get("intent")

    # --- Minimum version check (§4.3.1) --------------------------------
    # If the sender set min_v and the SDK's PROTOCOL_VERSION is below it,
    # the recipient MUST reject with not_implemented — validation reports
    # the mismatch here; the transport layer surfaces it as the error code.
    min_v = envelope.get("min_v")
    if isinstance(min_v, str):
        required: tuple[int, int] | None
        ours: tuple[int, int] | None
        try:
            required = parse_version(min_v)
            ours = parse_version(PROTOCOL_VERSION)
        except ValueError:
            required = None
            ours = None
        if required is not None and ours is not None and ours < required:
            errors.append(
                ValidationError(
                    code="unsupported_min_v",
                    message=(
                        f"min_v {min_v!r} exceeds this SDK's PROTOCOL_VERSION "
                        f"{PROTOCOL_VERSION!r} — recipient MUST respond with "
                        "not_implemented"
                    ),
                    details={"min_v": min_v, "protocol_version": PROTOCOL_VERSION},
                    spec_ref="Core §4.3.1",
                )
            )

    # --- Major version ceiling (§4.1.1) ---------------------------------
    v_field = envelope.get("v")
    if isinstance(v_field, str):
        try:
            v_parsed = parse_version(v_field)
            max_major = parse_version(PROTOCOL_VERSION)[0]
            if v_parsed[0] > max_major:
                errors.append(
                    ValidationError(
                        code="unsupported_protocol_version",
                        message=(
                            f"v {v_field!r} has major version {v_parsed[0]} which "
                            f"exceeds the maximum supported major version "
                            f"{max_major}"
                        ),
                        details={
                            "v": v_field,
                            "major": v_parsed[0],
                            "max_supported_major": max_major,
                        },
                        spec_ref="Core §4.1.1",
                    )
                )
        except ValueError:
            pass

    # --- Intent-conditional fields -------------------------------------
    if intent == "request":
        if envelope.get("expires_at") is None:
            errors.append(
                ValidationError(
                    code="missing_expires_at",
                    message="expires_at is required when intent='request'",
                    details={"field": "expires_at", "intent": "request"},
                    spec_ref="Core §4.2.2",
                )
            )
        capabilities = envelope.get("capabilities")
        if capabilities is None:
            errors.append(
                ValidationError(
                    code="missing_capabilities",
                    message="capabilities is required when intent='request'",
                    details={"field": "capabilities", "intent": "request"},
                    spec_ref="Core §4.2.3",
                )
            )
        elif not isinstance(capabilities, list) or len(capabilities) == 0:
            errors.append(
                ValidationError(
                    code="empty_capabilities",
                    message="capabilities must be a non-empty list when intent='request'",
                    details={"field": "capabilities", "intent": "request"},
                    spec_ref="Core §4.2.3",
                )
            )
        elif len(set(capabilities)) != len(capabilities):
            errors.append(
                ValidationError(
                    code="duplicate_capabilities",
                    message="capabilities must contain unique entries",
                    details={"field": "capabilities"},
                    spec_ref="Core §4.2.3",
                )
            )
        else:
            for cap in capabilities:
                if isinstance(cap, str) and not CAPABILITY_PATTERN.fullmatch(cap):
                    errors.append(
                        ValidationError(
                            code="invalid_capability_format",
                            message=(
                                f"capability {cap!r} does not match the Actions §1.1 "
                                "grammar — must have at least 2 dot-separated segments"
                            ),
                            details={"capability": cap},
                            spec_ref="Actions §1.1",
                        )
                    )
    elif intent == "pending_approval":
        if envelope.get("expires_at") is None:
            errors.append(
                ValidationError(
                    code="missing_expires_at",
                    message="expires_at is required when intent='pending_approval'",
                    details={"field": "expires_at", "intent": "pending_approval"},
                    spec_ref="Core §4.2.2",
                )
            )
    elif intent in ("response", "error", "approval_decision"):
        if envelope.get("correlation_id") is None:
            errors.append(
                ValidationError(
                    code="missing_correlation_id",
                    message=f"correlation_id is required when intent='{intent}'",
                    details={"field": "correlation_id", "intent": intent},
                    spec_ref="Core §4.2.1",
                )
            )
        if intent == "approval_decision":
            capabilities = envelope.get("capabilities")
            if capabilities is None:
                errors.append(
                    ValidationError(
                        code="missing_capabilities",
                        message=(
                            "capabilities is required when intent='approval_decision'"
                        ),
                        details={
                            "field": "capabilities",
                            "intent": "approval_decision",
                        },
                        spec_ref="Core §4.2.3",
                    )
                )
            elif not isinstance(capabilities, list) or len(capabilities) == 0:
                errors.append(
                    ValidationError(
                        code="empty_capabilities",
                        message=(
                            "capabilities must be a non-empty list when "
                            "intent='approval_decision'"
                        ),
                        details={
                            "field": "capabilities",
                            "intent": "approval_decision",
                        },
                        spec_ref="Core §4.2.3",
                    )
                )

    # --- Error payload shape -------------------------------------------
    if intent == "error":
        payload = envelope.get("payload")
        if not isinstance(payload, dict):
            errors.append(
                ValidationError(
                    code="missing_error_payload",
                    message="intent='error' requires a payload object",
                    details={"field": "payload"},
                    spec_ref="Core §4.4.6",
                )
            )
        else:
            error_obj = payload.get("error")
            if not isinstance(error_obj, dict):
                errors.append(
                    ValidationError(
                        code="missing_error_object",
                        message="intent='error' requires payload.error object",
                        details={"field": "payload.error"},
                        spec_ref="Core §4.4.6",
                    )
                )
            else:
                if not isinstance(error_obj.get("code"), str):
                    errors.append(
                        ValidationError(
                            code="missing_error_code",
                            message="payload.error.code is required when intent='error'",
                            details={"field": "payload.error.code"},
                            spec_ref="Core §4.4.6",
                        )
                    )
                if not isinstance(error_obj.get("description"), str):
                    errors.append(
                        ValidationError(
                            code="missing_error_description",
                            message=(
                                "payload.error.description is required when "
                                "intent='error'"
                            ),
                            details={"field": "payload.error.description"},
                            spec_ref="Core §4.4.6",
                        )
                    )

    # --- Payload type recognition (§4.4.1) --------------------------------
    if payload_type_registry is not None:
        payload_obj = envelope.get("payload")
        if isinstance(payload_obj, dict):
            p_type = payload_obj.get("type")
            if isinstance(p_type, str) and not payload_type_registry.is_recognized(
                p_type
            ):
                errors.append(
                    ValidationError(
                        code="unrecognised_payload_type",
                        message=(
                            f"payload.type {p_type!r} is not a recognised "
                            "payload type — respond with not_implemented"
                        ),
                        details={"payload_type": p_type},
                        spec_ref="Core §4.4.1",
                    )
                )

    # --- expires_at > ts ------------------------------------------------
    ts_raw = envelope.get("ts")
    expires_at_raw = envelope.get("expires_at")
    if isinstance(ts_raw, str) and isinstance(expires_at_raw, str):
        ts = _parse_rfc3339_ms(ts_raw)
        expires_at = _parse_rfc3339_ms(expires_at_raw)
        if ts is not None and expires_at is not None and not (expires_at > ts):
            errors.append(
                ValidationError(
                    code="expires_at_not_after_ts",
                    message="expires_at must be strictly greater than ts",
                    details={"field": "expires_at"},
                    spec_ref="Core §4.2.2",
                )
            )

    # --- idempotency.expires_at > ts -----------------------------------
    idempotency_raw = envelope.get("idempotency")
    if isinstance(idempotency_raw, dict) and isinstance(ts_raw, str):
        idem_expires_raw = idempotency_raw.get("expires_at")
        if isinstance(idem_expires_raw, str):
            ts_parsed = _parse_rfc3339_ms(ts_raw)
            idem_expires = _parse_rfc3339_ms(idem_expires_raw)
            if (
                ts_parsed is not None
                and idem_expires is not None
                and not (idem_expires > ts_parsed)
            ):
                errors.append(
                    ValidationError(
                        code="idempotency_expires_at_not_after_ts",
                        message=(
                            "idempotency.expires_at must be strictly greater than ts"
                        ),
                        details={"field": "idempotency.expires_at"},
                        spec_ref="Core §4.3.2",
                    )
                )

    # --- Idempotency key charset (§4.3.2) ------------------------------
    # The idempotency.key MAY contain any printable ASCII character, i.e.
    # code points 0x20-0x7E inclusive. Tabs, newlines, control characters
    # and any non-ASCII bytes are rejected.
    idempotency = envelope.get("idempotency")
    if isinstance(idempotency, dict):
        key = idempotency.get("key")
        if isinstance(key, str):
            for ch in key:
                if not (0x20 <= ord(ch) <= 0x7E):
                    errors.append(
                        ValidationError(
                            code="idempotency_key_invalid_char",
                            message=(
                                f"idempotency.key contains non-printable-ASCII "
                                f"character U+{ord(ch):04X}; only code points "
                                "0x20-0x7E are permitted"
                            ),
                            details={
                                "field": "idempotency.key",
                                "codepoint": f"U+{ord(ch):04X}",
                            },
                            spec_ref="Core §4.3.2",
                        )
                    )
                    break

    # --- Security block ------------------------------------------------
    security = envelope.get("security")
    if isinstance(security, dict):
        kid = security.get("kid")
        sig = security.get("sig")
        if isinstance(from_agent, str) and isinstance(kid, str):
            expected_prefix = f"{from_agent}#"
            if not kid.startswith(expected_prefix):
                errors.append(
                    ValidationError(
                        code="kid_prefix_mismatch",
                        message=(
                            f"security.kid {kid!r} must start with {expected_prefix!r}"
                        ),
                        details={"kid": kid, "expected_prefix": expected_prefix},
                        spec_ref="Core §5.2",
                    )
                )
        if isinstance(sig, str):
            if not _BASE64URL_RE.fullmatch(sig):
                errors.append(
                    ValidationError(
                        code="invalid_sig_encoding",
                        message=(
                            "security.sig must be base64url-encoded without padding"
                        ),
                        details={"field": "security.sig"},
                        spec_ref="Core §5.1",
                    )
                )

    # --- Compliance rules (§4.3.8) -------------------------------------

    errors.extend(validate_compliance(envelope, strict=strict))

    return errors


def validate_envelope(
    envelope: dict[str, Any],
    *,
    strict: bool = False,
    payload_type_registry: PayloadTypeRegistry | None = None,
) -> list[ValidationError]:
    """Run L1 + L2 validation against ``envelope``.

    L1 (schema) runs first. If L1 reports any error, L2 is skipped
    because semantic checks on a structurally broken envelope produce
    noisy, confusing results. Consumers that want both layers
    regardless can call :func:`validate_schema` and
    :func:`validate_semantic` directly.

    Args:
        envelope: The envelope to validate.
        strict: Promotes SHOULD-level rules to errors.
        payload_type_registry: Optional registry of recognised payload
            types. When provided, unrecognised types produce an error
            per §4.4.1.

    Returns:
        A list of :class:`ValidationError`. Empty means valid.

    Spec: ARSIA-Core.md §4.
    """
    if not isinstance(envelope, dict):
        return [
            ValidationError(
                code="invalid_envelope_type",
                message=f"Envelope must be a dict, got {type(envelope).__name__}",
                spec_ref="Core §4",
            )
        ]

    # Encrypted envelope guard — if the payload is JWE ciphertext,
    # L1/L2 validation cannot proceed meaningfully.
    security = envelope.get("security")
    payload = envelope.get("payload")
    if (
        isinstance(security, dict)
        and security.get("encrypted") is True
        and isinstance(payload, str)
    ):
        return [
            ValidationError(
                code="encrypted_payload",
                message=(
                    "Envelope payload is encrypted (JWE). "
                    "Call decrypt_and_verify() before validate_envelope(). "
                    "Encrypted payloads cannot be validated until decrypted."
                ),
                spec_ref="Core §6",
            )
        ]

    l1_errors = validate_schema(envelope)
    if l1_errors:
        return l1_errors
    return validate_semantic(
        envelope, strict=strict, payload_type_registry=payload_type_registry
    )


def validate_identity_record(record: dict[str, Any]) -> list[ValidationError]:
    """Run L1 validation against ``arsia-identity-record.schema.json``.

    Spec: ARSIA-Identity.md §1.
    """
    return validate_schema(record, "arsia-identity-record.schema.json")


def validate_compliance_field(compliance: dict[str, Any]) -> list[ValidationError]:
    """Run L1 validation against ``arsia-compliance-field.schema.json``.

    Spec: ARSIA-Core.md §4.3.6.
    """
    return validate_schema(compliance, "arsia-compliance-field.schema.json")


@dataclass(frozen=True)
class IdentityConsistencyResult:
    """Result of :func:`check_identity_consistency`.

    Attributes:
        is_consistent: ``True`` when all identity layers agree.
        warnings: Non-empty when inconsistencies are detected.
    """

    is_consistent: bool
    warnings: tuple[str, ...]


def check_identity_consistency(
    *,
    from_agent: str,
    kid: str,
    identity_agent_id: str | None = None,
) -> IdentityConsistencyResult:
    """Cross-check the three identity layers per Identity §1.1.

    The three layers are:
    1. Message ``from`` field (agent-id of the sender)
    2. ``security.kid`` prefix (before ``#``)
    3. IdentityRecord ``agent_id`` (owner)

    When any pair is inconsistent, the result carries a compliance
    warning. Callers SHOULD reject or log according to their policy.

    Args:
        from_agent: The ``from`` field of the envelope.
        kid: The ``security.kid`` field of the envelope.
        identity_agent_id: The ``agent_id`` from the sender's
            IdentityRecord, if available.

    Returns:
        An :class:`IdentityConsistencyResult`.

    Spec: ARSIA-Identity.md §1.1.
    """
    warnings: list[str] = []

    kid_prefix = kid.split("#", 1)[0] if "#" in kid else kid

    if kid_prefix != from_agent:
        warnings.append(
            f"kid prefix {kid_prefix!r} does not match from field "
            f"{from_agent!r} (Identity §1.1)"
        )

    if identity_agent_id is not None:
        if identity_agent_id != from_agent:
            warnings.append(
                f"IdentityRecord agent_id {identity_agent_id!r} does not "
                f"match from field {from_agent!r} (Identity §1.1)"
            )
        if identity_agent_id != kid_prefix:
            warnings.append(
                f"IdentityRecord agent_id {identity_agent_id!r} does not "
                f"match kid prefix {kid_prefix!r} (Identity §1.1)"
            )

    is_consistent = len(warnings) == 0
    if not is_consistent:
        for w in warnings:
            logger.warning("identity_consistency: %s", w)

    return IdentityConsistencyResult(
        is_consistent=is_consistent,
        warnings=tuple(warnings),
    )


def validate_correlation(
    request_envelope: dict[str, Any],
    response_envelope: dict[str, Any],
) -> list[ValidationError]:
    """Verify response.correlation_id == request.id (byte-for-byte).

    Spec: ARSIA-Core.md §4.2.1.
    """
    errors: list[ValidationError] = []
    request_id = request_envelope.get("id")
    correlation_id = response_envelope.get("correlation_id")

    if correlation_id is None:
        errors.append(
            ValidationError(
                code="missing_correlation_id",
                message="response envelope is missing correlation_id",
                details={"field": "correlation_id"},
                spec_ref="Core §4.2.1",
            )
        )
        return errors

    if correlation_id != request_id:
        errors.append(
            ValidationError(
                code="correlation_mismatch",
                message=(
                    f"correlation_id {correlation_id!r} does not match "
                    f"request id {request_id!r} (byte-for-byte equality required)"
                ),
                details={"correlation_id": correlation_id, "request_id": request_id},
                spec_ref="Core §4.2.1",
            )
        )

    return errors


__all__ = [
    "INTENT_CONTENT_FIELD",
    "IdentityConsistencyResult",
    "PayloadTypeRegistry",
    "check_identity_consistency",
    "resolve_content_field",
    "validate_correlation",
    "validate_schema",
    "validate_semantic",
    "validate_envelope",
    "validate_identity_record",
    "validate_compliance_field",
]
