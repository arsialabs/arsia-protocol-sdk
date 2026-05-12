# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Agent identifier parsing, validation, and comparison.

This module is Layer 0 in the SDK dependency graph: it has no imports
from other ``arsia_protocol`` modules. It implements the agent identifier
grammar and rules defined in ARSIA-Core.md §3.

An agent identifier takes the form::

    agent:{org}.{sub}[.{sub}]*[/{resource}]

where ``org`` and each ``sub`` segment consist of ASCII letters, digits,
and hyphens (no leading or trailing hyphen), and the optional
``resource`` segment additionally permits underscores. The whole string
MUST NOT exceed 256 characters and is case-sensitive.

Spec: ARSIA-Core.md §3.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from arsia_protocol._errors import ValidationError

# Compiled regex from ARSIA-Core.md §3.3 Rule 8.
AGENT_ID_PATTERN: re.Pattern[str] = re.compile(
    r"^agent:"
    r"[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?"
    r"\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*"
    r"(/[a-zA-Z0-9][a-zA-Z0-9_-]*)?$"
)

_MAX_LENGTH = 256
_PREFIX = "agent:"


@dataclass(frozen=True)
class AgentId:
    """Parsed ARSIA agent identifier.

    Instances are constructed via :func:`parse_agent_id`. Equality and
    hashing are based on the full string and are case-sensitive, as
    required by ARSIA-Core.md §3.3 Rule 4.

    Attributes:
        org: The organisation segment (first segment after ``agent:``).
        name: The primary sub-segment (second segment).
        sub: Additional sub-segments beyond ``name``. May be empty.
        resource: Optional resource segment after ``/``. ``None`` if
            absent.
        full: The complete identifier string including the ``agent:``
            prefix.
    """

    org: str
    name: str
    sub: tuple[str, ...] = field(default_factory=tuple)
    resource: str | None = None
    full: str = ""

    def __str__(self) -> str:
        return self.full

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AgentId):
            return NotImplemented
        return self.full == other.full

    def __hash__(self) -> int:
        return hash(self.full)


def _collect_errors(raw: str) -> list[ValidationError]:
    """Return a list of validation errors for ``raw``. Empty = valid.

    Spec: ARSIA-Core.md §3.3 Rules 1-8.
    """
    errors: list[ValidationError] = []

    if raw == "":
        errors.append(
            ValidationError(
                code="agent_id_empty",
                message="agent identifier must not be empty",
                spec_ref="Core §3.3",
            )
        )
        return errors

    # Rule 1: max length.
    if len(raw) > _MAX_LENGTH:
        errors.append(
            ValidationError(
                code="agent_id_too_long",
                message=f"agent identifier exceeds maximum length of {_MAX_LENGTH} characters",
                details={"max_length": _MAX_LENGTH, "actual_length": len(raw)},
                spec_ref="Core §3.3 R1",
            )
        )

    # Rule 5: mandatory prefix.
    if not raw.startswith(_PREFIX):
        errors.append(
            ValidationError(
                code="agent_id_missing_prefix",
                message="agent identifier must start with 'agent:' prefix",
                spec_ref="Core §3.3 R5",
            )
        )
        return errors

    body = raw[len(_PREFIX) :]
    if body == "":
        errors.append(
            ValidationError(
                code="agent_id_insufficient_segments",
                message="agent identifier must contain at least an org and one sub-segment",
                spec_ref="Core §3.1",
            )
        )
        return errors

    # Split optional resource segment.
    resource: str | None
    if "/" in body:
        dotted, _, resource = body.partition("/")
        # Rule 7: resource must not be empty if '/' is present.
        if resource == "":
            errors.append(
                ValidationError(
                    code="agent_id_empty_resource",
                    message="resource segment must not be empty",
                    spec_ref="Core §3.3 R7",
                )
            )
    else:
        dotted = body
        resource = None

    segments = dotted.split(".")
    # Need at least org + one sub-segment.
    if len(segments) < 2:
        errors.append(
            ValidationError(
                code="agent_id_insufficient_segments",
                message="agent identifier must contain at least an org segment and one sub-segment",
                spec_ref="Core §3.1",
            )
        )

    # Rule 6 & 7: per-segment character and hyphen restrictions.
    segment_re = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$|^[a-zA-Z0-9]$")
    for idx, seg in enumerate(segments):
        if seg == "":
            errors.append(
                ValidationError(
                    code="agent_id_empty_segment",
                    message=f"segment at position {idx} must not be empty",
                    details={"position": idx},
                    spec_ref="Core §3.3 R6",
                )
            )
            continue
        if not segment_re.fullmatch(seg):
            # Narrow the error message.
            if seg.startswith("-") or seg.endswith("-"):
                errors.append(
                    ValidationError(
                        code="agent_id_segment_hyphen",
                        message=f"segment '{seg}' must not start or end with a hyphen",
                        details={"segment": seg},
                        spec_ref="Core §3.3 R7",
                    )
                )
            elif not all(c.isascii() and (c.isalnum() or c == "-") for c in seg):
                errors.append(
                    ValidationError(
                        code="agent_id_segment_invalid_chars",
                        message=f"segment '{seg}' contains characters outside [A-Za-z0-9-]",
                        details={"segment": seg},
                        spec_ref="Core §3.3 R6",
                    )
                )
            else:
                errors.append(
                    ValidationError(
                        code="agent_id_segment_invalid",
                        message=f"segment '{seg}' is not a valid agent-id segment",
                        details={"segment": seg},
                        spec_ref="Core §3.3 R6",
                    )
                )

    # Resource segment validation (Rule 6: letters, digits, hyphens, underscores).
    if resource is not None and resource != "":
        resource_re = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$")
        if not resource_re.fullmatch(resource):
            errors.append(
                ValidationError(
                    code="agent_id_resource_invalid",
                    message=f"resource segment '{resource}' must match [a-zA-Z0-9][a-zA-Z0-9_-]*",
                    details={"resource": resource},
                    spec_ref="Core §3.3 R6",
                )
            )

    # Final authoritative check against the compiled regex, but only if
    # no other errors were raised — the regex gives a boolean answer,
    # whereas the checks above produce descriptive messages.
    if not errors and not AGENT_ID_PATTERN.fullmatch(raw):
        errors.append(
            ValidationError(
                code="agent_id_pattern_mismatch",
                message="agent identifier does not match the ARSIA-Core §3.3 pattern",
                spec_ref="Core §3.3 R8",
            )
        )

    return errors


def parse_agent_id(raw: str) -> AgentId:
    """Parse a string into an :class:`AgentId`.

    Args:
        raw: The candidate agent identifier string.

    Returns:
        The parsed :class:`AgentId`.

    Raises:
        ValueError: if ``raw`` does not satisfy the rules in
            ARSIA-Core.md §3.3. The exception message lists every
            detected violation.

    Spec: ARSIA-Core.md §3.1-§3.3.
    """
    errors = _collect_errors(raw)
    if errors:
        raise ValueError(
            "invalid ARSIA agent identifier: " + "; ".join(str(e) for e in errors)
        )

    body = raw[len(_PREFIX) :]
    if "/" in body:
        dotted, _, resource = body.partition("/")
    else:
        dotted = body
        resource = None

    segments = dotted.split(".")
    org = segments[0]
    name = segments[1]
    sub = tuple(segments[2:])

    return AgentId(
        org=org,
        name=name,
        sub=sub,
        resource=resource if resource not in ("", None) else None,
        full=raw,
    )


def validate_agent_id(raw: str) -> list[ValidationError]:
    """Return a list of validation errors for ``raw``.

    An empty list means the identifier is valid. This function never
    raises — prefer :func:`parse_agent_id` when you want an exception,
    or :func:`is_valid_agent_id` for a simple boolean check.

    Spec: ARSIA-Core.md §3.3.
    """
    return _collect_errors(raw)


def is_valid_agent_id(raw: str) -> bool:
    """Return ``True`` iff ``raw`` is a valid ARSIA agent identifier.

    Spec: ARSIA-Core.md §3.3.
    """
    return len(raw) <= _MAX_LENGTH and AGENT_ID_PATTERN.fullmatch(raw) is not None


def is_identity_record_expired(
    record: dict[str, object],
    *,
    now: datetime | None = None,
) -> bool:
    """Return ``True`` if the IdentityRecord's ``valid_until`` has elapsed.

    Per ARSIA-Identity.md §1.2 the ``valid_until`` field is OPTIONAL.
    When absent (or explicitly ``None``), the record has no declared
    expiry and this function returns ``False``. When present, it MUST
    be an RFC 3339 millisecond-precision UTC timestamp (``Z`` suffix)
    matching the format on :class:`IdentityRecord`.

    Args:
        record: An IdentityRecord as a dict (e.g. ``model_dump()`` of
            :class:`arsia_protocol.types.identity.IdentityRecord` or
            the parsed JSON body of an identity endpoint response).
        now: Reference instant. Defaults to ``datetime.now(UTC)``;
            tests pass an explicit value for determinism.

    Returns:
        ``True`` iff ``valid_until`` is present and earlier than
        ``now``. ``False`` if the field is absent, ``None``, or in
        the future.

    Raises:
        ValueError: if ``valid_until`` is present but cannot be
            parsed as an RFC 3339 timestamp.

    Spec: ARSIA-Identity.md §1.2 (``valid_until``).
    """
    valid_until = record.get("valid_until")
    if valid_until is None:
        return False
    if not isinstance(valid_until, str):
        raise ValueError("valid_until must be a string when present")
    # ``Z`` suffix is mandatory per the schema; accept it explicitly.
    parsed = datetime.fromisoformat(valid_until.replace("Z", "+00:00"))
    reference = now if now is not None else datetime.now(UTC)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=UTC)
    return reference > parsed


__all__ = [
    "AGENT_ID_PATTERN",
    "AgentId",
    "parse_agent_id",
    "validate_agent_id",
    "is_valid_agent_id",
    "is_identity_record_expired",
]
