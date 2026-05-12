# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Compliance profile loading, field inheritance, and validation rules.

This module is Layer 2 (Core) in the SDK dependency graph. It depends
only on :mod:`arsia_protocol._data_resolver`, :mod:`logging`, and the
standard library — never on ``message``, ``errors``, ``hazmat``, or
``validation``.

It exposes three things:

- :func:`load_profiles` / :func:`get_profile` / :func:`get_profile_names`
  — access to the four bundled compliance profiles
  (``GDPR-STANDARD``, ``EU-AI-ACT-HIGH-RISK``, ``MIFID-II``,
  ``PAC-AGRICULTURE``) defined in
  ``shared/profiles/arsia-compliance-profiles.json``
  (ARSIA-State.md §6).
- :func:`apply_profile` and :func:`get_effective_retention` — field
  inheritance per the 4-level priority chain in ARSIA-Core.md §4.3.7
  and the retention-floor rule.
- :func:`validate_compliance` — the six compliance rules in
  ARSIA-Core.md §4.3.8. R1–R5 run unconditionally; R6 (classification
  escalation) runs when the caller passes
  ``identity_classification`` resolved from the sender's
  :class:`IdentityRecord`.

Sender-side normalization vs receiver-side rejection
-----------------------------------------------------

The two public entry points operate on opposite sides of the wire and
MUST NOT be confused:

- :func:`apply_profile` is **sender-side normalization**. It takes an
  envelope the local agent is about to emit and silently rewrites its
  ``compliance`` sub-object so that unspecified fields inherit from the
  declared profile (or ``GDPR-STANDARD`` as a fallback), and so that a
  per-message ``retention_days`` below the profile minimum is floored
  to the profile minimum. ``apply_profile`` never raises for
  policy-violation inputs in non-strict mode — its job is to produce a
  fully-resolved envelope, not to reject one.
- :func:`validate_compliance` is **receiver-side rejection**. It takes
  an envelope that arrived on the wire and reports every §4.3.8 rule
  the sender violated. It MUST NOT silently rewrite fields; it MUST
  surface violations so the receiver can reject the message with an
  ``invalid_request`` error per §11.2.

This split matters most at R4 (MiFID-II retention floor): the same raw
``retention_days=90`` on a MiFID-II envelope is a no-op normalization
for the sender (floored to 1827 in the outgoing copy) but a hard
rejection for the receiver (the sender declared an intent to retain
for less than the regulated minimum, and that declaration itself is
non-conformant). See the R4 block in :func:`validate_compliance` for
the concrete consequence on the check it runs.

``types/compliance.py`` (Layer 1) defines the Pydantic model and
enum aliases for the compliance sub-object. This module adds the
behaviour on top of it — same split as
``types/errors.py`` vs ``errors.py``.
"""

from __future__ import annotations

import copy
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Final

from arsia_protocol._data_resolver import profiles_dir
from arsia_protocol.types.errors import ValidationError

_LOGGER = logging.getLogger("arsia_protocol.compliance")

_PROFILE_CACHE: dict[str, dict[str, Any]] | None = None
"""Lazy cache of the bundled compliance profiles keyed by profile name."""

_CLASSIFICATION_HIERARCHY: tuple[str, ...] = (
    "minimal-risk",
    "limited-risk",
    "high-risk",
    "unacceptable-risk",
)
"""AI system classification hierarchy from lowest to highest risk.

Spec: ARSIA-Core.md §4.3.7, §4.3.8 Rule 6.
"""

CLASSIFICATION_HIERARCHY: Final[tuple[str, ...]] = _CLASSIFICATION_HIERARCHY
"""Public alias for the EU AI Act classification hierarchy (lowest→highest).

Re-exported so that Layer 4 modules such as :mod:`arsia_protocol.onboarding`
can consume the hierarchy without reaching into the private symbol. Any
string **not** present in this tuple is treated as unknown: callers that
receive such a value from an :class:`IdentityRecord` SHOULD surface it as
a validation error rather than silently default to a rank.

Spec: ARSIA-Core.md §4.3.8 Rule 6.
"""

_DEFAULT_PROFILE: str = "GDPR-STANDARD"
"""Profile applied when ``compliance`` is present but ``profile`` is not set.

Spec: ARSIA-Core.md §4.3.7 (Priority 3).
"""

_MIFID_RETENTION_FLOOR: int = 1827
"""MiFID II minimum retention in days (5 × 365.25 = 1826.25, rounded up).

Spec: ARSIA-Core.md §4.3.8 Rule 4.
"""

_ISO_3166_RE = re.compile(r"^[A-Z]{2}$")
"""ISO 3166-1 alpha-2 / supranational code pattern (e.g. 'EU', 'DE').

Spec: ARSIA-Core.md §4.3.6.2, §4.3.8 Rule 5.
"""

ART_9_LEGAL_BASES: Final[frozenset[str]] = frozenset(
    {
        "explicit_consent",
        "employment_social_security",
        "vital_interests_incapacity",
        "legitimate_activities",
        "manifestly_public",
        "legal_claims",
        "substantial_public_interest",
        "health_medicine",
        "public_health",
        "archiving_research",
    }
)
"""GDPR Article 9(2) legal bases for sensitive (special category) data.

Spec: ARSIA-Core.md §4.3.6.8.
"""

ART_6_LEGAL_BASES: Final[frozenset[str]] = frozenset(
    {
        "consent",
        "contract",
        "legal_obligation",
        "vital_interests",
        "public_task",
        "legitimate_interests",
    }
)
"""GDPR Article 6(1) legal bases for personal data.

Spec: ARSIA-Core.md §4.3.6.8.
"""


def _is_profile_required_for_classification(
    classification: str | None,
    intent: str | None,
) -> bool:
    """Return ``True`` when §4.2 requires a compliance profile for this pair.

    Per ARSIA-Identity.md §4.2 (Classification Consistency Rule):

    - ``ai_system_classification="high-risk"`` requires the sender to
      declare a compliance profile (``EU-AI-ACT-HIGH-RISK`` or
      stricter).
    - Intents ``"error"`` and ``"event"`` are exempt — they are
      operational envelopes, not business requests.
    - Other classifications do not mandate a profile.

    This is the shared predicate used by both receiver-side envelope
    validation (R7 in :func:`validate_compliance`) and agent-level
    onboarding evaluation (in
    :func:`arsia_protocol.onboarding.validate_profile_requirement`).
    """
    if classification != "high-risk":
        return False
    if intent in ("error", "event"):
        return False
    return True


def load_profiles() -> dict[str, dict[str, Any]]:
    """Return all bundled compliance profiles, loading on first call.

    The profiles are read from
    ``shared/profiles/arsia-compliance-profiles.json`` via
    :func:`arsia_protocol._data_resolver.profiles_dir` and cached on
    the module for subsequent calls.

    Returns:
        A dict keyed by profile name. Each value is the raw profile
        object (``{name, description, status, regulatory_references,
        defaults}``) as stored in the JSON file.

    Raises:
        FileNotFoundError: if the bundled profiles file is missing.

    Spec: ARSIA-State.md §6; ARSIA-Core.md §4.3.6.1.
    """
    global _PROFILE_CACHE
    if _PROFILE_CACHE is None:
        path = profiles_dir() / "arsia-compliance-profiles.json"
        with path.open("r", encoding="utf-8") as fh:
            raw = json.load(fh)
        profiles = raw.get("profiles", {})
        if not isinstance(profiles, dict):
            raise ValueError(
                "arsia-compliance-profiles.json: 'profiles' must be an object"
            )
        _PROFILE_CACHE = dict(profiles)
    return _PROFILE_CACHE


def get_profile(name: str) -> dict[str, Any]:
    """Return the profile named ``name``.

    Args:
        name: The profile name (e.g. ``"GDPR-STANDARD"``).

    Returns:
        The profile object dict.

    Raises:
        ValueError: if ``name`` is not a known profile.

    Spec: ARSIA-State.md §6.
    """
    profiles = load_profiles()
    if name not in profiles:
        raise ValueError(
            f"unknown ARSIA compliance profile: {name!r} "
            f"(known: {sorted(profiles.keys())})"
        )
    return profiles[name]


def get_profile_names() -> list[str]:
    """Return the sorted list of available profile names.

    Spec: ARSIA-State.md §6.
    """
    return sorted(load_profiles().keys())


def get_clock_skew_seconds(
    envelope: dict[str, Any],
    *,
    default: int = 300,
) -> int:
    """Return the clock-skew tolerance for ``envelope``.

    Resolves the ``clock_skew_seconds`` value from the envelope's
    declared compliance profile. Returns ``default`` (300 s per
    Core §8.3) when no profile is declared or the profile does not
    define ``clock_skew_seconds``.

    Spec: ARSIA-Core.md §8.3.
    """
    compliance = envelope.get("compliance")
    if isinstance(compliance, dict):
        profile_name = compliance.get("profile")
        if isinstance(profile_name, str):
            profiles = load_profiles()
            profile = profiles.get(profile_name)
            if isinstance(profile, dict):
                defaults = profile.get("defaults")
                if isinstance(defaults, dict):
                    cs = defaults.get("clock_skew_seconds")
                    if isinstance(cs, int):
                        return cs
    return default


def _resolve_effective_compliance(
    compliance: dict[str, Any] | None,
    *,
    strict: bool,
) -> tuple[dict[str, Any] | None, str | None, bool]:
    """Apply the §4.3.7 priority chain and return the merged compliance.

    Returns a 3-tuple ``(effective, profile_used, retention_floor_hit)``:

    - ``effective`` — the merged compliance dict, or ``None`` when the
      message carries no ``compliance`` field at all (Priority 4).
    - ``profile_used`` — the profile name whose defaults were merged,
      or ``None`` when no profile applied.
    - ``retention_floor_hit`` — ``True`` when the profile minimum
      overrode a lower per-message ``retention_days``.

    Raises:
        ValueError: in ``strict`` mode if the declared profile is
            unknown.
    """
    if compliance is None:
        return None, None, False

    effective: dict[str, Any] = copy.deepcopy(compliance)

    declared_profile = effective.get("profile")
    profile_used: str | None
    profile_defaults: dict[str, Any]

    profiles = load_profiles()
    if declared_profile is None:
        # Priority 3: no profile declared, apply GDPR-STANDARD defaults.
        profile_used = _DEFAULT_PROFILE
        profile_defaults = dict(profiles[_DEFAULT_PROFILE]["defaults"])
    elif declared_profile in profiles:
        # Priority 2: profile defaults apply.
        profile_used = declared_profile
        profile_defaults = dict(profiles[declared_profile]["defaults"])
    else:
        # Unknown profile — strict rejects, lenient falls back to GDPR.
        if strict:
            raise ValueError(
                f"unknown compliance profile {declared_profile!r} "
                "(Core §4.3.8 Rule 1, strict mode)"
            )
        _LOGGER.warning(
            "unknown compliance profile %r, falling back to %s (Core §4.3.8 Rule 1)",
            declared_profile,
            _DEFAULT_PROFILE,
        )
        profile_used = _DEFAULT_PROFILE
        profile_defaults = dict(profiles[_DEFAULT_PROFILE]["defaults"])

    # Priority 1: per-message values override profile defaults. Fill
    # any field not explicitly set in the message from the profile.
    for key, default_value in profile_defaults.items():
        if key not in effective or effective[key] is None:
            if default_value is not None:
                effective[key] = default_value

    # Retention floor enforcement (§4.3.7). When the per-message value
    # is lower than the profile minimum, the effective value MUST be
    # the profile minimum.
    retention_floor_hit = False
    profile_min = profile_defaults.get("retention_days")
    message_retention = compliance.get("retention_days")
    if (
        profile_min is not None
        and message_retention is not None
        and message_retention < profile_min
    ):
        effective["retention_days"] = profile_min
        retention_floor_hit = True
        _LOGGER.warning(
            "retention_days %d is below profile %s minimum %d — "
            "using profile minimum (Core §4.3.7)",
            message_retention,
            profile_used,
            profile_min,
        )

    if (
        effective.get("pii_involved") is True
        and effective.get("audit_required") is not True
    ):
        effective["audit_required"] = True
        _LOGGER.warning(
            "pii_involved=true forces audit_required=true "
            "(Core §4.3.8 Rule 7 — compliance_warning)",
        )

    return effective, profile_used, retention_floor_hit


def apply_profile(
    envelope: dict[str, Any],
    *,
    strict: bool = False,
) -> dict[str, Any]:
    """Return a copy of ``envelope`` with compliance fields inherited.

    This is the **sender-side normalization** entry point. Senders
    call it just before signing to produce the canonical, fully
    resolved compliance sub-object that the wire envelope will carry.
    It never raises on policy violations in non-strict mode: it
    always returns a usable envelope, even if the declared values
    conflict with the profile (the retention floor, for instance, is
    silently applied). Rejection of non-conformant envelopes is the
    job of :func:`validate_compliance`, which the *receiver* runs
    against the arriving message.

    Implements the 4-level priority chain from ARSIA-Core.md §4.3.7:

    1. Per-message explicit values (highest)
    2. Profile defaults (from ``compliance.profile``)
    3. ``GDPR-STANDARD`` defaults (when ``compliance`` is present but
       ``profile`` is not set)
    4. No compliance (lowest — envelope returned unchanged)

    Also enforces the retention floor: when a per-message
    ``retention_days`` is below the profile minimum, the effective
    value is the profile minimum (a warning is logged).

    Args:
        envelope: The ARSIA envelope dict. Not mutated.
        strict: When ``True``, an unknown ``compliance.profile`` raises
            ``ValueError``. When ``False`` (default), a warning is
            logged and GDPR-STANDARD defaults are applied instead
            (Rule 1 in §4.3.8).

    Returns:
        A new envelope dict. When the input has no ``compliance``
        field, the returned dict is a deep copy with no compliance
        field either (Priority 4).

    Raises:
        ValueError: in strict mode when ``compliance.profile`` is not a
            known profile name.

    Spec: ARSIA-Core.md §4.3.7, §4.3.8 Rule 1.
    """
    out = copy.deepcopy(envelope)
    compliance = out.get("compliance")
    if compliance is None:
        # Priority 4: no compliance obligations declared.
        return out

    effective, _profile_used, _floor_hit = _resolve_effective_compliance(
        compliance, strict=strict
    )
    if effective is not None:
        out["compliance"] = effective
    return out


def get_effective_retention(envelope: dict[str, Any]) -> int | None:
    """Return the effective ``retention_days`` after profile inheritance.

    Args:
        envelope: The ARSIA envelope dict.

    Returns:
        The resolved retention period in days, or ``None`` when the
        envelope has no ``compliance`` field or when neither the
        per-message value nor the profile default set a retention.

    Spec: ARSIA-Core.md §4.3.6.4, §4.3.7.
    """
    compliance = envelope.get("compliance")
    if compliance is None:
        return None
    effective, _profile_used, _floor_hit = _resolve_effective_compliance(
        compliance, strict=False
    )
    if effective is None:
        return None
    value = effective.get("retention_days")
    if isinstance(value, int):
        return value
    return None


def validate_compliance(
    envelope: dict[str, Any],
    *,
    strict: bool = False,
    identity_classification: str | None = None,
) -> list[ValidationError]:
    """Apply the seven compliance validation rules from §4.3.8 + §4.2.

    This is the **receiver-side rejection** entry point. Receivers
    call it on every arriving envelope and MUST reject the message
    (with ``invalid_request`` per §11.2) if the returned list is
    non-empty. Unlike :func:`apply_profile`, this function never
    rewrites fields — its only job is to surface the §4.3.8
    violations the sender committed so the receiver can refuse the
    message instead of silently accepting it.

    Returns a list of :class:`ValidationError` in the spec's emission
    order (R1, R2, R3, R7, R4, R5, R6) with §12.4-shaped ``details``
    dicts attached. Empty means the envelope passes compliance
    validation.

    - **R1** — Unknown profile name. In ``strict`` mode this is an
      error; otherwise it is silently tolerated (the warning is logged
      inside :func:`apply_profile`).
    - **R2** — ``pii_involved=true`` without ``legal_basis`` is an
      error.
    - **R3** — Effective ``ai_system_classification='high-risk'``
      without ``human_oversight`` is an error.
    - **R4** — ``profile='MIFID-II'`` with effective
      ``retention_days`` below 1827 is an error.
    - **R5** — ``data_residency`` format is validated against the
      ISO 3166-1 alpha-2 / supranational pattern. Format errors are
      always reported.
    - **R6** — Classification escalation against the agent-level
      ``IdentityRecord.ai_system_classification``. When the caller
      passes ``identity_classification``, the rule compares it against
      the per-message ``compliance.ai_system_classification`` using
      :data:`CLASSIFICATION_HIERARCHY` and rejects any escalation
      (per-message rank strictly greater than the agent rank). §4.2's
      exemption for ``error`` and ``event`` intents applies to its
      own Classification Consistency Rule and **not** to §4.3.8 R6,
      which is about the ``compliance`` sub-object on any envelope; R6
      is therefore applied unconditionally. When
      ``identity_classification`` is ``None`` (caller has no identity
      context or did not look it up), R6 is skipped — receivers that
      want strict enforcement MUST provide the value.
    - **R7** — Per-message ``ai_system_classification='high-risk'``
      requires a compliance ``profile`` to be declared. Unlike R6
      (which compares envelope vs. IdentityRecord using an external
      ``identity_classification``), R7 is self-contained: it inspects
      only the envelope's own ``compliance`` sub-object. Intents
      ``"error"`` and ``"event"`` are exempt per §4.2. This rule
      complements :func:`arsia_protocol.onboarding.validate_profile_requirement`
      (agent-level check at onboarding time) with per-message
      enforcement on the wire.

    Args:
        envelope: The ARSIA envelope dict.
        strict: When ``True``, unknown profile names (R1) are reported
            as errors and non-strict warnings become errors.
        identity_classification: The agent-level classification string
            from the sender's :class:`IdentityRecord` (e.g.
            ``"limited-risk"``). When provided, R6 compares it to the
            per-message classification. When ``None``, R6 is skipped.

    Returns:
        A list of :class:`ValidationError`. Empty means valid.

    Spec: ARSIA-Core.md §4.3.8, §12.4; ARSIA-Identity.md §4.2.
    """
    return _detect_violations(
        envelope,
        strict=strict,
        identity_classification=identity_classification,
    )


def _detect_violations(
    envelope: dict[str, Any],
    *,
    strict: bool,
    identity_classification: str | None,
) -> list[ValidationError]:
    """Run R1–R7 and emit structured violations.

    Emission order matches the historical :func:`validate_compliance`
    order so that stringified output is byte-identical: R1, R2, R3, R7,
    R4, R5, R6. ``details`` carries the §12.4 normative keys.
    """
    violations: list[ValidationError] = []

    compliance = envelope.get("compliance")
    if compliance is None:
        return violations

    profiles = load_profiles()

    # Rule 1 — Profile name validation.
    declared_profile = compliance.get("profile")
    if declared_profile is not None and declared_profile not in profiles:
        if strict:
            violations.append(
                ValidationError(
                    code="unknown_profile",
                    message=(
                        f"R1: unknown compliance profile {declared_profile!r} "
                        "(Core §4.3.8 Rule 1)"
                    ),
                    details={"unknown_profile": True},
                    spec_ref="Core §4.3.8 R1",
                )
            )
        # Non-strict: warning only (logged inside apply_profile); omitted
        # from the returned list per §4.3.8 Rule 1.

    # Resolve the effective compliance for R2–R5. Non-strict so an
    # unknown profile does not short-circuit the remaining checks.
    try:
        effective, profile_used, _floor_hit = _resolve_effective_compliance(
            compliance, strict=False
        )
    except ValueError as exc:  # pragma: no cover - defensive
        violations.append(
            ValidationError(
                code="unknown_profile",
                message=f"R1: {exc}",
                details={"unknown_profile": declared_profile},
                spec_ref="Core §4.3.8 R1",
            )
        )
        return violations
    if effective is None:
        return violations

    # Rule 2 — pii_involved requires legal_basis. §12.4 normative
    # details shape: {"missing_legal_basis": true}.
    if effective.get("pii_involved") is True and effective.get("legal_basis") is None:
        violations.append(
            ValidationError(
                code="missing_legal_basis",
                message=(
                    "R2: compliance.legal_basis is required when "
                    "compliance.pii_involved is true (Core §4.3.8 Rule 2)"
                ),
                details={"missing_legal_basis": True},
                spec_ref="Core §4.3.8 R2",
            )
        )

    # Rule 3 — high-risk requires human_oversight.
    if (
        effective.get("ai_system_classification") == "high-risk"
        and effective.get("human_oversight") is None
    ):
        violations.append(
            ValidationError(
                code="missing_human_oversight",
                message=(
                    "R3: compliance.human_oversight is required when "
                    "compliance.ai_system_classification is 'high-risk' "
                    "(Core §4.3.8 Rule 3)"
                ),
                details={"missing_human_oversight": True},
                spec_ref="Core §4.3.8 R3",
            )
        )

    # Rule 7 — §4.2 per-message profile requirement.
    if _is_profile_required_for_classification(
        effective.get("ai_system_classification"),
        envelope.get("intent"),
    ):
        if declared_profile is None:
            violations.append(
                ValidationError(
                    code="missing_profile",
                    message=(
                        "R7: compliance profile required when "
                        "ai_system_classification='high-risk' "
                        "(Identity §4.2)"
                    ),
                    details={
                        "missing_profile": True,
                        "ai_system_classification": "high-risk",
                    },
                    spec_ref="Identity §4.2",
                )
            )

    # Rule 4 — MiFID II retention floor. See the long block in the
    # module docstring: we check the RAW ``compliance["retention_days"]``
    # (what the sender wrote on the wire), not the floor-rewritten
    # ``effective["retention_days"]`` — otherwise the floor logic would
    # mask every R4 violation.
    if profile_used == "MIFID-II":
        raw_retention = compliance.get("retention_days")
        if isinstance(raw_retention, int) and raw_retention < _MIFID_RETENTION_FLOOR:
            violations.append(
                ValidationError(
                    code="insufficient_retention",
                    message=(
                        f"R4: MIFID-II requires retention_days >= "
                        f"{_MIFID_RETENTION_FLOOR}, got {raw_retention} "
                        "(Core §4.3.8 Rule 4)"
                    ),
                    details={
                        "insufficient_retention": True,
                        "required": _MIFID_RETENTION_FLOOR,
                        "provided": raw_retention,
                    },
                    spec_ref="Core §4.3.8 R4",
                )
            )

    # Rule 5 — data_residency format.
    residency = effective.get("data_residency")
    if residency is not None and (
        not isinstance(residency, str) or not _ISO_3166_RE.fullmatch(residency)
    ):
        violations.append(
            ValidationError(
                code="invalid_data_residency",
                message=(
                    f"R5: compliance.data_residency {residency!r} must be an "
                    "ISO 3166-1 alpha-2 or supranational code "
                    "(Core §4.3.8 Rule 5)"
                ),
                details={
                    "invalid_data_residency": True,
                    "value": residency,
                },
                spec_ref="Core §4.3.8 R5",
            )
        )

    # Rule 6 — Classification escalation. §12.4 normative details shape:
    # {"classification_escalation": true}.
    if identity_classification is not None:
        per_message = effective.get("ai_system_classification")
        if per_message is not None:
            try:
                identity_rank = _CLASSIFICATION_HIERARCHY.index(identity_classification)
            except ValueError:
                violations.append(
                    ValidationError(
                        code="classification_escalation",
                        message=(
                            f"R6: unknown identity classification "
                            f"{identity_classification!r} — expected one of "
                            f"{list(_CLASSIFICATION_HIERARCHY)} "
                            "(Core §4.3.8 Rule 6)"
                        ),
                        details={
                            "classification_escalation": True,
                            "unknown_identity_classification": (
                                identity_classification
                            ),
                        },
                        spec_ref="Core §4.3.8 R6",
                    )
                )
            else:
                try:
                    message_rank = _CLASSIFICATION_HIERARCHY.index(per_message)
                except ValueError:
                    violations.append(
                        ValidationError(
                            code="classification_escalation",
                            message=(
                                f"R6: unknown per-message classification "
                                f"{per_message!r} — expected one of "
                                f"{list(_CLASSIFICATION_HIERARCHY)} "
                                "(Core §4.3.8 Rule 6)"
                            ),
                            details={
                                "classification_escalation": True,
                                "unknown_per_message_classification": per_message,
                            },
                            spec_ref="Core §4.3.8 R6",
                        )
                    )
                else:
                    if message_rank > identity_rank:
                        violations.append(
                            ValidationError(
                                code="classification_escalation",
                                message=(
                                    f"R6: per-message classification "
                                    f"{per_message!r} escalates above "
                                    f"agent-level classification "
                                    f"{identity_classification!r} "
                                    "(Core §4.3.8 Rule 6)"
                                ),
                                details={
                                    "classification_escalation": True,
                                    "identity_classification": (
                                        identity_classification
                                    ),
                                    "per_message_classification": per_message,
                                },
                                spec_ref="Core §4.3.8 R6",
                            )
                        )

    return violations


_OVERSIGHT_TIMEOUT_HOURS: Final[int] = 24
"""Oversight review deadline for ``required_within_24h`` mode.

Spec: ARSIA-Core.md §4.3.6.5.
"""


def check_oversight_timeout(
    human_oversight: str | None,
    executed_at: datetime,
    *,
    reviewed_at: datetime | None = None,
    now: datetime | None = None,
) -> ValidationError | None:
    """Check whether a ``required_within_24h`` action was reviewed in time.

    When ``human_oversight`` is ``"required_within_24h"`` and no review
    has occurred within 24 hours of ``executed_at``, this function logs
    a compliance warning with event type ``oversight_timeout`` and
    returns a :class:`ValidationError`.

    Args:
        human_oversight: The ``compliance.human_oversight`` value from
            the envelope.
        executed_at: When the action was executed (timezone-aware).
        reviewed_at: When a human reviewed the action, or ``None`` if
            no review has occurred yet.
        now: Override for the current time (for testing). Defaults to
            ``datetime.now(timezone.utc)``.

    Returns:
        A :class:`ValidationError` if the review deadline has
        passed without review, otherwise ``None``.

    Spec: ARSIA-Core.md §4.3.6.5.
    """
    if human_oversight != "required_within_24h":
        return None

    if now is None:
        now = datetime.now(timezone.utc)

    deadline = executed_at.timestamp() + (_OVERSIGHT_TIMEOUT_HOURS * 3600)

    if reviewed_at is not None and reviewed_at.timestamp() <= deadline:
        return None

    if now.timestamp() <= deadline:
        return None

    _LOGGER.warning(
        "oversight_timeout: no human review within %d hours of execution "
        "at %s (Core §4.3.6.5)",
        _OVERSIGHT_TIMEOUT_HOURS,
        executed_at.isoformat(),
    )
    return ValidationError(
        code="oversight_timeout",
        message=(
            f"oversight_timeout: no human review within "
            f"{_OVERSIGHT_TIMEOUT_HOURS} hours of execution "
            f"(Core §4.3.6.5)"
        ),
        details={"oversight_timeout": True},
        spec_ref="Core §4.3.6.5",
    )


def validate_explainability(
    request_envelope: dict[str, Any],
    response_envelope: dict[str, Any],
) -> ValidationError | None:
    """Validate that a response includes an explanation when required.

    When the request envelope's ``compliance.explainability_required``
    is ``true``, the response MUST include a ``payload.explanation``
    object with ``reasoning``, ``confidence``, and ``inputs_used``
    fields per ARSIA-Actions.md §5.2.

    Args:
        request_envelope: The original request envelope dict.
        response_envelope: The response envelope dict to validate.

    Returns:
        A :class:`ValidationError` if the explanation is missing
        or incomplete, otherwise ``None``.

    Spec: ARSIA-Core.md §4.3.6.6; ARSIA-Actions.md §5.2.
    """
    req_compliance = request_envelope.get("compliance")
    if req_compliance is None:
        return None
    if req_compliance.get("explainability_required") is not True:
        return None

    payload = response_envelope.get("payload", {})
    explanation = payload.get("explanation")

    if explanation is None:
        return ValidationError(
            code="missing_explanation",
            message=(
                "explainability: response must include payload.explanation "
                "when request has explainability_required=true "
                "(Core §4.3.6.6)"
            ),
            details={"missing_explanation": True},
            spec_ref="Core §4.3.6.6",
        )

    missing_fields = [
        f
        for f in ("reasoning", "confidence", "inputs_used")
        if f not in explanation or explanation[f] is None
    ]
    if missing_fields:
        return ValidationError(
            code="incomplete_explanation",
            message=(
                f"explainability: payload.explanation missing required "
                f"fields {missing_fields} (Core §4.3.6.6)"
            ),
            details={
                "incomplete_explanation": True,
                "missing_fields": missing_fields,
            },
            spec_ref="Core §4.3.6.6",
        )

    return None


__all__ = [
    "ART_6_LEGAL_BASES",
    "ART_9_LEGAL_BASES",
    "CLASSIFICATION_HIERARCHY",
    "ValidationError",
    "check_oversight_timeout",
    "load_profiles",
    "get_clock_skew_seconds",
    "get_profile",
    "get_profile_names",
    "apply_profile",
    "get_effective_retention",
    "validate_compliance",
    "validate_explainability",
]
