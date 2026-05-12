# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Assets primitive — transfers, reversals, escrow, and EU financial compliance.

This module is Layer 4 (Primitives) in the SDK dependency graph. It
depends only on :mod:`arsia_protocol.types` (Layer 1),
:mod:`arsia_protocol.validation` (Layer 3),
:mod:`arsia_protocol.compliance` (Layer 2), and
:mod:`arsia_protocol.actions` (Layer 4) — never on ``message``,
``errors``, ``hazmat``, ``identity``, ``authorization``,
``discovery``, ``certificates``, ``onboarding``, ``state``,
or ``audit``.

It covers the offline, SDK-level portions of ARSIA-Assets.md:

- **§1 Scope boundary** — :data:`FINANCIAL_ASSET_TYPES` exposes the
  subset that activates financial regulation; the §1.3 heuristic for
  rejecting payment instrument numbers is deliberately not implemented
  (high false-positive risk, SHOULD-level).
- **§2 Asset types + precision** — :data:`ASSET_TYPES`,
  :data:`ASSET_PRECISION`, :func:`count_decimal_places`,
  :func:`validate_transfer_amount`.
- **§3.1 AssetTransferRequest** — :func:`validate_transfer_request`
  composes L1 (schema) and L2 (precision + ISO 4217 + escrow coupling).
- **§3.2 AssetTransferReceipt** — :func:`validate_transfer_receipt`
  runs schema validation; status invariants are enforced by the
  Pydantic model in ``types/assets.py``.
- **§3.3 AssetTransferReversal** — :func:`validate_transfer_reversal`
  (schema) plus :func:`validate_reversal_precondition` (semantic:
  original status must be completed, cumulative amount bounds, T+1/T+30
  windows). The SDK validates; the store provides the original status.
- **§4 Escrow lifecycle** — :data:`ESCROW_STATES`,
  :data:`ESCROW_TRANSITIONS`, :func:`is_valid_escrow_transition`,
  :func:`is_terminal_escrow_state`, :func:`can_reach_disputed`, plus
  :func:`validate_escrow_conditions` (schema + ``timeout_at > ts``).
- **§5.1 Capabilities** — :data:`ASSETS_CAPABILITIES`, the seven reserved
  capability strings. Membership checks delegate to
  :data:`arsia_protocol.actions.RESERVED_CAPABILITIES`.
- **§5.2 Two-party authorisation** — :func:`validate_two_party_auth`
  enforces initiator ≠ approver and that the approver carries both
  required capabilities.
- **§6.1 MiFID II** — :data:`MIFID_RETENTION_DAYS_MIN` (1827),
  :func:`is_mifid_applicable`, :func:`build_mifid_audit_fields` (the
  22-field record from §6.1.1). Storage is the store's job.
- **§6.2 DORA** — :data:`DORA_INCIDENT_TYPES`, :data:`DORA_SEVERITIES`,
  :func:`is_infrastructure_failure`,
  :func:`classify_dora_incident_type`, :func:`build_dora_incident_event`
  (returns ``payload.data`` dict; caller composes the envelope via
  :func:`arsia_protocol.message.create_event`).
- **§6.3 PSD2** — :data:`SCA_REQUIRED_MIN_RISK_LEVEL` (7),
  :func:`requires_psd2_sca`, :func:`validate_psd2_sca_factors` (Option
  A knowledge + possession; Option B ``cnf`` claim).

What this module does NOT cover (deferred to later slices or
out-of-scope):

- Payment execution, account lifecycle, settlement rails (§1.2 —
  outside ARSIA scope entirely).
- §1.3 payload.args scrubbing for IBANs/card numbers — a SHOULD with
  very high false-positive risk; deliberately not implemented.
- HTTP routing to the DORA reporting agent (§6.2.3) — transport layer.
- Persisted idempotency store, cumulative-reversal counter (§3.3.2) —
  store's job; :func:`validate_reversal_precondition` accepts them as
  parameters.
- Live approval flow (§5.2 steps 3-5) — requires HTTP and the oversight
  middleware (Slice 8).

Spec: ARSIA-Assets.md §1-§6 Draft-01.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from types import MappingProxyType
from typing import Any, Final, Literal, Mapping, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from arsia_protocol.actions.actions import RESERVED_CAPABILITIES
from arsia_protocol.core.compliance import get_effective_retention
from arsia_protocol.identity.agent_id import is_valid_agent_id
from arsia_protocol.types.assets import (
    AssetTransferReceiptResult,
    AssetTransferRequestArgs,
    AssetTransferReversalArgs,
    AssetType,
    EscrowConditions,
    TransferStatus,
)
from arsia_protocol.types.errors import ValidationError
from arsia_protocol.core.validation import validate_schema

# ---------------------------------------------------------------------------
# §2 — Asset types + precision
# ---------------------------------------------------------------------------

ASSET_TYPES: Final[frozenset[AssetType]] = frozenset(
    {"currency", "token", "entitlement", "service_unit"}
)
"""The four asset types defined in ARSIA-Assets.md §2."""

ASSET_PRECISION: Final[Mapping[AssetType, int]] = MappingProxyType(
    {
        "currency": 2,
        "token": 8,
        "entitlement": 2,
        "service_unit": 4,
    }
)
"""Maximum decimal places per asset type (§2.1-§2.4).

Entitlement SHOULD be integer but fractional is tolerated up to 2
decimal places per §2.3. Currency is non-negotiable at 2."""

FINANCIAL_ASSET_TYPES: Final[frozenset[AssetType]] = frozenset({"currency"})
"""Asset types that activate MiFID II / PSD2 / DORA obligations (§2.1)."""

ASSETS_PAYLOAD_PREFIX: Final[str] = "arsiaprotocol.assets/"
"""Payload type prefix for assets messages."""

PAYLOAD_TYPE_TRANSFER_REQUEST: Final[str] = "arsiaprotocol.assets/transfer-request"
PAYLOAD_TYPE_TRANSFER_RECEIPT: Final[str] = "arsiaprotocol.assets/transfer-receipt"
PAYLOAD_TYPE_TRANSFER_REVERSAL: Final[str] = "arsiaprotocol.assets/transfer-reversal"
PAYLOAD_TYPE_ESCROW_DISPUTE: Final[str] = "arsiaprotocol.assets/escrow-dispute"
PAYLOAD_TYPE_ESCROW_CANCEL: Final[str] = "arsiaprotocol.assets/escrow-cancel"
PAYLOAD_TYPE_DORA_INCIDENT: Final[str] = "arsiaprotocol.dora/incident"

_CURRENCY_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Z]{3}$")
"""ISO 4217 alphabetic code pattern for ``asset_type='currency'`` (§2.1)."""

_NON_CURRENCY_UNIT_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[a-z0-9][a-z0-9-]{0,30}[a-z0-9]$"
)
"""Application-defined unit pattern for ``asset_type`` ∈ {token, entitlement,
service_unit} per §3.1.1 ``currency_or_unit``."""

ISO_4217_CURRENCY_CODES: Final[frozenset[str]] = frozenset(
    {
        "AED",
        "AFN",
        "ALL",
        "AMD",
        "ANG",
        "AOA",
        "ARS",
        "AUD",
        "AWG",
        "AZN",
        "BAM",
        "BBD",
        "BDT",
        "BGN",
        "BHD",
        "BIF",
        "BMD",
        "BND",
        "BOB",
        "BOV",
        "BRL",
        "BSD",
        "BTN",
        "BWP",
        "BYN",
        "BZD",
        "CAD",
        "CDF",
        "CHE",
        "CHF",
        "CHW",
        "CLF",
        "CLP",
        "CNY",
        "COP",
        "COU",
        "CRC",
        "CUP",
        "CVE",
        "CZK",
        "DJF",
        "DKK",
        "DOP",
        "DZD",
        "EGP",
        "ERN",
        "ETB",
        "EUR",
        "FJD",
        "FKP",
        "GBP",
        "GEL",
        "GHS",
        "GIP",
        "GMD",
        "GNF",
        "GTQ",
        "GYD",
        "HKD",
        "HNL",
        "HTG",
        "HUF",
        "IDR",
        "ILS",
        "INR",
        "IQD",
        "IRR",
        "ISK",
        "JMD",
        "JOD",
        "JPY",
        "KES",
        "KGS",
        "KHR",
        "KMF",
        "KPW",
        "KRW",
        "KWD",
        "KYD",
        "KZT",
        "LAK",
        "LBP",
        "LKR",
        "LRD",
        "LSL",
        "LYD",
        "MAD",
        "MDL",
        "MGA",
        "MKD",
        "MMK",
        "MNT",
        "MOP",
        "MRU",
        "MUR",
        "MVR",
        "MWK",
        "MXN",
        "MXV",
        "MYR",
        "MZN",
        "NAD",
        "NGN",
        "NIO",
        "NOK",
        "NPR",
        "NZD",
        "OMR",
        "PAB",
        "PEN",
        "PGK",
        "PHP",
        "PKR",
        "PLN",
        "PYG",
        "QAR",
        "RON",
        "RSD",
        "RUB",
        "RWF",
        "SAR",
        "SBD",
        "SCR",
        "SDG",
        "SEK",
        "SGD",
        "SHP",
        "SLE",
        "SLL",
        "SOS",
        "SRD",
        "SSP",
        "STN",
        "SVC",
        "SYP",
        "SZL",
        "THB",
        "TJS",
        "TMT",
        "TND",
        "TOP",
        "TRY",
        "TTD",
        "TWD",
        "TZS",
        "UAH",
        "UGX",
        "USD",
        "USN",
        "UYI",
        "UYU",
        "UYW",
        "UZS",
        "VED",
        "VES",
        "VND",
        "VUV",
        "WST",
        "XAF",
        "XAG",
        "XAU",
        "XBA",
        "XBB",
        "XBC",
        "XBD",
        "XCD",
        "XDR",
        "XOF",
        "XPD",
        "XPF",
        "XPT",
        "XSU",
        "XTS",
        "XUA",
        "XXX",
        "YER",
        "ZAR",
        "ZMW",
        "ZWL",
    }
)
"""Active ISO 4217 alphabetic currency codes.

Used by :func:`validate_currency_or_unit` for the §3.1.1 collision
check: application-defined units for non-currency asset types MUST NOT
match any ISO 4217 code (case-insensitively) to avoid ambiguity."""

_RFC3339_MS_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"
)
"""RFC 3339 timestamp with 3 fractional digits and UTC designator."""


def _parse_rfc3339_ms(value: str) -> datetime | None:
    """Parse a spec-format timestamp; return ``None`` on failure."""
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def count_decimal_places(value: float | int | Decimal | str) -> int:
    """Return the number of fractional digits in ``value``.

    Conversion goes through :func:`str` to preserve the representation
    JSON round-trip would produce. Integers and integral decimals
    return ``0``. ``bool`` is explicitly rejected so that a stray
    ``True``/``False`` doesn't sneak through as ``1``/``0``.

    Spec: ARSIA-Assets.md §2 (precision rules).

    Raises:
        TypeError: if ``value`` is a ``bool`` or not a supported type.
        ValueError: if a string cannot be parsed as a decimal number.
    """
    if isinstance(value, bool):
        raise TypeError("bool is not a valid numeric amount")
    if isinstance(value, Decimal):
        decimal_value = value
    elif isinstance(value, int):
        decimal_value = Decimal(value)
    elif isinstance(value, float):
        decimal_value = Decimal(str(value))
    elif isinstance(value, str):
        try:
            decimal_value = Decimal(value)
        except InvalidOperation as exc:
            raise ValueError(
                f"amount: {value!r} is not a valid decimal string. "
                "Expected a numeric string (e.g. '100.50')."
            ) from exc
    else:
        raise TypeError(f"amount must be numeric, got {type(value).__name__}")
    exponent = decimal_value.as_tuple().exponent
    if isinstance(exponent, int) and exponent < 0:
        return -exponent
    return 0


def validate_transfer_amount(amount: Any, asset_type: Any) -> list[ValidationError]:
    """Validate ``amount`` against the precision limit of ``asset_type``.

    Returns an empty list on success, or a list of errors. The
    currency-specific message matches the vocabulary expected by
    invalid vector INV-09.

    Spec: ARSIA-Assets.md §2.1-§2.4.
    """
    errors: list[ValidationError] = []
    if asset_type not in ASSET_TYPES:
        errors.append(
            ValidationError(
                code="invalid_asset_type",
                message=(
                    f"asset_type {asset_type!r} is not one of {sorted(ASSET_TYPES)}"
                ),
                details={
                    "field": "asset_type",
                    "value": asset_type,
                    "allowed": sorted(ASSET_TYPES),
                },
                spec_ref="Assets §2",
            )
        )
        return errors
    if isinstance(amount, bool) or not isinstance(amount, (int, float, Decimal)):
        errors.append(
            ValidationError(
                code="invalid_amount_type",
                message=(
                    f"amount must be a positive number, got {type(amount).__name__}"
                ),
                details={"field": "amount", "got": type(amount).__name__},
                spec_ref="Assets §3.1.1",
            )
        )
        return errors
    if amount <= 0:
        errors.append(
            ValidationError(
                code="amount_not_positive",
                message="amount must be greater than 0",
                details={"field": "amount"},
                spec_ref="Assets §3.1.1",
            )
        )
    try:
        places = count_decimal_places(amount)
    except (TypeError, ValueError) as exc:
        errors.append(
            ValidationError(
                code="amount_precision_error",
                message=f"amount precision check failed: {exc}",
                details={"field": "amount", "error": str(exc)},
                spec_ref="Assets §2",
            )
        )
        return errors
    limit = ASSET_PRECISION[asset_type]
    if places > limit:
        errors.append(
            ValidationError(
                code="amount_precision_exceeded",
                message=(
                    f"currency amount precision exceeds {limit} decimal places"
                    if asset_type == "currency"
                    else f"{asset_type} amount precision exceeds {limit} decimal places"
                ),
                details={
                    "field": "amount",
                    "max_decimals": limit,
                    "asset_type": asset_type,
                },
                spec_ref="Assets §2.1" if asset_type == "currency" else "Assets §2",
            )
        )
    return errors


# ---------------------------------------------------------------------------
# §3.1 — AssetTransferRequest
# ---------------------------------------------------------------------------


def validate_currency_or_unit(value: Any, asset_type: Any) -> list[ValidationError]:
    """Validate ``currency_or_unit`` against the §3.1.1 shape rules.

    Dispatches by ``asset_type``:

    - ``"currency"``: value MUST match ``^[A-Z]{3}$`` (ISO 4217
      alphabetic code). The SHOULD-level "validate against the ISO
      4217 code list" is not enforced here — the frozenset
      :data:`ISO_4217_CURRENCY_CODES` is maintained for the
      non-currency collision check and exposed for callers that want
      to apply the stronger check themselves.
    - non-currency (``token`` / ``entitlement`` / ``service_unit``):
      value MUST match ``^[a-z0-9][a-z0-9-]{0,30}[a-z0-9]$`` (2-32
      chars, lowercase alphanumeric + hyphens, no leading/trailing
      hyphen). In addition, a 3-letter value (even after lowercasing)
      MUST NOT collide with any ISO 4217 code — the §3.1.1 rule
      "MUST NOT match any ISO 4217 code to avoid ambiguity."

    Unknown ``asset_type`` values return no errors (they're rejected
    upstream by :func:`validate_transfer_amount`). A non-string
    ``value`` is rejected.

    Spec: ARSIA-Assets.md §2.1, §3.1.1.
    """
    errors: list[ValidationError] = []
    if not isinstance(value, str):
        errors.append(
            ValidationError(
                code="invalid_currency_type",
                message="currency_or_unit must be a string",
                details={"field": "currency_or_unit"},
                spec_ref="Assets §3.1.1",
            )
        )
        return errors
    if asset_type == "currency":
        if not _CURRENCY_PATTERN.fullmatch(value):
            errors.append(
                ValidationError(
                    code="invalid_currency_code",
                    message=(
                        f"currency_or_unit {value!r} is not an ISO 4217 "
                        "alphabetic code for asset_type='currency'"
                    ),
                    details={"field": "currency_or_unit", "value": value},
                    spec_ref="Assets §2.1",
                )
            )
        return errors
    if asset_type in ("token", "entitlement", "service_unit"):
        if not _NON_CURRENCY_UNIT_PATTERN.fullmatch(value):
            errors.append(
                ValidationError(
                    code="invalid_unit_pattern",
                    message=(
                        f"currency_or_unit {value!r} does not match the "
                        "application-defined unit pattern "
                        "^[a-z0-9][a-z0-9-]{0,30}[a-z0-9]$"
                    ),
                    details={"field": "currency_or_unit", "value": value},
                    spec_ref="Assets §3.1.1",
                )
            )
            return errors
        if value.upper() in ISO_4217_CURRENCY_CODES:
            errors.append(
                ValidationError(
                    code="unit_currency_collision",
                    message=(
                        f"currency_or_unit {value!r} collides with ISO 4217 "
                        f"currency code {value.upper()!r} and MUST NOT be used "
                        f"for asset_type={asset_type!r}"
                    ),
                    details={
                        "field": "currency_or_unit",
                        "value": value,
                        "collides_with": value.upper(),
                    },
                    spec_ref="Assets §3.1.1",
                )
            )
    return errors


_IBAN_PATTERN: Final[re.Pattern[str]] = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
"""Best-effort IBAN shape: 2-letter country + 2 check digits + 11-30 alphanum.

Real IBANs are 15-34 characters long. The lower bound of 15 is enforced
by the 11-char minimum body; 34 is enforced by the 30-char maximum body.
The character class after the check digits is alphanumeric per
ISO 13616, though in practice only uppercase letters appear."""

_UK_SORT_CODE_PATTERN: Final[re.Pattern[str]] = re.compile(r"\b\d{2}-\d{2}-\d{2}\b")
"""UK sort code: three pairs of digits separated by hyphens (e.g. 20-00-00).

Chosen because the hyphenated form is highly distinctive; a naked six
digit run would match too many non-sort-code contexts."""

_CARD_CANDIDATE_PATTERN: Final[re.Pattern[str]] = re.compile(r"(?:\d[ -]?){12,18}\d")
"""Candidate card number: 13-19 digits, optionally separated by space/hyphen.

Matches are verified by :func:`_passes_luhn` before being reported."""


def _passes_luhn(digits: str) -> bool:
    """Return ``True`` when ``digits`` satisfies the Luhn checksum.

    Non-digit characters are ignored. The function expects to be called
    with a candidate already narrowed to 13-19 digits after stripping."""
    stripped = "".join(c for c in digits if c.isdigit())
    if not 13 <= len(stripped) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(stripped)):
        d = ord(ch) - ord("0")
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _passes_aba_routing(digits: str) -> bool:
    """Return ``True`` when a 9-digit string passes the ABA routing checksum.

    ABA checksum: 3·d1 + 7·d2 + d3 + 3·d4 + 7·d5 + d6 + 3·d7 + 7·d8 + d9
    ≡ 0 (mod 10). A naked 9-digit match without this check would
    generate many false positives on arbitrary numeric metadata."""
    if len(digits) != 9 or not digits.isdigit():
        return False
    weights = (3, 7, 1, 3, 7, 1, 3, 7, 1)
    total = sum(int(d) * w for d, w in zip(digits, weights))
    return total % 10 == 0


_ROUTING_PATTERN: Final[re.Pattern[str]] = re.compile(r"\b\d{9}\b")
"""US ABA routing: 9 contiguous digits. Verified via :func:`_passes_aba_routing`."""


def validate_metadata_no_financial_data(
    metadata: Any, *, path: str = "metadata"
) -> list[ValidationError]:
    """Best-effort scan of ``metadata`` for financial account identifiers.

    Enforces the §1.3 MUST NOT at a heuristic level: the ``metadata``
    object "MUST NOT contain financial account identifiers, payment
    card data, or banking credentials" but the spec acknowledges this
    as a detection rather than rejection concern.

    The following patterns are flagged:

    - **IBAN** — ``^[A-Z]{2}\\d{2}[A-Z0-9]{11,30}$`` matching the
      realistic 15-34 char range per ISO 13616.
    - **Card number** — 13-19 contiguous digits (space/hyphen separators
      ignored) that pass the Luhn checksum. The Luhn filter prunes the
      vast majority of arbitrary numeric strings.
    - **UK sort code** — hyphenated ``NN-NN-NN``.
    - **US ABA routing number** — 9 digits that satisfy the ABA
      weighted checksum.

    This is deliberately a **warning** surface, not a rejection: the
    spec flags §1.3 as a SHOULD at the pattern level (§1.3 final
    paragraph) and arbitrary JSON carries a high false-positive rate.
    Callers that want a hard failure should invoke
    :func:`validate_transfer_request` with ``strict=True`` (§1.3
    rejection) or inspect the warnings and decide per message.

    Traversal is recursive: nested dicts and lists are walked and the
    ``path`` annotation in each warning is a dotted JSON pointer
    (``metadata.customer.iban``, ``metadata.items.0.reference``) so the
    caller can locate the offending field.

    Returns an empty list when no pattern matches. Non-dict ``metadata``
    (``None``, primitives) returns an empty list — the caller decides
    whether absence is itself acceptable.

    Spec: ARSIA-Assets.md §1.3.
    """
    if metadata is None:
        return []
    warnings: list[ValidationError] = []

    def _scan_string(value: str, at: str) -> None:
        upper = value.upper()
        if _IBAN_PATTERN.search(upper):
            warnings.append(
                ValidationError(
                    code="possible_iban",
                    message=(
                        f"{at} may contain an IBAN — financial account "
                        "identifiers MUST NOT be embedded in payload.args"
                    ),
                    details={"path": at},
                    spec_ref="Assets §1.3",
                )
            )
        for candidate in _CARD_CANDIDATE_PATTERN.findall(value):
            if _passes_luhn(candidate):
                warnings.append(
                    ValidationError(
                        code="possible_card_number",
                        message=(
                            f"{at} may contain a payment card number "
                            "(Luhn-valid) — payment card data MUST NOT be "
                            "embedded in payload.args"
                        ),
                        details={"path": at},
                        spec_ref="Assets §1.3",
                    )
                )
                break
        if _UK_SORT_CODE_PATTERN.search(value):
            warnings.append(
                ValidationError(
                    code="possible_sort_code",
                    message=(
                        f"{at} may contain a UK sort code — financial "
                        "account identifiers MUST NOT be embedded in "
                        "payload.args"
                    ),
                    details={"path": at},
                    spec_ref="Assets §1.3",
                )
            )
        for candidate in _ROUTING_PATTERN.findall(value):
            if _passes_aba_routing(candidate):
                warnings.append(
                    ValidationError(
                        code="possible_routing_number",
                        message=(
                            f"{at} may contain a US ABA routing number — "
                            "financial account identifiers MUST NOT be "
                            "embedded in payload.args"
                        ),
                        details={"path": at},
                        spec_ref="Assets §1.3",
                    )
                )
                break

    def _walk(value: Any, at: str) -> None:
        if isinstance(value, str):
            _scan_string(value, at)
        elif isinstance(value, dict):
            for key, child in value.items():
                _walk(child, f"{at}.{key}")
        elif isinstance(value, list):
            for i, child in enumerate(value):
                _walk(child, f"{at}.{i}")

    _walk(metadata, path)
    return warnings


@runtime_checkable
class PaymentReferenceStore(Protocol):
    """Structural interface for a ``payment_reference`` uniqueness store.

    §3.1.1 ``payment_reference`` states: "The ``payment_reference``
    MUST be unique within the deployment scope — that is, no two
    AssetTransferRequest messages within the same deployment MAY
    share a ``payment_reference``." The SDK is offline by design and
    cannot enforce deployment-wide uniqueness itself; consumers plug
    in a concrete backend (Redis, Postgres, DynamoDB, etc.) behind
    this Protocol. The contract is intentionally minimal — the only
    operation the SDK calls is :meth:`exists`. Mirrors the pattern
    used by :class:`arsia_protocol.idempotency.IdempotencyStore`.

    Implementations MUST treat ``exists`` as a read-only probe: it
    MUST NOT reserve or persist the reference. The caller is expected
    to reserve the reference in the same transaction that writes the
    outgoing message, typically via an idempotency-store ``put``
    keyed on ``(from_agent, to_agent, payload_type, payment_reference)``.

    Spec: ARSIA-Assets.md §3.1.1.
    """

    def exists(self, payment_reference: str) -> bool:
        """Return ``True`` iff ``payment_reference`` has been used."""
        ...


def validate_payment_reference_unique(
    reference: Any,
    *,
    store: PaymentReferenceStore | None = None,
) -> list[ValidationError]:
    """Check that ``reference`` is not already present in ``store``.

    When ``store`` is ``None`` (offline mode — e.g. the SDK is being
    used by a library that has no deployment-scoped uniqueness
    backend), the check is skipped and the function returns ``[]``.
    Callers operating without a store are trusting upstream systems
    to enforce uniqueness (most commonly the Authorization Server or
    the producer-side reservation logic).

    When ``store`` is provided:

    - if ``reference`` is not a non-empty string, the function returns
      an error — the check cannot meaningfully run on a missing or
      malformed reference;
    - if ``store.exists(reference)`` returns ``True``, the function
      returns an error with error-code vocabulary matching the
      §3.1.1 "unique within the deployment scope" requirement.

    Spec: ARSIA-Assets.md §3.1.1.
    """
    if store is None:
        return []
    if not isinstance(reference, str) or not reference:
        return [
            ValidationError(
                code="invalid_payment_reference",
                message=(
                    "payment_reference uniqueness check requires a non-empty "
                    "string reference"
                ),
                details={"field": "payment_reference"},
                spec_ref="Assets §3.1.1",
            )
        ]
    if store.exists(reference):
        return [
            ValidationError(
                code="duplicate_payment_reference",
                message=(
                    f"payment_reference {reference!r} is already present in the "
                    "deployment — MUST be unique within the deployment scope"
                ),
                details={"field": "payment_reference", "value": reference},
                spec_ref="Assets §3.1.1",
            )
        ]
    return []


def validate_transfer_delegation(
    *, args_from_agent: Any, envelope_from: Any
) -> list[ValidationError]:
    """Flag a delegated transfer where ``args.from_agent != envelope.from``.

    Per §3.1.1 ``from_agent``: "When ``from_agent`` differs from the
    envelope's ``from``, the sender MUST possess a valid access token
    that authorises the delegation — the mechanism for delegation
    authorisation is defined by the Authorization Server and is
    outside the scope of this specification."

    This helper cannot verify the token — the SDK has no access to
    the AS — so it emits an **informational** entry that surfaces the
    delegation to the caller. The caller is expected to perform the
    token check before trusting the delegation. Matching agents
    return an empty list.

    Both arguments are permitted to be ``None``: callers may have
    either half and still invoke the function. When either side is
    ``None`` (or not a string), the helper returns no entries —
    absence is not itself a delegation signal.

    Spec: ARSIA-Assets.md §3.1.1.
    """
    if not isinstance(args_from_agent, str) or not isinstance(envelope_from, str):
        return []
    if args_from_agent == envelope_from:
        return []
    return [
        ValidationError(
            code="delegated_transfer",
            message=(
                f"delegated transfer — args.from_agent "
                f"{args_from_agent!r} differs from envelope.from "
                f"{envelope_from!r}; caller must verify delegation "
                "authorization via the Authorization Server"
            ),
            details={
                "args_from_agent": args_from_agent,
                "envelope_from": envelope_from,
            },
            spec_ref="Assets §3.1.1",
        )
    ]


_UNSET: Final[object] = object()


def validate_transfer_request(
    args: dict[str, Any],
    *,
    strict: bool = False,
    envelope_from: str | None = None,
    envelope_expires_at: str | None | object = _UNSET,
) -> list[ValidationError]:
    """Validate an ``AssetTransferRequest`` ``payload.args`` dict.

    Runs in two passes:

    - **L1.** JSON Schema validation against
      ``arsia-asset-transfer-request.schema.json``.
    - **L2.** Precision via :func:`validate_transfer_amount`, currency
      and application-unit shape via :func:`validate_currency_or_unit`,
      and escrow-conditions coupling (``release_agent`` is required
      whenever ``escrow_conditions`` is present — this is the rule
      exercised by invalid vector INV-13).

    When ``strict=True`` is passed, the best-effort §1.3 heuristic
    implemented by :func:`validate_metadata_no_financial_data` is
    additionally applied to ``payload.args.metadata``. Any pattern
    matches (IBAN / card number / sort code / routing number) are
    appended to the returned error list and the request is treated as
    rejected. Off by default because the spec flags §1.3 as a
    SHOULD-level concern with a high false-positive risk on arbitrary
    JSON; callers that need the rejection semantics opt in explicitly.

    When ``envelope_from`` is supplied, the §3.1.1 delegation flag
    is emitted via :func:`validate_transfer_delegation` whenever
    ``args.from_agent`` differs from the envelope's ``from``. The
    entry is informational, not a rejection — callers inspecting the
    returned list are expected to verify the delegation token against
    the Authorization Server themselves.

    The Pydantic model :class:`AssetTransferRequestArgs` is not invoked
    here: callers that already hold a model instance can dump it to a
    dict first. Keeping the validator dict-native mirrors the pattern
    used by :func:`arsia_protocol.state.validate_state_entry` and lets
    raw-JSON callers use the same entry point.

    Spec: ARSIA-Assets.md §3.1.1, §1.3.
    """
    errors = validate_schema(args, "arsia-asset-transfer-request.schema.json")
    if not isinstance(args, dict):
        return errors

    asset_type = args.get("asset_type")
    amount = args.get("amount")
    if asset_type is not None:
        errors.extend(validate_transfer_amount(amount, asset_type))

    currency = args.get("currency_or_unit")
    if currency is not None and asset_type in ASSET_TYPES:
        errors.extend(validate_currency_or_unit(currency, asset_type))

    ec = args.get("escrow_conditions")
    if ec is not None:
        if not isinstance(ec, dict):
            errors.append(
                ValidationError(
                    code="invalid_escrow_conditions_type",
                    message="escrow_conditions must be an object",
                    details={"field": "escrow_conditions"},
                    spec_ref="Assets §4.1",
                )
            )
        else:
            if "release_agent" not in ec or ec.get("release_agent") is None:
                errors.append(
                    ValidationError(
                        code="missing_release_agent",
                        message="escrow_conditions.release_agent is required",
                        details={"field": "escrow_conditions.release_agent"},
                        spec_ref="Assets §4.1",
                    )
                )
            errors.extend(validate_escrow_conditions(ec))

    if strict:
        metadata = args.get("metadata")
        if metadata is not None:
            errors.extend(
                validate_metadata_no_financial_data(
                    metadata, path="payload.args.metadata"
                )
            )

    if envelope_from is not None:
        errors.extend(
            validate_transfer_delegation(
                args_from_agent=args.get("from_agent"),
                envelope_from=envelope_from,
            )
        )

    if envelope_expires_at is not _UNSET:
        if not isinstance(envelope_expires_at, str) or not envelope_expires_at:
            errors.append(
                ValidationError(
                    code="missing_expires_at",
                    message=(
                        "expires_at is REQUIRED on asset transfer request envelopes"
                    ),
                    details={"field": "expires_at"},
                    spec_ref="Assets §3.1, Core §4.2.2",
                )
            )

    return errors


# ---------------------------------------------------------------------------
# §3.2 — AssetTransferReceipt
# ---------------------------------------------------------------------------


def validate_transfer_receipt(result: dict[str, Any]) -> list[ValidationError]:
    """Validate an ``AssetTransferReceipt`` ``payload.result`` dict.

    Runs JSON Schema validation against
    ``arsia-asset-transfer-receipt.schema.json``. The schema's
    ``allOf`` conditionals enforce the status invariants from §3.2.1:
    ``completed`` requires ``settled_at`` and forbids ``failure_reason``;
    ``failed`` requires ``failure_reason`` and forbids ``settled_at``;
    ``pending``/``escrowed`` forbid both.

    The Pydantic model :class:`AssetTransferReceiptResult` enforces
    the same invariants for code paths that construct results
    programmatically.

    Spec: ARSIA-Assets.md §3.2.1.
    """
    return validate_schema(result, "arsia-asset-transfer-receipt.schema.json")


# ---------------------------------------------------------------------------
# §3.3 — AssetTransferReversal
# ---------------------------------------------------------------------------


def validate_transfer_reversal(args: dict[str, Any]) -> list[ValidationError]:
    """Validate an ``AssetTransferReversal`` ``payload.args`` dict.

    Runs JSON Schema validation only — semantic preconditions
    (original status, cumulative amount, reversal window) are the
    job of :func:`validate_reversal_precondition`, which requires
    out-of-band state (the original transfer's status/amount/settled_at
    and the accumulated reversed total for that ``payment_reference``).

    Spec: ARSIA-Assets.md §3.3.1.
    """
    return validate_schema(args, "arsia-asset-transfer-reversal.schema.json")


def validate_reversal_precondition(
    reversal_args: dict[str, Any],
    *,
    original_status: TransferStatus | str,
    original_amount: float | int | Decimal | None = None,
    original_settled_at: str | None = None,
    now: datetime | None = None,
    already_reversed_total: float | int | Decimal = 0,
    full_reversal_window_days: int = 1,
    partial_reversal_window_days: int = 30,
    envelope_expires_at: str | None | object = _UNSET,
    requestor_capabilities: list[str] | set[str] | None = None,
) -> list[ValidationError]:
    """Check the semantic preconditions that §3.3.2 places on a reversal.

    The SDK does not persist transfer state; the caller is expected to
    have looked up the original transfer's ``status``, ``amount``, and
    ``settled_at`` (and the cumulative reversed total for that
    ``payment_reference``) before invoking this function. The rules
    enforced are:

    - **Original status.** The original transfer MUST have status
      ``completed``. This is the rule exercised by invalid vector
      INV-12; the error phrasing matches the vector's
      ``expected_error``.
    - **Reversal window.** A full reversal (``reversal_amount`` absent)
      is allowed within ``full_reversal_window_days`` from
      ``settled_at`` (RECOMMENDED T+1). A partial reversal is allowed
      within ``partial_reversal_window_days`` (RECOMMENDED T+30). The
      window check requires both ``original_settled_at`` and ``now``
      to be supplied together: passing only one (the caller forgot the
      other) returns an explicit error so window enforcement cannot be
      silently bypassed. If neither is supplied — the caller has no
      settlement data at hand (e.g. the original status is still
      ``pending`` and will fail the status precondition anyway) — the
      window check is skipped without error.
    - **Cumulative bound.** If ``original_amount`` is known, the sum of
      ``already_reversed_total`` and the new reversal amount MUST NOT
      exceed ``original_amount``. A full reversal is rejected if any
      partial reversal has already been processed.

    Spec: ARSIA-Assets.md §3.3.2.
    """
    errors: list[ValidationError] = []

    if original_status != "completed":
        errors.append(
            ValidationError(
                code="invalid_reversal_status",
                message=(
                    "reversal requires original transfer status completed, "
                    f"got {original_status!r}"
                ),
                details={
                    "field": "original_status",
                    "value": original_status,
                    "required": "completed",
                },
                spec_ref="Assets §3.3",
            )
        )

    reversal_amount_raw = (
        reversal_args.get("reversal_amount")
        if isinstance(reversal_args, dict)
        else None
    )
    is_partial = reversal_amount_raw is not None

    if (original_settled_at is None) != (now is None):
        errors.append(
            ValidationError(
                code="incomplete_reversal_window_args",
                message=(
                    "cannot verify reversal window: both original_settled_at "
                    "and now are required for window check"
                ),
                spec_ref="Assets §3.3.2",
            )
        )
    elif original_settled_at is not None and now is not None:
        settled = _parse_rfc3339_ms(original_settled_at)
        if settled is None:
            errors.append(
                ValidationError(
                    code="unparseable_settled_at",
                    message=(
                        f"original_settled_at {original_settled_at!r} is not a "
                        "parseable RFC 3339 millisecond timestamp"
                    ),
                    details={
                        "field": "original_settled_at",
                        "value": original_settled_at,
                    },
                    spec_ref="Assets §3.3.2",
                )
            )
        else:
            window_days = (
                partial_reversal_window_days
                if is_partial
                else full_reversal_window_days
            )
            deadline = settled + timedelta(days=window_days)
            now_aware = (
                now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)
            )
            if now_aware > deadline:
                errors.append(
                    ValidationError(
                        code="reversal_window_expired",
                        message=(
                            f"reversal window has expired "
                            f"(T+{window_days} from "
                            f"settled_at={original_settled_at})"
                        ),
                        details={
                            "window_days": window_days,
                            "settled_at": original_settled_at,
                        },
                        spec_ref="Assets §3.3.2",
                    )
                )

    if original_amount is not None:
        try:
            original_d = Decimal(str(original_amount))
            already_d = Decimal(str(already_reversed_total))
        except (InvalidOperation, TypeError):
            errors.append(
                ValidationError(
                    code="invalid_decimal_amount",
                    message=(
                        "original_amount and already_reversed_total must be "
                        "decimal-compatible"
                    ),
                    spec_ref="Assets §3.3.2",
                )
            )
            return errors
        if is_partial:
            try:
                new_d = Decimal(str(reversal_amount_raw))
            except (InvalidOperation, TypeError):
                errors.append(
                    ValidationError(
                        code="invalid_reversal_amount",
                        message="reversal_amount must be decimal-compatible",
                        details={"field": "reversal_amount"},
                        spec_ref="Assets §3.3.2",
                    )
                )
                return errors
        else:
            new_d = original_d - already_d
            if already_d > 0:
                errors.append(
                    ValidationError(
                        code="full_reversal_after_partial",
                        message=(
                            "full reversal is prohibited once any partial "
                            "reversal has been processed"
                        ),
                        spec_ref="Assets §3.3.2",
                    )
                )
        if already_d + new_d > original_d:
            errors.append(
                ValidationError(
                    code="cumulative_reversal_exceeded",
                    message=(
                        f"cumulative reversals "
                        f"({already_d + new_d}) would exceed original_amount "
                        f"({original_d})"
                    ),
                    details={
                        "cumulative": str(already_d + new_d),
                        "original": str(original_d),
                    },
                    spec_ref="Assets §3.3.2",
                )
            )

    if envelope_expires_at is not _UNSET:
        if not isinstance(envelope_expires_at, str) or not envelope_expires_at:
            errors.append(
                ValidationError(
                    code="missing_expires_at",
                    message="expires_at is REQUIRED on reversal envelopes",
                    details={"field": "expires_at"},
                    spec_ref="Assets §3.3, Core §4.2.2",
                )
            )

    if requestor_capabilities is not None:
        cap_set = set(requestor_capabilities)
        if "arsiaprotocol.assets.transfer.reverse" not in cap_set:
            errors.append(
                ValidationError(
                    code="missing_reversal_capability",
                    message=(
                        "requested_by agent must possess "
                        "'arsiaprotocol.assets.transfer.reverse' capability"
                    ),
                    details={"required": "arsiaprotocol.assets.transfer.reverse"},
                    spec_ref="Assets §3.3",
                )
            )

    return errors


def validate_receipt_against_request(
    *,
    request_args: Mapping[str, Any],
    receipt_result: Mapping[str, Any],
) -> list[ValidationError]:
    """Cross-check an :class:`AssetTransferReceipt` ``result`` against its request.

    §3.2.1 of ARSIA-Assets specifies strict echo rules that no single-
    message schema can enforce — they only make sense with both sides
    in hand. This validator is the L2 (semantic) cross-message check
    for the receipt/request pair.

    Spec: ARSIA-Assets.md §3.2.1.
    """
    errors: list[ValidationError] = []
    if not isinstance(request_args, Mapping):
        errors.append(
            ValidationError(
                code="invalid_request_args_type",
                message="receipt/request check requires request_args to be a mapping",
                details={"field": "request_args"},
                spec_ref="Assets §3.2.1",
            )
        )
    if not isinstance(receipt_result, Mapping):
        errors.append(
            ValidationError(
                code="invalid_receipt_result_type",
                message="receipt/request check requires receipt_result to be a mapping",
                details={"field": "receipt_result"},
                spec_ref="Assets §3.2.1",
            )
        )
    if errors:
        return errors

    req_payment_ref = request_args.get("payment_reference")
    rec_payment_ref = receipt_result.get("payment_reference")
    if req_payment_ref != rec_payment_ref:
        errors.append(
            ValidationError(
                code="payment_reference_mismatch",
                message=(
                    f"receipt payment_reference {rec_payment_ref!r} does not "
                    f"match request {req_payment_ref!r} (byte-for-byte equality "
                    "required)"
                ),
                details={"receipt": rec_payment_ref, "request": req_payment_ref},
                spec_ref="Assets §3.2.1",
            )
        )

    req_ccy = request_args.get("currency_or_unit")
    rec_ccy = receipt_result.get("currency_or_unit")
    if req_ccy != rec_ccy:
        errors.append(
            ValidationError(
                code="currency_mismatch",
                message=(
                    f"receipt currency_or_unit {rec_ccy!r} does not match "
                    f"request {req_ccy!r} (exact match required)"
                ),
                details={"receipt": rec_ccy, "request": req_ccy},
                spec_ref="Assets §3.2.1",
            )
        )

    req_amount_raw = request_args.get("amount")
    rec_amount_raw = receipt_result.get("amount")
    if req_amount_raw is not None and rec_amount_raw is not None:
        try:
            req_amount = Decimal(str(req_amount_raw))
            rec_amount = Decimal(str(rec_amount_raw))
        except (InvalidOperation, TypeError):
            errors.append(
                ValidationError(
                    code="invalid_decimal_amount",
                    message="receipt/request amount values must be decimal-compatible",
                    spec_ref="Assets §3.2.1",
                )
            )
        else:
            if rec_amount > req_amount:
                errors.append(
                    ValidationError(
                        code="receipt_amount_exceeds_request",
                        message=(
                            f"receipt amount {rec_amount} exceeds request "
                            f"amount {req_amount} (partial execution may "
                            "under-fill but never over-fill)"
                        ),
                        details={
                            "receipt_amount": str(rec_amount),
                            "request_amount": str(req_amount),
                        },
                        spec_ref="Assets §3.2.1",
                    )
                )

    req_asset_type = request_args.get("asset_type")
    rec_asset_type = receipt_result.get("asset_type")
    if req_asset_type is not None and rec_asset_type is not None:
        if req_asset_type != rec_asset_type:
            errors.append(
                ValidationError(
                    code="asset_type_mismatch",
                    message=(
                        f"receipt asset_type {rec_asset_type!r} does not match "
                        f"request {req_asset_type!r}"
                    ),
                    details={"receipt": rec_asset_type, "request": req_asset_type},
                    spec_ref="Assets §3.2.1",
                )
            )

    if request_args.get("escrow_conditions") is not None:
        rec_status = receipt_result.get("status")
        if rec_status != "escrowed":
            errors.append(
                ValidationError(
                    code="invalid_escrow_receipt_status",
                    message=(
                        f"initial receipt status MUST be 'escrowed' when "
                        f"escrow_conditions is present, got {rec_status!r}"
                    ),
                    details={
                        "field": "status",
                        "value": rec_status,
                        "required": "escrowed",
                    },
                    spec_ref="Assets §3.1",
                )
            )

    return errors


# ---------------------------------------------------------------------------
# §4 — Escrow
# ---------------------------------------------------------------------------

EscrowState = Literal["ESCROWED", "RELEASED", "RETURNED", "DISPUTED"]
"""The four escrow states defined in ARSIA-Assets.md §4.2.

ESCROWED is the sole initial state. RELEASED and RETURNED are
terminal. DISPUTED is reachable only when ``arbitration_agent`` is
present; from DISPUTED the arbitration outcome drives the escrow to
either RELEASED or RETURNED."""

ESCROW_STATES: Final[frozenset[EscrowState]] = frozenset(
    {"ESCROWED", "RELEASED", "RETURNED", "DISPUTED"}
)

ESCROW_TRANSITIONS: Final[Mapping[EscrowState, frozenset[EscrowState]]] = (
    MappingProxyType(
        {
            "ESCROWED": frozenset({"RELEASED", "RETURNED", "DISPUTED"}),
            "DISPUTED": frozenset({"RELEASED", "RETURNED"}),
            "RELEASED": frozenset(),
            "RETURNED": frozenset(),
        }
    )
)
"""Read-only escrow state-machine transition table per §4.2.

RELEASED and RETURNED are terminal. DISPUTED is non-terminal but can
only resolve to one of the two terminals; §4.2.3 leaves the resolution
logic to the arbitration agent."""


def is_valid_escrow_transition(from_state: str, to_state: str) -> bool:
    """Return ``True`` if ``from_state → to_state`` is allowed by §4.2.

    Unknown state names return ``False``. DISPUTED is reachable only
    when ``arbitration_agent`` is set on the EscrowConditions;
    callers that want to enforce that precondition should call
    :func:`can_reach_disputed` first.

    Spec: ARSIA-Assets.md §4.2.
    """
    allowed = ESCROW_TRANSITIONS.get(from_state)  # type: ignore[call-overload]
    if allowed is None:
        return False
    if to_state not in ESCROW_STATES:
        return False
    return to_state in allowed


def is_terminal_escrow_state(state: str) -> bool:
    """Return ``True`` if ``state`` has no outgoing escrow transitions.

    ``RELEASED`` and ``RETURNED`` are terminal per §4.2.
    ``DISPUTED`` is NOT terminal — it must resolve to one of the two
    terminals. An unknown state returns ``False``.

    Spec: ARSIA-Assets.md §4.2.
    """
    allowed = ESCROW_TRANSITIONS.get(state)  # type: ignore[call-overload]
    if allowed is None:
        return False
    return not allowed


def can_reach_disputed(escrow_conditions: dict[str, Any]) -> bool:
    """Return ``True`` if the escrow can transition to ``DISPUTED``.

    Per §4.2.3, the DISPUTED state is reachable only when the
    EscrowConditions object has a non-null ``arbitration_agent``.
    Without an arbitration agent the escrow can only resolve to
    RELEASED or RETURNED.

    Spec: ARSIA-Assets.md §4.2.3.
    """
    if not isinstance(escrow_conditions, dict):
        return False
    return escrow_conditions.get("arbitration_agent") is not None


def validate_escrow_conditions(
    conditions: dict[str, Any], *, envelope_ts: str | None = None
) -> list[ValidationError]:
    """Validate an ``EscrowConditions`` dict.

    Runs JSON Schema validation against
    ``arsia-escrow-conditions.schema.json``. When ``envelope_ts`` is
    provided, additionally enforces ``timeout_at > envelope.ts``:
    a timeout already past at send time would make the escrow
    immediately eligible for the RETURNED transition, defeating the
    signalling semantics of §4.1.

    Spec: ARSIA-Assets.md §4.1.
    """
    errors = validate_schema(conditions, "arsia-escrow-conditions.schema.json")
    if not isinstance(conditions, dict) or envelope_ts is None:
        return errors

    timeout_at = conditions.get("timeout_at")
    if isinstance(timeout_at, str) and _RFC3339_MS_PATTERN.fullmatch(timeout_at):
        ts = _parse_rfc3339_ms(envelope_ts)
        to = _parse_rfc3339_ms(timeout_at)
        if ts is not None and to is not None and to <= ts:
            errors.append(
                ValidationError(
                    code="escrow_timeout_not_future",
                    message=(
                        f"escrow_conditions.timeout_at ({timeout_at}) must be "
                        f"later than envelope.ts ({envelope_ts})"
                    ),
                    details={"timeout_at": timeout_at, "envelope_ts": envelope_ts},
                    spec_ref="Assets §4.1",
                )
            )
    return errors


# ---------------------------------------------------------------------------
# §5 — Capability model + two-party auth
# ---------------------------------------------------------------------------

ASSETS_CAPABILITIES: Final[frozenset[str]] = frozenset(
    {
        "arsiaprotocol.assets.transfer.initiate",
        "arsiaprotocol.assets.transfer.approve",
        "arsiaprotocol.assets.transfer.reverse",
        "arsiaprotocol.assets.escrow.create",
        "arsiaprotocol.assets.escrow.release",
        "arsiaprotocol.assets.escrow.cancel",
        "arsiaprotocol.assets.audit.read",
    }
)
"""The seven reserved assets capabilities defined in ARSIA-Assets.md §5.1.

Every entry is also a member of
:data:`arsia_protocol.actions.RESERVED_CAPABILITIES`; this set is the
assets-specific view over the subset."""

ASSETS_CAPABILITY_RISK_LEVELS: Final[Mapping[str, int]] = MappingProxyType(
    {
        "arsiaprotocol.assets.transfer.initiate": 5,
        "arsiaprotocol.assets.transfer.approve": 7,
        "arsiaprotocol.assets.transfer.reverse": 6,
        "arsiaprotocol.assets.escrow.create": 5,
        "arsiaprotocol.assets.escrow.release": 7,
        "arsiaprotocol.assets.escrow.cancel": 6,
        "arsiaprotocol.assets.audit.read": 3,
    }
)
"""Risk levels assigned to each §5.1 capability by the spec.

Per ARSIA-Assets.md §5.1.1-§5.1.7, each reserved capability declares a
fixed risk level that determines audit and human-oversight obligations
(ARSIA-Actions.md §2.2). Capabilities at level ≥ 7 trigger the §5.2
two-party authorisation / §6.3 PSD2 SCA flow."""


def is_assets_capability(capability: str) -> bool:
    """Return ``True`` if ``capability`` is one of the seven §5.1 entries."""
    return capability in ASSETS_CAPABILITIES


# Sanity check: every assets capability is registered as reserved.
assert ASSETS_CAPABILITIES <= RESERVED_CAPABILITIES, (
    "ASSETS_CAPABILITIES must be a subset of actions.RESERVED_CAPABILITIES"
)
assert set(ASSETS_CAPABILITY_RISK_LEVELS.keys()) == ASSETS_CAPABILITIES, (
    "ASSETS_CAPABILITY_RISK_LEVELS must cover every ASSETS_CAPABILITIES entry"
)


def validate_assets_token_scope(
    scope: set[str] | list[str] | tuple[str, ...],
) -> list[ValidationError]:
    """Validate an Assets access-token scope against §5.1.2 constraints.

    §5.1.2 states: "the Authorization Server MUST NOT issue a token
    that contains both ``arsiaprotocol.assets.transfer.initiate`` and
    ``arsiaprotocol.assets.transfer.approve`` in its scope." The rule
    enforces separation of duties — the same agent cannot both initiate
    and approve the same transfer.

    Returns an empty list when the scope is valid. The caller
    (typically an Authorization Server or the request processing steps) is
    responsible for rejecting the token issuance on non-empty errors.

    Spec: ARSIA-Assets.md §5.1.2.
    """
    errors: list[ValidationError] = []
    if not isinstance(scope, (set, list, tuple)):
        return [
            ValidationError(
                code="invalid_scope_type",
                message="scope must be a set/list/tuple of capability strings",
                details={"field": "scope"},
                spec_ref="Assets §5.1.2",
            )
        ]
    scope_set = {item for item in scope if isinstance(item, str)}
    if (
        "arsiaprotocol.assets.transfer.initiate" in scope_set
        and "arsiaprotocol.assets.transfer.approve" in scope_set
    ):
        errors.append(
            ValidationError(
                code="separation_of_duties_violation",
                message=(
                    "token scope MUST NOT contain both "
                    "'arsiaprotocol.assets.transfer.initiate' and "
                    "'arsiaprotocol.assets.transfer.approve' — separation of duties "
                    "for two-party authorisation"
                ),
                details={"field": "scope"},
                spec_ref="Assets §5.1.2",
            )
        )
    return errors


def validate_two_party_auth(
    *,
    initiator_agent_id: str,
    approver_agent_id: str,
    approver_capabilities: list[str],
) -> list[ValidationError]:
    """Enforce the two-party authorisation rule from §5.2.

    Separation of duties requires that the initiator and approver are
    distinct agents and that the approver carries BOTH
    ``arsiaprotocol.assets.transfer.approve`` AND
    ``arsiaprotocol.oversight.approve`` (§5.2 Step 4).

    Spec: ARSIA-Assets.md §5.2.
    """
    errors: list[ValidationError] = []
    if initiator_agent_id == approver_agent_id:
        errors.append(
            ValidationError(
                code="same_initiator_approver",
                message=(
                    "initiator and approver must be distinct agents for "
                    "two-party authorisation"
                ),
                details={
                    "initiator": initiator_agent_id,
                    "approver": approver_agent_id,
                },
                spec_ref="Assets §5.2",
            )
        )
    required = {
        "arsiaprotocol.assets.transfer.approve",
        "arsiaprotocol.oversight.approve",
    }
    held = set(approver_capabilities)
    missing = sorted(required - held)
    if missing:
        errors.append(
            ValidationError(
                code="missing_approver_capabilities",
                message=f"approver is missing required capabilities {missing}",
                details={"missing": missing},
                spec_ref="Assets §5.2",
            )
        )
    return errors


SCA_REQUIRED_MIN_RISK_LEVEL: Final[int] = 7
"""Minimum risk level at which PSD2 SCA applies (§5.2, §6.3)."""


def requires_psd2_sca(risk_level: int) -> bool:
    """Return ``True`` when PSD2 SCA is required for this risk level.

    Financial capabilities at ``risk_level ≥ 7`` trigger SCA per §6.3.
    Callers SHOULD also consult the SCA exemptions table in §6.3.3
    (low-value / trusted-beneficiary / recurring / TRA) to suppress
    the requirement when applicable.

    Spec: ARSIA-Assets.md §5.2, §6.3.
    """
    if isinstance(risk_level, bool) or not isinstance(risk_level, int):
        return False
    return risk_level >= SCA_REQUIRED_MIN_RISK_LEVEL


def requires_human_oversight(risk_level: int) -> bool:
    """Return ``True`` when two-party authorisation is required.

    Alias of :func:`requires_psd2_sca` kept as a separate name because
    §5.2 motivates the check from human oversight (dual control)
    while §6.3 motivates it from PSD2 SCA. The protocol-level trigger
    is the same risk level but the narrative context differs.

    Spec: ARSIA-Assets.md §5.2.
    """
    return requires_psd2_sca(risk_level)


# ---------------------------------------------------------------------------
# §6.1 — MiFID II audit record
# ---------------------------------------------------------------------------

MIFID_RETENTION_DAYS_MIN: Final[int] = 1827
"""MiFID II minimum retention for asset audit records (5 × 365.25, rounded up)."""

MIFID_AUDIT_FIELDS: Final[tuple[str, ...]] = (
    "audit_id",
    "message_id",
    "receipt_message_id",
    "from_agent",
    "to_agent",
    "amount",
    "actual_amount",
    "currency_or_unit",
    "asset_type",
    "payment_reference",
    "provider_reference",
    "initiated_at",
    "settled_at",
    "status",
    "failure_reason",
    "compliance_profile",
    "data_residency",
    "payload_hash",
    "human_oversight_status",
    "approver_id",
    "approval_timestamp",
    "created_at",
    "updated_at",
)
"""The 22-field MiFID II audit record shape from §6.1.1.

Two of these are the "generated" pair ``audit_id``/``created_at``/
``updated_at`` (the spec lists ``audit_id`` and both timestamps, so
the tuple length is 23 entries in strict reading; the builder writes
all 23 and simply treats the "22 fields" wording as a shorthand for
"business-level fields plus housekeeping")."""


_EU_EEA_JURISDICTIONS: Final[frozenset[str]] = frozenset(
    {
        # 27 EU member states
        "AT",
        "BE",
        "BG",
        "HR",
        "CY",
        "CZ",
        "DK",
        "EE",
        "FI",
        "FR",
        "DE",
        "GR",
        "HU",
        "IE",
        "IT",
        "LV",
        "LT",
        "LU",
        "MT",
        "NL",
        "PL",
        "PT",
        "RO",
        "SK",
        "SI",
        "ES",
        "SE",
        # 3 EEA (non-EU) member states
        "IS",
        "LI",
        "NO",
    }
)
"""ISO 3166-1 alpha-2 codes of EU/EEA member states.

Duplicated locally (rather than imported from ``routing.py``) to
preserve the Layer-4 primitive boundary: ``assets.py`` must not import
from other primitives (see ``test_module_boundaries``)."""


def _is_eu_regulated_identity(identity: dict[str, Any] | None) -> bool:
    """Return ``True`` if the identity record declares an EU/EEA jurisdiction.

    Per ARSIA-Identity.md §1.2, ``jurisdiction`` is a REQUIRED ISO
    3166-1 alpha-2 country code on every IdentityRecord. This helper
    treats any value in :data:`_EU_EEA_JURISDICTIONS` as evidence that
    the entity is EU-regulated for MiFID II §6.1 condition 2 purposes.
    """
    if not isinstance(identity, dict):
        return False
    jurisdiction = identity.get("jurisdiction")
    if not isinstance(jurisdiction, str):
        return False
    return jurisdiction.upper() in _EU_EEA_JURISDICTIONS


def is_mifid_applicable(
    envelope: dict[str, Any],
    *,
    from_identity: dict[str, Any] | None = None,
    to_identity: dict[str, Any] | None = None,
    is_investment_services: bool = False,
) -> bool:
    """Return ``True`` when the transfer activates MiFID II obligations.

    §6.1 defines three OR-combined trigger conditions:

    1. ``compliance.profile == "MIFID-II"`` on the envelope.
    2. ``payload.args.asset_type == "currency"`` **AND** either the
       ``from_agent`` or the ``to_agent`` is an EU-regulated entity.
       "EU-regulated" is determined by the agent's IdentityRecord
       (ARSIA-Identity.md §1.2 ``jurisdiction`` field) — callers pass
       ``from_identity`` / ``to_identity`` dicts carrying that field.
       When neither identity dict is supplied this condition cannot be
       evaluated and MUST NOT fire (§6.1 requires positive evidence of
       EU regulation; a conservative-true would mis-flag non-EU
       currency flows as MiFID II).
    3. ``compliance.audit_required == true`` **AND** the operation
       relates to an investment service or activity per MiFID II
       Annex I Section A. The "relates to" test is application-defined
       — callers pass ``is_investment_services=True`` when their own
       classifier has decided the operation is in scope.

    Callers SHOULD provide ``from_identity`` / ``to_identity`` whenever
    possible; without them this predicate is limited to condition 1
    (and to condition 3 when the caller has already classified the
    investment-services aspect).

    Spec: ARSIA-Assets.md §6.1.
    """
    if not isinstance(envelope, dict):
        return False

    compliance = envelope.get("compliance")
    if isinstance(compliance, dict):
        # Condition 1 — explicit profile declaration.
        if compliance.get("profile") == "MIFID-II":
            return True
        # Condition 3 — audit_required + investment services classifier.
        if compliance.get("audit_required") is True and is_investment_services:
            return True

    # Condition 2 — currency + EU-regulated counterparty.
    payload = envelope.get("payload")
    asset_type = None
    if isinstance(payload, dict):
        args = payload.get("args")
        if isinstance(args, dict):
            asset_type = args.get("asset_type")
    if asset_type == "currency":
        if _is_eu_regulated_identity(from_identity) or _is_eu_regulated_identity(
            to_identity
        ):
            return True

    return False


def build_mifid_audit_fields(
    *,
    audit_id: str,
    request_envelope: dict[str, Any],
    receipt_envelope: dict[str, Any] | None = None,
    payload_hash: str,
    human_oversight_status: Literal[
        "not_required", "pending", "approved", "rejected", "timeout"
    ] = "not_required",
    approver_id: str | None = None,
    approval_timestamp: str | None = None,
    created_at: str,
    updated_at: str | None = None,
) -> dict[str, Any]:
    """Project the 22-field MiFID II audit record from envelope data.

    ``request_envelope`` supplies the business fields (amount, parties,
    payment_reference, etc.). When ``receipt_envelope`` is supplied,
    the receipt-scoped fields (``actual_amount``, ``provider_reference``,
    ``initiated_at``, ``settled_at``, ``status``, ``failure_reason``)
    are populated; otherwise they are ``None``.

    The function does no persistence and no hashing — ``payload_hash``
    is a parameter because §6.1.1 requires SHA-256 over the RFC 8785
    canonical form of the payload, which is computed by
    :func:`arsia_protocol.audit.compute_payload_hash` in the audit
    module. Keeping the assets module decoupled from ``audit`` /
    ``hazmat`` preserves the Layer 4 boundary.

    Spec: ARSIA-Assets.md §6.1.1.
    """
    req_payload = (
        request_envelope.get("payload", {})
        if isinstance(request_envelope, dict)
        else {}
    )
    req_args = req_payload.get("args", {}) if isinstance(req_payload, dict) else {}

    compliance = (
        request_envelope.get("compliance")
        if isinstance(request_envelope, dict)
        else None
    )
    compliance_profile = (
        compliance.get("profile") if isinstance(compliance, dict) else None
    )
    data_residency = (
        compliance.get("data_residency") if isinstance(compliance, dict) else None
    )

    rec_payload = (
        receipt_envelope.get("payload", {})
        if isinstance(receipt_envelope, dict)
        else {}
    )
    rec_result = rec_payload.get("result", {}) if isinstance(rec_payload, dict) else {}

    record: dict[str, Any] = {
        "audit_id": audit_id,
        "message_id": request_envelope.get("id")
        if isinstance(request_envelope, dict)
        else None,
        "receipt_message_id": receipt_envelope.get("id")
        if isinstance(receipt_envelope, dict)
        else None,
        "from_agent": req_args.get("from_agent"),
        "to_agent": req_args.get("to_agent"),
        "amount": req_args.get("amount"),
        "actual_amount": rec_result.get("amount") if rec_result else None,
        "currency_or_unit": req_args.get("currency_or_unit"),
        "asset_type": req_args.get("asset_type"),
        "payment_reference": req_args.get("payment_reference"),
        "provider_reference": (
            rec_result.get("provider_reference") if rec_result else None
        ),
        "initiated_at": rec_result.get("initiated_at") if rec_result else None,
        "settled_at": rec_result.get("settled_at") if rec_result else None,
        "status": rec_result.get("status") if rec_result else None,
        "failure_reason": rec_result.get("failure_reason") if rec_result else None,
        "compliance_profile": compliance_profile,
        "data_residency": data_residency,
        "payload_hash": payload_hash,
        "human_oversight_status": human_oversight_status,
        "approver_id": approver_id,
        "approval_timestamp": approval_timestamp,
        "created_at": created_at,
        "updated_at": updated_at if updated_at is not None else created_at,
    }
    return record


def build_reversal_audit_fields(
    *,
    audit_id: str,
    created_at: str,
    original_audit_id: str,
    original_payment_reference: str,
    reversal_payment_reference: str | None = None,
    reversal_amount: float | int | Decimal | str | None = None,
    reversal_reason: str,
    requested_by: str,
) -> dict[str, Any]:
    """Project the chain-of-custody fields for a reversal audit record.

    §3.3.2 of ARSIA-Assets mandates that "the reversal audit record
    MUST reference the original transfer's ``audit_id`` and
    ``payment_reference`` to maintain the chain of custody." This
    builder returns the linkage projection that a reversal audit
    record MUST embed; callers typically merge it into the full MiFID
    audit record produced by :func:`build_mifid_audit_fields` for the
    reversal's own request/receipt pair.

    Parameters follow the same convention as
    :func:`build_mifid_audit_fields`:

    - ``audit_id`` / ``created_at`` identify the *new* reversal audit
      record (a new UUID and timestamp — the reversal generates its
      own ``audit_id`` per §3.3.2 "Reversal receipt" rules).
    - ``original_audit_id`` / ``original_payment_reference`` link back
      to the original transfer. These are the two chain-of-custody
      fields named by the §3.3.2 MUST.
    - ``reversal_payment_reference`` is the NEW payment reference for
      the reversal (§3.3.2 recommends
      ``"{original_reference}-REV-{sequence}"``). It is optional
      because the reversal receipt's ``payment_reference`` may not yet
      be assigned at the moment the audit record is built (e.g., when
      the audit is opened before provider execution).
    - ``reversal_amount`` is ``None`` for a full reversal and the
      partial amount otherwise, matching ``AssetTransferReversalArgs``
      in §3.3.1.
    - ``reversal_reason`` and ``requested_by`` are echoed straight
      from the reversal's ``payload.args`` for auditor convenience.

    Spec: ARSIA-Assets.md §3.3.2.
    """
    return {
        "audit_id": audit_id,
        "created_at": created_at,
        "original_audit_id": original_audit_id,
        "original_payment_reference": original_payment_reference,
        "reversal_payment_reference": reversal_payment_reference,
        "reversal_amount": reversal_amount,
        "is_full_reversal": reversal_amount is None,
        "reversal_reason": reversal_reason,
        "requested_by": requested_by,
    }


def enforce_mifid_retention(envelope: dict[str, Any]) -> list[ValidationError]:
    """Return errors when the effective retention is below the MiFID floor.

    This is a thin wrapper over
    :func:`arsia_protocol.compliance.get_effective_retention` for
    asset-specific callers that want a MiFID-branded error.

    Spec: ARSIA-Assets.md §6.1.2.
    """
    effective = get_effective_retention(envelope)
    if effective is None:
        return []
    if effective < MIFID_RETENTION_DAYS_MIN:
        return [
            ValidationError(
                code="insufficient_mifid_retention",
                message=(
                    f"MiFID II audit retention is {effective} days, below the "
                    f"{MIFID_RETENTION_DAYS_MIN}-day (5-year) minimum"
                ),
                details={
                    "effective_days": effective,
                    "minimum_days": MIFID_RETENTION_DAYS_MIN,
                },
                spec_ref="Assets §6.1.2",
            )
        ]
    return []


# ---------------------------------------------------------------------------
# §6.2 — DORA incident events
# ---------------------------------------------------------------------------

DoraIncidentType = Literal[
    "provider_unavailable",
    "network_failure",
    "database_failure",
    "broker_failure",
    "tls_failure",
    "unknown",
]

DORA_INCIDENT_TYPES: Final[frozenset[DoraIncidentType]] = frozenset(
    {
        "provider_unavailable",
        "network_failure",
        "database_failure",
        "broker_failure",
        "tls_failure",
        "unknown",
    }
)
"""The six DORA incident types defined in ARSIA-Assets.md §6.2.1."""

DoraSeverity = Literal["low", "medium", "high", "critical"]

DORA_SEVERITIES: Final[frozenset[DoraSeverity]] = frozenset(
    {"low", "medium", "high", "critical"}
)
"""The four DORA severity classes defined in §6.2.2."""

_INFRASTRUCTURE_KEYWORDS: Final[tuple[tuple[str, DoraIncidentType], ...]] = (
    ("provider timeout", "provider_unavailable"),
    ("provider unavailable", "provider_unavailable"),
    ("network", "network_failure"),
    ("tcp", "network_failure"),
    ("database", "database_failure"),
    ("broker", "broker_failure"),
    ("tls", "tls_failure"),
    ("certificate", "tls_failure"),
)

_BUSINESS_FAILURE_KEYWORDS: Final[tuple[str, ...]] = (
    "insufficient funds",
    "insufficient_funds",
    "invalid account",
    "invalid_account",
    "compliance rejection",
    "compliance_rejection",
    "amount limit",
    "limit exceeded",
    "duplicate",
    "idempotency",
    "validation",
    "authorization",
    "unauthorized",
    "forbidden",
)


def is_infrastructure_failure(failure_reason: str | None) -> bool:
    """Heuristically classify a ``failure_reason`` as infrastructure vs business.

    Returns ``True`` when the text matches one of the §6.2.1
    infrastructure keywords (provider timeout, network, TLS, broker,
    database) and ``False`` otherwise. The heuristic is intentionally
    simple — the spec leaves the final classification to the operator,
    and callers that need a stricter rule should inspect their own
    failure taxonomy directly.

    When in doubt (no keyword matches, but the caller has other
    infrastructure signals), pass the classification through
    :func:`classify_dora_incident_type` with an explicit type.

    Spec: ARSIA-Assets.md §6.2.1.
    """
    if not isinstance(failure_reason, str):
        return False
    lower = failure_reason.lower()
    for kw in _BUSINESS_FAILURE_KEYWORDS:
        if kw in lower:
            return False
    for kw, _type in _INFRASTRUCTURE_KEYWORDS:
        if kw in lower:
            return True
    return False


def classify_dora_incident_type(
    failure_reason: str | None,
) -> DoraIncidentType | None:
    """Return the §6.2.1 incident_type that best matches ``failure_reason``.

    Returns one of the specific types
    (``"provider_unavailable"`` / ``"network_failure"`` /
    ``"database_failure"`` / ``"broker_failure"`` /
    ``"tls_failure"``) when an infrastructure keyword matches.
    Returns ``None`` when the reason matches a business-logic keyword
    (§6.2.1 "Business logic failures") or when no keyword matches —
    in either case the failure is not classifiable as an ICT-related
    incident from the text alone and the caller gets a clear "not a
    DORA incident" signal.

    Callers that have already decided the failure IS infrastructure
    but does not fit a specific type SHOULD pass ``"unknown"``
    explicitly to :func:`build_dora_incident_event` — the §6.2.1
    catch-all for infrastructure failures the operator's taxonomy
    does not classify further. This function never returns
    ``"unknown"`` itself; a ``None`` result is the signal that the
    caller must apply their own classifier.

    Spec: ARSIA-Assets.md §6.2.1.
    """
    if not isinstance(failure_reason, str):
        return None
    lower = failure_reason.lower()
    for kw in _BUSINESS_FAILURE_KEYWORDS:
        if kw in lower:
            return None
    for kw, incident_type in _INFRASTRUCTURE_KEYWORDS:
        if kw in lower:
            return incident_type
    return None


def build_dora_incident_event(
    *,
    incident_type: DoraIncidentType | str,
    affected_service: str,
    started_at: str,
    estimated_impact: str,
    severity: DoraSeverity | str,
    original_payment_reference: str,
    resolved_at: str | None = None,
) -> dict[str, Any]:
    """Build the ``payload.data`` dict for a DORA incident event.

    The caller is expected to wrap this dict into an ``intent="event"``
    envelope via :func:`arsia_protocol.message.create_event`, setting
    ``payload.type`` to :data:`PAYLOAD_TYPE_DORA_INCIDENT` and
    ``payload.version`` to ``"1.0"``. Keeping this module independent
    of ``message`` preserves the Layer 4 boundary.

    Args:
        incident_type: One of the six values in
            :data:`DORA_INCIDENT_TYPES`.
        affected_service: Agent identifier of the failing component.
        started_at: RFC 3339 millisecond UTC timestamp of detection.
        estimated_impact: Human-readable impact (≤ 512 chars).
        severity: ``"low"`` / ``"medium"`` / ``"high"`` / ``"critical"``.
        original_payment_reference: ``payment_reference`` of the transfer
            that triggered detection.
        resolved_at: Optional RFC 3339 timestamp when the incident was
            resolved; ``None`` signals an ongoing incident.

    Returns:
        The ``payload.data`` dict with the seven fields specified by
        §6.2.2.

    Raises:
        ValueError: if ``incident_type`` or ``severity`` is not in the
            allowed set, or if ``estimated_impact`` exceeds 512 chars.

    Spec: ARSIA-Assets.md §6.2.2.
    """
    if incident_type not in DORA_INCIDENT_TYPES:
        raise ValueError(
            f"incident_type {incident_type!r} is not one of "
            f"{sorted(DORA_INCIDENT_TYPES)} (Assets §6.2.2)"
        )
    if severity not in DORA_SEVERITIES:
        raise ValueError(
            f"severity {severity!r} is not one of "
            f"{sorted(DORA_SEVERITIES)} (Assets §6.2.2)"
        )
    if not isinstance(estimated_impact, str) or len(estimated_impact) > 512:
        raise ValueError(
            "estimated_impact must be a string of at most 512 characters "
            "(Assets §6.2.2)"
        )
    return {
        "incident_type": incident_type,
        "affected_service": affected_service,
        "started_at": started_at,
        "resolved_at": resolved_at,
        "estimated_impact": estimated_impact,
        "severity": severity,
        "original_payment_reference": original_payment_reference,
    }


# ---------------------------------------------------------------------------
# §6.3 — PSD2 Strong Customer Authentication
# ---------------------------------------------------------------------------


_SCA_LOW_VALUE_EUR_THRESHOLD: Final[Decimal] = Decimal("30")
"""PSD2 RTS Article 16 low-value transaction cap per transaction (EUR)."""

_SCA_EXEMPT_MAX_RISK_LEVEL: Final[int] = 7
"""SCA exemption upper bound — ``risk_level < 7`` per §6.3.3 mapping."""


def is_sca_exempt(
    *,
    amount: float | int | Decimal | str | None = None,
    currency: str = "EUR",
    beneficiary_trusted: bool = False,
    recurring: bool = False,
    tra_risk_level: int | None = None,
) -> tuple[bool, str]:
    """Classify a transfer against the §6.3.3 PSD2 SCA exemption table.

    Returns a ``(exempt, reason)`` tuple. When ``exempt`` is ``True``,
    ``reason`` identifies which exemption category applied, matching
    the labels used by the audit builder's ``exemption_reason``
    metadata field. When ``exempt`` is ``False``, ``reason`` is a
    human-readable description of why no exemption fired.

    Categories and their spec mappings (§6.3.3 table):

    - **Low-value transactions** — ``amount ≤ 30`` in EUR. The spec
      also caps the *cumulative* exempt amount at EUR 100 within a
      rolling window; cumulative tracking is the caller's
      responsibility (it depends on per-payer state) so this helper
      only checks the per-transaction cap. Non-EUR currencies do NOT
      qualify here; implementations may pre-convert or route via a
      different policy. Mapped to ``risk_level < 7`` in the spec.
    - **Trusted beneficiary** — ``beneficiary_trusted=True``.
      Implementation-defined trust list at the Authorization Server.
    - **Recurring transactions** — ``recurring=True``. Same amount +
      payee + frequency pattern; the caller (typically the AS) has
      already verified the pattern via idempotency key + AS policy.
    - **Transaction risk analysis (TRA)** — ``tra_risk_level < 7``
      per PSD2 Article 98. Maps to the §5.2 Step 2 risk assessment.

    Ordering: low-value → trusted beneficiary → recurring → TRA. The
    first matching category is returned; callers that care about
    which category fired should read ``reason``.

    When an exemption applies, the caller MUST record
    ``human_oversight_status="not_required"`` and ``exemption_reason``
    in the audit record's metadata (§6.3.3 final paragraph).

    Spec: ARSIA-Assets.md §6.3.3.
    """
    if amount is not None and currency == "EUR":
        try:
            amount_decimal = (
                amount if isinstance(amount, Decimal) else Decimal(str(amount))
            )
        except (InvalidOperation, TypeError, ValueError):
            amount_decimal = None
        if (
            amount_decimal is not None
            and amount_decimal <= _SCA_LOW_VALUE_EUR_THRESHOLD
        ):
            return True, "low_value"

    if beneficiary_trusted:
        return True, "trusted_beneficiary"

    if recurring:
        return True, "recurring"

    if (
        isinstance(tra_risk_level, int)
        and not isinstance(tra_risk_level, bool)
        and tra_risk_level < _SCA_EXEMPT_MAX_RISK_LEVEL
    ):
        return True, "tra"

    return False, "no_exemption_applies"


def validate_psd2_sca_factors(
    *,
    knowledge_factor_present: bool,
    possession_factor_present: bool,
    cnf_claim: dict[str, Any] | None = None,
) -> list[ValidationError]:
    """Validate that the PSD2 SCA factor requirement is met.

    Two compliant shapes per §6.3:

    - **Option A (Human Oversight).** The ``approval_decision``
      flow provides Knowledge (AS-authenticated approver) and
      Possession (Ed25519 signature). Pass both booleans as ``True``
      and ``cnf_claim=None``.
    - **Option B (cnf claim).** A hardware-bound token carries a
      ``cnf.jkt`` claim. Pass ``cnf_claim`` as the claim dict;
      knowledge is assumed satisfied by AS authentication. Possession
      is satisfied by DPoP binding to the hardware-bound key.

    Returns an error list; empty means the factors requirement is met.

    Spec: ARSIA-Assets.md §6.3.
    """
    errors: list[ValidationError] = []
    if cnf_claim is not None:
        if not isinstance(cnf_claim, dict) or "jkt" not in cnf_claim:
            errors.append(
                ValidationError(
                    code="missing_cnf_jkt",
                    message=("Option B requires cnf claim with a 'jkt' JWK thumbprint"),
                    details={"field": "cnf.jkt"},
                    spec_ref="Assets §6.3.2",
                )
            )
        return errors
    if not knowledge_factor_present:
        errors.append(
            ValidationError(
                code="missing_knowledge_factor",
                message=(
                    "PSD2 SCA Option A requires a knowledge factor "
                    "(AS-authenticated approver identity)"
                ),
                details={"factor": "knowledge"},
                spec_ref="Assets §6.3.1",
            )
        )
    if not possession_factor_present:
        errors.append(
            ValidationError(
                code="missing_possession_factor",
                message=(
                    "PSD2 SCA Option A requires a possession factor "
                    "(Ed25519-signed approval_decision)"
                ),
                details={"factor": "possession"},
                spec_ref="Assets §6.3.1",
            )
        )
    return errors


# ---------------------------------------------------------------------------
# §4.3 — Escrow audit trail builders
# ---------------------------------------------------------------------------

_ESCROW_EVENT_TYPE: Final[str] = "asset_transfer"


def build_escrow_created_audit(
    *,
    audit_id: str,
    timestamp: str,
    payment_reference: str,
    amount: float | int | Decimal | str,
    currency_or_unit: str,
    from_agent: str,
    to_agent: str,
    release_agent: str,
    timeout_at: str,
) -> dict[str, Any]:
    """Build the §4.3.1 ``escrow_created`` audit record.

    Generated when the initial ``AssetTransferReceipt`` with
    ``status: "escrowed"`` is produced. The record is the 11-field
    shape mandated by the §4.3.1 MUST table; no additional fields are
    emitted so the output matches the spec exactly.

    Spec: ARSIA-Assets.md §4.3.1.
    """
    return {
        "event_type": _ESCROW_EVENT_TYPE,
        "sub_type": "escrow_created",
        "payment_reference": payment_reference,
        "amount": amount,
        "currency_or_unit": currency_or_unit,
        "from_agent": from_agent,
        "to_agent": to_agent,
        "release_agent": release_agent,
        "timeout_at": timeout_at,
        "audit_id": audit_id,
        "timestamp": timestamp,
    }


def build_escrow_released_audit(
    *,
    audit_id: str,
    timestamp: str,
    payment_reference: str,
    released_by: str,
    release_trigger: str,
    original_audit_id: str,
) -> dict[str, Any]:
    """Build the §4.3.2 ``escrow_released`` audit record.

    Generated when the escrow transitions from ``ESCROWED`` to
    ``RELEASED``. ``released_by`` is the agent-id that sent the release
    trigger (the ``release_agent`` — or a delegate such as the
    ``arbitration_agent`` resolving a dispute per §4.2.3).
    ``release_trigger`` is the ``payload.type`` of the release message.
    ``original_audit_id`` chains this record to the ``escrow_created``
    record so auditors can reconstruct the escrow lifecycle.

    Spec: ARSIA-Assets.md §4.3.2.
    """
    return {
        "event_type": _ESCROW_EVENT_TYPE,
        "sub_type": "escrow_released",
        "payment_reference": payment_reference,
        "released_by": released_by,
        "release_trigger": release_trigger,
        "original_audit_id": original_audit_id,
        "audit_id": audit_id,
        "timestamp": timestamp,
    }


def build_escrow_returned_audit(
    *,
    audit_id: str,
    timestamp: str,
    payment_reference: str,
    timeout_at: str,
    actual_timeout: str,
    original_audit_id: str,
    cancellation_reason: str | None = None,
) -> dict[str, Any]:
    """Build the §4.3.3 ``escrow_returned`` audit record.

    Generated when the escrow transitions from ``ESCROWED`` to
    ``RETURNED`` (either via ``timeout_at`` expiry or via an explicit
    ``arsiaprotocol.assets/escrow-cancel`` message per §5.1.6). When a
    cancellation drives the return, the caller SHOULD pass
    ``cancellation_reason`` so the audit record carries the rationale
    per §5.1.6 ("Cancellation generates an escrow_returned audit event
    (§4.3.3) with an additional cancellation_reason field").

    Spec: ARSIA-Assets.md §4.3.3, §5.1.6.
    """
    record: dict[str, Any] = {
        "event_type": _ESCROW_EVENT_TYPE,
        "sub_type": "escrow_returned",
        "payment_reference": payment_reference,
        "timeout_at": timeout_at,
        "actual_timeout": actual_timeout,
        "original_audit_id": original_audit_id,
        "audit_id": audit_id,
        "timestamp": timestamp,
    }
    if cancellation_reason is not None:
        record["cancellation_reason"] = cancellation_reason
    return record


def build_escrow_disputed_audit(
    *,
    audit_id: str,
    timestamp: str,
    payment_reference: str,
    disputed_by: str,
    dispute_reason: str,
    arbitration_agent: str,
    original_audit_id: str,
) -> dict[str, Any]:
    """Build the §4.3.4 ``escrow_disputed`` audit record.

    Generated when the escrow transitions from ``ESCROWED`` to
    ``DISPUTED``. ``arbitration_agent`` is required because §4.2.3
    makes the DISPUTED state unreachable unless the EscrowConditions
    object carried an ``arbitration_agent``.

    Spec: ARSIA-Assets.md §4.3.4.
    """
    return {
        "event_type": _ESCROW_EVENT_TYPE,
        "sub_type": "escrow_disputed",
        "payment_reference": payment_reference,
        "disputed_by": disputed_by,
        "dispute_reason": dispute_reason,
        "arbitration_agent": arbitration_agent,
        "original_audit_id": original_audit_id,
        "audit_id": audit_id,
        "timestamp": timestamp,
    }


# ---------------------------------------------------------------------------
# §4.2.3 / §5.1.6 — escrow-dispute + escrow-cancel payload validators
# ---------------------------------------------------------------------------

_DISPUTE_REASON_MAX_LEN: Final[int] = 512


def validate_escrow_dispute(
    args: dict[str, Any],
    *,
    sender_agent_id: str | None = None,
    escrow_parties: tuple[str, str] | None = None,
) -> list[ValidationError]:
    """Validate an ``arsiaprotocol.assets/escrow-dispute`` ``payload.args`` dict.

    §4.2.3 mandates three fields: ``payment_reference`` (string),
    ``dispute_reason`` (human-readable, ``maxLength 512``), and
    ``disputed_by`` (agent-id of the disputing party).

    When ``sender_agent_id`` and ``escrow_parties`` are both provided,
    the sender is verified as a party to the escrow (§4.2.3).

    Spec: ARSIA-Assets.md §4.2.3.
    """
    errors: list[ValidationError] = []
    if not isinstance(args, dict):
        return [
            ValidationError(
                code="invalid_args_type",
                message="escrow-dispute payload.args must be an object",
                details={"field": "args"},
                spec_ref="Assets §4.2.3",
            )
        ]

    payment_reference = args.get("payment_reference")
    if not isinstance(payment_reference, str) or not payment_reference:
        errors.append(
            ValidationError(
                code="missing_payment_reference",
                message=(
                    "escrow-dispute payload.args.payment_reference is required "
                    "(non-empty string)"
                ),
                details={"field": "payment_reference"},
                spec_ref="Assets §4.2.3",
            )
        )

    dispute_reason = args.get("dispute_reason")
    if not isinstance(dispute_reason, str) or not dispute_reason:
        errors.append(
            ValidationError(
                code="missing_dispute_reason",
                message=(
                    "escrow-dispute payload.args.dispute_reason is required "
                    "(non-empty string)"
                ),
                details={"field": "dispute_reason"},
                spec_ref="Assets §4.2.3",
            )
        )
    elif len(dispute_reason) > _DISPUTE_REASON_MAX_LEN:
        errors.append(
            ValidationError(
                code="dispute_reason_too_long",
                message=(
                    f"escrow-dispute payload.args.dispute_reason exceeds "
                    f"maxLength {_DISPUTE_REASON_MAX_LEN}"
                ),
                details={
                    "field": "dispute_reason",
                    "max_length": _DISPUTE_REASON_MAX_LEN,
                },
                spec_ref="Assets §4.2.3",
            )
        )

    disputed_by = args.get("disputed_by")
    if not isinstance(disputed_by, str) or not disputed_by:
        errors.append(
            ValidationError(
                code="missing_disputed_by",
                message=(
                    "escrow-dispute payload.args.disputed_by is required (agent-id)"
                ),
                details={"field": "disputed_by"},
                spec_ref="Assets §4.2.3",
            )
        )
    elif not is_valid_agent_id(disputed_by):
        errors.append(
            ValidationError(
                code="invalid_disputed_by",
                message=(
                    f"escrow-dispute payload.args.disputed_by "
                    f"{disputed_by!r} is not a valid agent-id"
                ),
                details={"field": "disputed_by", "value": disputed_by},
                spec_ref="Assets §4.2.3",
            )
        )

    if (
        sender_agent_id is not None
        and escrow_parties is not None
        and sender_agent_id not in {escrow_parties[0], escrow_parties[1]}
    ):
        errors.append(
            ValidationError(
                code="forbidden",
                message=(
                    f"dispute sender {sender_agent_id!r} is not a party to the escrow"
                ),
                details={
                    "field": "sender_agent_id",
                    "sender": sender_agent_id,
                    "from_agent": escrow_parties[0],
                    "to_agent": escrow_parties[1],
                },
                spec_ref="Assets §4.2.3",
            )
        )

    return errors


def validate_escrow_cancel(
    args: dict[str, Any],
    *,
    sender_agent_id: str | None = None,
    from_agent: str | None = None,
) -> list[ValidationError]:
    """Validate an ``arsiaprotocol.assets/escrow-cancel`` ``payload.args`` dict.

    §5.1.6 requires the cancellation message to carry a
    ``payment_reference``. The SDK additionally requires
    ``cancellation_reason`` because §5.1.6 states that cancellation
    generates an ``escrow_returned`` audit event with an additional
    ``cancellation_reason`` field — the reason cannot be populated in
    the audit record unless it rides in on the cancel message.

    When ``sender_agent_id`` and ``from_agent`` are both provided,
    the sender is verified as the escrow creator (§4.2.4).

    Spec: ARSIA-Assets.md §5.1.6, §4.2.4.
    """
    errors: list[ValidationError] = []
    if not isinstance(args, dict):
        return [
            ValidationError(
                code="invalid_args_type",
                message="escrow-cancel payload.args must be an object",
                details={"field": "args"},
                spec_ref="Assets §5.1.6",
            )
        ]

    payment_reference = args.get("payment_reference")
    if not isinstance(payment_reference, str) or not payment_reference:
        errors.append(
            ValidationError(
                code="missing_payment_reference",
                message=(
                    "escrow-cancel payload.args.payment_reference is required "
                    "(non-empty string)"
                ),
                details={"field": "payment_reference"},
                spec_ref="Assets §5.1.6",
            )
        )

    cancellation_reason = args.get("cancellation_reason")
    if not isinstance(cancellation_reason, str) or not cancellation_reason:
        errors.append(
            ValidationError(
                code="missing_cancellation_reason",
                message=(
                    "escrow-cancel payload.args.cancellation_reason is required "
                    "(non-empty string)"
                ),
                details={"field": "cancellation_reason"},
                spec_ref="Assets §5.1.6",
            )
        )

    if (
        sender_agent_id is not None
        and from_agent is not None
        and sender_agent_id != from_agent
    ):
        errors.append(
            ValidationError(
                code="forbidden",
                message=(
                    f"cancel sender {sender_agent_id!r} is not the escrow "
                    f"creator ({from_agent!r})"
                ),
                details={
                    "field": "sender_agent_id",
                    "sender": sender_agent_id,
                    "from_agent": from_agent,
                },
                spec_ref="Assets §4.2.4",
            )
        )

    return errors


PAYLOAD_TYPE_ESCROW_RELEASE: Final[str] = "arsiaprotocol.assets/escrow-release"
"""Payload type for escrow release messages."""


def validate_escrow_release(args: dict[str, Any]) -> list[ValidationError]:
    """Validate an ``arsiaprotocol.assets/escrow-release`` ``payload.args`` dict.

    §4.2 mandates that the release message MUST include the
    ``payment_reference`` of the escrowed transfer to link the release
    to the specific escrow.

    Spec: ARSIA-Assets.md §4.2.
    """
    errors: list[ValidationError] = []
    if not isinstance(args, dict):
        return [
            ValidationError(
                code="invalid_args_type",
                message="escrow-release payload.args must be an object",
                details={"field": "args"},
                spec_ref="Assets §4.2",
            )
        ]

    payment_reference = args.get("payment_reference")
    if not isinstance(payment_reference, str) or not payment_reference:
        errors.append(
            ValidationError(
                code="missing_payment_reference",
                message=(
                    "escrow-release payload.args.payment_reference is required "
                    "(non-empty string)"
                ),
                details={"field": "payment_reference"},
                spec_ref="Assets §4.2",
            )
        )

    return errors


# ---------------------------------------------------------------------------
# §5.2 — pending_approval content model for asset transfers
# ---------------------------------------------------------------------------


class AssetPendingApprovalArgs(BaseModel):
    """Content model for an asset transfer ``pending_approval`` payload.

    §5.2 requires the pending_approval message to include a
    human-readable ``summary`` of the transfer so the approver can
    make an informed decision without consulting the original request.

    Spec: ARSIA-Assets.md §5.2.
    """

    model_config = ConfigDict(extra="allow")

    payment_reference: str = Field(
        max_length=128,
        description="payment_reference of the transfer under review.",
    )
    summary: str = Field(
        min_length=1,
        max_length=1024,
        description="Human-readable transfer summary for the approver.",
    )


def validate_asset_pending_approval(args: dict[str, Any]) -> list[ValidationError]:
    """Validate an asset transfer ``pending_approval`` payload.

    §5.2 mandates a human-readable ``summary`` field so the approver
    can make an informed decision without consulting the original
    request. ``payment_reference`` is also required to link the
    approval to the specific transfer.

    Spec: ARSIA-Assets.md §5.2.
    """
    errors: list[ValidationError] = []
    if not isinstance(args, dict):
        return [
            ValidationError(
                code="invalid_args_type",
                message="asset pending_approval payload.args must be an object",
                details={"field": "args"},
                spec_ref="Assets §5.2",
            )
        ]

    summary = args.get("summary")
    if not isinstance(summary, str) or not summary:
        errors.append(
            ValidationError(
                code="missing_summary",
                message=(
                    "pending_approval MUST include a human-readable summary "
                    "of the transfer"
                ),
                details={"field": "summary"},
                spec_ref="Assets §5.2",
            )
        )

    payment_reference = args.get("payment_reference")
    if not isinstance(payment_reference, str) or not payment_reference:
        errors.append(
            ValidationError(
                code="missing_payment_reference",
                message=(
                    "pending_approval MUST include payment_reference "
                    "to link to the transfer"
                ),
                details={"field": "payment_reference"},
                spec_ref="Assets §5.2",
            )
        )

    return errors


# ---------------------------------------------------------------------------
# §3.2 — Compliance echo validation (cross-message)
# ---------------------------------------------------------------------------


def validate_compliance_echo(
    request_compliance: dict[str, Any] | None,
    receipt_compliance: dict[str, Any] | None,
) -> list[ValidationError]:
    """Check receipt compliance echoes request compliance.

    Spec: ARSIA-Assets.md §3.2.
    """
    errors: list[ValidationError] = []

    if request_compliance is None:
        return errors

    if receipt_compliance is None:
        errors.append(
            ValidationError(
                code="compliance_echo_missing",
                message=(
                    "receipt SHOULD echo the compliance object from the "
                    "original transfer request"
                ),
                details={"field": "compliance"},
                spec_ref="Assets §3.2",
            )
        )
        return errors

    req_profile = request_compliance.get("profile")
    rec_profile = receipt_compliance.get("profile")
    if req_profile is not None and rec_profile is not None:
        if req_profile != rec_profile:
            errors.append(
                ValidationError(
                    code="compliance_profile_mismatch",
                    message=(
                        f"receipt compliance profile {rec_profile!r} does not "
                        f"match request profile {req_profile!r}"
                    ),
                    details={
                        "receipt_profile": rec_profile,
                        "request_profile": req_profile,
                    },
                    spec_ref="Assets §3.2",
                )
            )

    return errors


# ---------------------------------------------------------------------------
# §3.1.1 — Idempotency key envelope consistency
# ---------------------------------------------------------------------------


def validate_idempotency_key_in_envelope(
    envelope: Mapping[str, Any],
    payload_args: Mapping[str, Any],
) -> list[ValidationError]:
    """Verify payload.args.idempotency_key matches envelope.idempotency.key.

    Spec: ARSIA-Assets.md §3.1.1, ARSIA-Core.md §10.4.
    """
    errors: list[ValidationError] = []
    args_key = payload_args.get("idempotency_key")
    if args_key is None:
        return errors

    idem = envelope.get("idempotency")
    envelope_key = idem.get("key") if isinstance(idem, Mapping) else None

    if envelope_key is None:
        errors.append(
            ValidationError(
                code="idempotency_key_not_in_envelope",
                message=(
                    "payload.args.idempotency_key is present but "
                    "envelope.idempotency.key is missing"
                ),
                details={"args_idempotency_key": args_key},
                spec_ref="Assets §3.1.1, Core §10.4",
            )
        )
        return errors

    if args_key != envelope_key:
        errors.append(
            ValidationError(
                code="idempotency_key_mismatch",
                message=(
                    f"payload.args.idempotency_key {args_key!r} does not match "
                    f"envelope.idempotency.key {envelope_key!r}"
                ),
                details={"args_key": args_key, "envelope_key": envelope_key},
                spec_ref="Assets §3.1.1, Core §10.4",
            )
        )

    return errors


__all__ = [
    # §2 — asset types + precision
    "ASSET_TYPES",
    "ASSET_PRECISION",
    "FINANCIAL_ASSET_TYPES",
    "ASSETS_PAYLOAD_PREFIX",
    "PAYLOAD_TYPE_TRANSFER_REQUEST",
    "PAYLOAD_TYPE_TRANSFER_RECEIPT",
    "PAYLOAD_TYPE_TRANSFER_REVERSAL",
    "PAYLOAD_TYPE_ESCROW_DISPUTE",
    "PAYLOAD_TYPE_ESCROW_CANCEL",
    "PAYLOAD_TYPE_DORA_INCIDENT",
    "ISO_4217_CURRENCY_CODES",
    "count_decimal_places",
    "validate_currency_or_unit",
    "validate_metadata_no_financial_data",
    "validate_transfer_amount",
    # §3 — messages
    "validate_transfer_request",
    "validate_transfer_receipt",
    "validate_transfer_reversal",
    "validate_reversal_precondition",
    "validate_payment_reference_unique",
    "validate_receipt_against_request",
    "validate_compliance_echo",
    "validate_idempotency_key_in_envelope",
    "validate_transfer_delegation",
    "PaymentReferenceStore",
    # §4 — escrow
    "EscrowState",
    "ESCROW_STATES",
    "ESCROW_TRANSITIONS",
    "is_valid_escrow_transition",
    "is_terminal_escrow_state",
    "can_reach_disputed",
    "validate_escrow_conditions",
    "validate_escrow_dispute",
    "validate_escrow_cancel",
    "validate_escrow_release",
    "PAYLOAD_TYPE_ESCROW_RELEASE",
    "build_escrow_created_audit",
    "build_escrow_released_audit",
    "build_escrow_returned_audit",
    "build_escrow_disputed_audit",
    # §5 — capabilities + two-party auth
    "ASSETS_CAPABILITIES",
    "ASSETS_CAPABILITY_RISK_LEVELS",
    "is_assets_capability",
    "validate_assets_token_scope",
    "validate_two_party_auth",
    "SCA_REQUIRED_MIN_RISK_LEVEL",
    "requires_psd2_sca",
    "requires_human_oversight",
    # §6.1 — MiFID II
    "MIFID_RETENTION_DAYS_MIN",
    "MIFID_AUDIT_FIELDS",
    "is_mifid_applicable",
    "build_mifid_audit_fields",
    "build_reversal_audit_fields",
    "enforce_mifid_retention",
    # §6.2 — DORA
    "DoraIncidentType",
    "DORA_INCIDENT_TYPES",
    "DoraSeverity",
    "DORA_SEVERITIES",
    "is_infrastructure_failure",
    "classify_dora_incident_type",
    "build_dora_incident_event",
    # §6.3 — PSD2
    "is_sca_exempt",
    "validate_psd2_sca_factors",
    # §5.2 — pending_approval content model
    "AssetPendingApprovalArgs",
    "validate_asset_pending_approval",
    # types re-exports (Layer 1 models for callers that construct via assets)
    "AssetType",
    "TransferStatus",
    "EscrowConditions",
    "AssetTransferRequestArgs",
    "AssetTransferReceiptResult",
    "AssetTransferReversalArgs",
]
