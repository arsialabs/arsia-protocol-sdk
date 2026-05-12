# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Unit tests for :mod:`arsia_protocol.assets` (Slice 6).

Organised by §-section of ARSIA-Assets.md:

- §2 precision + asset types
- §3.1 AssetTransferRequest validation
- §3.2 AssetTransferReceipt validation
- §3.3 AssetTransferReversal + reversal precondition
- §4 Escrow state machine + validate_escrow_conditions
- §5 Capability + two-party authorisation
- §6.1 MiFID II audit record
- §6.2 DORA incident events
- §6.3 PSD2 SCA

Each test docstring cites the spec section it exercises. No pytest
markers — the SDK does not use RTM (see CONTRIBUTING.md).
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal

import pytest

from arsia_protocol.assets.assets import (
    ASSET_PRECISION,
    ASSET_TYPES,
    ASSETS_CAPABILITIES,
    ASSETS_CAPABILITY_RISK_LEVELS,
    ASSETS_PAYLOAD_PREFIX,
    DORA_INCIDENT_TYPES,
    DORA_SEVERITIES,
    ESCROW_STATES,
    ESCROW_TRANSITIONS,
    FINANCIAL_ASSET_TYPES,
    ISO_4217_CURRENCY_CODES,
    MIFID_AUDIT_FIELDS,
    MIFID_RETENTION_DAYS_MIN,
    PAYLOAD_TYPE_DORA_INCIDENT,
    PAYLOAD_TYPE_TRANSFER_RECEIPT,
    PAYLOAD_TYPE_TRANSFER_REQUEST,
    PAYLOAD_TYPE_TRANSFER_REVERSAL,
    SCA_REQUIRED_MIN_RISK_LEVEL,
    build_dora_incident_event,
    build_escrow_created_audit,
    build_escrow_disputed_audit,
    build_escrow_released_audit,
    build_escrow_returned_audit,
    build_mifid_audit_fields,
    build_reversal_audit_fields,
    can_reach_disputed,
    classify_dora_incident_type,
    count_decimal_places,
    enforce_mifid_retention,
    is_assets_capability,
    is_infrastructure_failure,
    is_mifid_applicable,
    is_sca_exempt,
    is_terminal_escrow_state,
    is_valid_escrow_transition,
    requires_human_oversight,
    requires_psd2_sca,
    validate_assets_token_scope,
    validate_escrow_cancel,
    validate_escrow_conditions,
    validate_escrow_dispute,
    validate_psd2_sca_factors,
    validate_compliance_echo,
    validate_idempotency_key_in_envelope,
    validate_receipt_against_request,
    validate_reversal_precondition,
    validate_transfer_amount,
    validate_transfer_receipt,
    validate_transfer_request,
    validate_transfer_reversal,
    PaymentReferenceStore,
    validate_currency_or_unit,
    validate_metadata_no_financial_data,
    validate_payment_reference_unique,
    validate_transfer_delegation,
    validate_two_party_auth,
)


# ---------------------------------------------------------------------------
# §2 — asset types + precision
# ---------------------------------------------------------------------------


class TestAssetTypeRegistry:
    def test_four_asset_types_defined(self) -> None:
        """§2 — exactly four asset types, no additions."""
        assert ASSET_TYPES == frozenset(
            {"currency", "token", "entitlement", "service_unit"}
        )

    def test_precision_table_matches_spec(self) -> None:
        """§2.1-§2.4 — currency:2, token:8, entitlement:2, service_unit:4."""
        assert ASSET_PRECISION["currency"] == 2
        assert ASSET_PRECISION["token"] == 8
        assert ASSET_PRECISION["entitlement"] == 2
        assert ASSET_PRECISION["service_unit"] == 4

    def test_financial_asset_types_are_currency_only(self) -> None:
        """§2.1 — currency is the only MiFID/PSD2/DORA-regulated type."""
        assert FINANCIAL_ASSET_TYPES == frozenset({"currency"})

    def test_payload_prefix(self) -> None:
        """§3 — all transfer messages share the assets payload prefix."""
        assert PAYLOAD_TYPE_TRANSFER_REQUEST.startswith(ASSETS_PAYLOAD_PREFIX)
        assert PAYLOAD_TYPE_TRANSFER_RECEIPT.startswith(ASSETS_PAYLOAD_PREFIX)
        assert PAYLOAD_TYPE_TRANSFER_REVERSAL.startswith(ASSETS_PAYLOAD_PREFIX)

    def test_dora_payload_type(self) -> None:
        """§6.2.2 — DORA events use the dora/ namespace."""
        assert PAYLOAD_TYPE_DORA_INCIDENT == "arsiaprotocol.dora/incident"


class TestCountDecimalPlaces:
    def test_integer_has_zero_places(self) -> None:
        """§2 — integer amounts have 0 decimal places."""
        assert count_decimal_places(100) == 0

    def test_single_decimal(self) -> None:
        """§2.1 — 100.0 floats stringify to one decimal."""
        assert count_decimal_places(100.0) == 1

    def test_three_decimal_currency_amount(self) -> None:
        """§2.1 — the INV-09 amount of 150.123 has 3 decimal places."""
        assert count_decimal_places(150.123) == 3

    def test_string_preserves_trailing_zeros(self) -> None:
        """§2 — string input '100.00' preserves the 2-decimal shape."""
        assert count_decimal_places("100.00") == 2

    def test_decimal_object_with_exponent(self) -> None:
        """§2 — Decimal('0.0001') reports 4 places for service_unit."""
        assert count_decimal_places(Decimal("0.0001")) == 4

    def test_bool_is_rejected(self) -> None:
        """§2 — bool is not numeric, even though Python treats it as int."""
        with pytest.raises(TypeError):
            count_decimal_places(True)

    def test_invalid_string_raises_value_error(self) -> None:
        """§2 — non-decimal strings raise ValueError."""
        with pytest.raises(ValueError):
            count_decimal_places("not-a-number")

    def test_unsupported_type_raises_type_error(self) -> None:
        """§2 — objects that are not numeric raise TypeError."""
        with pytest.raises(TypeError):
            count_decimal_places([1, 2, 3])  # type: ignore[arg-type]


class TestValidateTransferAmount:
    def test_currency_two_places_ok(self) -> None:
        """§2.1 — 100.00 is a valid currency amount."""
        assert validate_transfer_amount(100.00, "currency") == []

    def test_currency_three_places_rejected_with_inv09_keyword(self) -> None:
        """§2.1 — 150.123 must be rejected with the INV-09 phrasing."""
        errors = validate_transfer_amount(150.123, "currency")
        assert any(
            "currency amount precision exceeds 2 decimal places" in str(e)
            for e in errors
        ), errors

    def test_token_eight_places_ok(self) -> None:
        """§2.2 — token amounts allow up to 8 decimal places."""
        assert validate_transfer_amount(0.12345678, "token") == []

    def test_token_nine_places_rejected(self) -> None:
        """§2.2 — 9 decimal places rejected for token."""
        errors = validate_transfer_amount(Decimal("0.123456789"), "token")
        assert any("precision exceeds 8" in str(e) for e in errors)

    def test_service_unit_four_places_ok(self) -> None:
        """§2.4 — service_unit allows 4 decimal places."""
        assert validate_transfer_amount(0.0001, "service_unit") == []

    def test_service_unit_five_places_rejected(self) -> None:
        """§2.4 — 5 decimal places rejected for service_unit."""
        errors = validate_transfer_amount(Decimal("0.00001"), "service_unit")
        assert any("precision exceeds 4" in str(e) for e in errors)

    def test_entitlement_integer_ok(self) -> None:
        """§2.3 — entitlement integers are ideal."""
        assert validate_transfer_amount(5, "entitlement") == []

    def test_entitlement_three_places_rejected(self) -> None:
        """§2.3 — entitlement precision capped at 2."""
        errors = validate_transfer_amount(Decimal("0.500"), "entitlement")
        assert any("precision exceeds 2" in str(e) for e in errors)

    def test_zero_amount_rejected(self) -> None:
        """§3.1.1 — amount MUST be > 0."""
        errors = validate_transfer_amount(0, "currency")
        assert any("greater than 0" in str(e) for e in errors)

    def test_negative_amount_rejected(self) -> None:
        """§3.1.1 — negative amount MUST be rejected."""
        errors = validate_transfer_amount(-1.0, "currency")
        assert any("greater than 0" in str(e) for e in errors)

    def test_non_numeric_rejected(self) -> None:
        """§3.1.1 — string amounts fed as number must be rejected."""
        errors = validate_transfer_amount("ten", "currency")
        assert errors  # any error message is acceptable here

    def test_unknown_asset_type_rejected(self) -> None:
        """§2 — unknown asset_type rejected before precision check."""
        errors = validate_transfer_amount(1.0, "crypto")
        assert any("is not one of" in str(e) for e in errors)


# ---------------------------------------------------------------------------
# §3.1 — AssetTransferRequest validation
# ---------------------------------------------------------------------------


def _valid_transfer_args() -> dict:
    return {
        "amount": 100.00,
        "currency_or_unit": "EUR",
        "asset_type": "currency",
        "from_agent": "agent:acme.payer",
        "to_agent": "agent:contoso.payee",
        "payment_reference": "acme-2026-0001",
        "description": "Unit test transfer",
        "idempotency_key": "idem-0001",
    }


class TestValidateTransferRequest:
    def test_valid_currency_transfer(self) -> None:
        """§3.1.1 — a fully-populated currency transfer passes."""
        assert validate_transfer_request(_valid_transfer_args()) == []

    def test_missing_idempotency_key_rejected(self) -> None:
        """§3.1.1 — idempotency_key is REQUIRED."""
        args = _valid_transfer_args()
        del args["idempotency_key"]
        errors = validate_transfer_request(args)
        assert any("idempotency_key" in str(e) for e in errors)

    def test_inv09_keyword_surfaced(self) -> None:
        """§2.1 — the INV-09 rejection keyword reaches the caller."""
        args = _valid_transfer_args()
        args["amount"] = 150.123
        errors = validate_transfer_request(args)
        assert any(
            "currency amount precision exceeds 2 decimal places" in str(e)
            for e in errors
        )

    def test_currency_code_pattern(self) -> None:
        """§2.1 — currency_or_unit MUST match ^[A-Z]{3}$ for currency."""
        args = _valid_transfer_args()
        args["currency_or_unit"] = "eur"
        errors = validate_transfer_request(args)
        assert any("ISO 4217" in str(e) for e in errors)

    def test_token_allows_non_iso_unit(self) -> None:
        """§2.2 — token amounts accept application-defined unit strings."""
        args = _valid_transfer_args()
        args["asset_type"] = "token"
        args["currency_or_unit"] = "api-credits"
        args["amount"] = 1.5
        assert validate_transfer_request(args) == []

    def test_token_lowercase_units_accepted(self) -> None:
        """§3.1.1 — non-currency units accept the lowercase pattern."""
        for unit in ("api-credits", "compute-hours", "premium-seats", "gpu-h"):
            args = _valid_transfer_args()
            args["asset_type"] = "token"
            args["currency_or_unit"] = unit
            args["amount"] = 1
            assert validate_transfer_request(args) == [], unit

    def test_non_currency_iso_4217_collision_rejected(self) -> None:
        """§3.1.1 — non-currency units MUST NOT collide with ISO 4217."""
        args = _valid_transfer_args()
        args["asset_type"] = "token"
        args["currency_or_unit"] = "usd"  # lowercase but collides with USD
        errors = validate_transfer_request(args)
        assert any("collides with ISO 4217" in str(e) for e in errors)

    def test_non_currency_pattern_violations(self) -> None:
        """§3.1.1 — non-currency units must match the restrictive pattern."""
        bad_units = (
            "API_CREDITS",      # uppercase + underscore
            "-leading-hyphen",  # leading hyphen
            "trailing-",        # trailing hyphen
            "a",                # too short (min 2)
            "",                 # empty
            "has space",        # space
        )
        for unit in bad_units:
            args = _valid_transfer_args()
            args["asset_type"] = "token"
            args["currency_or_unit"] = unit
            errors = validate_transfer_request(args)
            assert errors, f"expected rejection for {unit!r}"

    def test_escrow_missing_release_agent_inv13(self) -> None:
        """§4.1 — the INV-13 rejection keyword reaches the caller."""
        args = _valid_transfer_args()
        args["escrow_conditions"] = {
            "release_condition": "Goods delivered",
            "release_trigger": "com.acme/release",
            "timeout_at": "2026-04-01T00:00:00.000Z",
        }
        errors = validate_transfer_request(args)
        assert any(
            "escrow_conditions.release_agent is required" in str(e) for e in errors
        )

    def test_escrow_all_fields_ok(self) -> None:
        """§4.1 — fully-specified escrow conditions pass."""
        args = _valid_transfer_args()
        args["escrow_conditions"] = {
            "release_condition": "Goods delivered and accepted",
            "release_trigger": "com.acme/release",
            "release_agent": "agent:acme.trustee",
            "timeout_at": "2027-01-01T00:00:00.000Z",
        }
        assert validate_transfer_request(args) == []

    def test_non_dict_args_returns_schema_errors_only(self) -> None:
        """§3.1.1 — non-dict args bail after L1 schema rejects the type."""
        errors = validate_transfer_request("not an object")  # type: ignore[arg-type]
        assert errors  # L1 reports the type mismatch

    def test_reserved_payload_prefix_shared(self) -> None:
        """§3 — constants expose the three transfer payload types."""
        assert PAYLOAD_TYPE_TRANSFER_REQUEST == (
            "arsiaprotocol.assets/transfer-request"
        )


class TestValidateCurrencyOrUnit:
    def test_currency_known_iso_code_ok(self) -> None:
        """§2.1 — known ISO 4217 codes pass."""
        for code in ("EUR", "USD", "GBP", "JPY", "CHF", "SEK"):
            assert validate_currency_or_unit(code, "currency") == [], code

    def test_currency_lowercase_rejected(self) -> None:
        """§2.1 — currency_or_unit must be uppercase ISO 4217."""
        errors = validate_currency_or_unit("eur", "currency")
        assert any("ISO 4217" in str(e) for e in errors)

    def test_currency_unknown_3letter_accepted(self) -> None:
        """§2.1 — SHOULD-level ISO list check is not enforced for currency."""
        assert validate_currency_or_unit("XYZ", "currency") == []

    def test_iso_4217_set_contains_common_codes(self) -> None:
        """The frozenset exposes a recognisable active subset."""
        for code in ("EUR", "USD", "GBP", "JPY", "CHF", "XXX"):
            assert code in ISO_4217_CURRENCY_CODES

    def test_non_currency_pattern_ok(self) -> None:
        """§3.1.1 — lowercase hyphen-separated units pass for token/etc."""
        for t in ("token", "entitlement", "service_unit"):
            assert validate_currency_or_unit("api-credits", t) == []
            assert validate_currency_or_unit("gpu-h", t) == []

    def test_non_currency_uppercase_rejected(self) -> None:
        """§3.1.1 — uppercase is not allowed in application-defined units."""
        errors = validate_currency_or_unit("API-CREDITS", "token")
        assert any("pattern" in str(e) for e in errors)

    def test_non_currency_collision_case_insensitive(self) -> None:
        """§3.1.1 — lowercase "usd" collides with ISO 4217 "USD"."""
        errors = validate_currency_or_unit("usd", "token")
        assert any("collides with ISO 4217" in str(e) for e in errors)
        errors = validate_currency_or_unit("eur", "entitlement")
        assert any("collides with ISO 4217" in str(e) for e in errors)

    def test_non_currency_4_letter_does_not_collide(self) -> None:
        """4+ letter units cannot collide with 3-letter ISO codes."""
        assert validate_currency_or_unit("usdc", "token") == []

    def test_non_string_rejected(self) -> None:
        """Non-string values are rejected with a clear L2 error."""
        errors = validate_currency_or_unit(123, "currency")
        assert any("must be a string" in str(e) for e in errors)

    def test_unknown_asset_type_no_errors(self) -> None:
        """Unknown asset_type is upstream's responsibility — no extra noise."""
        assert validate_currency_or_unit("anything", "bogus") == []


class TestValidateMetadataNoFinancialData:
    def test_clean_metadata_no_warnings(self) -> None:
        """Benign metadata produces no warnings."""
        metadata = {"product": "widget", "qty": 3, "tags": ["a", "b"]}
        assert validate_metadata_no_financial_data(metadata) == []

    def test_iban_flagged(self) -> None:
        """§1.3 — an IBAN in a string value is flagged."""
        # DE89 3704 0044 0532 0130 00 (spec example IBAN)
        metadata = {"note": "wire to DE89370400440532013000 by EOD"}
        warnings = validate_metadata_no_financial_data(metadata)
        assert any(w.code == "possible_iban" for w in warnings)

    def test_luhn_valid_card_flagged(self) -> None:
        """§1.3 — a Luhn-valid card number is flagged."""
        # 4111 1111 1111 1111 is the canonical Visa test card (Luhn valid).
        metadata = {"memo": "card on file 4111 1111 1111 1111"}
        warnings = validate_metadata_no_financial_data(metadata)
        assert any(w.code == "possible_card_number" for w in warnings)

    def test_luhn_invalid_digits_not_flagged(self) -> None:
        """A bare 16-digit string that fails Luhn does not flag."""
        metadata = {"tracking_number": "1234567890123456"}  # fails Luhn
        warnings = validate_metadata_no_financial_data(metadata)
        assert not any(w.code == "possible_card_number" for w in warnings)

    def test_uk_sort_code_flagged(self) -> None:
        """§1.3 — a UK sort code NN-NN-NN is flagged."""
        metadata = {"bank": "sort 20-00-00"}
        warnings = validate_metadata_no_financial_data(metadata)
        assert any(w.code == "possible_sort_code" for w in warnings)

    def test_aba_routing_flagged(self) -> None:
        """§1.3 — a 9-digit ABA routing number passing checksum is flagged."""
        # 021000021 — Chase NY, passes ABA checksum.
        metadata = {"wire": "routing 021000021"}
        warnings = validate_metadata_no_financial_data(metadata)
        assert any(w.code == "possible_routing_number" for w in warnings)

    def test_bare_9_digits_without_aba_checksum_not_flagged(self) -> None:
        """A random 9-digit string that fails the ABA checksum is not flagged."""
        metadata = {"ref": "order 123456789"}  # fails ABA checksum
        warnings = validate_metadata_no_financial_data(metadata)
        assert not any(w.code == "possible_routing_number" for w in warnings)

    def test_nested_path_reported(self) -> None:
        """Nested dict/list paths are reported via dotted JSON pointer."""
        metadata = {
            "customer": {"iban": "DE89370400440532013000"},
            "items": [{"note": "harmless"}],
        }
        warnings = validate_metadata_no_financial_data(metadata)
        assert any("metadata.customer.iban" in str(w) for w in warnings)

    def test_list_index_in_path(self) -> None:
        """List indices appear in the warning path."""
        metadata = {"notes": ["clean", "DE89370400440532013000"]}
        warnings = validate_metadata_no_financial_data(metadata)
        assert any("metadata.notes.1" in str(w) for w in warnings)

    def test_none_metadata_returns_empty(self) -> None:
        assert validate_metadata_no_financial_data(None) == []

    def test_strict_mode_surfaces_warnings_as_errors(self) -> None:
        """§1.3 — validate_transfer_request(strict=True) rejects IBAN-bearing metadata."""
        args = _valid_transfer_args()
        args["metadata"] = {"note": "wire to DE89370400440532013000"}
        # Without strict, clean.
        assert validate_transfer_request(args) == []
        # With strict, IBAN warning is returned as an error.
        errors = validate_transfer_request(args, strict=True)
        assert any("IBAN" in str(e) for e in errors)

    def test_strict_mode_clean_metadata_still_passes(self) -> None:
        """strict=True does not generate false positives on benign metadata."""
        args = _valid_transfer_args()
        args["metadata"] = {"product": "widget", "qty": 3}
        assert validate_transfer_request(args, strict=True) == []


class TestValidateTransferDelegation:
    def test_matching_agents_no_flag(self) -> None:
        """§3.1.1 — no delegation when envelope.from == args.from_agent."""
        assert validate_transfer_delegation(
            args_from_agent="agent:acme.billing",
            envelope_from="agent:acme.billing",
        ) == []

    def test_differing_agents_flagged_as_info(self) -> None:
        """§3.1.1 — delegation emits an L2-INFO entry, not a rejection."""
        result = validate_transfer_delegation(
            args_from_agent="agent:acme.client",
            envelope_from="agent:acme.broker",
        )
        assert len(result) == 1
        assert result[0].code == "delegated_transfer"

    def test_non_string_inputs_no_flag(self) -> None:
        """Missing/None inputs are not themselves a delegation signal."""
        assert validate_transfer_delegation(
            args_from_agent=None, envelope_from="agent:acme.broker"
        ) == []
        assert validate_transfer_delegation(
            args_from_agent="agent:acme.client", envelope_from=None
        ) == []

    def test_wired_into_transfer_request(self) -> None:
        """validate_transfer_request(envelope_from=...) emits the INFO entry."""
        args = _valid_transfer_args()
        args["from_agent"] = "agent:acme.client"
        # No envelope_from → no delegation flag.
        assert not any(
            e.code == "delegated_transfer" for e in validate_transfer_request(args)
        )
        errors = validate_transfer_request(
            args, envelope_from="agent:acme.broker"
        )
        assert any("delegated transfer" in str(e) for e in errors)

    def test_wired_matching_agents_no_info(self) -> None:
        """envelope_from == args.from_agent → no delegation entry."""
        args = _valid_transfer_args()
        args["from_agent"] = "agent:acme.billing"
        errors = validate_transfer_request(
            args, envelope_from="agent:acme.billing"
        )
        assert not any("delegated transfer" in str(e) for e in errors)


class _MockPaymentReferenceStore:
    """Minimal in-memory store used by the uniqueness-hook tests."""

    def __init__(self, existing: set[str] | None = None) -> None:
        self._existing: set[str] = set(existing or ())

    def exists(self, payment_reference: str) -> bool:
        return payment_reference in self._existing


class TestValidatePaymentReferenceUnique:
    def test_protocol_satisfied_by_mock(self) -> None:
        """Mock store is a structural instance of PaymentReferenceStore."""
        store = _MockPaymentReferenceStore()
        assert isinstance(store, PaymentReferenceStore)

    def test_store_none_skips_check(self) -> None:
        """Offline mode (store=None) returns [] — caller trusts upstream."""
        assert validate_payment_reference_unique("acme-2026-00042") == []
        assert validate_payment_reference_unique("acme-2026-00042", store=None) == []

    def test_reference_absent_passes(self) -> None:
        """A fresh reference returns no errors."""
        store = _MockPaymentReferenceStore({"acme-2026-00001"})
        errors = validate_payment_reference_unique(
            "acme-2026-00099", store=store
        )
        assert errors == []

    def test_reference_present_rejected(self) -> None:
        """A duplicate reference yields an L2 error."""
        store = _MockPaymentReferenceStore({"acme-2026-00042"})
        errors = validate_payment_reference_unique(
            "acme-2026-00042", store=store
        )
        assert any(
            "already present in the deployment" in str(e) for e in errors
        )

    def test_empty_reference_with_store(self) -> None:
        """A missing reference cannot be meaningfully checked."""
        store = _MockPaymentReferenceStore()
        errors = validate_payment_reference_unique("", store=store)
        assert any("non-empty string" in str(e) for e in errors)

    def test_non_string_reference_with_store(self) -> None:
        """A non-string reference is rejected before hitting the store."""
        store = _MockPaymentReferenceStore()
        errors = validate_payment_reference_unique(12345, store=store)
        assert any("non-empty string" in str(e) for e in errors)


# ---------------------------------------------------------------------------
# §3.2 — AssetTransferReceipt validation
# ---------------------------------------------------------------------------


class TestValidateTransferReceipt:
    def test_completed_receipt_passes(self) -> None:
        """§3.2.1 — status=completed with settled_at passes schema."""
        result = {
            "status": "completed",
            "payment_reference": "r-1",
            "amount": 100.0,
            "currency_or_unit": "EUR",
            "initiated_at": "2026-04-01T12:00:00.000Z",
            "settled_at": "2026-04-01T12:00:05.000Z",
            "audit_id": "11111111-1111-4111-9111-111111111111",
        }
        assert validate_transfer_receipt(result) == []

    def test_failed_receipt_without_reason_rejected(self) -> None:
        """§3.2.1 — failed status MUST carry failure_reason."""
        result = {
            "status": "failed",
            "payment_reference": "r-1",
            "amount": 100.0,
            "currency_or_unit": "EUR",
            "initiated_at": "2026-04-01T12:00:00.000Z",
            "audit_id": "11111111-1111-4111-9111-111111111111",
        }
        errors = validate_transfer_receipt(result)
        assert errors

    def test_completed_with_failure_reason_rejected(self) -> None:
        """§3.2.1 — completed + failure_reason is forbidden."""
        result = {
            "status": "completed",
            "payment_reference": "r-1",
            "amount": 100.0,
            "currency_or_unit": "EUR",
            "initiated_at": "2026-04-01T12:00:00.000Z",
            "settled_at": "2026-04-01T12:00:05.000Z",
            "failure_reason": "should not be here",
            "audit_id": "11111111-1111-4111-9111-111111111111",
        }
        errors = validate_transfer_receipt(result)
        assert errors

    def test_pending_with_settled_at_rejected(self) -> None:
        """§3.2.1 — pending/escrowed MUST NOT carry settled_at."""
        result = {
            "status": "pending",
            "payment_reference": "r-1",
            "amount": 100.0,
            "currency_or_unit": "EUR",
            "initiated_at": "2026-04-01T12:00:00.000Z",
            "settled_at": "2026-04-01T12:00:05.000Z",
            "audit_id": "11111111-1111-4111-9111-111111111111",
        }
        errors = validate_transfer_receipt(result)
        assert errors


# ---------------------------------------------------------------------------
# §3.3 — Reversal validation + precondition
# ---------------------------------------------------------------------------


class TestValidateTransferReversal:
    def test_minimal_reversal_passes_schema(self) -> None:
        """§3.3.1 — three required fields suffice for L1."""
        args = {
            "original_payment_reference": "r-1",
            "reversal_reason": "Client dispute",
            "requested_by": "agent:acme.payer",
        }
        assert validate_transfer_reversal(args) == []

    def test_missing_reason_rejected(self) -> None:
        """§3.3.1 — reversal_reason is required."""
        args = {
            "original_payment_reference": "r-1",
            "requested_by": "agent:acme.payer",
        }
        assert validate_transfer_reversal(args)


class TestReversalPrecondition:
    def test_pending_original_rejected(self) -> None:
        """§3.3 — INV-12 rule: original MUST be completed."""
        errors = validate_reversal_precondition(
            {"original_payment_reference": "r-1",
             "reversal_reason": "x", "requested_by": "agent:a.b"},
            original_status="pending",
        )
        assert any(e.code == "invalid_reversal_status" for e in errors)

    def test_completed_original_accepted(self) -> None:
        """§3.3 — completed originals pass the status precondition."""
        errors = validate_reversal_precondition(
            {"original_payment_reference": "r-1",
             "reversal_reason": "x", "requested_by": "agent:a.b"},
            original_status="completed",
        )
        assert errors == []

    def test_window_expired_full_reversal(self) -> None:
        """§3.3.2 — full reversal beyond T+1 window rejected."""
        settled = "2026-04-01T12:00:00.000Z"
        now = datetime(2026, 4, 3, 12, 0, 0, tzinfo=timezone.utc)
        errors = validate_reversal_precondition(
            {"original_payment_reference": "r-1",
             "reversal_reason": "x", "requested_by": "agent:a.b"},
            original_status="completed",
            original_settled_at=settled,
            now=now,
        )
        assert any("reversal window has expired" in str(e) for e in errors)

    def test_partial_window_still_open_at_t_plus_20(self) -> None:
        """§3.3.2 — partial reversal at T+20 stays inside the T+30 window."""
        settled = "2026-04-01T12:00:00.000Z"
        now = datetime(2026, 4, 21, 12, 0, 0, tzinfo=timezone.utc)
        errors = validate_reversal_precondition(
            {"original_payment_reference": "r-1",
             "reversal_reason": "x", "requested_by": "agent:a.b",
             "reversal_amount": 10.0},
            original_status="completed",
            original_settled_at=settled,
            original_amount=100.0,
            now=now,
        )
        assert errors == []

    def test_cumulative_exceeds_original(self) -> None:
        """§3.3.2 — sum of reversals MUST NOT exceed original."""
        errors = validate_reversal_precondition(
            {"original_payment_reference": "r-1",
             "reversal_reason": "x", "requested_by": "agent:a.b",
             "reversal_amount": 60.0},
            original_status="completed",
            original_amount=100.0,
            already_reversed_total=50.0,
        )
        assert any("cumulative reversals" in str(e) for e in errors)

    def test_full_reversal_blocked_after_partial(self) -> None:
        """§3.3.2 — full reversal forbidden when partial exists."""
        errors = validate_reversal_precondition(
            {"original_payment_reference": "r-1",
             "reversal_reason": "x", "requested_by": "agent:a.b"},
            original_status="completed",
            original_amount=100.0,
            already_reversed_total=25.0,
        )
        assert any("full reversal is prohibited" in str(e) for e in errors)

    def test_window_unknown_when_both_absent(self) -> None:
        """§3.3.2 — skip is acceptable when no settlement data is supplied."""
        errors = validate_reversal_precondition(
            {"original_payment_reference": "r-1",
             "reversal_reason": "x", "requested_by": "agent:a.b"},
            original_status="completed",
        )
        assert errors == []

    def test_window_error_when_only_settled_at_provided(self) -> None:
        """§3.3.2 — forgetting ``now`` must not silently skip the window check."""
        errors = validate_reversal_precondition(
            {"original_payment_reference": "r-1",
             "reversal_reason": "x", "requested_by": "agent:a.b"},
            original_status="completed",
            original_settled_at="2026-04-01T12:00:00.000Z",
        )
        assert any(e.code == "incomplete_reversal_window_args" for e in errors)

    def test_window_error_when_only_now_provided(self) -> None:
        """§3.3.2 — forgetting ``original_settled_at`` is equally rejected."""
        errors = validate_reversal_precondition(
            {"original_payment_reference": "r-1",
             "reversal_reason": "x", "requested_by": "agent:a.b"},
            original_status="completed",
            now=datetime(2026, 4, 2, 12, 0, 0, tzinfo=timezone.utc),
        )
        assert any(e.code == "incomplete_reversal_window_args" for e in errors)

    def test_window_runs_when_both_provided(self) -> None:
        """§3.3.2 — when both params are present, window check runs normally."""
        errors = validate_reversal_precondition(
            {"original_payment_reference": "r-1",
             "reversal_reason": "x", "requested_by": "agent:a.b"},
            original_status="completed",
            original_settled_at="2026-04-01T12:00:00.000Z",
            now=datetime(2026, 4, 1, 18, 0, 0, tzinfo=timezone.utc),
        )
        assert errors == []


# ---------------------------------------------------------------------------
# §4 — Escrow
# ---------------------------------------------------------------------------


class TestEscrowStateMachine:
    def test_escrow_states(self) -> None:
        """§4.2 — four states with three transitions from ESCROWED."""
        assert ESCROW_STATES == {"ESCROWED", "RELEASED", "RETURNED", "DISPUTED"}

    def test_escrowed_to_released_valid(self) -> None:
        """§4.2.1 — ESCROWED → RELEASED is allowed."""
        assert is_valid_escrow_transition("ESCROWED", "RELEASED")

    def test_escrowed_to_returned_valid(self) -> None:
        """§4.2.2 — ESCROWED → RETURNED is allowed on timeout."""
        assert is_valid_escrow_transition("ESCROWED", "RETURNED")

    def test_escrowed_to_disputed_valid(self) -> None:
        """§4.2.3 — ESCROWED → DISPUTED is allowed when arbitration_agent set."""
        assert is_valid_escrow_transition("ESCROWED", "DISPUTED")

    def test_disputed_to_released_valid(self) -> None:
        """§4.2.3 — arbitration may resolve DISPUTED → RELEASED."""
        assert is_valid_escrow_transition("DISPUTED", "RELEASED")

    def test_disputed_to_returned_valid(self) -> None:
        """§4.2.3 — arbitration may resolve DISPUTED → RETURNED."""
        assert is_valid_escrow_transition("DISPUTED", "RETURNED")

    def test_released_is_terminal(self) -> None:
        """§4.2 — RELEASED has no outgoing edges."""
        assert is_terminal_escrow_state("RELEASED")
        assert ESCROW_TRANSITIONS["RELEASED"] == frozenset()

    def test_returned_is_terminal(self) -> None:
        """§4.2 — RETURNED has no outgoing edges."""
        assert is_terminal_escrow_state("RETURNED")

    def test_disputed_is_not_terminal(self) -> None:
        """§4.2.3 — DISPUTED resolves to a terminal but is not itself terminal."""
        assert not is_terminal_escrow_state("DISPUTED")

    def test_backwards_transition_rejected(self) -> None:
        """§4.2 — terminal states have no outgoing transitions."""
        assert not is_valid_escrow_transition("RELEASED", "ESCROWED")
        assert not is_valid_escrow_transition("RETURNED", "DISPUTED")

    def test_unknown_from_state(self) -> None:
        """§4.2 — unknown from_state returns False."""
        assert not is_valid_escrow_transition("FROZEN", "RELEASED")

    def test_unknown_to_state(self) -> None:
        """§4.2 — unknown to_state returns False."""
        assert not is_valid_escrow_transition("ESCROWED", "CANCELLED")

    def test_can_reach_disputed_requires_arbitration_agent(self) -> None:
        """§4.2.3 — DISPUTED unreachable without arbitration_agent."""
        assert can_reach_disputed({"arbitration_agent": "agent:acme.court"})
        assert not can_reach_disputed({})
        assert not can_reach_disputed({"arbitration_agent": None})


class TestValidateEscrowConditions:
    def test_minimal_valid_escrow(self) -> None:
        """§4.1 — the four required fields pass schema validation."""
        conditions = {
            "release_condition": "Goods delivered",
            "release_trigger": "com.acme/release",
            "release_agent": "agent:acme.trustee",
            "timeout_at": "2027-01-01T00:00:00.000Z",
        }
        assert validate_escrow_conditions(conditions) == []

    def test_timeout_not_after_envelope_ts_rejected(self) -> None:
        """§4.1 — timeout_at MUST be later than envelope.ts."""
        conditions = {
            "release_condition": "Goods delivered",
            "release_trigger": "com.acme/release",
            "release_agent": "agent:acme.trustee",
            "timeout_at": "2026-04-01T12:00:00.000Z",
        }
        errors = validate_escrow_conditions(
            conditions, envelope_ts="2026-04-01T12:00:00.000Z"
        )
        assert any("later than envelope.ts" in str(e) for e in errors)

    def test_timeout_after_envelope_ts_ok(self) -> None:
        """§4.1 — a future timeout passes when envelope.ts is given."""
        conditions = {
            "release_condition": "Goods delivered",
            "release_trigger": "com.acme/release",
            "release_agent": "agent:acme.trustee",
            "timeout_at": "2026-05-01T00:00:00.000Z",
        }
        assert (
            validate_escrow_conditions(
                conditions, envelope_ts="2026-04-01T12:00:00.000Z"
            )
            == []
        )

    def test_missing_release_agent_inv13(self) -> None:
        """§4.1 — L1 schema rejects missing release_agent."""
        conditions = {
            "release_condition": "Goods delivered",
            "release_trigger": "com.acme/release",
            "timeout_at": "2026-05-01T00:00:00.000Z",
        }
        errors = validate_escrow_conditions(conditions)
        assert any("release_agent" in str(e) for e in errors)


# ---------------------------------------------------------------------------
# §5 — Capabilities + two-party auth
# ---------------------------------------------------------------------------


class TestCapabilities:
    def test_seven_assets_capabilities(self) -> None:
        """§5.1 — exactly seven reserved assets capabilities."""
        assert len(ASSETS_CAPABILITIES) == 7

    def test_all_are_reserved(self) -> None:
        """§5.1 — each assets capability uses the arsiaprotocol. prefix."""
        for cap in ASSETS_CAPABILITIES:
            assert cap.startswith("arsiaprotocol.assets.")

    def test_is_assets_capability(self) -> None:
        """§5.1 — membership helper matches the set."""
        assert is_assets_capability("arsiaprotocol.assets.transfer.initiate")
        assert not is_assets_capability("notes.read")
        assert not is_assets_capability("arsiaprotocol.oversight.approve")


class TestAssetsCapabilityRiskLevels:
    def test_seven_entries(self) -> None:
        """§5.1.1–§5.1.7 — risk-level map covers all seven capabilities."""
        assert len(ASSETS_CAPABILITY_RISK_LEVELS) == 7
        assert set(ASSETS_CAPABILITY_RISK_LEVELS.keys()) == ASSETS_CAPABILITIES

    def test_values_match_spec(self) -> None:
        """§5.1.1–§5.1.7 — risk levels match the spec field tables."""
        assert ASSETS_CAPABILITY_RISK_LEVELS[
            "arsiaprotocol.assets.transfer.initiate"
        ] == 5
        assert ASSETS_CAPABILITY_RISK_LEVELS[
            "arsiaprotocol.assets.transfer.approve"
        ] == 7
        assert ASSETS_CAPABILITY_RISK_LEVELS[
            "arsiaprotocol.assets.transfer.reverse"
        ] == 6
        assert ASSETS_CAPABILITY_RISK_LEVELS[
            "arsiaprotocol.assets.escrow.create"
        ] == 5
        assert ASSETS_CAPABILITY_RISK_LEVELS[
            "arsiaprotocol.assets.escrow.release"
        ] == 7
        assert ASSETS_CAPABILITY_RISK_LEVELS[
            "arsiaprotocol.assets.escrow.cancel"
        ] == 6
        assert ASSETS_CAPABILITY_RISK_LEVELS[
            "arsiaprotocol.assets.audit.read"
        ] == 3

    def test_mapping_is_read_only(self) -> None:
        """§5.1 — risk-level map is a MappingProxyType (immutable)."""
        with pytest.raises(TypeError):
            ASSETS_CAPABILITY_RISK_LEVELS["arsiaprotocol.assets.transfer.initiate"] = 9  # type: ignore[index]


class TestValidateAssetsTokenScope:
    def test_clean_scope(self) -> None:
        """§5.1.2 — scope without conflicts passes."""
        assert validate_assets_token_scope(
            {"arsiaprotocol.assets.transfer.initiate"}
        ) == []
        assert validate_assets_token_scope(
            ["arsiaprotocol.assets.transfer.approve", "arsiaprotocol.oversight.approve"]
        ) == []

    def test_initiate_and_approve_conflict(self) -> None:
        """§5.1.2 — initiate + approve in same token is forbidden."""
        errors = validate_assets_token_scope(
            [
                "arsiaprotocol.assets.transfer.initiate",
                "arsiaprotocol.assets.transfer.approve",
            ]
        )
        assert len(errors) == 1
        assert errors[0].code == "separation_of_duties_violation"

    def test_conflict_detected_in_set(self) -> None:
        """§5.1.2 — works on a set as well as a list."""
        errors = validate_assets_token_scope(
            {
                "arsiaprotocol.assets.transfer.initiate",
                "arsiaprotocol.assets.transfer.approve",
                "arsiaprotocol.assets.audit.read",
            }
        )
        assert errors  # conflict present

    def test_non_sequence_rejected(self) -> None:
        """§5.1.2 — non-sequence scope is flagged."""
        errors = validate_assets_token_scope("arsiaprotocol.assets.transfer.initiate")  # type: ignore[arg-type]
        assert errors and errors[0].code == "invalid_scope_type"


class TestTwoPartyAuth:
    def test_distinct_parties_with_both_caps(self) -> None:
        """§5.2 — initiator ≠ approver and approver holds both caps."""
        errors = validate_two_party_auth(
            initiator_agent_id="agent:acme.bot",
            approver_agent_id="agent:acme.human",
            approver_capabilities=[
                "arsiaprotocol.assets.transfer.approve",
                "arsiaprotocol.oversight.approve",
            ],
        )
        assert errors == []

    def test_same_party_rejected(self) -> None:
        """§5.2 — initiator cannot approve their own request."""
        errors = validate_two_party_auth(
            initiator_agent_id="agent:acme.bot",
            approver_agent_id="agent:acme.bot",
            approver_capabilities=[
                "arsiaprotocol.assets.transfer.approve",
                "arsiaprotocol.oversight.approve",
            ],
        )
        assert any("distinct agents" in str(e) for e in errors)

    def test_missing_approve_cap_rejected(self) -> None:
        """§5.2 — approver MUST carry assets.transfer.approve."""
        errors = validate_two_party_auth(
            initiator_agent_id="agent:acme.bot",
            approver_agent_id="agent:acme.human",
            approver_capabilities=["arsiaprotocol.oversight.approve"],
        )
        assert any("missing required capabilities" in str(e) for e in errors)

    def test_missing_oversight_cap_rejected(self) -> None:
        """§5.2 — approver MUST carry oversight.approve too."""
        errors = validate_two_party_auth(
            initiator_agent_id="agent:acme.bot",
            approver_agent_id="agent:acme.human",
            approver_capabilities=["arsiaprotocol.assets.transfer.approve"],
        )
        assert any("missing required capabilities" in str(e) for e in errors)


class TestSCAAndOversightHelpers:
    def test_sca_threshold_is_seven(self) -> None:
        """§5.2 / §6.3 — SCA applies at risk_level ≥ 7."""
        assert SCA_REQUIRED_MIN_RISK_LEVEL == 7

    def test_requires_psd2_sca_at_threshold(self) -> None:
        """§6.3 — risk_level=7 triggers SCA."""
        assert requires_psd2_sca(7) is True
        assert requires_psd2_sca(10) is True

    def test_does_not_require_below_threshold(self) -> None:
        """§6.3 — risk_level<7 does not trigger SCA."""
        assert requires_psd2_sca(6) is False

    def test_bool_not_accepted_as_risk_level(self) -> None:
        """§6.3 — bool is not an int risk level."""
        assert requires_psd2_sca(True) is False  # type: ignore[arg-type]

    def test_requires_human_oversight_is_alias(self) -> None:
        """§5.2 — two-party auth trigger equals SCA trigger."""
        for level in range(0, 11):
            assert requires_human_oversight(level) == requires_psd2_sca(level)


# ---------------------------------------------------------------------------
# §6.1 — MiFID II
# ---------------------------------------------------------------------------


class TestMifidAudit:
    def test_retention_floor_is_1827_days(self) -> None:
        """§6.1.2 — MiFID II retention minimum is 5 years (1827 days)."""
        assert MIFID_RETENTION_DAYS_MIN == 1827

    def test_audit_fields_listing(self) -> None:
        """§6.1.1 — 23-entry record (22 business + housekeeping)."""
        assert "audit_id" in MIFID_AUDIT_FIELDS
        assert "payload_hash" in MIFID_AUDIT_FIELDS
        assert "compliance_profile" in MIFID_AUDIT_FIELDS
        assert "human_oversight_status" in MIFID_AUDIT_FIELDS

    def test_is_mifid_applicable_mifid_profile(self) -> None:
        """§6.1 condition 1 — MIFID-II profile alone activates MiFID II."""
        env = {
            "payload": {"args": {"asset_type": "token"}},
            "compliance": {"profile": "MIFID-II"},
        }
        assert is_mifid_applicable(env)

    def test_is_mifid_applicable_currency_eu_from(self) -> None:
        """§6.1 condition 2 — currency + EU ``from_agent`` jurisdiction."""
        env = {"payload": {"args": {"asset_type": "currency"}}}
        assert is_mifid_applicable(
            env,
            from_identity={"jurisdiction": "DE"},
            to_identity={"jurisdiction": "US"},
        )

    def test_is_mifid_applicable_currency_eu_to(self) -> None:
        """§6.1 condition 2 — currency + EU ``to_agent`` jurisdiction."""
        env = {"payload": {"args": {"asset_type": "currency"}}}
        assert is_mifid_applicable(
            env,
            from_identity={"jurisdiction": "US"},
            to_identity={"jurisdiction": "FR"},
        )

    def test_is_mifid_applicable_currency_eea_nonuk(self) -> None:
        """§6.1 condition 2 — EEA non-EU jurisdictions (NO/IS/LI) count."""
        env = {"payload": {"args": {"asset_type": "currency"}}}
        assert is_mifid_applicable(
            env, from_identity={"jurisdiction": "NO"}
        )

    def test_is_mifid_applicable_audit_required_investment(self) -> None:
        """§6.1 condition 3 — audit_required + investment-services flag."""
        env = {
            "payload": {"args": {"asset_type": "token"}},
            "compliance": {"audit_required": True},
        }
        assert is_mifid_applicable(env, is_investment_services=True)

    def test_condition_3_requires_investment_services_flag(self) -> None:
        """§6.1 condition 3 — audit_required alone does NOT fire."""
        env = {
            "payload": {"args": {"asset_type": "token"}},
            "compliance": {"audit_required": True},
        }
        assert not is_mifid_applicable(env, is_investment_services=False)

    def test_condition_3_requires_audit_required_true(self) -> None:
        """§6.1 condition 3 — investment_services alone does NOT fire."""
        env = {
            "payload": {"args": {"asset_type": "token"}},
            "compliance": {"audit_required": False},
        }
        assert not is_mifid_applicable(env, is_investment_services=True)

    def test_currency_without_identity_does_not_fire(self) -> None:
        """§6.1 condition 2 — no identity context ⇒ cannot fire.

        The previous SDK behaviour fired on ANY currency transfer; the
        spec requires positive evidence that one counterparty is
        EU-regulated.
        """
        env = {"payload": {"args": {"asset_type": "currency"}}}
        assert not is_mifid_applicable(env)

    def test_currency_non_eu_counterparties_do_not_fire(self) -> None:
        """§6.1 condition 2 — neither jurisdiction EU/EEA ⇒ false."""
        env = {"payload": {"args": {"asset_type": "currency"}}}
        assert not is_mifid_applicable(
            env,
            from_identity={"jurisdiction": "US"},
            to_identity={"jurisdiction": "JP"},
        )

    def test_not_applicable_for_token_no_profile(self) -> None:
        """§6.1 — pure token transfers do NOT activate MiFID."""
        env = {"payload": {"args": {"asset_type": "token"}}}
        assert not is_mifid_applicable(env)

    def test_conditions_combined(self) -> None:
        """§6.1 — OR logic: any single condition is sufficient."""
        env = {
            "payload": {"args": {"asset_type": "currency"}},
            "compliance": {"profile": "MIFID-II", "audit_required": True},
        }
        # Even with no identity context, condition 1 fires.
        assert is_mifid_applicable(env)
        # And with identity context, still fires.
        assert is_mifid_applicable(
            env,
            from_identity={"jurisdiction": "DE"},
            is_investment_services=True,
        )

    def test_build_mifid_record_from_request_only(self) -> None:
        """§6.1.1 — receipt-scoped fields are None when no receipt."""
        request = {
            "id": "mmmmmmmm-0000-4000-8000-000000000001",
            "payload": {
                "args": {
                    "amount": 100.0,
                    "currency_or_unit": "EUR",
                    "asset_type": "currency",
                    "from_agent": "agent:a.b",
                    "to_agent": "agent:c.d",
                    "payment_reference": "ref-1",
                }
            },
            "compliance": {
                "profile": "MIFID-II",
                "data_residency": "EU",
            },
        }
        record = build_mifid_audit_fields(
            audit_id="a1",
            request_envelope=request,
            payload_hash="0" * 64,
            created_at="2026-04-13T12:00:00.000Z",
        )
        assert record["audit_id"] == "a1"
        assert record["message_id"] == request["id"]
        assert record["receipt_message_id"] is None
        assert record["actual_amount"] is None
        assert record["settled_at"] is None
        assert record["compliance_profile"] == "MIFID-II"
        assert record["data_residency"] == "EU"
        assert record["payload_hash"] == "0" * 64
        assert record["human_oversight_status"] == "not_required"

    def test_build_mifid_record_with_receipt(self) -> None:
        """§6.1.1 — receipt fields populate when the envelope is provided."""
        request = {
            "id": "m-req",
            "payload": {
                "args": {
                    "amount": 100.0,
                    "currency_or_unit": "EUR",
                    "asset_type": "currency",
                    "from_agent": "agent:a.b",
                    "to_agent": "agent:c.d",
                    "payment_reference": "ref-1",
                }
            },
        }
        receipt = {
            "id": "m-rec",
            "payload": {
                "result": {
                    "status": "completed",
                    "amount": 100.0,
                    "initiated_at": "2026-04-13T12:00:00.000Z",
                    "settled_at": "2026-04-13T12:00:05.000Z",
                    "provider_reference": "prov-tx-1",
                }
            },
        }
        record = build_mifid_audit_fields(
            audit_id="a2",
            request_envelope=request,
            receipt_envelope=receipt,
            payload_hash="1" * 64,
            created_at="2026-04-13T12:00:00.000Z",
        )
        assert record["receipt_message_id"] == "m-rec"
        assert record["actual_amount"] == 100.0
        assert record["status"] == "completed"
        assert record["settled_at"] == "2026-04-13T12:00:05.000Z"
        assert record["provider_reference"] == "prov-tx-1"

    def test_enforce_mifid_retention_below_floor(self) -> None:
        """§6.1.2 — effective retention below 1827 days is flagged."""
        env = {
            "compliance": {
                "profile": "GDPR-STANDARD",
                "retention_days": 365,
            }
        }
        errors = enforce_mifid_retention(env)
        assert any("below the 1827" in str(e) for e in errors)

    def test_enforce_mifid_retention_at_floor(self) -> None:
        """§6.1.2 — exactly 1827 days passes."""
        env = {
            "compliance": {
                "profile": "MIFID-II",
                "retention_days": 1827,
            }
        }
        assert enforce_mifid_retention(env) == []

    def test_enforce_mifid_retention_no_compliance(self) -> None:
        """§6.1.2 — no compliance section means no retention floor check."""
        assert enforce_mifid_retention({"payload": {}}) == []


# ---------------------------------------------------------------------------
# §6.2 — DORA
# ---------------------------------------------------------------------------


class TestDoraClassification:
    def test_incident_types(self) -> None:
        """§6.2.1 — six incident types enumerated."""
        assert len(DORA_INCIDENT_TYPES) == 6
        assert "provider_unavailable" in DORA_INCIDENT_TYPES
        assert "unknown" in DORA_INCIDENT_TYPES

    def test_severities(self) -> None:
        """§6.2.2 — four severity classes."""
        assert DORA_SEVERITIES == {"low", "medium", "high", "critical"}

    def test_provider_timeout_is_infrastructure(self) -> None:
        """§6.2.1 — provider timeouts are infrastructure failures."""
        assert is_infrastructure_failure("Provider timeout after 30s")

    def test_network_is_infrastructure(self) -> None:
        """§6.2.1 — network keywords classify as infrastructure."""
        assert is_infrastructure_failure("TCP connection reset")

    def test_insufficient_funds_is_business(self) -> None:
        """§6.2.1 — insufficient_funds is a business logic failure."""
        assert not is_infrastructure_failure("Insufficient funds in payer account")

    def test_compliance_rejection_is_business(self) -> None:
        """§6.2.1 — compliance rejections do NOT trigger DORA."""
        assert not is_infrastructure_failure("Compliance rejection — sanctions list")

    def test_none_returns_false(self) -> None:
        """§6.2.1 — None/missing reason is not infrastructure."""
        assert not is_infrastructure_failure(None)

    def test_classify_provider_unavailable(self) -> None:
        """§6.2.1 — provider keyword maps to provider_unavailable."""
        assert (
            classify_dora_incident_type("Provider timeout after 30s")
            == "provider_unavailable"
        )

    def test_classify_tls(self) -> None:
        """§6.2.1 — TLS keyword maps to tls_failure."""
        assert (
            classify_dora_incident_type("TLS handshake failed: cert expired")
            == "tls_failure"
        )

    def test_classify_no_match_returns_none(self) -> None:
        """§6.2.1 — no keyword match returns None (caller applies 'unknown')."""
        assert classify_dora_incident_type("Cosmic ray flipped a bit") is None

    def test_classify_business_logic_returns_none(self) -> None:
        """§6.2.1 — business-logic strings never map to a DORA incident type."""
        for reason in (
            "Insufficient funds",
            "Invalid account",
            "Compliance rejection — sanctions list",
            "Amount limit exceeded",
            "Duplicate transfer detected",
            "Validation error: schema mismatch",
            "Unauthorized caller",
        ):
            assert classify_dora_incident_type(reason) is None, reason

    def test_classify_none_reason_returns_none(self) -> None:
        """Non-string reasons return None consistently."""
        assert classify_dora_incident_type(None) is None
        assert classify_dora_incident_type(42) is None  # type: ignore[arg-type]

    def test_classify_database(self) -> None:
        """§6.2.1 — database keyword maps to database_failure."""
        assert (
            classify_dora_incident_type("Database unavailable during write")
            == "database_failure"
        )


class TestDoraIncidentEvent:
    def test_minimal_event(self) -> None:
        """§6.2.2 — seven required fields in the payload.data dict."""
        data = build_dora_incident_event(
            incident_type="provider_unavailable",
            affected_service="agent:europa.payments",
            started_at="2026-04-13T12:00:00.000Z",
            estimated_impact="1 transfer affected",
            severity="medium",
            original_payment_reference="ref-42",
        )
        expected_keys = {
            "incident_type",
            "affected_service",
            "started_at",
            "resolved_at",
            "estimated_impact",
            "severity",
            "original_payment_reference",
        }
        assert set(data.keys()) == expected_keys

    def test_resolved_at_ongoing(self) -> None:
        """§6.2.2 — resolved_at defaults to None (incident ongoing)."""
        data = build_dora_incident_event(
            incident_type="network_failure",
            affected_service="agent:acme.broker",
            started_at="2026-04-13T12:00:00.000Z",
            estimated_impact="x",
            severity="low",
            original_payment_reference="ref-1",
        )
        assert data["resolved_at"] is None

    def test_resolved_at_populated(self) -> None:
        """§6.2.2 — caller can set resolved_at for resolution events."""
        data = build_dora_incident_event(
            incident_type="network_failure",
            affected_service="agent:acme.broker",
            started_at="2026-04-13T12:00:00.000Z",
            resolved_at="2026-04-13T12:05:00.000Z",
            estimated_impact="x",
            severity="low",
            original_payment_reference="ref-1",
        )
        assert data["resolved_at"] == "2026-04-13T12:05:00.000Z"

    def test_invalid_incident_type_rejected(self) -> None:
        """§6.2.2 — unknown incident_type values raise ValueError."""
        with pytest.raises(ValueError):
            build_dora_incident_event(
                incident_type="rogue",  # type: ignore[arg-type]
                affected_service="agent:x.y",
                started_at="2026-04-13T12:00:00.000Z",
                estimated_impact="x",
                severity="low",
                original_payment_reference="ref-1",
            )

    def test_invalid_severity_rejected(self) -> None:
        """§6.2.2 — severity outside the enum is rejected."""
        with pytest.raises(ValueError):
            build_dora_incident_event(
                incident_type="unknown",
                affected_service="agent:x.y",
                started_at="2026-04-13T12:00:00.000Z",
                estimated_impact="x",
                severity="cataclysmic",  # type: ignore[arg-type]
                original_payment_reference="ref-1",
            )

    def test_impact_length_cap(self) -> None:
        """§6.2.2 — estimated_impact capped at 512 chars."""
        with pytest.raises(ValueError):
            build_dora_incident_event(
                incident_type="unknown",
                affected_service="agent:x.y",
                started_at="2026-04-13T12:00:00.000Z",
                estimated_impact="x" * 513,
                severity="low",
                original_payment_reference="ref-1",
            )


# ---------------------------------------------------------------------------
# §6.3 — PSD2 SCA
# ---------------------------------------------------------------------------


class TestPsd2Sca:
    def test_option_a_both_factors(self) -> None:
        """§6.3.1 — knowledge + possession factors satisfy Option A."""
        assert (
            validate_psd2_sca_factors(
                knowledge_factor_present=True,
                possession_factor_present=True,
            )
            == []
        )

    def test_option_a_missing_knowledge(self) -> None:
        """§6.3.1 — missing knowledge factor rejected."""
        errors = validate_psd2_sca_factors(
            knowledge_factor_present=False,
            possession_factor_present=True,
        )
        assert any("knowledge factor" in str(e) for e in errors)

    def test_option_a_missing_possession(self) -> None:
        """§6.3.1 — missing possession factor rejected."""
        errors = validate_psd2_sca_factors(
            knowledge_factor_present=True,
            possession_factor_present=False,
        )
        assert any("possession factor" in str(e) for e in errors)

    def test_option_b_cnf_valid(self) -> None:
        """§6.3.2 — a cnf claim with jkt satisfies Option B."""
        assert (
            validate_psd2_sca_factors(
                knowledge_factor_present=False,
                possession_factor_present=False,
                cnf_claim={"jkt": "NzbLsXh8uDCcd"},
            )
            == []
        )

    def test_option_b_cnf_missing_jkt(self) -> None:
        """§6.3.2 — cnf claim without jkt is rejected."""
        errors = validate_psd2_sca_factors(
            knowledge_factor_present=True,
            possession_factor_present=True,
            cnf_claim={"other": "value"},
        )
        assert any("jkt" in str(e) for e in errors)


class TestIsScaExempt:
    def test_low_value_eur(self) -> None:
        """§6.3.3 — ≤ EUR 30 qualifies as low-value exemption."""
        exempt, reason = is_sca_exempt(amount=25.00, currency="EUR")
        assert exempt is True
        assert reason == "low_value"

    def test_low_value_boundary(self) -> None:
        """§6.3.3 — EUR 30 exactly is still exempt (≤, not <)."""
        exempt, reason = is_sca_exempt(amount=Decimal("30"), currency="EUR")
        assert exempt is True
        assert reason == "low_value"

    def test_low_value_over_cap(self) -> None:
        """§6.3.3 — > EUR 30 is NOT low-value exempt."""
        exempt, reason = is_sca_exempt(amount=30.01, currency="EUR")
        assert exempt is False
        assert reason == "no_exemption_applies"

    def test_low_value_non_eur_does_not_apply(self) -> None:
        """§6.3.3 — low-value threshold is in EUR; other currencies bypass."""
        exempt, _ = is_sca_exempt(amount=5.00, currency="USD")
        assert exempt is False

    def test_trusted_beneficiary(self) -> None:
        """§6.3.3 — trusted-beneficiary exemption fires on flag."""
        exempt, reason = is_sca_exempt(
            amount=5000.0, beneficiary_trusted=True
        )
        assert exempt is True
        assert reason == "trusted_beneficiary"

    def test_recurring(self) -> None:
        """§6.3.3 — recurring transaction exemption fires on flag."""
        exempt, reason = is_sca_exempt(amount=5000.0, recurring=True)
        assert exempt is True
        assert reason == "recurring"

    def test_tra_below_threshold(self) -> None:
        """§6.3.3 — TRA risk_level < 7 qualifies."""
        exempt, reason = is_sca_exempt(amount=5000.0, tra_risk_level=6)
        assert exempt is True
        assert reason == "tra"

    def test_tra_at_or_above_threshold(self) -> None:
        """§6.3.3 — TRA risk_level ≥ 7 does NOT exempt."""
        assert is_sca_exempt(amount=5000.0, tra_risk_level=7)[0] is False
        assert is_sca_exempt(amount=5000.0, tra_risk_level=10)[0] is False

    def test_no_inputs_means_no_exemption(self) -> None:
        """§6.3.3 — default call returns ``(False, 'no_exemption_applies')``."""
        exempt, reason = is_sca_exempt()
        assert exempt is False
        assert reason == "no_exemption_applies"

    def test_ordering_low_value_wins(self) -> None:
        """§6.3.3 — low-value is evaluated first when multiple flags set."""
        exempt, reason = is_sca_exempt(
            amount=5.0,
            currency="EUR",
            beneficiary_trusted=True,
            recurring=True,
            tra_risk_level=3,
        )
        assert exempt is True
        assert reason == "low_value"

    def test_tra_bool_rejected(self) -> None:
        """§6.3.3 — ``True`` is not a valid int risk level."""
        exempt, _ = is_sca_exempt(tra_risk_level=True)  # type: ignore[arg-type]
        assert exempt is False


# ---------------------------------------------------------------------------
# §4.3 — Escrow audit trail builders
# ---------------------------------------------------------------------------


class TestEscrowCreatedAudit:
    def test_emits_all_spec_fields(self) -> None:
        """§4.3.1 — the 11 MUST fields are all present."""
        record = build_escrow_created_audit(
            audit_id="a-1",
            timestamp="2026-04-14T12:00:00.000Z",
            payment_reference="ref-1",
            amount=100.0,
            currency_or_unit="EUR",
            from_agent="agent:a.b",
            to_agent="agent:c.d",
            release_agent="agent:e.f",
            timeout_at="2026-04-15T12:00:00.000Z",
        )
        assert set(record.keys()) == {
            "event_type",
            "sub_type",
            "payment_reference",
            "amount",
            "currency_or_unit",
            "from_agent",
            "to_agent",
            "release_agent",
            "timeout_at",
            "audit_id",
            "timestamp",
        }
        assert record["event_type"] == "asset_transfer"
        assert record["sub_type"] == "escrow_created"
        assert record["payment_reference"] == "ref-1"
        assert record["release_agent"] == "agent:e.f"
        assert record["timeout_at"] == "2026-04-15T12:00:00.000Z"
        assert record["audit_id"] == "a-1"

    def test_required_fields_are_keyword_only(self) -> None:
        """§4.3.1 — caller MUST pass fields by keyword."""
        with pytest.raises(TypeError):
            build_escrow_created_audit(  # type: ignore[misc]
                "a-1",
                "2026-04-14T12:00:00.000Z",
                "ref",
                10.0,
                "EUR",
                "agent:a.b",
                "agent:c.d",
                "agent:e.f",
                "2026-04-15T12:00:00.000Z",
            )


class TestEscrowReleasedAudit:
    def test_emits_all_spec_fields(self) -> None:
        """§4.3.2 — 8 MUST fields including original_audit_id."""
        record = build_escrow_released_audit(
            audit_id="r-1",
            timestamp="2026-04-14T13:00:00.000Z",
            payment_reference="ref-1",
            released_by="agent:e.f",
            release_trigger="arsiaprotocol.assets/escrow-release",
            original_audit_id="a-1",
        )
        assert set(record.keys()) == {
            "event_type",
            "sub_type",
            "payment_reference",
            "released_by",
            "release_trigger",
            "original_audit_id",
            "audit_id",
            "timestamp",
        }
        assert record["sub_type"] == "escrow_released"
        assert record["original_audit_id"] == "a-1"
        assert record["released_by"] == "agent:e.f"


class TestEscrowReturnedAudit:
    def test_timeout_return_has_no_cancellation_reason(self) -> None:
        """§4.3.3 — timeout-driven return omits cancellation_reason."""
        record = build_escrow_returned_audit(
            audit_id="t-1",
            timestamp="2026-04-15T12:00:01.000Z",
            payment_reference="ref-1",
            timeout_at="2026-04-15T12:00:00.000Z",
            actual_timeout="2026-04-15T12:00:01.000Z",
            original_audit_id="a-1",
        )
        assert "cancellation_reason" not in record
        assert record["sub_type"] == "escrow_returned"
        assert record["actual_timeout"] == "2026-04-15T12:00:01.000Z"
        assert record["original_audit_id"] == "a-1"

    def test_cancellation_adds_reason(self) -> None:
        """§5.1.6 — cancellation-driven return carries cancellation_reason."""
        record = build_escrow_returned_audit(
            audit_id="t-2",
            timestamp="2026-04-14T14:00:00.000Z",
            payment_reference="ref-1",
            timeout_at="2026-04-15T12:00:00.000Z",
            actual_timeout="2026-04-14T14:00:00.000Z",
            original_audit_id="a-1",
            cancellation_reason="payer revoked authorisation",
        )
        assert record["cancellation_reason"] == "payer revoked authorisation"


class TestEscrowDisputedAudit:
    def test_emits_all_spec_fields(self) -> None:
        """§4.3.4 — 9 MUST fields including arbitration_agent."""
        record = build_escrow_disputed_audit(
            audit_id="d-1",
            timestamp="2026-04-14T15:00:00.000Z",
            payment_reference="ref-1",
            disputed_by="agent:a.b",
            dispute_reason="goods not delivered",
            arbitration_agent="agent:arb.eu",
            original_audit_id="a-1",
        )
        assert set(record.keys()) == {
            "event_type",
            "sub_type",
            "payment_reference",
            "disputed_by",
            "dispute_reason",
            "arbitration_agent",
            "original_audit_id",
            "audit_id",
            "timestamp",
        }
        assert record["sub_type"] == "escrow_disputed"
        assert record["disputed_by"] == "agent:a.b"
        assert record["arbitration_agent"] == "agent:arb.eu"


# ---------------------------------------------------------------------------
# §4.2.3 / §5.1.6 — escrow-dispute + escrow-cancel payload validators
# ---------------------------------------------------------------------------


class TestEscrowDisputeValidator:
    def test_valid_args(self) -> None:
        """§4.2.3 — all three required fields present + valid agent-id."""
        assert (
            validate_escrow_dispute(
                {
                    "payment_reference": "ref-1",
                    "dispute_reason": "goods not delivered",
                    "disputed_by": "agent:a.b",
                }
            )
            == []
        )

    def test_missing_payment_reference(self) -> None:
        """§4.2.3 — payment_reference is required."""
        errors = validate_escrow_dispute(
            {"dispute_reason": "x", "disputed_by": "agent:a.b"}
        )
        assert any("payment_reference" in str(e) for e in errors)

    def test_missing_dispute_reason(self) -> None:
        """§4.2.3 — dispute_reason is required."""
        errors = validate_escrow_dispute(
            {"payment_reference": "ref-1", "disputed_by": "agent:a.b"}
        )
        assert any("dispute_reason" in str(e) for e in errors)

    def test_missing_disputed_by(self) -> None:
        """§4.2.3 — disputed_by is required."""
        errors = validate_escrow_dispute(
            {"payment_reference": "ref-1", "dispute_reason": "x"}
        )
        assert any("disputed_by" in str(e) for e in errors)

    def test_invalid_disputed_by_agent_id(self) -> None:
        """§4.2.3 — disputed_by must be a valid agent-id."""
        errors = validate_escrow_dispute(
            {
                "payment_reference": "ref-1",
                "dispute_reason": "x",
                "disputed_by": "not-an-agent-id",
            }
        )
        assert any("valid agent-id" in str(e) for e in errors)

    def test_dispute_reason_too_long(self) -> None:
        """§4.2.3 — dispute_reason maxLength 512."""
        errors = validate_escrow_dispute(
            {
                "payment_reference": "ref-1",
                "dispute_reason": "x" * 513,
                "disputed_by": "agent:a.b",
            }
        )
        assert any("maxLength" in str(e) for e in errors)

    def test_non_dict_rejected(self) -> None:
        """§4.2.3 — payload.args must be an object."""
        errors = validate_escrow_dispute("not a dict")  # type: ignore[arg-type]
        assert any("must be an object" in str(e) for e in errors)

    def test_empty_strings_rejected(self) -> None:
        """§4.2.3 — empty strings are not valid values for required fields."""
        errors = validate_escrow_dispute(
            {
                "payment_reference": "",
                "dispute_reason": "",
                "disputed_by": "",
            }
        )
        assert any("payment_reference" in str(e) for e in errors)
        assert any("dispute_reason" in str(e) for e in errors)
        assert any("disputed_by" in str(e) for e in errors)

    def test_non_party_sender_forbidden(self) -> None:
        """§4.2.3 — sender not in {from_agent, to_agent} → forbidden."""
        errors = validate_escrow_dispute(
            {
                "payment_reference": "ref-1",
                "dispute_reason": "goods not delivered",
                "disputed_by": "agent:a.b",
            },
            sender_agent_id="agent:outsider.evil",
            escrow_parties=("agent:a.b", "agent:c.d"),
        )
        assert any(e.code == "forbidden" for e in errors)

    def test_from_agent_sender_accepted(self) -> None:
        """§4.2.3 — from_agent is a party → no forbidden error."""
        errors = validate_escrow_dispute(
            {
                "payment_reference": "ref-1",
                "dispute_reason": "goods not delivered",
                "disputed_by": "agent:a.b",
            },
            sender_agent_id="agent:a.b",
            escrow_parties=("agent:a.b", "agent:c.d"),
        )
        assert not any(e.code == "forbidden" for e in errors)

    def test_to_agent_sender_accepted(self) -> None:
        """§4.2.3 — to_agent is a party → no forbidden error."""
        errors = validate_escrow_dispute(
            {
                "payment_reference": "ref-1",
                "dispute_reason": "goods not delivered",
                "disputed_by": "agent:c.d",
            },
            sender_agent_id="agent:c.d",
            escrow_parties=("agent:a.b", "agent:c.d"),
        )
        assert not any(e.code == "forbidden" for e in errors)

    def test_no_sender_param_skips_party_check(self) -> None:
        """§4.2.3 — omitting sender_agent_id skips party check (backward compat)."""
        errors = validate_escrow_dispute(
            {
                "payment_reference": "ref-1",
                "dispute_reason": "goods not delivered",
                "disputed_by": "agent:a.b",
            },
        )
        assert not any(e.code == "forbidden" for e in errors)


class TestEscrowCancelValidator:
    def test_valid_args(self) -> None:
        """§5.1.6 — payment_reference + cancellation_reason present."""
        assert (
            validate_escrow_cancel(
                {
                    "payment_reference": "ref-1",
                    "cancellation_reason": "payer revoked authorisation",
                }
            )
            == []
        )

    def test_missing_payment_reference(self) -> None:
        """§5.1.6 — payment_reference is required."""
        errors = validate_escrow_cancel(
            {"cancellation_reason": "x"}
        )
        assert any("payment_reference" in str(e) for e in errors)

    def test_missing_cancellation_reason(self) -> None:
        """§5.1.6 — cancellation_reason is required so it can ride into
        the escrow_returned audit record per §4.3.3."""
        errors = validate_escrow_cancel({"payment_reference": "ref-1"})
        assert any("cancellation_reason" in str(e) for e in errors)

    def test_non_dict_rejected(self) -> None:
        """§5.1.6 — payload.args must be an object."""
        errors = validate_escrow_cancel(None)  # type: ignore[arg-type]
        assert any("must be an object" in str(e) for e in errors)

    def test_matching_sender_accepted(self) -> None:
        """§4.2.4 — from_agent sender → no forbidden error."""
        errors = validate_escrow_cancel(
            {
                "payment_reference": "ref-1",
                "cancellation_reason": "changed my mind",
            },
            sender_agent_id="agent:a.b",
            from_agent="agent:a.b",
        )
        assert not any(e.code == "forbidden" for e in errors)

    def test_non_matching_sender_forbidden(self) -> None:
        """§4.2.4 — sender != from_agent → forbidden."""
        errors = validate_escrow_cancel(
            {
                "payment_reference": "ref-1",
                "cancellation_reason": "changed my mind",
            },
            sender_agent_id="agent:other.agent",
            from_agent="agent:a.b",
        )
        assert any(e.code == "forbidden" for e in errors)

    def test_no_sender_param_skips_check(self) -> None:
        """§4.2.4 — omitting sender_agent_id skips sender check (backward compat)."""
        errors = validate_escrow_cancel(
            {
                "payment_reference": "ref-1",
                "cancellation_reason": "changed my mind",
            },
        )
        assert not any(e.code == "forbidden" for e in errors)


# ---------------------------------------------------------------------------
# §3.2.1 — receipt ↔ request cross-validator
# ---------------------------------------------------------------------------


class TestValidateReceiptAgainstRequest:
    def _base_request(self) -> dict[str, object]:
        return {
            "amount": 1500.00,
            "currency_or_unit": "EUR",
            "asset_type": "currency",
            "from_agent": "agent:acme.billing",
            "to_agent": "agent:contoso.treasury",
            "payment_reference": "acme-2026-00042",
        }

    def _base_receipt(self) -> dict[str, object]:
        return {
            "status": "completed",
            "payment_reference": "acme-2026-00042",
            "amount": 1500.00,
            "currency_or_unit": "EUR",
            "initiated_at": "2026-03-24T14:30:05.123Z",
            "settled_at": "2026-03-24T14:30:11.456Z",
            "audit_id": "c3d4e5f6-7890-4cde-b123-f56789012345",
        }

    def test_exact_match_returns_no_errors(self) -> None:
        """§3.2.1 — byte-identical echo with equal amount passes."""
        errors = validate_receipt_against_request(
            request_args=self._base_request(),
            receipt_result=self._base_receipt(),
        )
        assert errors == []

    def test_payment_reference_mismatch(self) -> None:
        """§3.2.1 — payment_reference MUST match byte-for-byte."""
        receipt = self._base_receipt()
        receipt["payment_reference"] = "acme-2026-00042 "  # trailing space
        errors = validate_receipt_against_request(
            request_args=self._base_request(),
            receipt_result=receipt,
        )
        assert any(
            e.code == "payment_reference_mismatch" for e in errors
        )

    def test_currency_or_unit_mismatch(self) -> None:
        """§3.2.1 — currency_or_unit MUST match exactly."""
        receipt = self._base_receipt()
        receipt["currency_or_unit"] = "USD"
        errors = validate_receipt_against_request(
            request_args=self._base_request(),
            receipt_result=receipt,
        )
        assert any(
            e.code == "currency_mismatch" for e in errors
        )

    def test_partial_execution_allowed(self) -> None:
        """§3.2.1 — receipt amount strictly less than request is legal."""
        receipt = self._base_receipt()
        receipt["amount"] = 1499.99
        errors = validate_receipt_against_request(
            request_args=self._base_request(),
            receipt_result=receipt,
        )
        assert errors == []

    def test_amount_exceeds_request(self) -> None:
        """§3.2.1 — receipt MUST NOT over-fill the request."""
        receipt = self._base_receipt()
        receipt["amount"] = 1500.01
        errors = validate_receipt_against_request(
            request_args=self._base_request(),
            receipt_result=receipt,
        )
        assert any(
            e.code == "receipt_amount_exceeds_request" for e in errors
        )

    def test_asset_type_mismatch_when_both_present(self) -> None:
        """§3.2.1 — asset_type is not a receipt field, but when echoed the
        validator flags a mismatch as a defensive check."""
        receipt = self._base_receipt()
        receipt["asset_type"] = "token"
        errors = validate_receipt_against_request(
            request_args=self._base_request(),
            receipt_result=receipt,
        )
        assert any("asset_type" in str(e) for e in errors)

    def test_missing_asset_type_in_receipt_ignored(self) -> None:
        """§3.2.1 — asset_type absent from receipt is tolerated (not a
        §3.2.1 receipt field)."""
        errors = validate_receipt_against_request(
            request_args=self._base_request(),
            receipt_result=self._base_receipt(),
        )
        assert errors == []

    def test_non_mapping_inputs_rejected(self) -> None:
        """§3.2.1 — defensive rejection of non-mapping inputs."""
        errors = validate_receipt_against_request(
            request_args=None,  # type: ignore[arg-type]
            receipt_result=self._base_receipt(),
        )
        assert any("request_args" in str(e) for e in errors)


# ---------------------------------------------------------------------------
# §3.3.2 — reversal chain-of-custody audit linkage
# ---------------------------------------------------------------------------


class TestBuildReversalAuditFields:
    def test_linkage_fields_present(self) -> None:
        """§3.3.2 — reversal audit record MUST carry the original
        audit_id and payment_reference."""
        record = build_reversal_audit_fields(
            audit_id="d4e5f6a7-8901-4def-c234-567890123456",
            created_at="2026-03-25T09:15:01.000Z",
            original_audit_id="c3d4e5f6-7890-4cde-b123-f56789012345",
            original_payment_reference="acme-2026-00042",
            reversal_payment_reference="acme-2026-00042-REV-1",
            reversal_reason="Client dispute — suitability assessment retracted.",
            requested_by="agent:acme.compliance-officer",
        )
        assert record["original_audit_id"] == (
            "c3d4e5f6-7890-4cde-b123-f56789012345"
        )
        assert record["original_payment_reference"] == "acme-2026-00042"

    def test_full_reversal_flag(self) -> None:
        """§3.3.1 / §3.3.2 — omitting reversal_amount marks a full reversal."""
        record = build_reversal_audit_fields(
            audit_id="d4e5f6a7-8901-4def-c234-567890123456",
            created_at="2026-03-25T09:15:01.000Z",
            original_audit_id="c3d4e5f6-7890-4cde-b123-f56789012345",
            original_payment_reference="acme-2026-00042",
            reversal_reason="Full refund — order cancelled.",
            requested_by="agent:acme.compliance-officer",
        )
        assert record["is_full_reversal"] is True
        assert record["reversal_amount"] is None

    def test_partial_reversal_amount_echoed(self) -> None:
        """§3.3.1 — partial reversals carry the reversal_amount verbatim."""
        record = build_reversal_audit_fields(
            audit_id="d4e5f6a7-8901-4def-c234-567890123456",
            created_at="2026-03-25T09:15:01.000Z",
            original_audit_id="c3d4e5f6-7890-4cde-b123-f56789012345",
            original_payment_reference="acme-2026-00042",
            reversal_amount=Decimal("500.00"),
            reversal_reason="Partial refund — service level credit.",
            requested_by="agent:acme.compliance-officer",
        )
        assert record["is_full_reversal"] is False
        assert record["reversal_amount"] == Decimal("500.00")

    def test_request_args_echo(self) -> None:
        """§3.3.2 — reason and requester are carried for auditor convenience."""
        record = build_reversal_audit_fields(
            audit_id="d4e5f6a7-8901-4def-c234-567890123456",
            created_at="2026-03-25T09:15:01.000Z",
            original_audit_id="c3d4e5f6-7890-4cde-b123-f56789012345",
            original_payment_reference="acme-2026-00042",
            reversal_reason="Client dispute",
            requested_by="agent:acme.compliance-officer",
        )
        assert record["reversal_reason"] == "Client dispute"
        assert record["requested_by"] == "agent:acme.compliance-officer"
        assert record["audit_id"] == "d4e5f6a7-8901-4def-c234-567890123456"
        assert record["created_at"] == "2026-03-25T09:15:01.000Z"


# ---------------------------------------------------------------------------
# Parametric — every asset_type / precision combination
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "asset_type,precision",
    sorted(ASSET_PRECISION.items()),
)
def test_precision_limit_enforced_for_each_type(
    asset_type: str, precision: int
) -> None:
    """§2 — each type rejects amounts exceeding its precision cap by one."""
    # Build a Decimal with precision+1 decimal places.
    overshoot = Decimal("1." + "1" * (precision + 1))
    errors = validate_transfer_amount(overshoot, asset_type)
    assert any("precision exceeds" in str(e) for e in errors), errors


# ---------------------------------------------------------------------------
# req:5a7d2347 — §3.1 expires_at REQUIRED for asset transfer request
# ---------------------------------------------------------------------------


class TestTransferRequestExpiresAt:
    def test_expires_at_present_passes(self) -> None:
        """§3.1 — envelope with a valid expires_at string is accepted."""
        errors = validate_transfer_request(
            _valid_transfer_args(),
            envelope_expires_at="2026-05-01T00:00:00.000Z",
        )
        assert not any("expires_at" in str(e) for e in errors)

    def test_expires_at_missing_rejected(self) -> None:
        """§3.1 — envelope with no expires_at is rejected for asset transfers."""
        errors = validate_transfer_request(
            _valid_transfer_args(),
            envelope_expires_at=None,
        )
        assert any(e.code == "missing_expires_at" for e in errors)

    def test_expires_at_empty_string_rejected(self) -> None:
        """§3.1 — empty-string expires_at is rejected."""
        errors = validate_transfer_request(
            _valid_transfer_args(),
            envelope_expires_at="",
        )
        assert any("expires_at is REQUIRED" in str(e) for e in errors)

    def test_expires_at_not_checked_when_unset(self) -> None:
        """§3.1 — default (no envelope context) skips the check."""
        errors = validate_transfer_request(_valid_transfer_args())
        assert not any("expires_at" in str(e) for e in errors)


# ---------------------------------------------------------------------------
# req:6d1ddfa0 — §3.3 expires_at REQUIRED for reversal envelopes
# ---------------------------------------------------------------------------


class TestReversalExpiresAt:
    def _base_reversal_args(self) -> dict[str, object]:
        return {
            "original_payment_reference": "acme-2026-0001",
            "reversal_reason": "Customer request",
            "requested_by": "agent:acme.compliance",
        }

    def test_expires_at_present_passes(self) -> None:
        """§3.3 — reversal envelope with valid expires_at is accepted."""
        errors = validate_reversal_precondition(
            self._base_reversal_args(),
            original_status="completed",
            envelope_expires_at="2026-05-01T00:00:00.000Z",
        )
        assert not any("expires_at" in str(e) for e in errors)

    def test_expires_at_missing_rejected(self) -> None:
        """§3.3 — reversal envelope without expires_at is rejected."""
        errors = validate_reversal_precondition(
            self._base_reversal_args(),
            original_status="completed",
            envelope_expires_at=None,
        )
        assert any(e.code == "missing_expires_at" for e in errors)

    def test_expires_at_not_checked_by_default(self) -> None:
        """§3.3 — default (no envelope context) skips the check."""
        errors = validate_reversal_precondition(
            self._base_reversal_args(),
            original_status="completed",
        )
        assert not any("expires_at" in str(e) for e in errors)


# ---------------------------------------------------------------------------
# req:e9397a9e + req:8bcf3c3b — §3.3 reversal idempotency
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# req:bc12a487 — §3.1 initial receipt status must be escrowed when escrow present
# ---------------------------------------------------------------------------


class TestReceiptEscrowCoupling:
    def _base_request(self) -> dict[str, object]:
        return {
            "amount": 1500.00,
            "currency_or_unit": "EUR",
            "asset_type": "currency",
            "from_agent": "agent:acme.billing",
            "to_agent": "agent:contoso.treasury",
            "payment_reference": "acme-2026-00042",
            "escrow_conditions": {
                "release_condition": "Goods delivered",
                "release_trigger": "com.acme/release",
                "release_agent": "agent:acme.trustee",
                "timeout_at": "2027-01-01T00:00:00.000Z",
            },
        }

    def _base_receipt(self) -> dict[str, object]:
        return {
            "status": "escrowed",
            "payment_reference": "acme-2026-00042",
            "amount": 1500.00,
            "currency_or_unit": "EUR",
            "initiated_at": "2026-03-24T14:30:05.123Z",
            "audit_id": "c3d4e5f6-7890-4cde-b123-f56789012345",
        }

    def test_escrowed_status_with_escrow_conditions_passes(self) -> None:
        """§3.1 — receipt with status=escrowed when escrow_conditions present passes."""
        errors = validate_receipt_against_request(
            request_args=self._base_request(),
            receipt_result=self._base_receipt(),
        )
        assert not any("initial receipt status" in str(e) for e in errors)

    def test_completed_status_with_escrow_conditions_rejected(self) -> None:
        """§3.1 — receipt with status=completed when escrow_conditions present is rejected."""
        receipt = self._base_receipt()
        receipt["status"] = "completed"
        receipt["settled_at"] = "2026-03-24T14:30:11.456Z"
        errors = validate_receipt_against_request(
            request_args=self._base_request(),
            receipt_result=receipt,
        )
        assert any(e.code == "invalid_escrow_receipt_status" for e in errors)

    def test_no_escrow_conditions_no_coupling_check(self) -> None:
        """§3.1 — without escrow_conditions, any receipt status is acceptable."""
        request = self._base_request()
        del request["escrow_conditions"]
        receipt = self._base_receipt()
        receipt["status"] = "completed"
        receipt["settled_at"] = "2026-03-24T14:30:11.456Z"
        errors = validate_receipt_against_request(
            request_args=request,
            receipt_result=receipt,
        )
        assert not any("initial receipt status" in str(e) for e in errors)


# ---------------------------------------------------------------------------
# req:f348826b — §4.2 escrow release must include payment_reference
# ---------------------------------------------------------------------------


class TestValidateEscrowRelease:
    def test_valid_release_args(self) -> None:
        """§4.2 — release message with payment_reference passes."""
        from arsia_protocol.assets.assets import validate_escrow_release

        errors = validate_escrow_release({
            "payment_reference": "acme-2026-00042",
        })
        assert errors == []

    def test_missing_payment_reference_rejected(self) -> None:
        """§4.2 — release message without payment_reference is rejected."""
        from arsia_protocol.assets.assets import validate_escrow_release

        errors = validate_escrow_release({})
        assert any(
            "payment_reference is required" in str(e) for e in errors
        )

    def test_non_dict_rejected(self) -> None:
        """§4.2 — non-dict args rejected."""
        from arsia_protocol.assets.assets import validate_escrow_release

        errors = validate_escrow_release("not a dict")  # type: ignore[arg-type]
        assert any("must be an object" in str(e) for e in errors)

    def test_empty_payment_reference_rejected(self) -> None:
        """§4.2 — empty-string payment_reference is rejected."""
        from arsia_protocol.assets.assets import validate_escrow_release

        errors = validate_escrow_release({"payment_reference": ""})
        assert any("payment_reference is required" in str(e) for e in errors)


# ---------------------------------------------------------------------------
# req:8d2494dd — §3.3 requested_by must possess transfer.reverse capability
# ---------------------------------------------------------------------------


class TestReversalCapabilityCheck:
    def _base_reversal_args(self) -> dict[str, object]:
        return {
            "original_payment_reference": "acme-2026-0001",
            "reversal_reason": "Customer request",
            "requested_by": "agent:acme.compliance",
        }

    def test_with_reverse_capability_passes(self) -> None:
        """§3.3 — requestor with transfer.reverse capability is accepted."""
        errors = validate_reversal_precondition(
            self._base_reversal_args(),
            original_status="completed",
            requestor_capabilities=[
                "arsiaprotocol.assets.transfer.reverse",
                "arsiaprotocol.assets.audit.read",
            ],
        )
        assert not any("transfer.reverse" in str(e) for e in errors)

    def test_without_reverse_capability_rejected(self) -> None:
        """§3.3 — requestor without transfer.reverse capability is rejected."""
        errors = validate_reversal_precondition(
            self._base_reversal_args(),
            original_status="completed",
            requestor_capabilities=["arsiaprotocol.assets.audit.read"],
        )
        assert any(
            "arsiaprotocol.assets.transfer.reverse" in str(e) for e in errors
        )

    def test_capability_not_checked_when_none(self) -> None:
        """§3.3 — capability check skipped when requestor_capabilities is None."""
        errors = validate_reversal_precondition(
            self._base_reversal_args(),
            original_status="completed",
        )
        assert not any("transfer.reverse" in str(e) for e in errors)


# ---------------------------------------------------------------------------
# req:783bfdbf — §5.2 pending_approval must include human-readable summary
# ---------------------------------------------------------------------------


class TestAssetPendingApproval:
    def test_valid_pending_approval_args(self) -> None:
        """§5.2 — pending_approval with summary and payment_reference passes."""
        from arsia_protocol.assets.assets import validate_asset_pending_approval

        errors = validate_asset_pending_approval({
            "summary": "Transfer of EUR 1500 from acme.billing to contoso.treasury",
            "payment_reference": "acme-2026-00042",
        })
        assert errors == []

    def test_missing_summary_rejected(self) -> None:
        """§5.2 — pending_approval without summary is rejected."""
        from arsia_protocol.assets.assets import validate_asset_pending_approval

        errors = validate_asset_pending_approval({
            "payment_reference": "acme-2026-00042",
        })
        assert any("summary" in str(e) for e in errors)

    def test_missing_payment_reference_rejected(self) -> None:
        """§5.2 — pending_approval without payment_reference is rejected."""
        from arsia_protocol.assets.assets import validate_asset_pending_approval

        errors = validate_asset_pending_approval({
            "summary": "Transfer of EUR 1500",
        })
        assert any("payment_reference" in str(e) for e in errors)

    def test_non_dict_rejected(self) -> None:
        """§5.2 — non-dict args rejected."""
        from arsia_protocol.assets.assets import validate_asset_pending_approval

        errors = validate_asset_pending_approval("not a dict")  # type: ignore[arg-type]
        assert any("must be an object" in str(e) for e in errors)

    def test_model_validates_summary_field(self) -> None:
        """§5.2 — AssetPendingApprovalArgs model enforces summary."""
        from arsia_protocol.assets.assets import AssetPendingApprovalArgs
        from pydantic import ValidationError

        obj = AssetPendingApprovalArgs(
            summary="Transfer of EUR 1500 to contoso.treasury",
            payment_reference="acme-2026-00042",
        )
        assert obj.summary == "Transfer of EUR 1500 to contoso.treasury"

        with pytest.raises(ValidationError, match="summary"):
            AssetPendingApprovalArgs(
                summary="",
                payment_reference="acme-2026-00042",
            )

    def test_empty_summary_rejected(self) -> None:
        """§5.2 — empty-string summary is rejected."""
        from arsia_protocol.assets.assets import validate_asset_pending_approval

        errors = validate_asset_pending_approval({
            "summary": "",
            "payment_reference": "acme-2026-00042",
        })
        assert any("summary" in str(e) for e in errors)


# ----------------------------------------------------------------------
# §3.2 — Compliance echo validation
# ----------------------------------------------------------------------


class TestValidateComplianceEcho:
    """Cross-message compliance echo checks.

    Spec: ARSIA-Assets.md §3.2 — Receipt compliance SHOULD echo
    the compliance object from the original request.
    """

    def test_both_matching_passes(self) -> None:
        """Matching profiles → no warnings."""
        req = {"profile": "eu_financial"}
        rec = {"profile": "eu_financial"}
        assert validate_compliance_echo(req, rec) == []

    def test_missing_receipt_compliance_warns(self) -> None:
        """Request has compliance but receipt doesn't → warning."""
        req = {"profile": "eu_financial"}
        errors = validate_compliance_echo(req, None)
        assert len(errors) == 1
        assert errors[0].code == "compliance_echo_missing"

    def test_profile_mismatch_warns(self) -> None:
        """Different profiles → compliance_profile_mismatch."""
        req = {"profile": "eu_financial"}
        rec = {"profile": "us_standard"}
        errors = validate_compliance_echo(req, rec)
        assert len(errors) == 1
        assert errors[0].code == "compliance_profile_mismatch"

    def test_no_request_compliance_no_warning(self) -> None:
        """No request compliance → no warning regardless of receipt."""
        assert validate_compliance_echo(None, {"profile": "eu_financial"}) == []
        assert validate_compliance_echo(None, None) == []


# ----------------------------------------------------------------------
# §3.1.1 — Idempotency key envelope consistency
# ----------------------------------------------------------------------


class TestValidateIdempotencyKeyInEnvelope:
    """Verify payload.args.idempotency_key matches envelope.idempotency.key.

    Spec: ARSIA-Assets.md §3.1.1, ARSIA-Core.md §10.4.
    """

    def test_matching_passes(self) -> None:
        """Matching keys → no errors."""
        envelope = {"idempotency": {"key": "txn-001"}}
        args = {"idempotency_key": "txn-001"}
        assert validate_idempotency_key_in_envelope(envelope, args) == []

    def test_missing_envelope_key_errors(self) -> None:
        """args has idempotency_key but envelope doesn't → error."""
        envelope: dict[str, object] = {}
        args = {"idempotency_key": "txn-001"}
        errors = validate_idempotency_key_in_envelope(envelope, args)
        assert len(errors) == 1
        assert errors[0].code == "idempotency_key_not_in_envelope"

    def test_mismatch_errors(self) -> None:
        """Different keys → idempotency_key_mismatch."""
        envelope = {"idempotency": {"key": "txn-002"}}
        args = {"idempotency_key": "txn-001"}
        errors = validate_idempotency_key_in_envelope(envelope, args)
        assert len(errors) == 1
        assert errors[0].code == "idempotency_key_mismatch"

    def test_no_args_key_skips(self) -> None:
        """No idempotency_key in args → no validation needed."""
        envelope = {"idempotency": {"key": "txn-001"}}
        args: dict[str, object] = {"from_agent": "agent:acme.sender"}
        assert validate_idempotency_key_in_envelope(envelope, args) == []
