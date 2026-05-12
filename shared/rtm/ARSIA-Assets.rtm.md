<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda) -->
# ARSIA-Assets — Requirements Traceability Matrix

| ID | § | Modal | Layer | Kind | Requirement | Schema | Vector |
|----|---|-------|-------|------|-------------|--------|--------|
| ASSETS-§Abstract-01 | Abstract | MUST | external | procedural | Payment-executing implementations must obtain regulatory licences independently of ARSIA conformance | — | — |
| ASSETS-§1.1.6-01 | 1.1.6 | MUST | sdk | behavioural_positive | Every financial operation must generate a MiFID II-compliant audit record | arsia-audit-record, arsia-mifid-audit-record | — |
| ASSETS-§1.1.7-01 | 1.1.7 | MUST | sdk_enabled | behavioural_positive | Infrastructure failures during financial operations must generate DORA-structured incident events | arsia-dora-incident | — |
| ASSETS-§1.2.5-01 | 1.2.5 | MAY | operational_policy | informational | Future versions may introduce a crypto asset type once MiCA implementation is mature | — | — |
| ASSETS-§1.2.6-01 | 1.2.6 | MUST | external | procedural | Cross-currency transfers must be delegated to a licensed FX provider with two separate receipts | — | — |
| ASSETS-§1.3-01 | 1.3 | MUST_NOT | sdk | behavioural_negative | ARSIA messages must not embed payment execution logic | — | — |
| ASSETS-§1.3-02 | 1.3 | MUST_NOT | sdk | behavioural_negative | payload.args must not contain account numbers, IBANs, card data, banking credentials, or wire instructions | arsia-asset-transfer-request | ITV-342, ITV-343, ITV-344, ITV-353 |
| ASSETS-§1.3-03 | 1.3 | MUST | deployment | behavioural_positive | Financial account identifiers must be transmitted via a separate encrypted channel, not in ARSIA messages | — | — |
| ASSETS-§1.3-04 | 1.3 | SHOULD | sdk | behavioural_positive | payload.args should be validated against financial account identifier patterns (IBAN, card numbers) | arsia-asset-transfer-request | ITV-342, ITV-343, ITV-344 |
| ASSETS-§1.3-05 | 1.3 | SHOULD | sdk | behavioural_negative | Messages matching financial account identifier patterns should be rejected with invalid_request | arsia-asset-transfer-request | ITV-342, ITV-343, ITV-344 |
| ASSETS-§2-01 | 2 | MUST | sdk | behavioural_positive | Implementations must support all four asset types (currency, token, entitlement, service_unit) | arsia-asset-transfer-request | ITV-20, ITV-67, ITV-118 |
| ASSETS-§2-02 | 2 | MUST_NOT | sdk | behavioural_negative | Implementations must not define asset types outside the normative enumeration | arsia-asset-transfer-request | — |
| ASSETS-§2-03 | 2 | MAY | operational_policy | informational | Future specification versions may extend the asset type enumeration | — | — |
| ASSETS-§2-04 | 2 | MUST | sdk | behavioural_positive | amount field must conform to the precision requirements of the declared asset_type | arsia-asset-transfer-request | INV-09, ITV-70 |
| ASSETS-§2.1-01 | 2.1 | MUST | sdk | structural | currency_or_unit must contain a valid ISO 4217 alphabetic code (three uppercase ASCII letters) | arsia-asset-transfer-request | ITV-72, ITV-345, ITV-346, ITV-349 |
| ASSETS-§2.1-02 | 2.1 | MUST | sdk | structural | Currency transfer amount must have at most 2 decimal places | arsia-asset-transfer-request | INV-09, ITV-70, ITV-347 |
| ASSETS-§2.1-03 | 2.1 | REQUIRED | sdk | behavioural_positive | 2-decimal-place constraint for currency amounts is required and non-negotiable | arsia-asset-transfer-request | ITV-70, ITV-347 |
| ASSETS-§2.1-04 | 2.1 | MUST | sdk | behavioural_negative | Currency amount exceeding 2 decimal places must be rejected | arsia-asset-transfer-request | INV-09, ITV-70, ITV-347 |
| ASSETS-§2.1-05 | 2.1 | SHOULD | sdk | behavioural_positive | Currencies with 0 or 3 minor units (e.g., JPY, KWD) should use ISO 4217 minor unit count | — | ITV-345, ITV-346 |
| ASSETS-§2.1-06 | 2.1 | MUST_NOT | sdk | behavioural_negative | Currency amounts must not exceed 2 decimal places regardless of ISO 4217 minor unit count | arsia-asset-transfer-request | ITV-346, ITV-347 |
| ASSETS-§2.1-07 | 2.1 | MUST | sdk_enabled | behavioural_positive | ICT-related incidents during currency transfers must be reported per §6.2 | — | — |
| ASSETS-§2.2-01 | 2.2 | MAY | sdk | structural | Token transfer amount may have up to 8 decimal places | arsia-asset-transfer-request | ITV-20 |
| ASSETS-§2.2-02 | 2.2 | MUST | sdk | behavioural_negative | Token amounts with more than 8 decimal places must be rejected | arsia-asset-transfer-request | ITV-71 |
| ASSETS-§2.2-03 | 2.2 | SHOULD | external | behavioural_positive | Fiat-exchangeable tokens should be classified as asset_type: currency with corresponding regulation | — | — |
| ASSETS-§2.3-01 | 2.3 | SHOULD | sdk | structural | Entitlement transfer amount should be an integer (no decimal places) | arsia-asset-transfer-request | ITV-118 |
| ASSETS-§2.3-02 | 2.3 | NOT_RECOMMENDED | sdk | informational | Fractional entitlements (e.g., 0.5 licence for half-year subscription) are not recommended | arsia-asset-transfer-request | ITV-118 |
| ASSETS-§2.3-03 | 2.3 | MUST_NOT | sdk | behavioural_negative | Fractional entitlement amounts must not exceed 2 decimal places | arsia-asset-transfer-request | ITV-119 |
| ASSETS-§2.3-04 | 2.3 | SHOULD | external | procedural | Tradeable monetary-value entitlements should be evaluated for MiFID II financial instrument classification | — | — |
| ASSETS-§2.4-01 | 2.4 | MAY | sdk | structural | Service unit transfer amount may have up to 4 decimal places | arsia-asset-transfer-request | ITV-67, ITV-348 |
| ASSETS-§2.4-02 | 2.4 | SHOULD | sdk_enabled | behavioural_positive | Billing-related service unit transfers should reference the currency payment request via metadata | — | ITV-348 |
| ASSETS-§2.5-01 | 2.5 | MUST | external | behavioural_positive | Tokens qualifying as EMD2 e-money or PSD2 payment instruments must use currency regulatory framework | — | — |
| ASSETS-§2.5-02 | 2.5 | MUST | sdk | behavioural_positive | Currency type: ISO 4217 code, max 2 decimals, MiFID II/PSD2/DORA apply, audit must be enabled | arsia-asset-transfer-request | ITV-345, ITV-346 |
| ASSETS-§2.5-03 | 2.5 | SHOULD | sdk | behavioural_positive | Token type: application-defined unit, max 8 decimals, audit should be enabled | arsia-asset-transfer-request | ITV-20 |
| ASSETS-§2.5-04 | 2.5 | SHOULD | sdk | behavioural_positive | Entitlement type: application-defined unit, max 2 decimals, audit should be enabled | arsia-asset-transfer-request | ITV-118 |
| ASSETS-§2.5-05 | 2.5 | SHOULD | sdk | behavioural_positive | Service unit type: application-defined unit, max 4 decimals, audit should be enabled | arsia-asset-transfer-request | ITV-67, ITV-348 |
| ASSETS-§3-01 | 3 | MUST | sdk | behavioural_positive | All asset transfer messages (request, receipt, reversal) must be signed with sender's Ed25519 key | arsia-message | ITV-357, ITV-358 |
| ASSETS-§3-02 | 3 | MUST | sdk | behavioural_negative | Unsigned asset transfer messages must be rejected | arsia-message | ITV-357, ITV-358 |
| ASSETS-§3.1-01 | 3.1 | MUST | sdk | structural | AssetTransferRequest capabilities must include arsiaprotocol.assets.transfer.initiate | arsia-message | — |
| ASSETS-§3.1-02 | 3.1 | REQUIRED | sdk | structural | AssetTransferRequest envelope must include expires_at per ARSIA-Core §4.2.2 | arsia-message | — |
| ASSETS-§3.1-03 | 3.1 | REQUIRED | sdk | structural | AssetTransferRequest envelope must include idempotency (see idempotency_key in §3.1.1) | arsia-asset-transfer-request | ITV-365 |
| ASSETS-§3.1-04 | 3.1 | REQUIRED | sdk | behavioural_positive | AssetTransferRequest must include security field (message must be signed) | arsia-message | ITV-357, ITV-358 |
| ASSETS-§3.1-05 | 3.1 | MUST | sdk | behavioural_positive | AssetTransferRequest message must be cryptographically signed | arsia-message | ITV-357, ITV-358 |
| ASSETS-§3.1-06 | 3.1 | RECOMMENDED | sdk | structural | compliance field recommended for currency transfers, optional for other asset types | arsia-compliance-field | — |
| ASSETS-§3.1-07 | 3.1 | OPTIONAL | sdk | structural | compliance field is optional for non-currency asset transfer requests | arsia-compliance-field | — |
| ASSETS-§3.1.1-01 | 3.1.1 | MUST | sdk | structural | AssetTransferRequest payload.args must contain all specified fields | arsia-asset-transfer-request | — |
| ASSETS-§3.1.1-02 | 3.1.1 | OPTIONAL | sdk | structural | Only fields explicitly marked OPTIONAL may be omitted from payload.args | arsia-asset-transfer-request | — |
| ASSETS-§3.1.1-03 | 3.1.1 | REQUIRED | sdk | structural | All payload.args fields are required unless explicitly marked OPTIONAL | arsia-asset-transfer-request | — |
| ASSETS-§3.1.1-04 | 3.1.1 | REQUIRED | sdk | structural | amount field is required in AssetTransferRequest payload.args | arsia-asset-transfer-request | — |
| ASSETS-§3.1.1-05 | 3.1.1 | MUST | sdk | behavioural_positive | amount value must be strictly greater than zero | arsia-asset-transfer-request | ITV-521 |
| ASSETS-§3.1.1-06 | 3.1.1 | SHOULD | sdk | structural | entitlement amount should be integer; max 2 decimal places if fractional | arsia-asset-transfer-request | ITV-118 |
| ASSETS-§3.1.1-07 | 3.1.1 | MUST | sdk | behavioural_negative | Requests with amount ≤ 0 must be rejected with error code invalid_request | arsia-asset-transfer-request | ITV-521 |
| ASSETS-§3.1.1-08 | 3.1.1 | MUST | sdk | behavioural_negative | Requests exceeding asset_type decimal precision limit must be rejected with invalid_request | arsia-asset-transfer-request | INV-09, ITV-70, ITV-71, ITV-119 |
| ASSETS-§3.1.1-09 | 3.1.1 | REQUIRED | sdk | structural | currency_or_unit field is required in AssetTransferRequest payload.args | arsia-asset-transfer-request | — |
| ASSETS-§3.1.1-10 | 3.1.1 | MUST | sdk | structural | currency_or_unit for currency type must be a valid ISO 4217 code (three uppercase ASCII letters) | arsia-asset-transfer-request | ITV-72, ITV-349 |
| ASSETS-§3.1.1-11 | 3.1.1 | SHOULD | sdk | behavioural_positive | currency_or_unit should be validated against the ISO 4217 code list | arsia-asset-transfer-request | ITV-349 |
| ASSETS-§3.1.1-12 | 3.1.1 | MUST | sdk | structural | Application-defined currency_or_unit identifiers must be lowercase ASCII, digits, and hyphens only | arsia-asset-transfer-request | ITV-350 |
| ASSETS-§3.1.1-13 | 3.1.1 | MUST_NOT | sdk | behavioural_negative | Application-defined identifiers must not match any ISO 4217 code | arsia-asset-transfer-request | ITV-351 |
| ASSETS-§3.1.1-14 | 3.1.1 | REQUIRED | sdk | structural | asset_type field is required in AssetTransferRequest payload.args | arsia-asset-transfer-request | — |
| ASSETS-§3.1.1-15 | 3.1.1 | REQUIRED | sdk | structural | from_agent field is required in AssetTransferRequest payload.args | arsia-asset-transfer-request | — |
| ASSETS-§3.1.1-16 | 3.1.1 | MAY | sdk | structural | from_agent may differ from envelope from field under delegated authority | arsia-asset-transfer-request | — |
| ASSETS-§3.1.1-17 | 3.1.1 | MUST | external | behavioural_positive | Delegated from_agent requires sender to possess a valid delegation access token | — | — |
| ASSETS-§3.1.1-18 | 3.1.1 | REQUIRED | sdk | structural | to_agent field is required in AssetTransferRequest payload.args | arsia-asset-transfer-request | — |
| ASSETS-§3.1.1-19 | 3.1.1 | MAY | sdk | structural | to_agent may differ from envelope to field (e.g., via transfer processing agent) | arsia-asset-transfer-request | — |
| ASSETS-§3.1.1-20 | 3.1.1 | MUST | sdk | structural | to_agent must be a valid ARSIA agent identifier | arsia-asset-transfer-request | — |
| ASSETS-§3.1.1-21 | 3.1.1 | MUST | deployment | behavioural_positive | Receiving agent must validate that to_agent is known and reachable | — | — |
| ASSETS-§3.1.1-22 | 3.1.1 | REQUIRED | sdk | structural | payment_reference field is required in AssetTransferRequest payload.args | arsia-asset-transfer-request | — |
| ASSETS-§3.1.1-23 | 3.1.1 | MUST | deployment | behavioural_positive | payment_reference must be unique within the deployment scope | — | ITV-364 |
| ASSETS-§3.1.1-24 | 3.1.1 | MAY | deployment | behavioural_negative | No two AssetTransferRequest messages within a deployment may share a payment_reference | — | ITV-364 |
| ASSETS-§3.1.1-25 | 3.1.1 | RECOMMENDED | sdk_enabled | structural | payment_reference recommended format: {org}-{year}-{sequence} | arsia-asset-transfer-request | — |
| ASSETS-§3.1.1-26 | 3.1.1 | REQUIRED | sdk | structural | description field is required in AssetTransferRequest payload.args | arsia-asset-transfer-request | — |
| ASSETS-§3.1.1-27 | 3.1.1 | SHOULD | sdk_enabled | behavioural_positive | description should convey the business purpose clearly to auditors and compliance officers | — | — |
| ASSETS-§3.1.1-28 | 3.1.1 | OPTIONAL | sdk | structural | provider field is optional in AssetTransferRequest payload.args | arsia-asset-transfer-request | ITV-118 |
| ASSETS-§3.1.1-29 | 3.1.1 | MUST | deployment | behavioural_positive | Transfer must be routed to the specified provider when provider field is present | — | — |
| ASSETS-§3.1.1-30 | 3.1.1 | MUST | external | behavioural_positive | provider must be a licensed payment institution (PSD2 Art. 11) for currency transfers | — | — |
| ASSETS-§3.1.1-31 | 3.1.1 | OPTIONAL | sdk | structural | escrow_conditions field is optional in AssetTransferRequest payload.args | arsia-asset-transfer-request, arsia-escrow-conditions | ITV-121 |
| ASSETS-§3.1.1-32 | 3.1.1 | MUST | sdk | behavioural_positive | Initial receipt for escrowed transfer must have status: escrowed | — | ATV-03, ITV-120, ITV-352 |
| ASSETS-§3.1.1-33 | 3.1.1 | REQUIRED | sdk | structural | idempotency_key field is required in AssetTransferRequest payload.args | arsia-asset-transfer-request | ITV-365 |
| ASSETS-§3.1.1-34 | 3.1.1 | REQUIRED | sdk | structural | idempotency_key is required for all asset transfer requests regardless of asset type | arsia-asset-transfer-request | ITV-365 |
| ASSETS-§3.1.1-35 | 3.1.1 | OPTIONAL | sdk | informational | Asset transfer idempotency is stricter than ARSIA-Core general idempotency (which is optional) | — | — |
| ASSETS-§3.1.1-36 | 3.1.1 | MUST | sdk | structural | idempotency_key must be placed in the envelope idempotency.key field per ARSIA-Core §4.3.2 | arsia-message | ITV-365 |
| ASSETS-§3.1.1-37 | 3.1.1 | MUST | sdk | behavioural_positive | Receiving agent must implement duplicate detection per ARSIA-Core §10.3 | — | ITV-365 |
| ASSETS-§3.1.1-38 | 3.1.1 | MUST | sdk | behavioural_positive | Duplicate idempotency_key must return original response without re-executing the transfer | — | ITV-366 |
| ASSETS-§3.1.1-39 | 3.1.1 | OPTIONAL | sdk | structural | metadata field is optional in AssetTransferRequest payload.args | arsia-asset-transfer-request | ITV-118 |
| ASSETS-§3.1.1-40 | 3.1.1 | MUST | sdk | behavioural_positive | metadata is included in audit payload_hash (SHA-256) when audit_required is true | — | — |
| ASSETS-§3.1.1-41 | 3.1.1 | MUST_NOT | sdk | behavioural_negative | metadata must not contain financial account identifiers, payment card data, or banking credentials | arsia-asset-transfer-request | ITV-342, ITV-343, ITV-344, ITV-353 |
| ASSETS-§3.2-01 | 3.2 | REQUIRED | sdk | behavioural_positive | AssetTransferReceipt correlation_id must equal the AssetTransferRequest id | arsia-message | ATV-01, ITV-367 |
| ASSETS-§3.2-02 | 3.2 | MUST | sdk | behavioural_positive | Receipt correlation_id must be byte-for-byte equal to the request message id | — | ITV-367 |
| ASSETS-§3.2-03 | 3.2 | REQUIRED | sdk | behavioural_positive | AssetTransferReceipt must include security field (message must be signed) | arsia-message | ITV-359, ITV-360 |
| ASSETS-§3.2-04 | 3.2 | MUST | sdk | behavioural_positive | AssetTransferReceipt message must be cryptographically signed | arsia-message | ITV-359, ITV-360 |
| ASSETS-§3.2-05 | 3.2 | SHOULD | sdk | behavioural_positive | Receipt compliance field should echo the compliance object from the original request | — | ITV-368 |
| ASSETS-§3.2.1-01 | 3.2.1 | MUST | sdk | structural | AssetTransferReceipt payload.result must contain all specified fields | arsia-asset-transfer-receipt | ATV-01, ATV-02 |
| ASSETS-§3.2.1-02 | 3.2.1 | OPTIONAL | sdk | structural | Only fields explicitly marked OPTIONAL may be omitted from receipt payload.result | arsia-asset-transfer-receipt | — |
| ASSETS-§3.2.1-03 | 3.2.1 | REQUIRED | sdk | structural | All receipt payload.result fields are required unless explicitly marked OPTIONAL | arsia-asset-transfer-receipt | — |
| ASSETS-§3.2.1-04 | 3.2.1 | REQUIRED | sdk | structural | status field is required in AssetTransferReceipt payload.result | arsia-asset-transfer-receipt | ATV-01, ATV-02, ATV-03, ITV-120, ITV-171, ITV-352 |
| ASSETS-§3.2.1-05 | 3.2.1 | SHOULD | external | procedural | Pending receipt should be followed by a completed or failed receipt when provider reports outcome | — | — |
| ASSETS-§3.2.1-06 | 3.2.1 | MUST | sdk | structural | failure_reason field must be present when receipt status is failed | arsia-asset-transfer-receipt | ATV-02 |
| ASSETS-§3.2.1-07 | 3.2.1 | REQUIRED | sdk | structural | payment_reference field is required in AssetTransferReceipt payload.result | arsia-asset-transfer-receipt | ATV-01, ITV-354 |
| ASSETS-§3.2.1-08 | 3.2.1 | MUST | sdk | behavioural_positive | Receipt payment_reference must match the request's payment_reference byte-for-byte | — | ITV-354 |
| ASSETS-§3.2.1-09 | 3.2.1 | OPTIONAL | sdk | structural | provider_reference is optional; present when the payment provider has processed the request | arsia-asset-transfer-receipt | — |
| ASSETS-§3.2.1-10 | 3.2.1 | REQUIRED | sdk | structural | amount field is required in AssetTransferReceipt payload.result | arsia-asset-transfer-receipt | ATV-01 |
| ASSETS-§3.2.1-11 | 3.2.1 | MAY | sdk | structural | Receipt amount may differ from requested amount in cases of partial execution | arsia-asset-transfer-receipt | ITV-355 |
| ASSETS-§3.2.1-12 | 3.2.1 | SHOULD | sdk_enabled | behavioural_positive | Partial execution receipt metadata should include partial_execution_reason explaining the discrepancy | — | ITV-355 |
| ASSETS-§3.2.1-13 | 3.2.1 | SHOULD | sdk_enabled | behavioural_positive | Requesting agent should be alerted when receipt amount differs from request amount | — | — |
| ASSETS-§3.2.1-14 | 3.2.1 | REQUIRED | sdk | structural | currency_or_unit field is required in AssetTransferReceipt payload.result | arsia-asset-transfer-receipt | ATV-01, ITV-356 |
| ASSETS-§3.2.1-15 | 3.2.1 | MUST | sdk | behavioural_positive | Receipt currency_or_unit must match the request's currency_or_unit exactly | — | ITV-356 |
| ASSETS-§3.2.1-16 | 3.2.1 | REQUIRED | sdk | structural | initiated_at timestamp is required in AssetTransferReceipt payload.result | arsia-asset-transfer-receipt | ATV-01 |
| ASSETS-§3.2.1-17 | 3.2.1 | OPTIONAL | sdk | structural | settled_at timestamp is optional in AssetTransferReceipt payload.result | arsia-asset-transfer-receipt | — |
| ASSETS-§3.2.1-18 | 3.2.1 | SHOULD | sdk | structural | settled_at should be present when receipt status is completed | arsia-asset-transfer-receipt | ATV-01 |
| ASSETS-§3.2.1-19 | 3.2.1 | MUST | sdk | behavioural_negative | settled_at must be absent when receipt status is failed | arsia-asset-transfer-receipt | ATV-02 |
| ASSETS-§3.2.1-20 | 3.2.1 | REQUIRED | sdk | structural | failure_reason is conditionally required: must be present when status is failed | arsia-asset-transfer-receipt | ATV-02 |
| ASSETS-§3.2.1-21 | 3.2.1 | MUST | sdk | behavioural_positive | failure_reason must be present when receipt status is failed | arsia-asset-transfer-receipt | ATV-02 |
| ASSETS-§3.2.1-22 | 3.2.1 | MUST | sdk | behavioural_negative | failure_reason must be absent when status is completed, pending, or escrowed | arsia-asset-transfer-receipt | ATV-03, ITV-120, ITV-171 |
| ASSETS-§3.2.1-23 | 3.2.1 | SHOULD | sdk_enabled | behavioural_positive | failure_reason should enable operator diagnosis without consulting provider logs | — | — |
| ASSETS-§3.2.1-24 | 3.2.1 | REQUIRED | sdk | structural | audit_id field is required in AssetTransferReceipt payload.result | arsia-asset-transfer-receipt | ATV-01 |
| ASSETS-§3.3-01 | 3.3 | MUST | sdk | structural | AssetTransferReversal capabilities must include arsiaprotocol.assets.transfer.reverse | arsia-message | ATV-04 |
| ASSETS-§3.3-02 | 3.3 | REQUIRED | sdk | structural | AssetTransferReversal envelope must include expires_at per ARSIA-Core §4.2.2 | arsia-message | — |
| ASSETS-§3.3-03 | 3.3 | REQUIRED | sdk_enabled | behavioural_positive | AssetTransferReversal must include idempotency field | arsia-message | ITV-361, ITV-369 |
| ASSETS-§3.3-04 | 3.3 | MUST | sdk_enabled | behavioural_positive | Reversal messages must be idempotent | arsia-message | ITV-361, ITV-369 |
| ASSETS-§3.3-05 | 3.3 | REQUIRED | sdk | behavioural_positive | AssetTransferReversal must include security field (message must be signed) | arsia-message | ITV-362, ITV-363 |
| ASSETS-§3.3-06 | 3.3 | MUST | sdk | behavioural_positive | AssetTransferReversal message must be cryptographically signed | arsia-message | ITV-362, ITV-363 |
| ASSETS-§3.3.1-01 | 3.3.1 | REQUIRED | sdk | structural | original_payment_reference field is required in reversal payload.args | arsia-asset-transfer-reversal | ATV-04 |
| ASSETS-§3.3.1-02 | 3.3.1 | MUST | sdk | behavioural_positive | Receiving agent must locate and verify original transfer exists, is completed, and is within reversal window | — | INV-12, ITV-370 |
| ASSETS-§3.3.1-03 | 3.3.1 | MUST | sdk | behavioural_negative | Missing original transfer must return not_found error with the payment_reference | — | ITV-371 |
| ASSETS-§3.3.1-04 | 3.3.1 | REQUIRED | sdk | structural | reversal_reason field is required in reversal payload.args | arsia-asset-transfer-reversal | ATV-04, ITV-29 |
| ASSETS-§3.3.1-05 | 3.3.1 | MUST | sdk_enabled | behavioural_positive | reversal_reason must convey business justification clearly to compliance officers | — | ITV-29 |
| ASSETS-§3.3.1-06 | 3.3.1 | REQUIRED | sdk | structural | requested_by field is required in reversal payload.args | arsia-asset-transfer-reversal | ATV-04 |
| ASSETS-§3.3.1-07 | 3.3.1 | MAY | sdk | structural | requested_by may differ from envelope from field (e.g., compliance officer acting on behalf) | arsia-asset-transfer-reversal | — |
| ASSETS-§3.3.1-08 | 3.3.1 | MUST | sdk | behavioural_positive | requested_by agent must possess the arsiaprotocol.assets.transfer.reverse capability | — | ITV-372 |
| ASSETS-§3.3.1-09 | 3.3.1 | OPTIONAL | sdk | structural | reversal_amount field is optional in reversal payload.args (defaults to full reversal) | arsia-asset-transfer-reversal | ATV-04 |
| ASSETS-§3.3.1-10 | 3.3.1 | MUST_NOT | sdk | behavioural_negative | reversal_amount must not exceed the original transfer amount | — | ITV-373 |
| ASSETS-§3.3.1-11 | 3.3.1 | MUST | sdk | behavioural_negative | Reversal exceeding original amount must be rejected with invalid_request error | — | ITV-373 |
| ASSETS-§3.3.2-01 | 3.3.2 | RECOMMENDED | sdk_enabled | behavioural_positive | Full reversal window recommended default: T+1 (one calendar day from settled_at) | — | — |
| ASSETS-§3.3.2-02 | 3.3.2 | MAY | external | behavioural_positive | Provider may define a shorter or longer full reversal window than T+1 | — | — |
| ASSETS-§3.3.2-03 | 3.3.2 | RECOMMENDED | sdk_enabled | behavioural_positive | Partial reversal window recommended default: T+30 (thirty calendar days from settled_at) | — | — |
| ASSETS-§3.3.2-04 | 3.3.2 | MUST | sdk | behavioural_negative | Expired reversal window must return conflict error with window details | — | ITV-374 |
| ASSETS-§3.3.2-05 | 3.3.2 | MUST | sdk | behavioural_positive | Cumulative reversals per payment_reference must not exceed the original transfer amount | — | ITV-375 |
| ASSETS-§3.3.2-06 | 3.3.2 | MUST_NOT | sdk | behavioural_negative | Full reversal must not be issued after any partial reversal has been processed | — | ITV-376 |
| ASSETS-§3.3.2-07 | 3.3.2 | MUST | sdk | behavioural_positive | Reversal receipt correlation_id must equal the AssetTransferReversal message id | — | ITV-377 |
| ASSETS-§3.3.2-08 | 3.3.2 | MUST | sdk | behavioural_positive | Reversal audit record must reference original transfer's audit_id and payment_reference | — | — |
| ASSETS-§3.3.2-09 | 3.3.2 | RECOMMENDED | sdk | structural | Reversal payment_reference recommended format: {original_reference}-REV-{sequence} | — | — |
| ASSETS-§4.1-01 | 4.1 | MUST | sdk | structural | EscrowConditions object MUST contain all specified fields | arsia-escrow-conditions | INV-13, ITV-121 |
| ASSETS-§4.1-02 | 4.1 | REQUIRED | sdk | structural | All EscrowConditions fields are required unless explicitly marked OPTIONAL | arsia-escrow-conditions | INV-13, ITV-121 |
| ASSETS-§4.1-03 | 4.1 | OPTIONAL | sdk | structural | Only fields marked OPTIONAL may be omitted from EscrowConditions | arsia-escrow-conditions | ITV-121 |
| ASSETS-§4.1-04 | 4.1 | REQUIRED | sdk | structural | release_condition field is required in EscrowConditions | arsia-escrow-conditions | ITV-30, ITV-121 |
| ASSETS-§4.1-05 | 4.1 | SHOULD | sdk_enabled | behavioural_positive | release_condition SHOULD be specific enough for a human auditor to evaluate | — | — |
| ASSETS-§4.1-06 | 4.1 | REQUIRED | sdk | structural | release_trigger field is required in EscrowConditions | arsia-escrow-conditions | ITV-121 |
| ASSETS-§4.1-07 | 4.1 | REQUIRED | sdk | structural | release_agent field is required in EscrowConditions | arsia-escrow-conditions | INV-13, ITV-121, ITV-394 |
| ASSETS-§4.1-08 | 4.1 | MUST | sdk | behavioural_negative | Release triggers from agents other than release_agent MUST be rejected with forbidden | — | ITV-378 |
| ASSETS-§4.1-09 | 4.1 | MUST | sdk | behavioural_positive | release_agent MUST possess the arsiaprotocol.assets.escrow.release capability | — | ATV-05 |
| ASSETS-§4.1-10 | 4.1 | SHOULD | operational_policy | procedural | release_agent SHOULD differ from payer and payee for third-party verification | — | ITV-379 |
| ASSETS-§4.1-11 | 4.1 | REQUIRED | sdk | structural | timeout_at field is required in EscrowConditions | arsia-escrow-conditions | ITV-121, ITV-395 |
| ASSETS-§4.1-12 | 4.1 | MUST | sdk | behavioural_positive | Unreleased escrow value MUST be returned to sender when timeout_at is reached | — | ATV-06 |
| ASSETS-§4.1-13 | 4.1 | MUST | sdk | behavioural_positive | timeout_at value MUST be strictly greater than the message ts | — | ITV-380 |
| ASSETS-§4.1-14 | 4.1 | RECOMMENDED | operational_policy | informational | Recommended minimum escrow timeout is 1 hour | — | — |
| ASSETS-§4.1-15 | 4.1 | RECOMMENDED | operational_policy | informational | Recommended maximum escrow timeout is 90 days | — | — |
| ASSETS-§4.1-16 | 4.1 | MAY | sdk_enabled | behavioural_positive | Implementations MAY enforce minimum and maximum escrow timeout constraints | — | — |
| ASSETS-§4.1-17 | 4.1 | OPTIONAL | sdk | structural | arbitration_agent field is optional in EscrowConditions | arsia-escrow-conditions | ITV-121 |
| ASSETS-§4.1-18 | 4.1 | MUST | sdk | behavioural_positive | Escrow without arbitration_agent MUST timeout normally when dispute arises | — | ITV-389 |
| ASSETS-§4.2.1-01 | 4.2.1 | MUST | sdk | behavioural_positive | Escrow release message MUST be signed by the release_agent's Ed25519 key | arsia-message | ATV-05, ITV-381, ITV-397 |
| ASSETS-§4.2.1-02 | 4.2.1 | MUST | sdk | structural | Release message MUST include escrowed transfer's payment_reference in payload | arsia-message | ATV-05, ITV-382 |
| ASSETS-§4.2.1-03 | 4.2.1 | MUST | sdk | behavioural_positive | Escrow holder MUST verify from, payload.type, signature, state, and timeout before release | — | ATV-05, ITV-383, ITV-384, ITV-385, ITV-386, ITV-387 |
| ASSETS-§4.2.1-04 | 4.2.1 | MUST | sdk | behavioural_negative | Failed release validation MUST be rejected and escrow MUST remain ESCROWED | — | ITV-386, ITV-388 |
| ASSETS-§4.2.2-01 | 4.2.2 | MUST | deployment | behavioural_positive | Escrow holder MUST implement timeout monitoring to detect when timeout_at is reached | — | — |
| ASSETS-§4.2.2-02 | 4.2.2 | MUST | deployment | behavioural_positive | Escrow timeout check MUST execute within 60 seconds of timeout_at | — | — |
| ASSETS-§4.2.2-03 | 4.2.2 | SHOULD_NOT | deployment | behavioural_negative | Escrow timeout SHOULD NOT be delayed by more than 60 seconds | — | — |
| ASSETS-§4.2.3-01 | 4.2.3 | MUST | sdk | structural | arbitration_agent MUST be present in EscrowConditions for DISPUTED state to be reachable | — | ITV-389 |
| ASSETS-§4.2.3-02 | 4.2.3 | MUST | sdk | structural | Dispute payload.args MUST include payment_reference, dispute_reason, and disputed_by | arsia-message | ITV-390, ITV-391, ITV-392 |
| ASSETS-§4.2.3-03 | 4.2.3 | MUST | sdk | behavioural_positive | arbitration_agent MUST verify dispute sender is a party (from_agent or to_agent) to the escrow | — | — |
| ASSETS-§4.2.3-04 | 4.2.3 | MUST | sdk | behavioural_negative | Dispute messages from agents not party to the escrow MUST be rejected with "forbidden" | — | — |
| ASSETS-§4.2.4-01 | 4.2.4 | MUST | sdk | behavioural_positive | Escrow holder MUST verify cancellation sender matches from_agent of original AssetTransferRequest | — | — |
| ASSETS-§4.2.4-02 | 4.2.4 | MUST | sdk | behavioural_negative | Cancellation requests from agents other than from_agent MUST be rejected with "forbidden" | — | — |
| ASSETS-§4.2.4-03 | 4.2.4 | MUST | sdk | structural | Cancellation is only permitted while escrow is in ESCROWED state (not terminal) | — | — |
| ASSETS-§4.3-01 | 4.3 | MUST | sdk | behavioural_positive | Every escrow state transition MUST generate an audit record | arsia-audit-record | ATV-03, ATV-05, ATV-06, ITV-88, ITV-89, ITV-90, ITV-91, ITV-92 |
| ASSETS-§5.1.1-01 | 5.1.1 | MUST | sdk | behavioural_positive | arsiaprotocol.assets.transfer.initiate: every use MUST generate an audit record | — | ITV-96 |
| ASSETS-§5.1.1-02 | 5.1.1 | MAY | operational_policy | informational | arsiaprotocol.assets.transfer.initiate: human oversight MAY be required | — | — |
| ASSETS-§5.1.1-03 | 5.1.1 | SHOULD | operational_policy | procedural | Operators SHOULD define threshold-based oversight policies for transfer initiation | — | — |
| ASSETS-§5.1.1-04 | 5.1.1 | MUST | sdk | behavioural_positive | Agents with transfer.initiate MUST declare supported asset types in their action registry | — | ITV-288 |
| ASSETS-§5.1.2-01 | 5.1.2 | MUST | sdk | behavioural_positive | arsiaprotocol.assets.transfer.approve: every use MUST generate an audit record | — | — |
| ASSETS-§5.1.2-02 | 5.1.2 | SHOULD | operational_policy | procedural | arsiaprotocol.assets.transfer.approve: human oversight SHOULD be required | — | — |
| ASSETS-§5.1.2-03 | 5.1.2 | SHOULD | operational_policy | procedural | Agents with transfer.approve SHOULD represent human oversight roles | — | — |
| ASSETS-§5.1.2-04 | 5.1.2 | MUST_NOT | sdk | behavioural_negative | Initiating agent MUST NOT also be the approving agent (separation of duties) | — | ITV-289, ITV-393 |
| ASSETS-§5.1.2-05 | 5.1.2 | MUST | external | behavioural_positive | Authorization Server MUST enforce separation between initiate and approve capabilities | — | — |
| ASSETS-§5.1.2-06 | 5.1.2 | MUST_NOT | external | behavioural_negative | Authorization Server MUST NOT issue a token with both initiate and approve scopes | — | — |
| ASSETS-§5.1.2-07 | 5.1.2 | MAY | sdk | informational | An agent MAY hold both transfer.approve and oversight.approve capabilities | — | — |
| ASSETS-§5.1.3-01 | 5.1.3 | MUST | sdk | behavioural_positive | arsiaprotocol.assets.transfer.reverse: every use MUST generate an audit record | — | — |
| ASSETS-§5.1.3-02 | 5.1.3 | MAY | operational_policy | informational | arsiaprotocol.assets.transfer.reverse: human oversight MAY be required | — | — |
| ASSETS-§5.1.3-03 | 5.1.3 | MUST | sdk | behavioural_positive | Reversal audit records MUST include original transfer's audit_id and payment_reference | — | — |
| ASSETS-§5.1.4-01 | 5.1.4 | MUST | sdk | behavioural_positive | arsiaprotocol.assets.escrow.create: every use MUST generate an audit record | — | — |
| ASSETS-§5.1.4-02 | 5.1.4 | MAY | operational_policy | informational | arsiaprotocol.assets.escrow.create: human oversight MAY be required | — | — |
| ASSETS-§5.1.4-03 | 5.1.4 | MUST | sdk | behavioural_positive | Escrow creator MUST specify a valid release_agent and timeout_at in EscrowConditions | arsia-escrow-conditions | ITV-394, ITV-395 |
| ASSETS-§5.1.5-01 | 5.1.5 | MUST | sdk | behavioural_positive | arsiaprotocol.assets.escrow.release: every use MUST generate an audit record | — | — |
| ASSETS-§5.1.5-02 | 5.1.5 | SHOULD | operational_policy | procedural | Human oversight SHOULD be required for currency escrow releases | — | — |
| ASSETS-§5.1.5-03 | 5.1.5 | RECOMMENDED | operational_policy | informational | Human oversight is RECOMMENDED for non-currency escrows above implementation-defined threshold | — | — |
| ASSETS-§5.1.5-04 | 5.1.5 | MUST | sdk | behavioural_positive | Escrow release requires both escrow.release capability and matching release_agent identity | — | ITV-290, ITV-396 |
| ASSETS-§5.1.5-05 | 5.1.5 | MUST | sdk | behavioural_positive | Escrow release message MUST be signed by the releasing agent's Ed25519 key | arsia-message | ITV-291, ITV-292, ITV-381, ITV-397 |
| ASSETS-§5.1.6-01 | 5.1.6 | MUST | sdk | behavioural_positive | arsiaprotocol.assets.escrow.cancel: every use MUST generate an audit record | — | — |
| ASSETS-§5.1.6-02 | 5.1.6 | MAY | operational_policy | informational | arsiaprotocol.assets.escrow.cancel: human oversight MAY be required | — | — |
| ASSETS-§5.1.6-03 | 5.1.6 | MUST | sdk | structural | Cancellation message MUST use payload.type arsiaprotocol.assets/escrow-cancel with payment_reference | arsia-message | ITV-398, ITV-399 |
| ASSETS-§5.1.7-01 | 5.1.7 | SHOULD | sdk_enabled | procedural | arsiaprotocol.assets.audit.read: audit trail access SHOULD generate an audit record | — | — |
| ASSETS-§5.1.7-02 | 5.1.7 | MAY | operational_policy | informational | arsiaprotocol.assets.audit.read: human oversight MAY be omitted (read-only access) | — | — |
| ASSETS-§5.1.7-03 | 5.1.7 | SHOULD | deployment | behavioural_positive | Access tokens with audit.read scope SHOULD have a short lifetime | — | — |
| ASSETS-§5.1.7-04 | 5.1.7 | RECOMMENDED | deployment | informational | Recommended maximum lifetime for audit.read access tokens is 300 seconds | — | — |
| ASSETS-§5.1.7-05 | 5.1.7 | MUST | deployment | behavioural_positive | Receiving agent MUST enforce record-level access controls for audit.read | — | — |
| ASSETS-§5.1.7-06 | 5.1.7 | MAY | sdk_enabled | informational | audit.read access MAY be restricted by date range, payment_reference, or compliance profile | — | — |
| ASSETS-§5.2-01 | 5.2 | MUST | sdk | behavioural_positive | Financial operations with risk_level ≥ 7 MUST require human oversight before execution | — | ITV-400 |
| ASSETS-§5.2-02 | 5.2 | SHOULD | sdk_enabled | procedural | Risk assessment SHOULD consider amount, asset_type, compliance profile, and operator policies | — | — |
| ASSETS-§5.2-03 | 5.2 | MUST | sdk | behavioural_positive | pending_approval message MUST include a human-readable transfer summary | arsia-message | ITV-400, ITV-401 |
| ASSETS-§5.2-04 | 5.2 | MUST | sdk | behavioural_positive | approval_decision message MUST be signed by the approver's Ed25519 key | arsia-message | ITV-402 |
| ASSETS-§5.2-05 | 5.2 | MAY | sdk_enabled | informational | Implementations MAY add biometric verification as a third authentication factor | — | — |
| ASSETS-§6.1-01 | 6.1 | MUST | sdk | behavioural_positive | Qualifying AssetTransferRequests MUST generate a MiFID II audit record | — | ITV-39, ITV-122 |
| ASSETS-§6.1-02 | 6.1 | REQUIRED | sdk | structural | All MiFID II audit record fields are required unless explicitly marked OPTIONAL | arsia-mifid-audit-record | ITV-39, ITV-122, ITV-144, ITV-145 |
| ASSETS-§6.1-03 | 6.1 | OPTIONAL | sdk | structural | Only fields marked OPTIONAL may be omitted from MiFID II audit records | arsia-mifid-audit-record | ITV-122 |
| ASSETS-§6.1.1-01 | 6.1.1 | OPTIONAL | sdk | structural | receipt_message_id is optional; absent when receipt has not yet been generated | arsia-mifid-audit-record | ITV-122 |
| ASSETS-§6.1.1-02 | 6.1.1 | OPTIONAL | sdk | structural | actual_amount is optional; absent when transfer has not yet completed | arsia-mifid-audit-record | ITV-122 |
| ASSETS-§6.1.1-03 | 6.1.1 | OPTIONAL | sdk | structural | provider_reference is optional; absent when provider has not yet responded | arsia-mifid-audit-record | ITV-122 |
| ASSETS-§6.1.1-04 | 6.1.1 | OPTIONAL | sdk | structural | settled_at is optional in MiFID II audit record; absent when not yet settled | arsia-mifid-audit-record | ITV-39, ITV-122 |
| ASSETS-§6.1.1-05 | 6.1.1 | OPTIONAL | sdk | structural | failure_reason is optional in MiFID II audit record; present only when status is failed | arsia-mifid-audit-record | ITV-40, ITV-123 |
| ASSETS-§6.1.1-06 | 6.1.1 | OPTIONAL | sdk | structural | data_residency field is optional in MiFID II audit record | arsia-mifid-audit-record | ITV-144 |
| ASSETS-§6.1.1-07 | 6.1.1 | OPTIONAL | sdk | structural | approver_id is optional; present only when oversight was required and approval granted | arsia-mifid-audit-record | ITV-39 |
| ASSETS-§6.1.1-08 | 6.1.1 | OPTIONAL | sdk | structural | approval_timestamp is optional; present only when approver_id is present | arsia-mifid-audit-record | ITV-39 |
| ASSETS-§6.1.1-09 | 6.1.1 | OPTIONAL | sdk | structural | exemption_reason is optional; present when transfer was exempt from SCA per §6.3 | arsia-mifid-audit-record | — |
| ASSETS-§6.1.2-01 | 6.1.2 | MUST | deployment | behavioural_positive | MiFID II audit records MUST be immutable once written | — | — |
| ASSETS-§6.1.2-02 | 6.1.2 | MUST_NOT | deployment | behavioural_negative | MiFID II audit records MUST NOT be modified or deleted after creation | — | — |
| ASSETS-§6.1.2-03 | 6.1.2 | MUST | deployment | procedural | Audit corrections MUST be appended as new records referencing the original | — | — |
| ASSETS-§6.1.2-04 | 6.1.2 | MUST | deployment | behavioural_positive | Implementations MUST support extending retention beyond 1827 days when required by authority | — | — |
| ASSETS-§6.1.2-05 | 6.1.2 | MAY | sdk_enabled | informational | compliance.retention_days MAY specify a retention period longer than 1827 days | — | — |
| ASSETS-§6.1.3-01 | 6.1.3 | SHOULD | sdk_enabled | behavioural_positive | EU-regulated agents SHOULD set compliance.data_residency to EU | — | — |
| ASSETS-§6.1.3-02 | 6.1.3 | MUST | deployment | behavioural_positive | Messages with data_residency set MUST be routed through a Compliance Broker in that zone | — | — |
| ASSETS-§6.1.4-01 | 6.1.4 | MUST | deployment | behavioural_positive | MiFID II audit records MUST be queryable by payment_reference, agents, dates, profile, status, and amount | — | — |
| ASSETS-§6.1.4-02 | 6.1.4 | MUST | deployment | behavioural_positive | Implementations MUST support at minimum the seven specified MiFID II query fields | — | — |
| ASSETS-§6.2-01 | 6.2 | MUST | sdk_enabled | behavioural_positive | Infrastructure failures during financial operations MUST generate a DORA incident event | — | — |
| ASSETS-§6.2.1-01 | 6.2.1 | MUST | sdk | behavioural_positive | Receiving agent MUST classify each failure as infrastructure or business logic | — | — |
| ASSETS-§6.2.1-02 | 6.2.1 | MUST | sdk | behavioural_negative | DORA incident events MUST only be generated for infrastructure failures, not business logic | — | — |
| ASSETS-§6.2.2-01 | 6.2.2 | MUST | sdk_enabled | behavioural_positive | Agent MUST generate a DORA incident event message on infrastructure failure | arsia-dora-incident | ITV-41 |
| ASSETS-§6.2.2-02 | 6.2.2 | REQUIRED | sdk | structural | incident_type field is required in DORA incident event | arsia-dora-incident | ITV-41, ITV-139, ITV-140, ITV-164, ITV-165, ITV-166 |
| ASSETS-§6.2.2-03 | 6.2.2 | REQUIRED | sdk | structural | affected_service field is required in DORA incident event | arsia-dora-incident | ITV-41 |
| ASSETS-§6.2.2-04 | 6.2.2 | REQUIRED | sdk | structural | started_at field is required in DORA incident event | arsia-dora-incident | ITV-41 |
| ASSETS-§6.2.2-05 | 6.2.2 | OPTIONAL | sdk | structural | resolved_at field is optional in DORA incident event; absent when incident is ongoing | arsia-dora-incident | ITV-41, ITV-139 |
| ASSETS-§6.2.2-06 | 6.2.2 | REQUIRED | sdk | structural | estimated_impact field is required in DORA incident event | arsia-dora-incident | ITV-41 |
| ASSETS-§6.2.2-07 | 6.2.2 | REQUIRED | sdk | structural | severity field is required in DORA incident event | arsia-dora-incident | ITV-41, ITV-42 |
| ASSETS-§6.2.2-08 | 6.2.2 | REQUIRED | sdk | structural | original_payment_reference field is required in DORA incident event | arsia-dora-incident | ITV-41 |
| ASSETS-§6.2.2-09 | 6.2.2 | SHOULD | sdk_enabled | behavioural_positive | Resolved incident SHOULD send a follow-up event with resolved_at populated | — | — |
| ASSETS-§6.2.2-10 | 6.2.2 | SHOULD | sdk_enabled | behavioural_positive | estimated_impact SHOULD include affected transfers, financial impact, services, and scope | — | — |
| ASSETS-§6.2.2-11 | 6.2.2 | RECOMMENDED | operational_policy | informational | Severity-to-characteristic mapping is implementation-defined with recommended guidelines | — | — |
| ASSETS-§6.2.3-01 | 6.2.3 | MUST | deployment | behavioural_positive | DORA incident events MUST be routed to the operator's DORA reporting system | — | — |
| ASSETS-§6.2.3-02 | 6.2.3 | MUST | sdk | behavioural_positive | Agent MUST also log DORA incident events in its local audit trail | — | ITV-102 |
| ASSETS-§6.3-01 | 6.3 | MUST | deployment | behavioural_positive | PSD2 SCA elements MUST be independent so breach of one does not compromise others | — | — |
| ASSETS-§6.3-02 | 6.3 | MUST | deployment | behavioural_positive | PSD2 SCA elements MUST protect confidentiality of authentication data | — | — |
| ASSETS-§6.3-03 | 6.3 | MUST | deployment | behavioural_positive | Implementations MUST use SCA Option A or B for financial capabilities with risk_level ≥ 7 | — | — |
| ASSETS-§6.3.1-01 | 6.3.1 | MUST | deployment | behavioural_positive | SCA Option A: authentication MUST include at least one knowledge factor | — | — |
| ASSETS-§6.3.1-02 | 6.3.1 | MUST_NOT | deployment | behavioural_negative | Ed25519 private key used for SCA possession factor MUST NOT be extractable in plaintext | — | — |
| ASSETS-§6.3.1-03 | 6.3.1 | RECOMMENDED | operational_policy | informational | SCA Option A is RECOMMENDED for human-in-the-loop approval flows | — | — |
| ASSETS-§6.3.1-04 | 6.3.1 | MAY | sdk_enabled | informational | Implementations MAY add biometric verification as an inherence factor for Option A | — | — |
| ASSETS-§6.3.2-01 | 6.3.2 | RECOMMENDED | operational_policy | informational | SCA Option B is RECOMMENDED for automated flows without human-in-the-loop approval | — | — |
| ASSETS-§6.3.2-02 | 6.3.2 | SHOULD | sdk_enabled | procedural | Option B implementations SHOULD implement PSD2 Art. 98 transaction risk analysis | — | — |
| ASSETS-§6.3.2-03 | 6.3.2 | MUST | deployment | behavioural_positive | Implementations without hardware-bound keys MUST use SCA Option A | — | — |
| ASSETS-§6.3.3-01 | 6.3.3 | MAY | sdk_enabled | behavioural_positive | Transfers qualifying for SCA exemption MAY proceed without two-party authorisation | — | — |
| ASSETS-§6.3.3-02 | 6.3.3 | MUST | sdk | behavioural_positive | SCA exemptions MUST be recorded in audit trail with human_oversight_status not_required | — | — |
| ASSETS-§7-01 | 7 | MUST | sdk | behavioural_positive | Conformant implementations MUST pass all eight Assets conformance tests | — | — |
| ASSETS-§7-02 | 7 | MAY | sdk_enabled | informational | Rejected request MAY generate an audit record (successful transfer audit is not generated) | — | — |
| ASSETS-§7-03 | 7 | MAY | sdk | informational | Duplicate response MAY have a different envelope id and ts than the original | — | ITV-403 |
| ASSETS-§7-04 | 7 | MUST | sdk | behavioural_positive | Duplicate response payload.result content MUST be identical to the original response | — | ITV-403 |

## Coverage Gaps

### Requirements with no enforcement (no schema, no vector)
| ID | § | Modal | Kind |
|----|---|-------|------|
| ASSETS-§Abstract-01 | Abstract | MUST | procedural |
| ASSETS-§1.2.5-01 | 1.2.5 | MAY | informational |
| ASSETS-§1.2.6-01 | 1.2.6 | MUST | procedural |
| ASSETS-§1.3-01 | 1.3 | MUST_NOT | behavioural_negative |
| ASSETS-§1.3-03 | 1.3 | MUST | behavioural_positive |
| ASSETS-§2-03 | 2 | MAY | informational |
| ASSETS-§2.1-07 | 2.1 | MUST | behavioural_positive |
| ASSETS-§2.2-03 | 2.2 | SHOULD | behavioural_positive |
| ASSETS-§2.3-04 | 2.3 | SHOULD | procedural |
| ASSETS-§2.5-01 | 2.5 | MUST | behavioural_positive |
| ASSETS-§3.1.1-17 | 3.1.1 | MUST | behavioural_positive |
| ASSETS-§3.1.1-21 | 3.1.1 | MUST | behavioural_positive |
| ASSETS-§3.1.1-27 | 3.1.1 | SHOULD | behavioural_positive |
| ASSETS-§3.1.1-29 | 3.1.1 | MUST | behavioural_positive |
| ASSETS-§3.1.1-30 | 3.1.1 | MUST | behavioural_positive |
| ASSETS-§3.1.1-35 | 3.1.1 | OPTIONAL | informational |
| ASSETS-§3.1.1-40 | 3.1.1 | MUST | behavioural_positive |
| ASSETS-§3.2.1-05 | 3.2.1 | SHOULD | procedural |
| ASSETS-§3.2.1-13 | 3.2.1 | SHOULD | behavioural_positive |
| ASSETS-§3.2.1-23 | 3.2.1 | SHOULD | behavioural_positive |
| ASSETS-§3.3.2-01 | 3.3.2 | RECOMMENDED | behavioural_positive |
| ASSETS-§3.3.2-02 | 3.3.2 | MAY | behavioural_positive |
| ASSETS-§3.3.2-03 | 3.3.2 | RECOMMENDED | behavioural_positive |
| ASSETS-§3.3.2-08 | 3.3.2 | MUST | behavioural_positive |
| ASSETS-§3.3.2-09 | 3.3.2 | RECOMMENDED | structural |
| ASSETS-§4.1-05 | 4.1 | SHOULD | behavioural_positive |
| ASSETS-§4.1-14 | 4.1 | RECOMMENDED | informational |
| ASSETS-§4.1-15 | 4.1 | RECOMMENDED | informational |
| ASSETS-§4.1-16 | 4.1 | MAY | behavioural_positive |
| ASSETS-§4.2.2-01 | 4.2.2 | MUST | behavioural_positive |
| ASSETS-§4.2.2-02 | 4.2.2 | MUST | behavioural_positive |
| ASSETS-§4.2.2-03 | 4.2.2 | SHOULD_NOT | behavioural_negative |
| ASSETS-§4.2.4-01 | 4.2.4 | MUST | behavioural_positive |
| ASSETS-§4.2.4-02 | 4.2.4 | MUST | behavioural_negative |
| ASSETS-§4.2.4-03 | 4.2.4 | MUST | structural |
| ASSETS-§5.1.1-02 | 5.1.1 | MAY | informational |
| ASSETS-§5.1.1-03 | 5.1.1 | SHOULD | procedural |
| ASSETS-§5.1.2-01 | 5.1.2 | MUST | behavioural_positive |
| ASSETS-§5.1.2-02 | 5.1.2 | SHOULD | procedural |
| ASSETS-§5.1.2-03 | 5.1.2 | SHOULD | procedural |
| ASSETS-§5.1.2-05 | 5.1.2 | MUST | behavioural_positive |
| ASSETS-§5.1.2-06 | 5.1.2 | MUST_NOT | behavioural_negative |
| ASSETS-§5.1.2-07 | 5.1.2 | MAY | informational |
| ASSETS-§5.1.3-01 | 5.1.3 | MUST | behavioural_positive |
| ASSETS-§5.1.3-02 | 5.1.3 | MAY | informational |
| ASSETS-§5.1.3-03 | 5.1.3 | MUST | behavioural_positive |
| ASSETS-§5.1.4-01 | 5.1.4 | MUST | behavioural_positive |
| ASSETS-§5.1.4-02 | 5.1.4 | MAY | informational |
| ASSETS-§5.1.5-01 | 5.1.5 | MUST | behavioural_positive |
| ASSETS-§5.1.5-02 | 5.1.5 | SHOULD | procedural |
| ASSETS-§5.1.5-03 | 5.1.5 | RECOMMENDED | informational |
| ASSETS-§5.1.6-01 | 5.1.6 | MUST | behavioural_positive |
| ASSETS-§5.1.6-02 | 5.1.6 | MAY | informational |
| ASSETS-§5.1.7-01 | 5.1.7 | SHOULD | procedural |
| ASSETS-§5.1.7-02 | 5.1.7 | MAY | informational |
| ASSETS-§5.1.7-03 | 5.1.7 | SHOULD | behavioural_positive |
| ASSETS-§5.1.7-04 | 5.1.7 | RECOMMENDED | informational |
| ASSETS-§5.1.7-05 | 5.1.7 | MUST | behavioural_positive |
| ASSETS-§5.1.7-06 | 5.1.7 | MAY | informational |
| ASSETS-§5.2-02 | 5.2 | SHOULD | procedural |
| ASSETS-§5.2-05 | 5.2 | MAY | informational |
| ASSETS-§6.1.2-01 | 6.1.2 | MUST | behavioural_positive |
| ASSETS-§6.1.2-02 | 6.1.2 | MUST_NOT | behavioural_negative |
| ASSETS-§6.1.2-03 | 6.1.2 | MUST | procedural |
| ASSETS-§6.1.2-04 | 6.1.2 | MUST | behavioural_positive |
| ASSETS-§6.1.2-05 | 6.1.2 | MAY | informational |
| ASSETS-§6.1.3-01 | 6.1.3 | SHOULD | behavioural_positive |
| ASSETS-§6.1.3-02 | 6.1.3 | MUST | behavioural_positive |
| ASSETS-§6.1.4-01 | 6.1.4 | MUST | behavioural_positive |
| ASSETS-§6.1.4-02 | 6.1.4 | MUST | behavioural_positive |
| ASSETS-§6.2-01 | 6.2 | MUST | behavioural_positive |
| ASSETS-§6.2.1-01 | 6.2.1 | MUST | behavioural_positive |
| ASSETS-§6.2.1-02 | 6.2.1 | MUST | behavioural_negative |
| ASSETS-§6.2.2-09 | 6.2.2 | SHOULD | behavioural_positive |
| ASSETS-§6.2.2-10 | 6.2.2 | SHOULD | behavioural_positive |
| ASSETS-§6.2.2-11 | 6.2.2 | RECOMMENDED | informational |
| ASSETS-§6.2.3-01 | 6.2.3 | MUST | behavioural_positive |
| ASSETS-§6.3-01 | 6.3 | MUST | behavioural_positive |
| ASSETS-§6.3-02 | 6.3 | MUST | behavioural_positive |
| ASSETS-§6.3-03 | 6.3 | MUST | behavioural_positive |
| ASSETS-§6.3.1-01 | 6.3.1 | MUST | behavioural_positive |
| ASSETS-§6.3.1-02 | 6.3.1 | MUST_NOT | behavioural_negative |
| ASSETS-§6.3.1-03 | 6.3.1 | RECOMMENDED | informational |
| ASSETS-§6.3.1-04 | 6.3.1 | MAY | informational |
| ASSETS-§6.3.2-01 | 6.3.2 | RECOMMENDED | informational |
| ASSETS-§6.3.2-02 | 6.3.2 | SHOULD | procedural |
| ASSETS-§6.3.2-03 | 6.3.2 | MUST | behavioural_positive |
| ASSETS-§6.3.3-01 | 6.3.3 | MAY | behavioural_positive |
| ASSETS-§6.3.3-02 | 6.3.3 | MUST | behavioural_positive |
| ASSETS-§7-01 | 7 | MUST | behavioural_positive |
| ASSETS-§7-02 | 7 | MAY | informational |

### Summary
- Total requirements: 256
- Schema coverage: 128 / 256 (50%)
- Vector coverage: 141 / 256 (55%)
- Both: 101 / 256
- Neither: 88 / 256 ← these are the gaps
