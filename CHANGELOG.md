# Changelog

All notable changes to the ARSIA Protocol SDK are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.1] — 2026-09-29

Corrections to how the SDK consumes the conformance corpus. No change to
the public API or to the wire format (`1.0`).

### Fixed

- **`arsia vectors run`** checks every bundled vector against its expected
  outcome in layers — JSON Schema (runtime-only vectors reported as SKIP
  with their reason), the SDK's semantic rules, and the signature
  (EdDSA and ES256, with the vector's `crypto` block or the published
  keypairs; RS256 reported as SKIP) — instead of hard-coded vector-ID
  lists. It reports passed, failed and skipped separately and exits 1 on
  any failure. On the bundled corpus: 545 passed, 0 failed, 66 skipped.
- **Vector tests** derive their cases from the corpus: every vector goes
  through the same layered check, every `crypto` block is checked for
  canonical bytes, and signatures of valid vectors are verified. No
  vector count or ID list is hard-coded.
- **Conformance executors** report a non-Ed25519 test keypair as an error
  instead of raising.
- **`[1.0.0]` entry** — the test-vector counts now state what the
  protocol's tools report for that corpus.

### Changed

- **Conformance corpus** re-synced from the ARSIA Protocol Draft-01.1
  errata (see `shared/SOURCE.md`): 611 test vectors (413 valid, 124
  invalid, 74 runtime-only); 57 keypairs (53 Ed25519, 2 ES256, 2 RS256);
  every signature in a valid vector verifies with a published key.
- **CI** runs `arsia vectors run` after the test suite.
- **Conformance suites** that reference vectors state that they are
  deliberate fixed subsets of the corpus.

## [1.0.0] — 2026-05-12

First public release of the ARSIA Protocol SDK — the reference
implementation of the [ARSIA Protocol](https://github.com/arsialabs/arsia-protocol)
for building, signing, verifying, and validating message envelopes exchanged
between autonomous agents. Transport-agnostic. Python 3.12+.

### Added

#### Core — Envelope Lifecycle

- **Envelope factory** — 7 `create_*` functions produce complete, signable
  ARSIA envelopes: `create_request`, `create_response`, `create_error`,
  `create_event`, `create_pending_approval`, `create_approval_decision`,
  `create_rollback_request`.
- **Ed25519 signing and verification** — `sign_message` and `verify_message`
  implement the ARSIA-Core §5 signing/verification procedure: strip
  `security`, canonicalize with RFC 8785 (JCS), sign with Ed25519,
  base64url-encode without padding. ES256 (ECDSA P-256) supported for
  verification. RS256 is not implemented.
- **Two-layer validation** — `validate_schema` (L1: JSON Schema Draft
  2020-12 against 31 shared schemas) and `validate_semantic` (L2: cross-field
  rules including timestamps, kid prefix, capabilities, min_v,
  idempotency key charset). `validate_envelope` combines both.
- **Compliance profiles** — 7 profiles (`GDPR-STANDARD`,
  `EU-AI-ACT-HIGH-RISK`, `EU-AI-ACT-LIMITED-RISK`, `MIFID-II`,
  `PAC-AGRICULTURE`, `DSA-VLOP`, `DORA`). `apply_profile` injects profile
  defaults into envelopes. `validate_compliance` enforces profile-specific
  rules (PII legal basis, high-risk AI oversight, retention floors).
  Oversight timeout and explainability validation.
- **Error system** — 14 error codes with HTTP status mapping, retry policy,
  and description templates. Builder functions for every §11.2 error shape:
  `build_forbidden_error`, `build_not_implemented_error`,
  `build_service_unavailable_error`, `build_payload_too_large_error`,
  `build_oversight_denied_error`, `build_oversight_expired_error`, and
  `build_retry_after_header` with exponential backoff and jitter.
- **Payload encryption** — ECDH-ES+A256GCM via `encrypt_payload` and
  `decrypt_payload`. Compact JWE serialization. P-256 key support in JWKS.
- **Payload type registry** — `PayloadTypeRegistry` maps `payload.type`
  strings to their expected content-field names per Core §4.4.
- **Envelope size check** — `check_envelope_size` utility with
  `DEFAULT_MAX_MESSAGE_BYTES` (1 MiB).
- **Version compatibility** — outbound version range check against
  recipient's `server_min`/`server_max`.

#### Identity

- **Agent ID** — `parse_agent_id`, `validate_agent_id`, `is_valid_agent_id`
  implementing ARSIA-Core §3 grammar. `AgentId` frozen dataclass with
  `org`, `name`, `sub`, `resource` fields.
- **Discovery** — `build_discovery_document`, `build_jwks`,
  `build_rotation_jwks`, `build_encryption_jwks`, `build_ec_jwk`.
  JWKS key rotation (`rotate_jwks_key`) and revocation (`revoke_jwks_key`)
  lifecycle builders. `select_jwk_from_jwks`, `public_key_from_jwk` for
  key resolution. `JWKSCachePolicy` for cache TTL and refresh signalling.
  `build_identity_record_signature` and `verify_identity_record_signature`
  for X-ARSIA-Sig (Identity §1.3). `verify_jwks_agent_id_consistency`
  for kid-to-agent-id cross-check.
- **Certificates** — X.509 trust levels L1/L2/L3 with
  `compute_trust_level`. `is_certificate_chain_expired` for chain-wide
  expiry pre-check.
- **Authorization** — `validate_token_claims` (JWT with iat/exp/nbf/iss/aud
  validation), `validate_dpop_proof` (DPoP binding), `validate_scope`
  (capability scope matching), `build_token_request` (§6.2 token-request
  shape). RSA key rejection in ARSIA contexts.
- **Onboarding** — 6-phase external agent onboarding:
  `build_onboarding_decision` (§7.6 approval/denial), capability policy
  evaluation with `evaluate_capability_policy` (§8.3 deny-by-default),
  `CapabilityPolicy` and `CapabilityRule` models, denial reason validation,
  `max_risk_level` enforcement.

#### Actions

- **Capability model** — `match_capability` with wildcard support,
  `downgrade_capabilities`, `attach_effective_capabilities`.
  `EXPLICIT_GRANT_ONLY` for capabilities requiring exact match
  (e.g., `state.purge`). Capability prerequisite checking.
- **Risk-level enforcement** — `validate_action_descriptor` enforces
  cross-field MUST rules for risk levels 5-6, 7-8, and 9-10
  (audit, explainability, human oversight requirements).
- **Rollback** — `create_rollback_request` produces rollback envelopes
  with original message linkage.

#### Routing

- **Topology selection** — `select_topology` implements the §1.3
  three-output algorithm: `direct`, `brokered`, or `error`. No
  hardcoded zone allowlist — any non-empty `data_residency` triggers
  the broker requirement.
- **Broker management** — `validate_broker_entry`, broker selection
  by priority (`select_broker_by_priority`) and random
  (`select_broker_random`). Degraded brokers deprioritized per §1.4.
  EU/EEA membership check (`EU_EEA_MEMBER_STATES`, 30 countries).
- **Message lifecycle** — 9-state machine (`LIFECYCLE_STATES`,
  `LIFECYCLE_TRANSITIONS`) aligned to ARSIA-Routing §4.2 exactly.
- **Relay audit** — `BrokerRelayAuditRecord` (11 REQUIRED fields per
  §7.4) with `build_broker_relay_audit_record` and
  `validate_broker_relay_audit_record`.
- **Rate limits** — `parse_rate_limit_headers` for `X-RateLimit-*`
  headers per §6.2.
- **Retry** — `compute_retry_delay` with exponential backoff capped
  at 32s.

#### State

- **State operations** — 8 argument builders (`build_set_args`,
  `build_get_args`, `build_delete_args`, `build_query_args`,
  `build_snapshot_args`, `build_purge_args`, `build_grant_args`,
  `build_revoke_args`) aligned to ARSIA-State §3 normative shapes.
- **Key validation** — `validate_state_key` with `arsia.meta.*`
  reserved prefix enforcement (§2.2). 1 MiB value size limit.
- **Access control** — `build_grant_result`, `build_revoke_result`,
  `AccessLevel` (`read` / `read_write`), key-pattern matching with
  trailing-`*` support.
- **Retention** — `compute_effective_retention` applying `max(profile,
  entry)` floor per §4.1.1. Scope-to-capability mapping via
  `required_capability_for`.
- **Audit records** — `build_audit_record` constructs `ArsiaAuditRecord`
  with UUID v4 `record_id`, `payload_hash` (SHA-256 of JCS-canonicalized
  payload), compliance profile inheritance, and retention enforcement.
  `compute_payload_hash`, `derive_event_type_from_intent`. 11 audit
  event types.
- **Breach** — breach detection and notification types.

#### Assets

- **Transfer lifecycle** — validators for the three §3 message shapes:
  `validate_transfer_request`, `validate_transfer_receipt`,
  `validate_transfer_reversal`. Decimal precision enforcement per
  asset type (currency: 2, token: 8, entitlement: 2, service_unit: 4).
  ISO 4217 validation. Cross-message receipt-vs-request validation
  (`validate_receipt_against_request`).
- **Reversal** — `validate_reversal_precondition` for T+1/T+30 windows
  and cumulative-bound enforcement. `build_reversal_audit_fields` for
  chain-of-custody linkage.
- **Escrow** — 4-state machine (ESCROWED, RELEASED, RETURNED, DISPUTED)
  via `is_valid_escrow_transition`. Escrow audit builders for each
  lifecycle event. Dispute and cancel validators.
- **Regulatory** — MiFID II audit-field projector (`build_mifid_audit_fields`,
  23 fields, `enforce_mifid_retention` 1825-day floor). DORA incident
  classification and event builder. PSD2 SCA factor validation with
  exemption helpers (`is_sca_exempt`). Token scope separation of duties
  (`validate_assets_token_scope`).
- **Capability risk levels** — `ASSETS_CAPABILITY_RISK_LEVELS` mapping
  per §5.1.

#### Idempotency

- **Key management** — `validate_idempotency_key` (1-128 printable ASCII),
  `resolve_idempotency_key` (header vs envelope precedence),
  `resolve_idempotency_source`, `compute_idempotency_expiry` with
  24-hour retention floor for header-only keys (Core §10.2).
- **Store protocol** — `IdempotencyStore` typing Protocol with
  `get`/`put`/`mark_pending`/`mark_complete`/`check_status`/
  `store_response`/`get_response`. `InMemoryIdempotencyStore`
  thread-safe reference implementation.
- **Duplicate detection** — `DuplicateIdempotencyKey` and
  `DuplicateRequestInProgress` exceptions. `IdempotencyStatus`
  (`new` / `pending` / `completed`) lifecycle.

#### Cryptographic Primitives (`hazmat`)

- **Ed25519** — `generate_ed25519_keypair`, raw `sign`/`verify`,
  JWK serialization.
- **ECDSA** — P-256 (ES256) primitives.
- **JWE** — ECDH-ES+A256GCM encrypt/decrypt with Compact JWE
  serialization.
- **Canonicalization** — RFC 8785 (JCS) via `canonicalize`.

#### Types

- **Pydantic v2 models** — 10 modules with `ConfigDict(...)` (never
  `class Config:`), `Literal` enums (never `StrEnum`), frozen
  immutability where applicable, `extra="forbid"` by default.
  Covers envelopes, identity, actions, compliance, assets, errors,
  routing, security, state, and breach.
- **Forward compatibility** — `ArsiaMessage` uses `extra="ignore"` to
  accept envelopes with optional fields from later minor versions.

#### CLI

- **`arsia` command** — 8 subcommands: `keygen`, `verify`,
  `canonicalize`, `inspect`, `schemas`, `vectors`, `profiles`,
  `version`. Requires `[cli]` extra (`click>=8.0`).

#### Documentation

- **Learning path** — step-by-step guide from install to production.
- **Concepts** — mental model: envelopes, lifecycle, naming, profiles.
- **Cookbook** — 22 copy-pasteable recipes for common tasks.
- **Examples** — 14 runnable scripts (10 basic + 4 regulated use cases:
  agriculture subsidy, fintech trade, healthcare PII, recruitment bias).
- **API reference** — 32 pages covering all modules (mkdocs-ready).

#### Conformance

- **19 conformance suites** — 541 declarative YAML test cases
  covering: actions, assets, authorization, canonicalization,
  certificates, compliance, discovery, encryption, errors,
  idempotency, identity, onboarding, routing, schema-validation,
  signing, state, validation-invalid, validation-valid, version.
- **Python conformance runner** — standalone package
  (`conformance/runners/python/`) that imports the SDK as an external
  consumer. Per-category executors. JSON and human-readable output.
- **613 test vectors** — 415 valid, 125 invalid and 73 runtime-only, as
  the protocol's `validate_vectors.py` reports them (corrected in 1.0.1),
  across Core, Identity, Actions, Routing, State, and Assets specs.
  9 keypairs (Ed25519, ES256, RS256).
- **31 JSON Schemas** — Draft 2020-12, mirrored from the spec repo.
- **7 compliance profiles** — all active.

#### Packaging

- **Python package** — `arsia-protocol` on PyPI. `pip install
  arsia-protocol`. Requires Python >= 3.12.
- **Dependencies** — `cryptography>=43.0`, `pydantic>=2.6.0`,
  `jsonschema>=4.21.0`, `rfc8785>=0.1.4`.
- **Optional extras** — `[cli]` (click), `[dev]` (pytest, mypy, ruff,
  hypothesis, httpx, build), `[docs]` (mkdocs, mkdocs-material,
  mkdocstrings).
- **PEP 561** — `py.typed` marker for typed package support.
- **Build system** — hatchling with custom build hook for bundling
  `shared/` artifacts into the wheel.

#### Licensing

- **SDK code** — Business Source License 1.1 (BUSL-1.1). Converts to
  MPL-2.0 four years after each version's release.
- **Shared artifacts** — `shared/` directory mirrored from the spec
  repo: schemas, profiles, and test vectors under Apache License 2.0;
  RTMs under CC BY-SA 4.0.

#### Quality

- **2998 tests** — unit, integration, property (hypothesis), adversarial,
  security, smoke, and vector tests. 0 failures, 18 skipped (1 RS256
  not implemented, 17 runtime-only vectors).
- **529 conformance cases passing** — 12 skipped (authorization-server,
  certificate-authority, multi-agent-flow, state-storage — all require
  infrastructure beyond the SDK boundary).
- **mypy --strict** — clean on 45 source files.
- **ruff** — clean (lint + format).
- **404 public symbols** exported from `arsia_protocol.__init__`.
- **35 non-init modules** organized in 5 dependency layers with
  enforced boundaries (no circular imports).

---

_ARSIA Protocol ([arsiaprotocol.org](https://arsiaprotocol.org)) | by [Arsia Labs (Arsia Tecnologia Unipessoal Lda)](https://arsialabs.ai)_
