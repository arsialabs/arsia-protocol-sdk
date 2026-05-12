# ARSIA Protocol SDK — Concepts Guide

This guide is for developers who have completed the
quickstart (see the project README) and want to understand the mental
model behind the SDK. It assumes you know Python but not the ARSIA
specification. Every section answers: *what does this do for me?*

An **ARSIA envelope** is a signed JSON message that carries metadata
(sender, recipient, timestamps, compliance rules) alongside a payload.
The SDK builds, signs, verifies, and validates these envelopes.

---

## 1. Envelope Lifecycle

Every envelope flows through the same ordered stages:

```
Sender                                          Receiver
──────                                          ────────
create_*        build the envelope
     │
apply_profile   inherit compliance defaults
     │
sign_message    attach Ed25519 signature
     │
    ─┼──── [ transport: HTTP, WebSocket, … ] ────┼─
     │                                            │
                                         verify_message
                                                  │
                                         validate_envelope
                                                  │
                                         validate_compliance
```

Transport (the middle step) is your responsibility — the SDK never
touches the network. For a step-by-step walkthrough, see the
[Learning Path](learning-path.md).

### Stages

| Stage | Function | What it does | Returns |
|-------|----------|-------------|---------|
| Create | `create_*` | Builds a complete envelope with required fields, UUIDs, timestamps | `dict` (unsigned envelope) |
| Profile | `apply_profile(envelope)` | Reads `compliance.profile`, inherits regulatory defaults | `dict` (enriched copy) |
| Sign | `sign_message(envelope, private_key, kid)` | Canonicalizes (RFC 8785), signs, attaches `security` object | `dict` (signed copy) |
| Verify | `verify_message(envelope, public_key)` | Strips `security`, re-canonicalizes, checks signature | `bool` |
| Validate | `validate_envelope(envelope)` | L1 schema + L2 semantic checks | `list[ValidationError]` (empty = valid) |
| Compliance | `validate_compliance(envelope)` | Checks regulatory rules (retention floor, PII, oversight) | `list[ValidationError]` (empty = valid) |

### The 7 Envelope Factories

Each `create_*` function produces a complete, signable envelope for a
specific intent:

| Factory | Intent |
|---------|--------|
| `create_request` | Ask another agent to do something |
| `create_response` | Reply to a request with a result |
| `create_error` | Reply to a request with an error |
| `create_event` | Emit a one-way notification (no reply expected) |
| `create_pending_approval` | Signal that a request is held for human review |
| `create_approval_decision` | Deliver the human's approve/deny decision |
| `create_rollback_request` | Ask to undo a previously completed action |

---

## 2. Naming Conventions

The SDK uses prefix-based naming so you can predict what a function does
before reading its docstring.

| Prefix | Count | Return type | Meaning |
|--------|------:|-------------|---------|
| `validate_*` | 54 | `list[ValidationError]` | Check rules, return all violations |
| `build_*` | 49 | `dict` (component) | Assemble a sub-component (audit record, error detail, JWK, state args) |
| `is_*` | 32 | `bool` | Predicate — yes/no question about a value |
| `check_*` | 13 | Varies (often richer than bool) | Inspect state or conditions with structured output |
| `compute_*` | 9 | `str`, `float`, or `int` | Derive a value deterministically (hash, delay, delta) |
| `resolve_*` | 8 | Varies | Look up or locate a resource (file path, profile, key) |
| `create_*` | 7 | `dict` (complete envelope) | Envelope factory — the only functions that produce signable envelopes |
| `verify_*` | 7 | `bool` | Cryptographic verification — checks a signature or proof |
| `get_*` | 6 | Varies | Retrieve a stored or computed value |
| `parse_*` | 5 | Parsed structure | Parse a string into a structured value |
| `select_*` | 4 | Varies | Choose among alternatives (topology, broker) |

### Key distinctions

- **`create_*` vs `build_*`** — `create_*` returns a complete envelope
  ready to sign. `build_*` returns a sub-component (audit record, JWK,
  error detail, state operation arguments).

- **`validate_*` vs `verify_*`** — `validate_*` checks structural and
  semantic rules, returns a list of errors. `verify_*` checks a
  cryptographic signature, returns `bool`.

- **`is_*` vs `check_*`** — `is_*` is always a simple `bool` predicate.
  `check_*` may return a richer result (status enum, structured record).

---

## 3. Compliance Profiles

A **compliance profile** is a bundle of regulatory defaults. You declare
which profile applies by setting `compliance.profile` on the envelope.
The SDK handles two sides:

- **Sender side:** `apply_profile()` reads the profile name and inherits
  its defaults into the envelope (retention period, oversight level,
  data residency, etc.).
- **Receiver side:** `validate_compliance()` checks the envelope against
  the profile's rules and returns violations.

### The 7 Profiles

| Profile | Audit | Retention | Oversight | Explainability | PII | Residency | Typical use |
|---------|:-----:|----------:|-----------|:--------------:|:---:|:---------:|-------------|
| `GDPR-STANDARD` | no | none | not_required | no | no | none | General-purpose baseline |
| `EU-AI-ACT-HIGH-RISK` | yes | 180 days | required_before_execution | yes | no | none | High-risk AI (Annex III) |
| `EU-AI-ACT-LIMITED-RISK` | yes | 90 days | not_required | yes | no | none | Chatbots, synthetic content |
| `MIFID-II` | yes | 1827 days | required_before_execution | yes | yes | EU | Financial services |
| `PAC-AGRICULTURE` | yes | 1096 days | required_post_execution | yes | no | EU | CAP subsidy management |
| `DSA-VLOP` | yes | 730 days | required_within_24h | yes | yes | none | Large platform moderation |
| `DORA` | yes | 1827 days | required_within_24h | no | no | EU | Financial ICT resilience |

### How it works

```python
from arsia_protocol import create_request, apply_profile, sign_message

envelope = create_request(
    from_agent="agent:acme.bot",
    to_agent="agent:bank.svc",
    payload_type="com.example.trade",
    capabilities=["com.example.trade"],
    args={"symbol": "AAPL", "qty": 100},
)
envelope["compliance"] = {"profile": "MIFID-II"}

enriched = apply_profile(envelope)
# enriched["compliance"] now has: audit_required=True,
# retention_days=1827, human_oversight="required_before_execution", etc.

signed = sign_message(enriched, private_key, kid)
```

### Priority chain

When the SDK resolves a compliance field it uses a 4-level priority
chain (highest wins):

1. **Per-message** — explicit value set on this envelope
2. **Profile defaults** — from the declared profile
3. **GDPR-STANDARD defaults** — when `compliance` is present but no
   profile is named
4. **No compliance** — envelope has no `compliance` object at all

**Retention floor:** a per-message `retention_days` can *extend* the
profile minimum but never *reduce* it. If you declare `MIFID-II` (1827
days) and set `retention_days: 30`, the effective value stays 1827.

> **See also:** [Cookbook Recipe 4 — Send a message with GDPR compliance](cookbook.md#recipe-4-send-a-message-with-gdpr-compliance) · `examples/02_compliance_profiles.py`

---

## 4. Capabilities and Authorization

**Capabilities** are reverse-DNS strings that scope what an agent is
allowed to do. Every request declares the capabilities it needs;
the receiver checks whether its scope covers them.

```
Request capabilities:  ["com.example.trade.execute"]
Receiver scope:        ["com.example.trade.*"]
→ Match: yes (wildcard covers the specific capability)
```

### Matching rules

- **Exact match:** scope `a.b.c` satisfies request `a.b.c`.
- **Wildcard:** scope `a.b.*` satisfies request `a.b.c` (and `a.b.d`,
  `a.b.anything`).
- **Direction matters:** a specific scope `a.b.c` does *not* satisfy a
  wildcard request `a.b.*`. Wildcards expand scope, not requests.

### Functions

| Function | What it does |
|----------|-------------|
| `match_capabilities(scope, requested)` | Returns `True` if `scope` covers all `requested` capabilities |
| `find_unsatisfied_capabilities(scope, requested)` | Returns the list of capabilities in `requested` that `scope` does not cover |
| `downgrade_capabilities(requested, scope)` | Returns the subset of `requested` that `scope` covers |
| `attach_effective_capabilities(envelope, scope)` | Annotates the envelope with the effective (intersected) capabilities |

### Denial flow

When a request arrives that the receiver cannot fulfill:

1. `match_capabilities(my_scope, request_caps)` returns `False`
2. `find_unsatisfied_capabilities(my_scope, request_caps)` tells you
   which specific capabilities are missing
3. `build_forbidden_error(...)` constructs a `403 forbidden` error
   envelope to send back

> **See also:** [Cookbook Recipe 5 — Handle capability denial](cookbook.md#recipe-5-handle-capability-denial) · [Recipe 18 — Validate JWT claims](cookbook.md#recipe-18-validate-jwt-claims-and-build-a-token) · `examples/08_authorization.py`

---

## 5. Human Oversight

Some regulatory profiles require a human to approve an action before
(or after) it executes. The SDK models this with four levels:

| Level | Meaning |
|-------|---------|
| `not_required` | Fully autonomous — no human review needed |
| `required_before_execution` | A human must approve before the action runs |
| `required_post_execution` | The action runs, but a human must review it afterward |
| `required_within_24h` | The action runs, but a human must review within 24 hours |

### The oversight flow

```
1. Request arrives requiring oversight
        │
2. create_pending_approval(...)
   → "Hold — waiting for human review"
        │
3. Human reviews and decides
        │
4. create_approval_decision(...)
   → "Approved" or "Denied" with deadline
        │
5. is_approval_expired(deadline)
   → Check the deadline before executing
```

### Which profiles require what

| Profile | Default oversight |
|---------|------------------|
| `GDPR-STANDARD` | `not_required` |
| `EU-AI-ACT-HIGH-RISK` | `required_before_execution` |
| `EU-AI-ACT-LIMITED-RISK` | `not_required` |
| `MIFID-II` | `required_before_execution` |
| `PAC-AGRICULTURE` | `required_post_execution` |
| `DSA-VLOP` | `required_within_24h` |
| `DORA` | `required_within_24h` |

### Timeout checking

For `required_within_24h`, the approval decision carries a deadline.
Before executing, call:

```python
from arsia_protocol import is_approval_expired

if is_approval_expired(decision["payload"]["approval_deadline"]):
    # Do not execute — the approval window has closed
    ...
```

`is_approval_expired` accounts for clock skew (default 300 seconds).

> **See also:** [Cookbook Recipe 7 — Pre-execution oversight](cookbook.md#recipe-7-implement-human-oversight-pre-execution) · [Recipe 8 — Post-execution oversight](cookbook.md#recipe-8-implement-human-oversight-post-execution) · `examples/04_oversight_flow.py`

---

## 6. Audit Records

An **audit record** captures what happened to an envelope — who sent it,
what type it was, whether it complied, and a hash of its payload.

### What goes in an audit record

- `message_id` — the envelope's unique ID
- `payload_hash` — SHA-256 of the JCS-canonicalized payload (never raw
  content)
- `event_type` — what happened (e.g. `message_received`,
  `compliance_checked`)
- `retention_days` — how long to keep this record
- `compliance_profile` — which profile was active
- `oversight_status` — whether human review occurred

### Key functions

| Function | What it does |
|----------|-------------|
| `build_audit_record(...)` | Assemble an audit record dict from envelope fields |
| `compute_payload_hash(payload)` | SHA-256 of JCS-canonicalized payload |
| `validate_audit_record(record)` | Check an audit record for required fields and consistency |
| `get_effective_retention(envelope)` | Resolve the effective retention period (profile + per-message) |

### Who stores what

The SDK **builds** audit records but does **not persist** them.
Persistence (append-only, immutable storage) is the caller's
responsibility — typically handled by `arsiactl` or your own audit
infrastructure. The SDK gives you a correct record; you decide where
it goes.

> **See also:** [Cookbook Recipe 9 — Build audit records with correct retention](cookbook.md#recipe-9-build-audit-records-with-correct-retention) · `examples/05_state_operations.py`

---

## 7. Extension Points (Protocol Classes)

The SDK defines **Protocol classes** — Python `typing.Protocol`
interfaces that specify a contract. Any class with the right methods
satisfies the contract without inheriting from anything (structural
subtyping).

### IdempotencyStore

Prevents duplicate processing of the same request. Implement this
over Redis, Postgres, DynamoDB, or any store that supports atomic
check-and-set.

| Method | Purpose |
|--------|---------|
| `get(scope, key)` | Return the completed record or `None` |
| `put(record)` | Persist a completed record (first write wins) |
| `mark_pending(scope, key)` | Atomically reserve a key for an in-flight request |
| `mark_complete(record)` | Transition a pending entry to completed |
| `check_status(scope, key)` | Return the lifecycle state: `"new"`, `"pending"`, or `"completed"` |
| `store_response(scope, key, response_bytes)` | Persist the serialized response for byte-exact replay |
| `get_response(scope, key)` | Retrieve the stored response bytes |

### PaymentReferenceStore

Enforces uniqueness of payment references across a deployment. A
single-method interface:

| Method | Purpose |
|--------|---------|
| `exists(payment_reference)` | Return `True` if the reference has already been used |

### No batteries included

The SDK ships no concrete implementations of these protocols. Test
fixtures provide in-memory versions for development. In production, you
plug in your own backend. The interface is intentionally minimal so
the implementation stays in your infrastructure layer, not in the SDK.

---

## 8. Validation Layers

A receiver typically asks three questions about every arriving envelope,
in order:

| Question | Function | Type of check |
|----------|----------|---------------|
| "Was this signed by who it claims?" | `verify_message(envelope, pub_key)` | Cryptographic |
| "Is this well-formed and consistent?" | `validate_envelope(envelope)` | Structural + semantic |
| "Does this comply with regulations?" | `validate_compliance(envelope)` | Regulatory rules |

### L1 vs L2

`validate_envelope` runs two layers internally:

- **L1 (schema)** — JSON Schema (Draft 2020-12) structure checks. Does
  the envelope have the right fields, types, and shapes?
- **L2 (semantic)** — Cross-field rules. Does `security.kid` start with
  `from + "#"`? Is `expires_at` after `ts`? Are `capabilities`
  non-empty for requests?

If L1 fails, L2 is skipped — semantic checks on a structurally broken
envelope produce noisy, misleading results. To run both layers
independently, call `validate_schema` and `validate_semantic` directly.

### All validation functions

The SDK has 54 `validate_*` functions spread across its modules. The
most commonly used ones on the receiver path:

| Function | What it checks | Return |
|----------|---------------|--------|
| `validate_envelope(envelope)` | L1 + L2 combined | `list[ValidationError]` |
| `validate_schema(envelope)` | L1 only (JSON Schema) | `list[ValidationError]` |
| `validate_semantic(envelope)` | L2 only (cross-field rules) | `list[ValidationError]` |
| `validate_compliance(envelope)` | Regulatory rules (7 checks from §4.3.8) | `list[ValidationError]` |
| `validate_agent_id(raw)` | Agent ID format (`agent:org.name`) | `list[ValidationError]` |
| `validate_capability(cap)` | Capability string format | `list[ValidationError]` |
| `validate_audit_record(record)` | Audit record completeness | `list[ValidationError]` |
| `validate_idempotency_key(key)` | Idempotency key format | `list[ValidationError]` |

All `validate_*` functions return `list[ValidationError]`. An empty list
means valid. They never raise exceptions for validation failures — errors
are data, not control flow.

> **See also:** [Cookbook Recipe 1 — Validate a received message](cookbook.md#recipe-1-validate-a-received-message) · `examples/01_sign_verify_validate.py`

---

## 9. Error Model

The SDK has three distinct error concepts:

### ValidationError (dataclass)

Returned by `validate_*` functions. Data, not an exception. You iterate
over the list and decide what to do.

```python
@dataclass(frozen=True)
class ValidationError:
    code: str                    # machine-parseable identifier
    message: str                 # human-readable description
    details: dict[str, Any]      # structured context
    spec_ref: str                # e.g. "Core §4.3.8 R2"
```

### ArsiaError (Pydantic model)

The wire-level error object inside error envelopes (`payload.error`).
Has `code`, `description`, and optional `details`. The 14 standard error
codes map to HTTP statuses:

| Code | HTTP | Retryable |
|------|-----:|:---------:|
| `invalid_request` | 400 | no |
| `unauthorized` | 401 | no |
| `forbidden` | 403 | no |
| `not_found` | 404 | no |
| `conflict` | 409 | no |
| `payload_too_large` | 413 | no |
| `rate_limited` | 429 | yes |
| `internal_error` | 500 | yes |
| `not_implemented` | 501 | no |
| `service_unavailable` | 503 | yes |
| `certificate_invalid` | 401 | no |
| `certificate_expired` | 401 | no |
| `key_mismatch` | 401 | no |
| `certificate_revoked` | 401 | no |

### Exceptions

Two exceptions are raised (not returned) for idempotency conflicts:

- `DuplicateIdempotencyKey` — a completed record already exists for this
  key
- `DuplicateRequestInProgress` — another request with this key is
  currently being processed

### Error envelope builders

| Builder | Produces |
|---------|----------|
| `build_error_envelope(...)` | Generic error envelope from any code |
| `build_forbidden_error(...)` | 403 — insufficient capabilities |
| `build_rate_limited_error(...)` | 429 — rate limit exceeded |
| `build_payload_too_large_error(...)` | 413 — message too large |
| `build_not_implemented_error(...)` | 501 — unsupported feature |
| `build_service_unavailable_error(...)` | 503 — temporary unavailability |
| `build_oversight_denied_error(...)` | Human denied the action |
| `build_oversight_expired_error(...)` | Approval deadline passed |

### Error registry

```python
from arsia_protocol import get_error_info, is_retryable, compute_retry_delay

info = get_error_info("rate_limited")   # ErrorCodeInfo(code=..., http_status=429, ...)
is_retryable("rate_limited")            # True
compute_retry_delay(attempt=3)          # exponential backoff in seconds
```

> **See also:** [Cookbook Recipe 14 — Handle error envelopes](cookbook.md#recipe-14-handle-error-envelopes-retry-logic) · `examples/03_error_handling.py`

---

## 10. SDK Boundary

### What the SDK does

- **Builds** envelopes with correct structure, UUIDs, timestamps
- **Signs** envelopes with Ed25519 (or ES256)
- **Verifies** signatures against a public key
- **Validates** structure (L1 schema), semantics (L2 cross-field), and
  compliance (regulatory rules)
- **Applies** compliance profiles (sender-side normalization)
- **Constructs** audit records, error envelopes, JWKs, discovery
  documents, state operation arguments

### What the SDK does NOT do

| Responsibility | Why it's not in the SDK | Who handles it |
|---------------|------------------------|----------------|
| Transport (HTTP, WebSocket, MCP, A2A) | The protocol is transport-agnostic by design | Your application or `arsiactl` |
| Agent execution (planning, tool use) | That's the agent framework's job | LangChain, AutoGen, custom code |
| Audit trail storage | The SDK builds records; persistence requires infrastructure | `arsiactl`, your database |
| OAuth2 token issuance | The SDK validates tokens, never issues them | Your identity provider |
| Payload inspection | The SDK signs envelopes; it never interprets payload content | Your application logic |

The boundary is always the specification: everything the ARSIA spec
defines, the SDK implements. Everything beyond the spec (servers,
storage, execution) is outside the SDK.

---

## 11. Other Modules

The sections above cover the core mental model. The SDK also includes
modules for routing, asset transfers, and breach notification — each
with its own cookbook recipes and examples.

- **Routing** — topology selection (direct vs. brokered), broker
  discovery, rate-limit header parsing, and retry delay computation.
  See `examples/06_routing.py` and
  [Cookbook Recipe 19 — Parse rate-limit headers](cookbook.md#recipe-19-parse-rate-limit-headers-and-compute-delay).

- **Assets and escrow** — transfer lifecycle (initiate → hold → release
  or dispute), MiFID II / DORA / PSD2 regulatory helpers.
  See `examples/07_escrow.py`.

- **Breach notification** — GDPR Article 33/34 breach notification
  builders and validators.
  See [Cookbook Recipe 17 — Build a breach notification](cookbook.md#recipe-17-build-a-breach-notification).

- **MCP and A2A compliance wrapping** — ARSIA sits above MCP and A2A as
  a compliance layer, adding identity, audit, and regulatory enforcement
  without modifying the inner protocol messages.
  See `examples/09_mcp_compliance.py`, `examples/10_a2a_oversight.py`,
  and [Cookbook Recipes 20–22](cookbook.md#recipe-20-wrap-an-mcp-tool-call-in-an-arsia-envelope).

For the full module map, see the project README section "Module map".
