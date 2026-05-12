# ARSIA Protocol SDK — Cookbook

Copy-pasteable recipes for common tasks. Each recipe is self-contained.
For a structured introduction, start with the
[Learning Path](learning-path.md). For the mental model behind these
functions, see the [Concepts Guide](concepts.md).

---

## Recipe 1 — Validate a received message

**Problem:** You received a signed envelope and need to verify its
authenticity, structure, and compliance before processing it.

**Solution:**

```python
from arsia_protocol import (
    verify_message,
    validate_envelope,
    validate_compliance,
)

def validate_received(envelope: dict, sender_public_key) -> list:
    # Step 1: Cryptographic verification (is the signature valid?)
    if not verify_message(envelope, sender_public_key):
        return [{"error": "signature_invalid"}]

    # Step 2: Structural + semantic validation (L1 schema + L2 rules)
    errors = validate_envelope(envelope)
    if errors:
        return errors

    # Step 3: Regulatory compliance (profile-specific rules)
    errors = validate_compliance(envelope)
    return errors
```

**Notes:**
- Order matters: verify first, then validate, then compliance. If the
  signature is invalid, don't trust the contents.
- `validate_envelope` runs L1 (schema) first; if L1 fails, L2 (semantic)
  is skipped. See [Concepts: §8. Validation Layers](concepts.md#8-validation-layers).
- The public key must be resolved from the sender's JWKS using
  `security.kid` — the SDK never performs network I/O.
- For a complete sign/verify/validate pipeline, see
  `examples/01_sign_verify_validate.py`.

---

## Recipe 2 — Cross-check identity consistency

**Problem:** You want to verify that an envelope's `from` field,
`security.kid` prefix, and the sender's IdentityRecord all agree.

**Solution:**

```python
from arsia_protocol import check_identity_consistency

# Extract fields from the received envelope
from_agent = envelope["from"]           # e.g. "agent:acme.bot"
kid = envelope["security"]["kid"]       # e.g. "agent:acme.bot#key-1"

# Two-layer check (from + kid)
result = check_identity_consistency(from_agent=from_agent, kid=kid)
assert result.is_consistent  # True — kid prefix matches from

# Three-layer check (from + kid + IdentityRecord)
result = check_identity_consistency(
    from_agent=from_agent,
    kid=kid,
    identity_agent_id="agent:acme.bot",  # from sender's IdentityRecord
)
assert result.is_consistent

# Inconsistent example — kid doesn't match from
result = check_identity_consistency(
    from_agent="agent:acme.bot",
    kid="agent:evil.impersonator#key-1",
)
assert not result.is_consistent
assert len(result.warnings) > 0
```

**Notes:**
- The third layer (`identity_agent_id`) is optional — pass it when you
  have the sender's IdentityRecord, omit it when you don't.
- `result.warnings` is a tuple of human-readable strings describing each
  inconsistency.

---

## Recipe 3 — Validate correlation between request and response

**Problem:** You need to verify that a response's `correlation_id`
matches the original request's `id`.

**Solution:**

```python
from arsia_protocol import validate_correlation

# Matched — correlation_id equals request.id
errors = validate_correlation(request_envelope, response_envelope)
assert errors == []  # valid

# Mismatched — returns validation errors
bad_response = {**response_envelope, "correlation_id": "wrong-id"}
errors = validate_correlation(request_envelope, bad_response)
assert len(errors) > 0
assert errors[0].code == "correlation_mismatch"
```

**Notes:**
- Comparison is byte-for-byte — UUIDs are case-sensitive.
- A missing `correlation_id` produces a `missing_correlation_id` error.

---

## Recipe 4 — Send a message with GDPR compliance

**Problem:** You need to send a request that involves personal data
under GDPR, with PII flagged and legal basis declared.

**Solution:**

```python
from arsia_protocol import (
    create_request,
    apply_profile,
    generate_ed25519_keypair,
    sign_message,
    validate_compliance,
)

private_key, public_key = generate_ed25519_keypair()

envelope = create_request(
    from_agent="agent:clinic.data-collector",
    to_agent="agent:clinic.analyzer",
    payload_type="com.clinic.lab-result",
    capabilities=["com.clinic.lab-result"],
    args={"patient_id": "P-1234", "test": "CBC"},
    compliance={
        "profile": "GDPR-STANDARD",
        "pii_involved": True,
        "legal_basis": "consent",
    },
)

enriched = apply_profile(envelope)
signed = sign_message(enriched, private_key, "agent:clinic.data-collector#key-1")

# Receiver validates compliance
errors = validate_compliance(signed)
assert errors == []  # valid — pii_involved has legal_basis

# What happens without legal_basis (R2 violation)
bad = create_request(
    from_agent="agent:clinic.data-collector",
    to_agent="agent:clinic.analyzer",
    payload_type="com.clinic.lab-result",
    capabilities=["com.clinic.lab-result"],
    compliance={"profile": "GDPR-STANDARD", "pii_involved": True},
)
bad = apply_profile(bad)
errors = validate_compliance(bad)
assert any(e.code == "missing_legal_basis" for e in errors)
```

**Notes:**
- `pii_involved=True` requires `legal_basis` — omitting it triggers R2
  (`missing_legal_basis`). See [Concepts: §3. Compliance Profiles](concepts.md#3-compliance-profiles).
- `apply_profile` is sender-side normalization; `validate_compliance` is
  receiver-side rejection. Both are needed.
- For a complete healthcare PII pipeline, see
  `examples/use-cases/healthcare_pii_pipeline.py`.

---

## Recipe 5 — Handle capability denial

**Problem:** A request arrives that requires capabilities your agent
doesn't support. You need to identify what's missing and build a 403
error response.

**Solution:**

```python
from arsia_protocol import (
    match_capabilities,
    find_unsatisfied_capabilities,
    build_forbidden_error,
    sign_message,
)

my_scope = ["com.acme.billing.*", "com.acme.reports.read"]
requested = ["com.acme.billing.create-invoice", "com.acme.admin.delete-user"]

if not match_capabilities(my_scope, requested):
    missing = find_unsatisfied_capabilities(my_scope, requested)
    # missing == ["com.acme.admin.delete-user"]

    error_envelope = build_forbidden_error(
        from_agent="agent:acme.billing-svc",
        to_agent="agent:partner.requester",
        correlation_id=request_envelope["id"],
        required_capabilities=requested,
        provided_capabilities=my_scope,
    )
    signed_error = sign_message(error_envelope, private_key, kid)
```

**Notes:**
- `build_forbidden_error` returns an unsigned envelope — you must sign
  it before sending.
- Wildcards expand scope, not requests: `com.acme.billing.*` in your
  scope covers `com.acme.billing.create-invoice`, but a wildcard in the
  request is not satisfied by a specific scope entry.
  See [Concepts: §4. Capabilities and Authorization](concepts.md#4-capabilities-and-authorization).

---

## Recipe 6 — Downgrade capabilities

**Problem:** A request asks for more capabilities than you support, but
you can fulfill a subset. You want to respond with the effective
(intersected) capabilities.

**Solution:**

```python
from arsia_protocol import (
    downgrade_capabilities,
    attach_effective_capabilities,
    create_response,
    sign_message,
    build_forbidden_error,
)

requested = ["com.acme.trade.execute", "com.acme.trade.cancel", "com.acme.admin.sudo"]
my_scope = ["com.acme.trade.*"]

try:
    effective = downgrade_capabilities(requested, my_scope)
    # effective == ["com.acme.trade.execute", "com.acme.trade.cancel"]

    response = create_response(
        from_agent="agent:acme.trade-svc",
        to_agent="agent:partner.requester",
        correlation_id=request_envelope["id"],
        payload_type="com.acme.trade.result",
        result={"status": "executed", "trade_id": "T-5678"},
    )
    response = attach_effective_capabilities(response, effective)
    signed = sign_message(response, private_key, kid)

except ValueError:
    # Empty intersection — must reject, not silently downgrade
    error = build_forbidden_error(
        from_agent="agent:acme.trade-svc",
        to_agent="agent:partner.requester",
        correlation_id=request_envelope["id"],
        required_capabilities=requested,
        provided_capabilities=my_scope,
    )
    signed = sign_message(error, private_key, kid)
```

**Notes:**
- `downgrade_capabilities` raises `ValueError` when the intersection is
  empty — silent downgrade to zero capabilities is prohibited by §1.3
  rule 3.
- `attach_effective_capabilities` sets
  `payload.result.effective_capabilities` on a deep copy.

---

## Recipe 7 — Implement human oversight (pre-execution)

**Problem:** A high-risk action requires human approval before
execution (e.g., EU AI Act high-risk, MiFID II).

**Solution:**

```python
from arsia_protocol import (
    create_request,
    create_pending_approval,
    create_approval_decision,
    generate_ed25519_keypair,
    sign_message,
    is_approval_expired,
)

agent_key, _ = generate_ed25519_keypair()
reviewer_key, _ = generate_ed25519_keypair()

AGENT = "agent:acme.assistant"
REVIEWER = "agent:acme.human-reviewer"

# 1. Original request arrives requiring oversight
request = create_request(
    from_agent=AGENT, to_agent=REVIEWER,
    payload_type="com.acme.financial.transfer",
    capabilities=["com.acme.financial.transfer"],
    args={"amount": 50_000, "currency": "EUR"},
    compliance={"profile": "MIFID-II"},
)
signed_request = sign_message(request, agent_key, f"{AGENT}#key-1")

# 2. Agent signals "waiting for human review"
pending = create_pending_approval(
    from_agent=AGENT, to_agent=REVIEWER,
    correlation_id=signed_request["id"],
    payload_type="com.acme.financial.transfer",
    args={"context": "€50K transfer requires MiFID II approval"},
    expires_in_seconds=3600,  # 1 hour (max 86400 = 24h)
)
signed_pending = sign_message(pending, agent_key, f"{AGENT}#key-1")

# 3. Human approves
decision = create_approval_decision(
    from_agent=REVIEWER, to_agent=AGENT,
    correlation_id=signed_pending["id"],
    payload_type="com.acme.financial.transfer",
    capabilities=["com.acme.financial.transfer"],
    result={"decision": "approved", "reason": "Amount within daily limit"},
)
signed_decision = sign_message(decision, reviewer_key, f"{REVIEWER}#key-1")

# 4. Check deadline before executing
deadline = signed_pending["expires_at"]
if is_approval_expired(deadline):
    pass  # Do NOT execute — window closed
else:
    pass  # Safe to execute the action
```

**Notes:**
- `expires_in_seconds` must not exceed 86400 (24 hours).
- `is_approval_expired` includes 300 seconds of clock-skew tolerance.
- See [Concepts: §5. Human Oversight](concepts.md#5-human-oversight) and
  `examples/04_oversight_flow.py`.

---

## Recipe 8 — Implement human oversight (post-execution)

**Problem:** An action runs immediately but must be reviewed afterward
(e.g., PAC-AGRICULTURE `required_post_execution` or DSA-VLOP
`required_within_24h`).

**Solution:**

```python
from datetime import datetime, timezone
from arsia_protocol import (
    create_request,
    create_pending_approval,
    create_approval_decision,
    apply_profile,
    generate_ed25519_keypair,
    sign_message,
    check_oversight_timeout,
)

agent_key, _ = generate_ed25519_keypair()
reviewer_key, _ = generate_ed25519_keypair()

AGENT = "agent:farm.classifier"
REVIEWER = "agent:farm.inspector"

# 1. Build and execute the request FIRST
request = create_request(
    from_agent=AGENT, to_agent=REVIEWER,
    payload_type="com.farm.crop-classify",
    capabilities=["com.farm.crop-classify"],
    args={"parcel_id": "PT-ALT-042"},
    compliance={"profile": "PAC-AGRICULTURE"},
)
enriched = apply_profile(request)
signed = sign_message(enriched, agent_key, f"{AGENT}#key-1")

# 2. Action executes immediately
executed_at = datetime.now(timezone.utc)

# 3. THEN create pending_approval for post-execution review
pending = create_pending_approval(
    from_agent=AGENT, to_agent=REVIEWER,
    correlation_id=signed["id"],
    payload_type="com.farm.crop-classify",
    args={"context": "Post-execution review of parcel classification"},
    expires_in_seconds=86400,  # 24h for post-execution review
)

# 4. Check if required_within_24h deadline has passed
timeout_error = check_oversight_timeout(
    human_oversight="required_within_24h",
    executed_at=executed_at,
    reviewed_at=None,  # no review yet
)
if timeout_error is not None:
    pass  # Log compliance violation — 24h window expired without review
```

**Notes:**
- The key difference from Recipe 7: the action runs before the
  `pending_approval` is created.
- `check_oversight_timeout` returns `None` when the deadline hasn't
  passed, or a `ValidationError` when it has.
- For a complete agriculture pipeline, see
  `examples/use-cases/agriculture_subsidy_pipeline.py`.

---

## Recipe 9 — Build audit records with correct retention

**Problem:** You need to create a compliant audit record for a
processed message, with the correct retention period from the
compliance profile.

**Solution:**

```python
from arsia_protocol import (
    get_effective_retention,
    build_audit_record,
    validate_audit_record,
)

# Resolve retention from the compliance profile
retention = get_effective_retention(signed_envelope)
if retention is None:
    retention = 90  # your organization's default

# Build the audit record
record = build_audit_record(
    signed_envelope,
    event_type="request",
    operator_id="org:acme-corp",
    effective_retention_days=retention,
    oversight_status="approved",      # or "pending", "denied", None
    approver_id="agent:acme.reviewer",  # required when status is "approved"/"denied"
)

# record is an ArsiaAuditRecord (Pydantic model)
# Validate it before persisting
errors = validate_audit_record(record)
assert errors == []

# Serialize for your storage backend
record_dict = record.model_dump(mode="json")
```

**Notes:**
- `build_audit_record` returns an `ArsiaAuditRecord` (Pydantic model),
  not a dict. Use `.model_dump(mode="json")` to serialize.
- `approver_id` is required when `oversight_status` is `"approved"` or
  `"denied"` — omitting it raises `ValueError`.
- `effective_retention_days` must be >= 1.
- The SDK builds audit records but does NOT persist them — that's your
  responsibility.
  See [Concepts: §6. Audit Records](concepts.md#6-audit-records).

---

## Recipe 10 — Key rotation with overlap period

**Problem:** You need to rotate your agent's signing key while
maintaining an overlap period so in-flight messages remain verifiable.

**Solution:**

```python
from arsia_protocol import (
    build_jwk, build_rotation_jwks, build_jwks,
    filter_compromised_keys, generate_ed25519_keypair,
)

AGENT = "agent:acme.bot"

# Current key (already in use)
current_priv, current_pub = generate_ed25519_keypair()
current_jwk = build_jwk(current_pub, f"{AGENT}#key-1")

# Generate new key
new_priv, new_pub = generate_ed25519_keypair()
new_jwk = build_jwk(new_pub, f"{AGENT}#key-2")

# Phase 1: Publish BOTH keys (overlap period — at least 24 hours)
rotation_jwks = build_rotation_jwks(
    current_keys=[current_jwk],
    new_keys=[new_jwk],
)
# rotation_jwks == {"keys": [current_jwk, new_jwk]}
# Serve this from /.well-known/arsia/jwks.json

# Phase 2: After 24h, retire old key — publish only the new one
final_jwks = build_jwks([new_jwk])

# If old key is compromised, filter it out immediately
clean_keys = filter_compromised_keys(
    rotation_jwks["keys"],
    compromised_kids={f"{AGENT}#key-1"},
)
emergency_jwks = build_jwks(clean_keys)
```

**Notes:**
- Per §7.3 Rule 1, old and new keys MUST be published simultaneously
  for at least 24 hours during rotation.
- Compromised keys must be removed immediately (§7.3 Rule 4) — the 24h
  overlap does not apply to compromised keys.
- `build_jwk` delegates to the hazmat Ed25519 encoder — you don't need
  to reach into `hazmat` directly.

---

## Recipe 11 — Encrypt a payload (JWE)

**Problem:** You need to encrypt the envelope payload so only the
intended recipient can read it, using JWE (ECDH-ES + A256GCM).

**Solution:**

```python
from arsia_protocol import (
    create_request,
    encrypt_payload,
    generate_ed25519_keypair,
    sign_message,
    decrypt_and_verify,
    build_ec_jwk,
)
from arsia_protocol.hazmat.primitives.ecdsa import generate_keypair as ec_keypair

# Sender: Ed25519 for signing
sender_priv, sender_pub = generate_ed25519_keypair()

# Recipient: P-256 for encryption
recipient_priv, recipient_pub = ec_keypair()
recipient_enc_jwk = build_ec_jwk(recipient_pub, "agent:bank.svc#enc-1", use="enc")
recipient_jwks = {"keys": [recipient_enc_jwk]}

# Build → encrypt → sign (encrypt BEFORE signing)
envelope = create_request(
    from_agent="agent:acme.bot",
    to_agent="agent:bank.svc",
    payload_type="com.bank.transfer",
    capabilities=["com.bank.transfer"],
    args={"amount": 10_000, "currency": "EUR"},
)

encrypted = encrypt_payload(envelope, recipient_jwks)
signed = sign_message(encrypted, sender_priv, "agent:acme.bot#key-1")

# Recipient: verify signature → decrypt payload
decrypted = decrypt_and_verify(signed, sender_pub, recipient_priv)
assert decrypted["payload"]["args"]["amount"] == 10_000
```

**Notes:**
- Signing and encryption use different key types: Ed25519 for signing,
  P-256 (ECDH-ES) for encryption.
- The caller SHOULD sign AFTER encrypting so the signature covers the
  JWE ciphertext.
- `decrypt_and_verify` verifies the signature first, then decrypts — if
  the signature is invalid, it raises `ValueError` without attempting
  decryption.

---

## Recipe 12 — Build a discovery document

**Problem:** You need to serve a discovery document at
`/.well-known/arsia` so other agents can find your inbox, JWKS, and
capabilities.

**Solution:**

```python
import json
from arsia_protocol import build_discovery_document

document = build_discovery_document(
    agent_id="agent:acme.billing-svc",
    name="Acme Billing Service",
    version="2.1.0",
    inbox="https://api.acme.com/arsia/inbox",
    jwks="https://api.acme.com/.well-known/arsia/jwks.json",
    capabilities_supported=[
        "com.acme.billing.create-invoice",
        "com.acme.billing.query",
    ],
    compliance_profiles_supported=["GDPR-STANDARD", "MIFID-II"],
    features={"encryption": True, "async_responses": False},
)

# Serve as JSON at GET /.well-known/arsia
print(json.dumps(document, indent=2))
```

**Notes:**
- The 11 required fields (§7.1) are always populated; optional fields
  (`features`, `rate_limits`, `compliance_profiles_supported`) are
  included only when you pass them.
- `version` is your agent's software version, not the protocol version.
- `max_message_bytes` defaults to 1 MiB, `request_timeout_ms` to 30s.

---

## Recipe 13 — Build an encryption JWKS

**Problem:** Your agent supports both signing and encryption. You need
to publish a JWKS containing both key types.

**Solution:**

```python
from arsia_protocol import (
    build_jwk, build_ec_jwk, build_encryption_jwks, generate_ed25519_keypair,
)
from arsia_protocol.hazmat.primitives.ecdsa import generate_keypair as ec_keypair

AGENT = "agent:acme.secure-svc"

# Signing key (Ed25519, use="sig")
sig_priv, sig_pub = generate_ed25519_keypair()
sig_jwk = build_jwk(sig_pub, f"{AGENT}#sig-1", use="sig")

# Encryption key (P-256, use="enc")
enc_priv, enc_pub = ec_keypair()
enc_jwk = build_ec_jwk(enc_pub, f"{AGENT}#enc-1", use="enc")

# Combine into a single JWKS
jwks = build_encryption_jwks(
    signing_keys=[sig_jwk],
    encryption_keys=[enc_jwk],
)
# jwks == {"keys": [sig_jwk, enc_jwk]}
```

**Notes:**
- Signing keys use `use="sig"` (Ed25519/OKP), encryption keys use
  `use="enc"` (P-256/EC).
- Senders find the encryption key by looking for `use="enc"` in your
  JWKS.

---

## Recipe 14 — Handle error envelopes (retry logic)

**Problem:** You received an error response and need to determine
whether to retry and how long to wait.

**Solution:**

```python
import time
import random
from arsia_protocol import get_error_info, is_retryable, compute_retry_delay

error_code = error_envelope["payload"]["error"]["code"]

info = get_error_info(error_code)
print(f"{info.code} → HTTP {info.http_status}, retryable={info.retryable}")

if is_retryable(error_code):
    for attempt in range(1, 4):  # up to 3 retries
        delay = compute_retry_delay(attempt)
        jitter = random.uniform(0.75, 1.25)
        wait = delay * jitter
        print(f"Retry {attempt}: waiting {wait:.1f}s (base {delay:.0f}s)")
        time.sleep(wait)
        # ... re-send the request ...
        break  # on success
else:
    print(f"Non-retryable error: {info.code} — {info.description}")
```

**Notes:**
- `compute_retry_delay` produces `1, 2, 4` seconds for attempts 1, 2, 3.
  The SDK enforces `max_retries=3` (Core §11.3) — passing attempt > 3
  raises `ValueError`.
- Jitter (0.75–1.25 multiplier) is NOT applied by `compute_retry_delay`
  — apply it yourself to avoid thundering herd.
- Retryable codes: `rate_limited`, `internal_error`,
  `service_unavailable`. All others are non-retryable.
- See [Concepts: §9. Error Model](concepts.md#9-error-model).

---

## Recipe 15 — Validate EU AI Act responses

**Problem:** You need to verify that a response from a high-risk AI
system includes the transparency fields required by the EU AI Act.

**Solution:**

```python
from arsia_protocol import (
    validate_eu_ai_act_response,
    validate_explainability,
    is_explanation_required,
    create_response,
)

# Check if a response needs an explanation
needs_it = is_explanation_required(
    compliance={"explainability_required": True},
)
assert needs_it is True

# Build a compliant response with explanation
response = create_response(
    from_agent="agent:acme.classifier",
    to_agent="agent:acme.requester",
    correlation_id=request_envelope["id"],
    payload_type="com.acme.classification",
    result={"class": "high-risk", "score": 0.92},
    explanation={
        "reasoning": "Model identified 3 risk indicators in the input data",
        "confidence": 0.92,
        "inputs_used": ["financial_history", "transaction_pattern", "geo_data"],
    },
    compliance={"profile": "EU-AI-ACT-HIGH-RISK"},
)

# Validate the response (checks profile, intent, explanation fields)
errors = validate_eu_ai_act_response(response)
assert errors == []

# Cross-validate against the original request
error = validate_explainability(request_envelope, response)
assert error is None  # None means valid
```

**Notes:**
- `validate_eu_ai_act_response` returns `list[ValidationError]` — checks
  that `explanation` contains `reasoning` (non-empty str), `confidence`
  (0.0–1.0), and `inputs_used` (non-empty list).
- `validate_explainability` returns a single `ValidationError | None` —
  it compares a request/response pair and checks that the response
  includes an explanation when the request's
  `compliance.explainability_required` is true.
- For a complete recruitment bias pipeline with EU AI Act compliance, see
  `examples/use-cases/recruitment_bias_pipeline.py`.

---

## Recipe 16 — Use idempotency

**Problem:** You need to prevent duplicate processing of the same
request using the SDK's idempotency protocol.

**Solution:**

```python
from arsia_protocol import (
    create_request,
    IdempotencyStore,
    IdempotencyScope,
    IdempotencyRecord,
    scope_tuple,
    resolve_idempotency_key,
    DuplicateIdempotencyKey,
)

# 1. Send a request with an idempotency key
request = create_request(
    from_agent="agent:acme.client",
    to_agent="agent:acme.payments",
    payload_type="com.acme.payment",
    capabilities=["com.acme.payment"],
    args={"amount": 100, "currency": "EUR"},
    idempotency={"key": "pay-order-42", "expires_at": "2026-05-12T00:00:00.000Z"},
)

# 2. Receiver extracts scope and key
scope = scope_tuple(request)       # IdempotencyScope(from_agent=..., to_agent=..., payload_type=...)
key = resolve_idempotency_key(request)  # "pay-order-42"

# 3. Minimal store implementation (use Redis/Postgres in production)
class MyIdempotencyStore:
    def __init__(self):
        self._pending: dict[tuple, bool] = {}
        self._records: dict[tuple, IdempotencyRecord] = {}
        self._responses: dict[tuple, bytes] = {}

    def _idx(self, scope: IdempotencyScope, key: str):
        return (scope.from_agent, scope.to_agent, scope.payload_type, key)

    def mark_pending(self, scope: IdempotencyScope, key: str) -> bool:
        idx = self._idx(scope, key)
        if idx in self._pending or idx in self._records:
            return False
        self._pending[idx] = True
        return True

    def check_status(self, scope: IdempotencyScope, key: str):
        idx = self._idx(scope, key)
        if idx in self._records:
            return "completed"
        if idx in self._pending:
            return "pending"
        return "new"

    def mark_complete(self, record: IdempotencyRecord) -> None:
        scope = IdempotencyScope(record.from_agent, record.to_agent, record.payload_type)
        idx = self._idx(scope, record.key)
        if idx in self._records:
            raise DuplicateIdempotencyKey(scope, record.key)
        self._records[idx] = record
        self._pending.pop(idx, None)

    def store_response(self, scope: IdempotencyScope, key: str, response_bytes: bytes):
        self._responses[self._idx(scope, key)] = response_bytes

    def get_response(self, scope: IdempotencyScope, key: str) -> bytes | None:
        return self._responses.get(self._idx(scope, key))

    def get(self, scope: IdempotencyScope, key: str) -> IdempotencyRecord | None:
        return self._records.get(self._idx(scope, key))

    def put(self, record: IdempotencyRecord) -> None:
        self.mark_complete(record)

# 4. Use the store
store = MyIdempotencyStore()
if store.mark_pending(scope, key):
    pass  # Process the request, then mark_complete
else:
    status = store.check_status(scope, key)
    if status == "completed":
        stored = store.get_response(scope, key)
        pass  # Replay the stored response
    else:
        pass  # Return 409 Conflict — request in progress
```

**Notes:**
- `IdempotencyStore` is a `typing.Protocol` — any class with the right
  methods satisfies it without inheriting.
- The lifecycle is `new → pending → completed`. Duplicates arriving
  during `pending` should get HTTP 409; duplicates arriving after
  `completed` get the stored response replayed.
- See [Concepts: §7. Extension Points](concepts.md#7-extension-points-protocol-classes).

---

## Recipe 17 — Build a breach notification

**Problem:** You need to build and send a GDPR Article 33 breach
notification to a supervisory authority.

**Solution:**

```python
from arsia_protocol import (
    build_breach_notification,
    validate_breach_notification,
    create_event,
    sign_message,
    generate_ed25519_keypair,
    PAYLOAD_TYPE_BREACH_NOTIFICATION,
)

private_key, public_key = generate_ed25519_keypair()

# 1. Build the payload data
breach_data = build_breach_notification(
    notification_target="supervisory_authority",
    breach_id="a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    nature_of_breach="Unauthorized access to patient records via compromised API key",
    awareness_timestamp="2026-05-10T14:30:00.000Z",
    likely_consequences="Exposure of health data for ~2,000 patients",
    measures_taken="API key revoked, affected accounts locked, forensic audit initiated",
    categories_of_data=["health", "contact"],
    approximate_data_subject_count=2000,
    dpo_contact="Jane Smith, dpo@example.com",
)

# 2. Validate before sending
errors = validate_breach_notification(breach_data)
assert not errors, f"Invalid breach notification: {errors}"

# 3. Wrap in an event envelope and sign
envelope = create_event(
    from_agent="agent:example.dpo-bot",
    to_agent="agent:authority.intake",
    payload_type=PAYLOAD_TYPE_BREACH_NOTIFICATION,
    data=breach_data,
)

signed = sign_message(envelope, private_key, "agent:example.dpo-bot#key-1")
```

**Notes:**
- GDPR Article 33 requires notification within **72 hours** of
  becoming aware of a breach. The `awareness_timestamp` field records
  the moment of awareness — downstream systems use it to verify
  timeliness.
- `notification_target` is either `"supervisory_authority"` (Art. 33) or
  `"data_subject"` (Art. 34). Any other value raises `ValueError`.
- The six required fields are keyword-only. Optional fields
  (`categories_of_data`, `approximate_data_subject_count`,
  `dpo_contact`, etc.) are omitted from the output when `None`.

---

## Recipe 18 — Validate JWT claims and build a token

**Problem:** You need to build a JWT for testing and validate incoming
token claims against a known public key.

**Solution:**

```python
import time
from arsia_protocol import (
    build_jwt,
    validate_token_claims,
    parse_scope,
    check_scope_coverage,
    generate_ed25519_keypair,
)

private_key, public_key = generate_ed25519_keypair()

# 1. Build a JWT (for testing — production tokens come from an OAuth2 server)
now = int(time.time())
token = build_jwt(
    {
        "iss": "https://auth.example.com",
        "sub": "agent:acme.bot",
        "aud": "agent:bank.svc",
        "scope": "notes.read notes.write transfers.execute",
        "exp": now + 3600,
        "iat": now,
        "jti": "unique-token-id-001",
    },
    private_key,
)

# 2. Validate the token (receiver side)
result = validate_token_claims(
    token,
    public_key,
    expected_sub="agent:acme.bot",
    expected_aud="agent:bank.svc",
    required_capabilities=["notes.read", "transfers.execute"],
)

print(f"Valid: {result.is_valid}")  # True
if not result.is_valid:
    for err in result.errors:
        print(f"  {err.code}: {err.message}")

# 3. Check scope coverage independently
scope = parse_scope(result.claims["scope"])
covered, missing = check_scope_coverage(scope, ["notes.read", "admin.delete"])
print(f"All covered: {covered}")  # False
print(f"Missing: {missing}")      # ["admin.delete"]
```

**Notes:**
- `build_jwt` is a test/demo helper. Production tokens are issued by an
  OAuth 2.0 Authorization Server — the SDK validates tokens, it does not
  issue them.
- `validate_token_claims` does NOT short-circuit: a single result can
  report a bad signature, an expired `exp`, and insufficient scope all
  at once. Default clock skew tolerance is ±300 seconds.
- `check_scope_coverage` uses **exact string comparison** — no wildcards.
  `"notes.*"` in the scope does NOT satisfy `"notes.read"`.
- See [Concepts: §4. Capabilities and Authorization](concepts.md#4-capabilities-and-authorization).
- For a complete DPoP flow, see `examples/08_authorization.py`.

---

## Recipe 19 — Parse rate-limit headers and compute delay

**Problem:** You received an HTTP response with rate-limit headers and
need to determine whether to retry and how long to wait.

**Solution:**

```python
import time
from arsia_protocol import (
    parse_rate_limit_headers,
    compute_rate_limited_delay,
    compute_retry_delay,
    resolve_priority,
)

# 1. Parse rate-limit headers from an HTTP response
headers = {
    "X-RateLimit-Limit": "100",
    "X-RateLimit-Remaining": "0",
    "X-RateLimit-Reset": "1747094400",
    "Retry-After": "30",
}

status = parse_rate_limit_headers(headers)
print(f"Limit: {status.limit}, Remaining: {status.remaining}")
print(f"Reset at: {status.reset_at}, Retry-After: {status.retry_after_seconds}")

# 2. Compute delay for a 429 response
delay = compute_rate_limited_delay(retry_after_header=status.retry_after_seconds)
print(f"Rate-limited delay: {delay}s")  # 30.0

# 3. Fall back to exponential backoff when no Retry-After is present
for attempt in range(1, 4):
    backoff = compute_retry_delay(attempt)
    print(f"Attempt {attempt}: backoff {backoff}s")  # 1, 2, 4

# 4. Resolve message priority for dispatch ordering
envelope = {"context": {"priority": 8}}
priority = resolve_priority(envelope)
print(f"Priority: {priority}")  # 8 (from envelope)
priority = resolve_priority(envelope, override=2)
print(f"Override: {priority}")  # 2 (caller override wins)
```

**Notes:**
- The SDK **parses** headers but does not make HTTP requests — transport
  is the consumer's responsibility.
- `parse_rate_limit_headers` is case-insensitive. Missing or malformed
  values are surfaced as `None`, not errors.
- `compute_rate_limited_delay` priority: `Retry-After` header →
  `payload.error.details.retry_after_seconds` → 60s default.
- `resolve_priority` priority: caller override → `context.priority` →
  default 5. Range is 0–10.
- For general retry logic (error codes + retryability), see
  [Recipe 14](#recipe-14-handle-error-envelopes-retry-logic).
- For a complete routing example with topology selection and broker
  discovery, see `examples/06_routing.py`.

---

## Recipe 20 — Wrap an MCP tool call in an ARSIA envelope

**Problem:** You have an MCP `tools/call` JSON-RPC message and need to
add GDPR compliance before it reaches the MCP server.

**Solution:**

```python
from arsia_protocol import (
    create_request,
    apply_profile,
    generate_ed25519_keypair,
    sign_message,
)

private_key, public_key = generate_ed25519_keypair()

# The MCP tool call — a standard JSON-RPC 2.0 object
mcp_tool_call = {
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
        "name": "get_customer_data",
        "arguments": {"customer_id": "C-12345"},
    },
    "id": 1,
}

# Wrap the MCP call in an ARSIA envelope with GDPR compliance
envelope = create_request(
    from_agent="agent:acme.assistant",
    to_agent="agent:acme.crm-service",
    payload_type="arsiaprotocol.mcp/tool-call",
    capabilities=["acme.crm.getCustomerData"],
    args=mcp_tool_call,
    compliance={
        "profile": "GDPR-STANDARD",
        "pii_involved": True,
        "legal_basis": "contract",
        "data_residency": "DE",
        "audit_required": True,
        "retention_days": 90,
    },
)

enriched = apply_profile(envelope)
signed = sign_message(enriched, private_key, "agent:acme.assistant#key-1")

print(f"payload_type: {signed['payload']['type']}")
# arsiaprotocol.mcp/tool-call

print(f"inner MCP method: {signed['payload']['args']['method']}")
# tools/call — the MCP JSON-RPC passes through untouched

print(f"compliance profile: {signed['compliance']['profile']}")
# GDPR-STANDARD
```

**Notes:**
- The SDK never inspects `args` — the MCP JSON-RPC object passes through
  untouched as the payload content (Core §1.3).
- `payload_type` uses the spec convention `arsiaprotocol.mcp/tool-call`
  (Core §1.3). For tool results, use `arsiaprotocol.mcp/tool-result`.
- The `capabilities` field lists *ARSIA* capabilities, not MCP tool names.
  Capabilities use dot-separated alphanumeric segments (e.g.
  `acme.crm.getCustomerData`), not hyphens.
- For the receiver-side unwrap pattern, see
  [Recipe 22](#recipe-22-extract-the-inner-protocol-message-after-verification).
- For a complete MCP + GDPR pipeline, see `examples/09_mcp_compliance.py`.

---

## Recipe 21 — Wrap an A2A task in an ARSIA envelope

**Problem:** You have an A2A `tasks/send` JSON-RPC message and need
to add EU AI Act oversight before the task is delegated.

**Solution:**

```python
from arsia_protocol import (
    create_request,
    apply_profile,
    generate_ed25519_keypair,
    sign_message,
)

private_key, public_key = generate_ed25519_keypair()

# The A2A task — a standard JSON-RPC 2.0 object
a2a_task = {
    "jsonrpc": "2.0",
    "method": "tasks/send",
    "params": {
        "id": "task-resume-screen-001",
        "message": {
            "role": "user",
            "parts": [
                {"type": "text", "text": "Screen 50 resumes for senior engineer role"}
            ],
        },
    },
}

# Wrap the A2A task in an ARSIA envelope with EU AI Act compliance
envelope = create_request(
    from_agent="agent:hiringco.platform",
    to_agent="agent:hiringco.screener",
    payload_type="arsiaprotocol.a2a/task",
    capabilities=["hiringco.recruitment.screen"],
    args=a2a_task,
    compliance={
        "profile": "EU-AI-ACT-HIGH-RISK",
        "ai_system_classification": "high-risk",
        "human_oversight": "required_before_execution",
        "explainability_required": True,
        "audit_required": True,
        "data_residency": "PT",
    },
)

enriched = apply_profile(envelope)
signed = sign_message(enriched, private_key, "agent:hiringco.platform#key-1")

print(f"payload_type: {signed['payload']['type']}")
# arsiaprotocol.a2a/task

print(f"inner A2A method: {signed['payload']['args']['method']}")
# tasks/send — the A2A JSON-RPC passes through untouched

print(f"human_oversight: {signed['compliance']['human_oversight']}")
# required_before_execution

print(f"explainability: {signed['compliance']['explainability_required']}")
# True — responses must include payload.explanation
```

**Notes:**
- `payload_type` uses the spec convention `arsiaprotocol.a2a/task`
  (Core §1.3, Appendix B.2). For task results, use
  `arsiaprotocol.a2a/task-result`.
- The A2A task lifecycle (`submitted` / `working` / `completed`) is
  separate from ARSIA's oversight lifecycle
  (`requested` / `pending_approval` / `executing` / `completed`).
  The ARSIA layer holds the A2A task until human approval is received.
- `EU-AI-ACT-HIGH-RISK` enforces `human_oversight` and
  `explainability_required` by default (ARSIA-Core.md §4.3.6).
- For the receiver-side unwrap pattern, see
  [Recipe 22](#recipe-22-extract-the-inner-protocol-message-after-verification).
- For a complete A2A + EU AI Act pipeline, see `examples/10_a2a_oversight.py`.

---

## Recipe 22 — Extract the inner protocol message after verification

**Problem:** You received a signed ARSIA envelope that wraps an MCP or
A2A message and need to extract the inner protocol message safely.

**Solution:**

```python
from arsia_protocol import (
    create_request,
    apply_profile,
    generate_ed25519_keypair,
    sign_message,
    verify_message,
    validate_envelope,
    validate_compliance,
)

# --- Sender side (for demonstration) ---
private_key, public_key = generate_ed25519_keypair()

mcp_tool_call = {
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {"name": "get_customer_data", "arguments": {"customer_id": "C-12345"}},
    "id": 1,
}

envelope = create_request(
    from_agent="agent:acme.assistant",
    to_agent="agent:acme.crm-service",
    payload_type="arsiaprotocol.mcp/tool-call",
    capabilities=["acme.crm.getCustomerData"],
    args=mcp_tool_call,
    compliance={"profile": "GDPR-STANDARD", "pii_involved": True, "legal_basis": "contract"},
)
signed = sign_message(apply_profile(envelope), private_key, "agent:acme.assistant#key-1")

# --- Receiver side (the middleware pattern) ---

# Step 1: Verify the cryptographic signature
assert verify_message(signed, public_key), "Signature invalid — reject"

# Step 2: Validate envelope structure (L1 schema + L2 semantic)
errors = validate_envelope(signed)
assert not errors, f"Validation failed: {errors}"

# Step 3: Validate regulatory compliance
errors = validate_compliance(signed)
assert not errors, f"Compliance failed: {errors}"

# Step 4: Determine the inner protocol from payload.type
payload_type = signed["payload"]["type"]

if payload_type.startswith("arsiaprotocol.mcp/"):
    inner_message = signed["payload"]["args"]
    print(f"MCP message: method={inner_message['method']}")
    # Forward inner_message to the MCP server

elif payload_type.startswith("arsiaprotocol.a2a/"):
    inner_message = signed["payload"]["args"]
    print(f"A2A message: method={inner_message['method']}")
    # Forward inner_message to the A2A agent

else:
    inner_message = signed["payload"]["args"]
    print(f"Application message: type={payload_type}")
    # Handle as a native ARSIA payload
```

**Notes:**
- Always verify and validate *before* extracting — never process an
  unverified payload. The order is: verify signature, validate structure,
  validate compliance, then extract.
- For requests, the inner message is in `payload["args"]`. For responses,
  it is in `payload["result"]`.
- This is the "unwrap" side of Recipes
  [20](#recipe-20-wrap-an-mcp-tool-call-in-an-arsia-envelope) and
  [21](#recipe-21-wrap-an-a2a-task-in-an-arsia-envelope). Together they
  form the middleware pattern: the ARSIA layer sits between the transport
  and the protocol handler, enforces compliance, then passes the inner
  message to the actual MCP server or A2A agent.
- The MCP/A2A server does not need to understand ARSIA — it receives the
  original JSON-RPC object unchanged (Core §1.3, Appendix B).
- See `examples/09_mcp_compliance.py` (Section 5) for the full
  receiver-side unwrap flow.
