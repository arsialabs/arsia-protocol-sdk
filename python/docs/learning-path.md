# ARSIA Protocol SDK — Learning Path

A progressive guide for developers who just installed the SDK and want to
reach production confidence. Follow the levels in order for a structured
journey, or jump to the level you need — each one lists its prerequisites.

## Legend

- 📖 **READ** — read this document or section
- ▶️ **RUN** — execute this script and read the output
- 🔍 **STUDY** — read the script carefully, understand the design pattern
- ⏱️ — estimated time for the level
- **Prereqs** — which levels you should complete first

All file paths are relative to the `python/` directory.

---

## Level 0 — Install ⏱️ 2 min

**What you'll learn:** How to install the SDK and verify it works.

- 📖 READ the project README, section "Install"

```bash
pip install arsia-protocol
python -c "from arsia_protocol import create_request; print('OK')"
```

**After this level, you can:** import the SDK and confirm your environment
is set up.

**Prereqs:** Python ≥ 3.12

---

## Level 1 — Your first envelope ⏱️ 5 min

**What you'll learn:** The golden path — generate a keypair, build a
request envelope, sign it, verify the signature, and validate the
structure.

- ▶️ RUN `examples/01_sign_verify_validate.py`
- 📖 READ the project README, section "Quickstart"

**After this level, you can:** create, sign, verify, and validate an
ARSIA envelope end-to-end.

**Prereqs:** Level 0

---

## Level 2 — The mental model ⏱️ 15 min

**What you'll learn:** The envelope lifecycle (stages every message passes
through), the 7 envelope factories, and why `build_*` and `create_*` are
different naming conventions.

- 📖 READ [Concepts §1 — Envelope Lifecycle](concepts.md#1-envelope-lifecycle)
- 📖 READ [Concepts §2 — Naming Conventions](concepts.md#2-naming-conventions)
- 📖 READ the project README, section "Key Concepts" — the
  `verify` vs. `validate` and `build_*` vs. `create_*` tables

**After this level, you can:** choose the right factory for any message
type and explain the difference between verification and validation.

**Prereqs:** Level 1

---

## Level 3 — Validating incoming messages ⏱️ 10 min

**What you'll learn:** The two validation layers (L1 schema, L2 semantic),
how to validate a received message, cross-check identity fields, and
verify request/response correlation.

- 📖 READ [Concepts §8 — Validation Layers](concepts.md#8-validation-layers)
- ▶️ RUN [Cookbook Recipe 1 — Validate a received message](cookbook.md#recipe-1-validate-a-received-message)
- ▶️ RUN [Cookbook Recipe 2 — Cross-check identity consistency](cookbook.md#recipe-2-cross-check-identity-consistency)
- ▶️ RUN [Cookbook Recipe 3 — Validate correlation between request and response](cookbook.md#recipe-3-validate-correlation-between-request-and-response)

**After this level, you can:** properly validate any received envelope
using `verify_message()` → `validate_schema()` → `validate_semantic()`.

**Prereqs:** Level 2

---

## Level 4 — Compliance profiles ⏱️ 10 min

**What you'll learn:** The 7 compliance profiles (GDPR, HIPAA, MiFID II,
DORA, PSD2, EU AI Act, SOC2), how `apply_profile()` inherits defaults,
and the priority chain for field resolution.

- ▶️ RUN `examples/02_compliance_profiles.py`
- 📖 READ [Concepts §3 — Compliance Profiles](concepts.md#3-compliance-profiles)
- ▶️ RUN [Cookbook Recipe 4 — Send a message with GDPR compliance](cookbook.md#recipe-4-send-a-message-with-gdpr-compliance)

**After this level, you can:** apply any compliance profile to an envelope
and understand which fields are inherited and why.

**Prereqs:** Level 2

---

## Level 5 — Error handling ⏱️ 10 min

**What you'll learn:** The 14 standard error codes, how to build
spec-compliant error envelopes, the error registry, and retry policies.

- ▶️ RUN `examples/03_error_handling.py`
- 📖 READ [Concepts §9 — Error Model](concepts.md#9-error-model)
- ▶️ RUN [Cookbook Recipe 14 — Handle error envelopes (retry logic)](cookbook.md#recipe-14-handle-error-envelopes-retry-logic)

**After this level, you can:** build error envelopes with correct codes
and implement retry logic based on the error registry.

**Prereqs:** Level 3

---

## Level 6 — Capabilities and authorization ⏱️ 10 min

**What you'll learn:** How the capability model works — matching rules,
reserved prefixes, denial flow, and graceful downgrade.

- 📖 READ [Concepts §4 — Capabilities and Authorization](concepts.md#4-capabilities-and-authorization)
- ▶️ RUN [Cookbook Recipe 5 — Handle capability denial](cookbook.md#recipe-5-handle-capability-denial)
- ▶️ RUN [Cookbook Recipe 6 — Downgrade capabilities](cookbook.md#recipe-6-downgrade-capabilities)
- 🔍 STUDY `examples/08_authorization.py` — JWT/DPoP token validation and scope coverage
- ▶️ RUN [Cookbook Recipe 18 — Validate JWT claims and build a token](cookbook.md#recipe-18-validate-jwt-claims-and-build-a-token)

**After this level, you can:** match capabilities against agent
permissions, deny unauthorized requests, downgrade gracefully, and
validate JWT/DPoP tokens for scope coverage.

**Prereqs:** Level 2

---

## Level 7 — Human oversight ⏱️ 10 min

**What you'll learn:** The full oversight lifecycle — risk classification,
`pending_approval` envelopes, `approval_decision` envelopes, state
transitions, and timeout checking.

- ▶️ RUN `examples/04_oversight_flow.py`
- 📖 READ [Concepts §5 — Human Oversight](concepts.md#5-human-oversight)
- ▶️ RUN [Cookbook Recipe 7 — Implement human oversight (pre-execution)](cookbook.md#recipe-7-implement-human-oversight-pre-execution)
- ▶️ RUN [Cookbook Recipe 8 — Implement human oversight (post-execution)](cookbook.md#recipe-8-implement-human-oversight-post-execution)

**After this level, you can:** implement both pre-execution and
post-execution human-in-the-loop approval flows.

**Prereqs:** Level 6

---

## Level 8 — State operations and audit records ⏱️ 15 min

**What you'll learn:** How to build SET/GET/DELETE/QUERY state operation
payloads with PII classification, data residency, and retention rules.
How audit records work — what goes in them, who stores them, and how
retention is enforced.

- ▶️ RUN `examples/05_state_operations.py`
- 📖 READ [Concepts §6 — Audit Records](concepts.md#6-audit-records)
- ▶️ RUN [Cookbook Recipe 9 — Build audit records with correct retention](cookbook.md#recipe-9-build-audit-records-with-correct-retention)

**After this level, you can:** build state operations with correct scope
and PII flags, and construct audit records that meet retention
requirements.

**Prereqs:** Level 4

---

## Level 9 — Routing, escrow, and breach ⏱️ 15 min

**What you'll learn:** How the SDK handles message routing (topology
selection, broker discovery), asset transfers with escrow, and breach
notification workflows.

- 🔍 STUDY `examples/06_routing.py` — topology selection and broker discovery
- ▶️ RUN [Cookbook Recipe 19 — Parse rate-limit headers and compute delay](cookbook.md#recipe-19-parse-rate-limit-headers-and-compute-delay)
- 🔍 STUDY `examples/07_escrow.py` — escrow lifecycle, hold/release/dispute
- ▶️ RUN [Cookbook Recipe 17 — Build a breach notification](cookbook.md#recipe-17-build-a-breach-notification)

**After this level, you can:** select routing topologies, work with
escrow-backed asset transfers, and construct GDPR Article 33 breach
notifications.

**Prereqs:** Level 8

---

## Level 10 — Production hardening ⏱️ 15 min

**What you'll learn:** Key rotation with overlap periods, payload
encryption (JWE), and idempotency stores for duplicate detection. These
are the extension points where you plug in production infrastructure.

- ▶️ RUN [Cookbook Recipe 10 — Key rotation with overlap period](cookbook.md#recipe-10-key-rotation-with-overlap-period)
- ▶️ RUN [Cookbook Recipe 11 — Encrypt a payload (JWE)](cookbook.md#recipe-11-encrypt-a-payload-jwe)
- ▶️ RUN [Cookbook Recipe 16 — Use idempotency](cookbook.md#recipe-16-use-idempotency)
- 📖 READ [Concepts §7 — Extension Points](concepts.md#7-extension-points-protocol-classes)

**After this level, you can:** rotate keys safely, encrypt payloads for
transit, and implement idempotent message handling.

**Prereqs:** Level 8

---

## Level 11 — Discovery and identity ⏱️ 10 min

**What you'll learn:** How to build discovery documents and JWKS so other
agents can find and authenticate yours. The 6-phase onboarding flow for
external agents.

- ▶️ RUN [Cookbook Recipe 12 — Build a discovery document](cookbook.md#recipe-12-build-a-discovery-document)
- ▶️ RUN [Cookbook Recipe 13 — Build an encryption JWKS](cookbook.md#recipe-13-build-an-encryption-jwks)
- 📖 READ [API reference — Discovery](api/identity/discovery.md)
- 📖 READ [API reference — Onboarding](api/identity/onboarding.md)

**After this level, you can:** publish your agent's discovery document and
JWKS, and onboard external agents into your system.

**Prereqs:** Level 6

---

## Level 12 — Regulated multi-agent pipelines ⏱️ 30+ min

**What you'll learn:** How all the primitives come together in real-world
regulated pipelines. Each use case demonstrates multi-agent data
isolation enforced at the protocol level — not by application logic.

- 🔍 STUDY `examples/use-cases/healthcare_pii_pipeline.py` — HIPAA-compliant clinical lab processing with PII isolation across 3 agents
- 🔍 STUDY `examples/use-cases/fintech_trade_pipeline.py` — MiFID II-compliant €200K investment trade with strict data partitioning
- 🔍 STUDY `examples/use-cases/recruitment_bias_pipeline.py` — EU AI Act-compliant recruitment screening with iterative bias detection
- 🔍 STUDY `examples/use-cases/agriculture_subsidy_pipeline.py` — EU PAC subsidy pipeline with penalty enforcement and fraud prevention
- ▶️ RUN [Cookbook Recipe 15 — Validate EU AI Act responses](cookbook.md#recipe-15-validate-eu-ai-act-responses)

**After this level, you can:** design multi-agent pipelines that enforce
regulatory compliance (MiFID II, GDPR/HIPAA, EU AI Act, EU PAC) through
the protocol rather than through trust in application code.

**Prereqs:** Level 7 + Level 9

---

## Level 13 — ARSIA as a compliance layer for MCP and A2A ⏱️ 15 min

**What you'll learn:** How ARSIA wraps MCP tool calls and A2A tasks
with compliance, identity, and audit — without modifying the underlying
protocols.

- 📖 READ [Cookbook Recipe 20 — Wrap an MCP tool call in an ARSIA envelope](cookbook.md#recipe-20-wrap-an-mcp-tool-call-in-an-arsia-envelope)
- 📖 READ [Cookbook Recipe 21 — Wrap an A2A task in an ARSIA envelope](cookbook.md#recipe-21-wrap-an-a2a-task-in-an-arsia-envelope)
- ▶️ RUN `examples/09_mcp_compliance.py` — full MCP + GDPR pipeline
- ▶️ RUN `examples/10_a2a_oversight.py` — full A2A + EU AI Act pipeline
- 📖 READ [Cookbook Recipe 22 — Extract the inner protocol message after verification](cookbook.md#recipe-22-extract-the-inner-protocol-message-after-verification)

**After this level, you can:** wrap any MCP or A2A message in a signed,
compliant ARSIA envelope and implement the middleware pattern that
verifies compliance before forwarding to the underlying protocol.

**Prereqs:** Level 4 (compliance), Level 7 (oversight)

---

## Quick reference

| Need | Where to look |
|------|---------------|
| Look up any function signature | [API reference](index.md) or run `mkdocs serve` from `python/` |
| CLI help | `arsia --help` (requires `pip install "arsia-protocol[cli]"`) |
| Run conformance tests | `cd conformance/runners/python && pip install -e . && python -m arsia_conformance` |
| Module map | See the project README, section "Module map" |
| What the SDK does NOT do | See the project README, section "What the SDK does NOT do", and [Concepts §10](concepts.md#10-sdk-boundary) |
| Report issues | [github.com/arsialabs/arsia-protocol-sdk/issues](https://github.com/arsialabs/arsia-protocol-sdk/issues) |

---

ARSIA Protocol ([arsiaprotocol.org](https://arsiaprotocol.org)) ·
by [Arsia Labs](https://arsialabs.ai) ·
[BSL 1.1](https://github.com/arsialabs/arsia-protocol-sdk/blob/main/LICENSE.md) — production use permitted; converts to MPL-2.0 after four years
