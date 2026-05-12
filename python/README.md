# arsia-protocol — Python SDK

Reference Python implementation of the
[ARSIA Protocol](https://arsiaprotocol.org): the compliance-enforced
communication layer for autonomous AI agents. The SDK builds, signs,
verifies, and validates ARSIA message envelopes. It is
**transport-agnostic** — you choose HTTP, WebSocket, gRPC, MCP, A2A,
stdio, or anything else.

- **License:** BSL 1.1
- **Python:** ≥ 3.12
- **Status:** `1.0.0`
- **Specification:** <https://github.com/arsialabs/arsia-protocol>

## Install

```bash
pip install arsia-protocol                # core SDK
pip install "arsia-protocol[cli]"         # plus the `arsia` CLI
pip install "arsia-protocol[dev]"         # development (tests, mypy, ruff)
```

## Quickstart

```python
from arsia_protocol import (
    create_request, generate_ed25519_keypair, sign_message, verify_message,
)

# 1. Generate an Ed25519 keypair (developer convenience — use an HSM / KMS
#    in production).
priv, pub = generate_ed25519_keypair()
kid = "agent:acme.bot#k1"

# 2. Build a signed request envelope.
envelope = create_request(
    from_agent="agent:acme.bot",
    to_agent="agent:other.svc",
    payload_type="com.arsiaprotocol.echo",
    capabilities=["com.arsiaprotocol.echo"],
    args={"msg": "hello"},
)
signed = sign_message(envelope, priv, kid)

# 3. On the recipient side — verify the signature.
assert verify_message(signed, pub) is True
```

### Validate against schema + semantics

```python
from arsia_protocol import validate_schema, validate_semantic

l1_errors = validate_schema(signed)       # L1: JSON Schema (Draft 2020-12)
l2_errors = validate_semantic(signed)     # L2: timestamps, kid match, etc.
assert l1_errors == [] and l2_errors == []
```

### Apply a compliance profile

```python
from arsia_protocol import apply_profile

# The envelope must declare compliance.profile — apply_profile reads it
# from there and inherits the profile's defaults (retention, jurisdiction, …).
envelope["compliance"] = {"profile": "GDPR-STANDARD"}
enriched = apply_profile(envelope)         # strict=False by default
```

## Documentation

| Resource | Description |
|----------|-------------|
| [Learning Path](docs/learning-path.md) | Step-by-step guide from install to production |
| [Concepts](docs/concepts.md) | Mental model: envelopes, lifecycle, naming, profiles |
| [Cookbook](docs/cookbook.md) | 22 copy-pasteable recipes for common tasks |
| [Examples](examples/) | 14 runnable scripts (10 basic + 4 regulated use cases) |
| [API Reference](docs/api/) | Full API documentation (run `mkdocs serve`) |

## Key Concepts

### verify vs. validate

| Function | What it checks | Question it answers |
|----------|---------------|---------------------|
| `verify_message(envelope, pub_key)` | Ed25519/ES256 signature | "Was this signed by the claimed sender?" |
| `validate_schema(envelope)` | JSON Schema (Draft 2020-12) | "Does this match the ARSIA envelope structure?" |
| `validate_semantic(envelope)` | Cross-field rules (timestamps, kid prefix, capabilities) | "Is this envelope internally consistent?" |
| `validate_envelope(envelope)` | Both schema + semantic (convenience) | "Is this well-formed and consistent?" |

A typical receiver calls both: `verify_message()` to trust the sender, then
`validate_envelope()` to trust the content.

### build_* vs. create_* naming

- **`create_*`** (7 functions) — envelope-level factories that produce a
  complete, signable ARSIA envelope: `create_request`, `create_response`,
  `create_error`, `create_event`, `create_pending_approval`,
  `create_approval_decision`, `create_rollback_request`.

- **`build_*`** (49 functions) — sub-component builders that produce parts of
  envelopes: audit records, error details, JWKs, state operation arguments,
  discovery documents, etc.

Rule of thumb: if it returns a complete envelope ready to sign, it's `create_*`.
If it returns a component or record, it's `build_*`.

## `arsia` command-line tool

Installed with the `cli` extra.

```bash
arsia --version
arsia keygen --kid agent:acme.bot#k1        # generate Ed25519 key material
arsia verify envelope.json --jwk sender.jwk # verify a signed envelope
arsia canonicalize doc.json                 # emit RFC 8785 canonical bytes
arsia inspect envelope.json                 # pretty-print with diagnostics
arsia schemas                               # list bundled JSON Schemas
arsia vectors                               # list bundled test vectors
arsia profiles GDPR-STANDARD                # print a compliance profile
```

The CLI is a thin operator-ergonomics wrapper around the public SDK API.
It is not a configuration surface for production agents — import the
SDK directly.

## Module map

| Module | Layer | Purpose |
|--------|-------|---------|
| `hazmat.canonicalization` | 0 | RFC 8785 JCS (use `rfc8785`; never `json.dumps(sort_keys=True)`) |
| `hazmat.primitives.ed25519` | 0 | Raw Ed25519 sign / verify / JWK helpers |
| `version`, `identity` | 0 | Semver parsing, `agent:org.name` validation |
| `types` | 1 | Pydantic v2 envelope / payload / audit models |
| `message` | 2 | Envelope factories (`create_request`, …), `sign_message`, `verify_message` |
| `errors` | 2 | Error-code registry, retry policy, error-envelope builders |
| `compliance` | 2 | Profile loading (GDPR, EU AI Act, MiFID II, DORA, …), retention floor |
| `validation` | 3 | L1 schema + L2 semantic validation |
| `actions` | 4 | Capability model, reserved prefixes, oversight, explainability |
| `state` | 4 | State operations, scope taxonomy, GDPR retention |
| `assets` | 4 | Transfer lifecycle, escrow, MiFID II, DORA, PSD2 SCA |
| `routing` | 4 | Topology determination, broker discovery, retry / lifecycle |
| `discovery` | 4 | Discovery document + JWKS builders |
| `authorization` | 4 | JWT + DPoP, scope coverage, JWK thumbprint |
| `certificates` | 4 | X.509 trust levels L1 / L2 / L3 |
| `onboarding` | 4 | External agent onboarding flow |
| `audit` | 5 | Audit record builders, payload hash, immutability |
| `idempotency` | 5 | Store protocol, duplicate detection, scope helpers |
| `__main__` | 6 | `arsia` CLI (optional dep) |

Primitive modules never import transport libraries (`httpx`, `fastapi`,
`websockets`). Boundary rules are enforced by
`tests/unit/test_module_boundaries.py`.

## What the SDK does NOT do

- Transport (HTTP, WebSocket, MCP, A2A) — that's
  `arsiactl`, not the SDK.
- Agent execution, planning, tool use — that's the agent framework.
- Audit trail storage — that's the server (`arsiactl`). The SDK
  builds audit records; it does not persist them.
- OAuth2 issuance — the SDK validates tokens, does not issue them.
- Payload interpretation — the SDK signs and verifies envelopes; it
  never inspects payload content beyond routing-relevant fields.

## Development

```bash
cd python
pip install -e ".[dev]"
pytest tests/ -v
mypy src/arsia_protocol/
ruff check src/
ruff format src/
python -m build
```

Cross-language conformance lives at
`../conformance/runners/python/` and is installed separately:

```bash
cd ../conformance/runners/python
pip install -e .
python -m arsia_conformance
```

## Links

- **Specification:** <https://github.com/arsialabs/arsia-protocol>
- **SDKs repo:** <https://github.com/arsialabs/arsia-protocol-sdk>
- **Website:** <https://arsiaprotocol.org>
- **Issues:** <https://github.com/arsialabs/arsia-protocol-sdk/issues>
- **Changelog:** [`CHANGELOG.md`](../CHANGELOG.md)

---

ARSIA Protocol ([arsiaprotocol.org](https://arsiaprotocol.org)) ·
by [Arsia Labs](https://arsialabs.ai) · BSL 1.1
