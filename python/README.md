# arsia-protocol — Python SDK

[![PyPI](https://img.shields.io/pypi/v/arsia-protocol)](https://pypi.org/project/arsia-protocol/)
[![Python](https://img.shields.io/pypi/pyversions/arsia-protocol)](https://pypi.org/project/arsia-protocol/)
[![License](https://img.shields.io/badge/license-BSL_1.1-blue)](https://github.com/arsialabs/arsia-protocol-sdk/blob/main/LICENSE.md)
[![Typed](https://img.shields.io/badge/typed-mypy%20%7C%20pyright-brightgreen)](https://github.com/arsialabs/arsia-protocol-sdk)

**The trust layer for AI agents.** Make any agent enterprise-ready — compliant,
secure, and auditable out of the box.

Python SDK for the [ARSIA Protocol](https://github.com/arsialabs/arsia-protocol):
the compliance-enforced communication layer for AI agents. Build, sign, verify,
and validate ARSIA message envelopes over any transport — HTTP, WebSocket, gRPC,
MCP, A2A, or your own.

Fully typed — works with mypy, pyright, and IDE autocompletion out of the box.

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

## `arsia` CLI

```bash
pip install "arsia-protocol[cli]"

arsia keygen --kid agent:acme.bot#k1        # generate Ed25519 key material
arsia verify envelope.json --jwk sender.jwk # verify a signed envelope
arsia canonicalize doc.json                 # emit RFC 8785 canonical bytes
arsia inspect envelope.json                 # pretty-print with diagnostics
arsia schemas                               # list bundled JSON Schemas
arsia vectors                               # list bundled test vectors
arsia profiles GDPR-STANDARD                # print a compliance profile
```

## What the SDK does NOT do

- **Transport** (HTTP, WebSocket, MCP, A2A) — that's `arsiactl`, not the SDK.
- **Agent execution**, planning, tool use — that's the agent framework.
- **Audit trail storage** — the SDK builds audit records; it does not persist them.
- **OAuth2 issuance** — the SDK validates tokens, does not issue them.
- **Payload interpretation** — the SDK signs and verifies envelopes; it never inspects payload content beyond routing-relevant fields.

## Documentation

| Resource | Description |
|----------|-------------|
| [Learning Path](https://github.com/arsialabs/arsia-protocol-sdk/blob/main/python/docs/learning-path.md) | Step-by-step guide from install to production |
| [Concepts](https://github.com/arsialabs/arsia-protocol-sdk/blob/main/python/docs/concepts.md) | Mental model: envelopes, lifecycle, naming, profiles |
| [Cookbook](https://github.com/arsialabs/arsia-protocol-sdk/blob/main/python/docs/cookbook.md) | 22 copy-pasteable recipes for common tasks |
| [Examples](https://github.com/arsialabs/arsia-protocol-sdk/tree/main/python/examples) | 14 runnable scripts (10 basic + 4 regulated use cases) |
| [API Reference](https://github.com/arsialabs/arsia-protocol-sdk/tree/main/python/docs/api) | Full API documentation (run `mkdocs serve`) |
| [Demos](https://github.com/arsialabs/arsia-protocol-sdk/tree/main/demos) | Production-realistic multi-agent scenarios — run any of them in under a minute |

## Development

```bash
cd python
pip install -e ".[dev]"
pytest tests/ -v
mypy src/arsia_protocol/
ruff check src/
ruff format src/
```

## Links

- **Specification:** <https://github.com/arsialabs/arsia-protocol>
- **Repository:** <https://github.com/arsialabs/arsia-protocol-sdk>
- **Website:** <https://arsiaprotocol.org>
- **Issues:** <https://github.com/arsialabs/arsia-protocol-sdk/issues>
- **Changelog:** [CHANGELOG.md](https://github.com/arsialabs/arsia-protocol-sdk/blob/main/CHANGELOG.md)

---

ARSIA Protocol ([arsiaprotocol.org](https://arsiaprotocol.org)) ·
by [Arsia Labs](https://arsialabs.ai) · BSL 1.1
