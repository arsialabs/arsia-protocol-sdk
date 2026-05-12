# ARSIA Protocol — Reference SDKs

Reference implementations of the [ARSIA Protocol](https://github.com/arsialabs/arsia-protocol):
the compliance-enforced communication layer for autonomous AI agents.
The SDKs build, sign, verify, and validate ARSIA message envelopes.
Transport-agnostic. Licensed under BSL 1.1 (SDK) and Apache 2.0 (shared artifacts).

## Quickstart (Python)

```bash
pip install arsia-protocol
```

```python
from arsia_protocol import (
    create_request, generate_ed25519_keypair, sign_message,
    verify_message, validate_schema, validate_semantic,
)

# 1. Generate an Ed25519 keypair.
priv, pub = generate_ed25519_keypair()
kid = "agent:acme.bot#k1"

# 2. Build and sign a request envelope.
envelope = create_request(
    from_agent="agent:acme.bot",
    to_agent="agent:other.svc",
    payload_type="com.arsiaprotocol.echo",
    capabilities=["com.arsiaprotocol.echo"],
    args={"msg": "hello"},
)
signed = sign_message(envelope, priv, kid)

# 3. Verify the signature (cryptographic check).
assert verify_message(signed, pub) is True

# 4. Validate envelope structure and semantics.
assert validate_schema(signed) == []
assert validate_semantic(signed) == []
```

See [python/](python/) for the full module map, CLI usage, and development setup.
For a guided introduction, start with the [Learning Path](python/docs/learning-path.md).

## Demos

End-to-end demonstrations of the ARSIA Protocol in realistic scenarios.
Each demo is self-contained with its own README, Docker setup, and run script.

| Demo | Description |
|------|-------------|
| [**Fintech Trade**](demos/fintech-trade/) | 3 autonomous AI agents execute a MiFID-II regulated securities trade — suitability assessment, human-in-the-loop oversight, order execution, full audit trail. Structural data isolation ensures each agent sees only what it needs. |

Run the fintech demo in under a minute:

```bash
cd demos/fintech-trade && ./run.sh
```

## Documentation

| Resource | Description |
|----------|-------------|
| [Learning Path](python/docs/learning-path.md) | Step-by-step guide from install to production |
| [Concepts](python/docs/concepts.md) | Mental model: envelopes, lifecycle, naming, profiles |
| [Cookbook](python/docs/cookbook.md) | 22 copy-pasteable recipes for common tasks |
| [Examples](python/examples/) | 14 runnable scripts (10 basic + 4 regulated use cases) |
| [API Reference](python/docs/api/) | Full API documentation (mkdocs) |

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

## Python SDK

```bash
pip install arsia-protocol
```

See [python/](python/) for full documentation.

## Conformance

The conformance runner validates any ARSIA implementation against the specification.

See [conformance/](conformance/) for usage.

## Links

- [Protocol Specification](https://github.com/arsialabs/arsia-protocol)
- [Website](https://arsiaprotocol.org)

## License

Licensed under BSL 1.1 (SDK code) and Apache 2.0 (shared protocol artifacts).
See [LICENSE.md](LICENSE.md) for details.

---

ARSIA Protocol ([arsiaprotocol.org](https://arsiaprotocol.org)) | by [Arsia Labs](https://arsialabs.ai)
