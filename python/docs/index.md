# ARSIA Protocol SDK — Python API Reference

Reference documentation for every public function, class, and type in the
`arsia_protocol` package, generated from source docstrings.

## Installation

```bash
pip install arsia-protocol
```

## Quick start

```python
from arsia_protocol import (
    create_request,
    sign_message,
    verify_message,
    validate_envelope,
)
```

## Package structure

| Package | Description |
|---------|-------------|
| [`core`](api/core/message.md) | Envelope factory, signing, verification, validation, compliance, encryption |
| [`identity`](api/identity/agent_id.md) | Agent ID parsing, X.509 trust levels, discovery documents, onboarding |
| [`actions`](api/actions.md) | Capability model, oversight, explainability |
| [`routing`](api/routing.md) | Topology selection, broker discovery |
| [`state`](api/state/state.md) | State operations, audit records, breach detection |
| [`assets`](api/assets.md) | Transfer lifecycle, escrow, regulatory helpers |
| [`types`](api/types/envelope.md) | Pydantic v2 models for all protocol objects |
| [`hazmat`](api/hazmat/canonicalization.md) | Low-level cryptographic primitives (Ed25519, JWE, ECDSA, JCS) |
