# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Property-based tests for canonicalization and Ed25519 sign/verify."""

from __future__ import annotations

from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from arsia_protocol.hazmat.canonicalization import canonicalize
from arsia_protocol.hazmat.primitives.ed25519 import (
    generate_keypair,
    sign,
    verify,
)

# JSON-compatible values accepted by ``rfc8785.dumps``:
#  - no NaN / Infinity floats (RFC 8785 rejects them)
#  - finite numeric range to avoid exotic float edge-cases
_json_scalars = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**53 - 1), max_value=2**53 - 1),
    st.floats(allow_nan=False, allow_infinity=False, width=64),
    st.text(max_size=40),
)

_json_values: st.SearchStrategy[Any] = st.recursive(
    _json_scalars,
    lambda children: st.one_of(
        st.lists(children, max_size=5),
        st.dictionaries(st.text(max_size=10), children, max_size=5),
    ),
    max_leaves=20,
)

_json_dicts = st.dictionaries(st.text(max_size=10), _json_values, max_size=5)


@given(obj=_json_dicts)
@settings(max_examples=200)
def test_canonicalize_deterministic_property(obj: dict[str, Any]) -> None:
    """Canonicalization of the same input always produces identical bytes.

    Spec: ARSIA-Core.md §5.1 Step 3.
    """
    assert canonicalize(obj) == canonicalize(obj)


@given(obj=_json_dicts)
@settings(max_examples=200)
def test_canonicalize_key_order_invariant_property(obj: dict[str, Any]) -> None:
    """Canonical bytes are invariant to top-level key insertion order.

    Spec: ARSIA-Core.md §5.1 Step 3.
    """
    reversed_obj = dict(reversed(list(obj.items())))
    assert canonicalize(obj) == canonicalize(reversed_obj)


@given(data=st.binary(max_size=1024))
@settings(max_examples=200)
def test_sign_verify_roundtrip_property(data: bytes) -> None:
    """For any byte string, sign-then-verify with the matching key succeeds.

    Spec: ARSIA-Core.md §5.1-5.2.
    """
    private_key, public_key = generate_keypair()
    signature = sign(private_key, data)
    assert verify(public_key, data, signature) is True
