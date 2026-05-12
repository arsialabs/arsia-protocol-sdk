# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Unit tests for ``arsia_protocol.hazmat.canonicalization``."""

from __future__ import annotations

from arsia_protocol.hazmat.canonicalization import (
    canonicalize,
    canonicalize_envelope_for_signing,
)


def test_canonicalize_simple_object() -> None:
    """Object keys are emitted in lexicographic order.

    Spec: ARSIA-Core.md §5.1 Step 3.
    """
    assert canonicalize({"b": 2, "a": 1}) == b'{"a":1,"b":2}'


def test_canonicalize_nested_objects() -> None:
    """Nested dicts and arrays canonicalize recursively.

    Spec: ARSIA-Core.md §5.1 Step 3.
    """
    obj = {"outer": {"z": [3, 2, 1], "a": True}, "first": 0}
    assert canonicalize(obj) == b'{"first":0,"outer":{"a":true,"z":[3,2,1]}}'


def test_canonicalize_unicode() -> None:
    """Unicode strings are preserved per RFC 8785 §3.2.2.

    Spec: ARSIA-Core.md §5.1 Step 3.
    """
    result = canonicalize({"greeting": "olá", "emoji": "🔐"})
    # RFC 8785 emits unicode code points directly (no \uXXXX escapes for
    # characters above U+001F that are not " or \).
    assert "olá".encode() in result
    assert "🔐".encode() in result


def test_canonicalize_numbers_integer() -> None:
    """Integers serialize without decimal point.

    Spec: ARSIA-Core.md §5.1 Step 3.
    """
    assert canonicalize({"n": 42}) == b'{"n":42}'


def test_canonicalize_numbers_float() -> None:
    """Floats use the shortest ECMAScript form per RFC 8785.

    Spec: ARSIA-Core.md §5.1 Step 3.
    """
    # 1.5 is exactly representable and emits as "1.5".
    assert canonicalize({"n": 1.5}) == b'{"n":1.5}'


def test_canonicalize_empty_object() -> None:
    """An empty object canonicalizes to ``{}``.

    Spec: ARSIA-Core.md §5.1 Step 3.
    """
    assert canonicalize({}) == b"{}"


def test_canonicalize_empty_array() -> None:
    """An empty array canonicalizes to ``[]``.

    Spec: ARSIA-Core.md §5.1 Step 3.
    """
    assert canonicalize([]) == b"[]"


def test_canonicalize_null_value() -> None:
    """``None`` serializes as JSON ``null``.

    Spec: ARSIA-Core.md §5.1 Step 3.
    """
    assert canonicalize({"x": None}) == b'{"x":null}'


def test_canonicalize_boolean_values() -> None:
    """Booleans serialize as ``true``/``false``.

    Spec: ARSIA-Core.md §5.1 Step 3.
    """
    assert canonicalize({"t": True, "f": False}) == b'{"f":false,"t":true}'


def test_canonicalize_deterministic() -> None:
    """Canonicalization is deterministic across invocations.

    Spec: ARSIA-Core.md §5.1 Step 3.
    """
    obj = {"z": 1, "a": 2, "m": [3, {"b": 4, "a": 5}]}
    assert canonicalize(obj) == canonicalize(obj)


def test_canonicalize_envelope_strips_security() -> None:
    """Canonicalization removes the entire security object before signing.

    Spec: ARSIA-Core.md §5.1 Step 2.
    """
    envelope = {
        "msg_id": "abc",
        "from": "agent:acme.echo-client",
        "security": {
            "alg": "EdDSA",
            "kid": "agent:acme.echo-client#key1",
            "sig": "should-be-removed",
        },
    }
    result = canonicalize_envelope_for_signing(envelope)
    assert b"security" not in result
    assert b"should-be-removed" not in result


def test_canonicalize_envelope_preserves_other_fields() -> None:
    """All non-security fields remain in the canonical output.

    Spec: ARSIA-Core.md §5.1 Step 2.
    """
    envelope = {
        "msg_id": "abc",
        "from": "agent:acme.echo-client",
        "to": "agent:arsialabs.demo.risk-assessor",
        "security": {"alg": "EdDSA", "kid": "x#key1", "sig": "deadbeef"},
    }
    result = canonicalize_envelope_for_signing(envelope)
    assert b'"msg_id":"abc"' in result
    assert b'"from":"agent:acme.echo-client"' in result
    assert b'"to":"agent:arsialabs.demo.risk-assessor"' in result


def test_canonicalize_envelope_deep_copies() -> None:
    """The original envelope is not mutated by canonicalization.

    Spec: ARSIA-Core.md §5.1 Step 1.
    """
    envelope = {
        "msg_id": "abc",
        "security": {"alg": "EdDSA", "kid": "x#k", "sig": "s"},
        "nested": {"list": [1, 2, 3]},
    }
    original_security = envelope["security"]
    canonicalize_envelope_for_signing(envelope)
    assert envelope["security"] is original_security
    assert envelope["nested"] == {"list": [1, 2, 3]}


def test_canonicalize_envelope_without_security() -> None:
    """Stripping security is a no-op if the field is absent.

    Spec: ARSIA-Core.md §5.1 Step 2.
    """
    envelope = {"msg_id": "abc", "from": "agent:acme.echo-client"}
    result = canonicalize_envelope_for_signing(envelope)
    assert result == b'{"from":"agent:acme.echo-client","msg_id":"abc"}'
