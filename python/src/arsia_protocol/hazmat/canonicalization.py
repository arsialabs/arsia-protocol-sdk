# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""RFC 8785 (JCS) canonicalization for ARSIA message envelopes.

This module is Layer 0 in the SDK dependency graph: it has no imports
from other ``arsia_protocol`` modules. It exposes the raw JCS primitive
and the envelope-specific helper that strips the ``security`` field
before canonicalizing, as required by the signing procedure.

High-level APIs in ``arsia_protocol.message`` wrap these primitives and
should be preferred over calling them directly.
"""

from __future__ import annotations

import copy
from typing import Any

import rfc8785


def canonicalize(obj: dict[str, Any] | list[Any]) -> bytes:
    """Canonicalize a JSON-serializable value per RFC 8785 (JCS).

    JCS produces a deterministic UTF-8 byte sequence from any JSON value,
    guaranteeing that semantically identical messages produce identical
    signing inputs regardless of field ordering, whitespace, or numeric
    representation differences in the original serialization.

    Args:
        obj: A JSON-serializable object (dict or list).

    Returns:
        The canonical UTF-8 encoded byte sequence.

    Spec: ARSIA-Core.md §5.1 Step 3.
    """
    return rfc8785.dumps(obj)


def canonicalize_envelope_for_signing(envelope: dict[str, Any]) -> bytes:
    """Produce the signing input for an ARSIA message envelope.

    Follows the normative signing procedure:

    1. Deep-copy the envelope so the original is not mutated.
    2. Remove the entire ``security`` field from the copy (no-op if
       absent). The ``security`` field is excluded from the signing input
       because it will eventually contain the signature itself.
    3. Canonicalize the remaining object per RFC 8785.

    Args:
        envelope: The complete ARSIA message envelope as a dict.

    Returns:
        The canonical UTF-8 encoded byte sequence ready for Ed25519
        signing.

    Spec: ARSIA-Core.md §5.1 Steps 1-3.
    """
    clone = copy.deepcopy(envelope)
    clone.pop("security", None)
    return canonicalize(clone)


__all__ = [
    "canonicalize",
    "canonicalize_envelope_for_signing",
]
