# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Structured validation error — Layer 0 (no SDK imports).

This module exists so that Layer 0 modules (``identity``, ``certificates``)
can use :class:`ValidationError` without importing from ``types/``, which
would create a circular dependency.  ``types.errors`` re-exports this class
so the public API is unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ValidationError:
    """A structured validation error.

    Attributes:
        code: Machine-parseable error identifier matching spec
              detail keys.
        message: Human-readable description including the
                 normative spec reference.
        details: Structured details dict.
        spec_ref: Normative specification reference
                  (e.g. ``"Core §4.3.8 R2"``, ``"State §2.1.10"``).
    """

    code: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    spec_ref: str = ""

    def __str__(self) -> str:
        return self.message
