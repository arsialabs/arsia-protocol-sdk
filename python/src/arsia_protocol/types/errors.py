# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""ARSIA error types — wire-level and SDK-side.

Wire-level:
    :class:`ArsiaError` mirrors the ``payload.error`` object defined in
    ARSIA-Core.md §4.4.6.  Standard error codes are enumerated in §11.2.

SDK-side:
    :class:`ValidationError` is the single structured error type returned
    by every ``validate_*`` function in the SDK.  Each instance carries a
    machine-parseable ``code`` that maps directly to the spec's required
    error detail keys (Core §11.2).
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from arsia_protocol._errors import ValidationError

ArsiaErrorCode = Literal[
    "invalid_request",
    "unauthorized",
    "forbidden",
    "not_found",
    "conflict",
    "payload_too_large",
    "rate_limited",
    "internal_error",
    "not_implemented",
    "service_unavailable",
    "certificate_invalid",
    "certificate_expired",
    "key_mismatch",
    "certificate_revoked",
]
"""Standard ARSIA error codes.

Includes the ten Core codes (Core §11.2) and the four certificate
error codes added by ARSIA-Identity.md §6.4.3.
"""


class ArsiaError(BaseModel):
    """Structured error object embedded in ``payload.error``.

    Spec: ARSIA-Core.md §4.4.6 and §11.2.
    """

    model_config = ConfigDict(extra="forbid")

    code: ArsiaErrorCode = Field(
        description="One of the standard ARSIA error codes (Core §11.2)."
    )
    description: str = Field(
        description=(
            "Human-readable description. MUST NOT contain stack traces, "
            "database queries, or credentials (Core §4.4.6)."
        ),
    )
    details: dict[str, Any] | None = Field(
        default=None,
        description="Optional structured context. Shape depends on code (Core §11.2).",
    )


__all__ = [
    "ArsiaErrorCode",
    "ArsiaError",
    "ValidationError",
]
