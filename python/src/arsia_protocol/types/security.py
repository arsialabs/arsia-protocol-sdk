# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Pydantic model for the ARSIA ``security`` envelope field.

Mirrors the ``security`` sub-schema inside
``shared/schemas/arsia-message.schema.json`` and the normative
definition in ARSIA-Core.md §4.3.5.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

SignatureAlgorithm = Literal["EdDSA", "ES256", "RS256"]
"""Signature algorithms listed in ARSIA-Core.md §4.3.5. ``EdDSA`` is the
primary algorithm and the only one conformant SDKs MUST support."""


class ArsiaSecurity(BaseModel):
    """Signature and optional encryption metadata for an ARSIA message.

    Spec: ARSIA-Core.md §4.3.5.
    """

    model_config = ConfigDict(extra="forbid")

    alg: SignatureAlgorithm = Field(description="Signature algorithm (Core §4.3.5).")
    kid: str = Field(description="Key identifier matching a JWK (Core §4.3.5).")
    sig: str = Field(
        description="base64url-encoded signature, no padding (Core §5.1 Step 5)."
    )
    encrypted: bool | None = Field(
        default=None,
        description="Whether the payload is encrypted. Defaults to false.",
    )
    enc_alg: str | None = Field(
        default=None,
        description="Key encryption algorithm; required when encrypted is true.",
    )
    enc_method: str | None = Field(
        default=None,
        description="Content encryption method; required when encrypted is true.",
    )

    @model_validator(mode="after")
    def _require_enc_fields_when_encrypted(self) -> "ArsiaSecurity":
        if self.encrypted is True:
            if self.enc_alg is None or self.enc_method is None:
                raise ValueError(
                    "security.enc_alg and security.enc_method are required "
                    "when security.encrypted is true (Core §4.3.5)"
                )
        return self


__all__ = [
    "SignatureAlgorithm",
    "ArsiaSecurity",
]
