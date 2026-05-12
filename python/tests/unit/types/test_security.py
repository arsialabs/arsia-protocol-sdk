# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Unit tests for ``arsia_protocol.types.security``.

Spec: ARSIA-Core.md §4.3.5.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from arsia_protocol.types.security import ArsiaSecurity


def test_security_minimal_valid() -> None:
    """A minimal signed envelope security block is valid.

    Spec: ARSIA-Core.md §4.3.5.
    """
    sec = ArsiaSecurity(
        alg="EdDSA",
        kid="agent:acme.billing#key1",
        sig="base64url-placeholder",
    )
    assert sec.alg == "EdDSA"


def test_security_all_three_algorithms_accepted() -> None:
    """All three Literal algorithm values are accepted.

    Spec: ARSIA-Core.md §4.3.5.
    """
    for alg in ("EdDSA", "ES256", "RS256"):
        sec = ArsiaSecurity(alg=alg, kid="k", sig="s")  # type: ignore[arg-type]
        assert sec.alg == alg


def test_security_rejects_unknown_algorithm() -> None:
    """Unknown algorithms are rejected by the Literal type.

    Spec: ARSIA-Core.md §4.3.5.
    """
    with pytest.raises(ValidationError):
        ArsiaSecurity(alg="HS256", kid="k", sig="s")  # type: ignore[arg-type]


def test_security_encrypted_requires_enc_fields() -> None:
    """Setting encrypted=true requires enc_alg and enc_method.

    Spec: ARSIA-Core.md §4.3.5.
    """
    with pytest.raises(ValidationError, match="enc_alg"):
        ArsiaSecurity(alg="EdDSA", kid="k", sig="s", encrypted=True)


def test_security_encrypted_with_enc_fields_ok() -> None:
    """encrypted=true with both enc_alg and enc_method is valid.

    Spec: ARSIA-Core.md §4.3.5.
    """
    sec = ArsiaSecurity(
        alg="EdDSA",
        kid="k",
        sig="s",
        encrypted=True,
        enc_alg="ECDH-ES",
        enc_method="A256GCM",
    )
    assert sec.encrypted is True
