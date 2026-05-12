# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Unit tests for ``arsia_protocol.types.errors``.

Spec: ARSIA-Core.md §4.4.6 and §11.2; Core §11.2 (ValidationError).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError as PydanticValidationError

from arsia_protocol.types.errors import ArsiaError, ValidationError


def test_error_minimal_valid() -> None:
    """Minimal error with code+description is valid.

    Spec: ARSIA-Core.md §4.4.6.
    """
    err = ArsiaError(code="invalid_request", description="bad envelope")
    assert err.code == "invalid_request"
    assert err.details is None


def test_error_with_details() -> None:
    """Details object is accepted.

    Spec: ARSIA-Core.md §11.2 forbidden error details.
    """
    err = ArsiaError(
        code="forbidden",
        description="missing capability",
        details={
            "required_capabilities": ["payments.charge"],
            "provided_capabilities": [],
        },
    )
    assert err.details is not None
    assert "required_capabilities" in err.details


def test_error_all_fourteen_codes_accepted() -> None:
    """All standard error codes (Core §11.2 + Identity §6.4.3) are accepted.

    Spec: ARSIA-Core.md §11.2, ARSIA-Identity.md §6.4.3.
    """
    codes = [
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
    for code in codes:
        err = ArsiaError(code=code, description="x")  # type: ignore[arg-type]
        assert err.code == code


def test_error_rejects_unknown_code() -> None:
    """Unknown error codes are rejected.

    Spec: ARSIA-Core.md §11.2.
    """
    with pytest.raises(PydanticValidationError):
        ArsiaError(code="teapot", description="x")  # type: ignore[arg-type]


def test_error_rejects_extra_fields() -> None:
    """The error object forbids additional properties.

    Spec: ARSIA-Core.md §4.4.6.
    """
    with pytest.raises(PydanticValidationError):
        ArsiaError(code="invalid_request", description="x", extra="no")  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# ValidationError (SDK-side structured validation error)
# ---------------------------------------------------------------------------


def test_validation_error_construction_all_fields() -> None:
    """All four fields are set correctly when provided."""
    err = ValidationError(
        code="missing_legal_basis",
        message="R2: legal_basis required",
        details={"missing_legal_basis": True},
        spec_ref="Core §4.3.8 R2",
    )
    assert err.code == "missing_legal_basis"
    assert err.message == "R2: legal_basis required"
    assert err.details == {"missing_legal_basis": True}
    assert err.spec_ref == "Core §4.3.8 R2"


def test_validation_error_construction_defaults() -> None:
    """details defaults to {} and spec_ref defaults to "" when omitted."""
    err = ValidationError(code="test", message="msg")
    assert err.details == {}
    assert err.spec_ref == ""


def test_validation_error_str_returns_message() -> None:
    """str(error) returns the human-readable message."""
    err = ValidationError(code="test", message="human-readable text")
    assert str(err) == "human-readable text"


def test_validation_error_frozen_immutable() -> None:
    """Frozen dataclass rejects attribute assignment."""
    err = ValidationError(code="test", message="msg")
    with pytest.raises(AttributeError):
        err.code = "other"  # type: ignore[misc]


def test_validation_error_equality() -> None:
    """Identical fields produce equal instances."""
    a = ValidationError(code="x", message="m", details={"k": 1}, spec_ref="s")
    b = ValidationError(code="x", message="m", details={"k": 1}, spec_ref="s")
    assert a == b


def test_validation_error_inequality_code() -> None:
    """Different code produces unequal instances."""
    a = ValidationError(code="x", message="m")
    b = ValidationError(code="y", message="m")
    assert a != b


def test_validation_error_inequality_message() -> None:
    """Different message produces unequal instances."""
    a = ValidationError(code="x", message="m1")
    b = ValidationError(code="x", message="m2")
    assert a != b


def test_validation_error_details_is_dict() -> None:
    """details field is always a dict."""
    err = ValidationError(code="x", message="m")
    assert isinstance(err.details, dict)


def test_validation_error_spec_ref_stored() -> None:
    """spec_ref is accessible on the instance."""
    err = ValidationError(code="x", message="m", spec_ref="State §2.1.10")
    assert err.spec_ref == "State §2.1.10"


def test_validation_error_repr_includes_code() -> None:
    """repr contains the code value."""
    err = ValidationError(code="insufficient_retention", message="m")
    assert "insufficient_retention" in repr(err)


def test_validation_error_not_hashable_with_dict() -> None:
    """Frozen dataclass with mutable dict field is not hashable."""
    err = ValidationError(code="x", message="m")
    with pytest.raises(TypeError, match="unhashable"):
        hash(err)


def test_validation_error_from_arsia_protocol_import() -> None:
    """ValidationError is importable from the top-level package."""
    from arsia_protocol import ValidationError as TopLevel
    assert TopLevel is ValidationError
