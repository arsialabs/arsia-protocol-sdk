# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Executor for the ``certificates`` category.

Dispatches on ``input.operation``. Each operation maps to a pure,
offline entry point from :mod:`arsia_protocol.certificates`:

- ``compute_trust_level`` — §6.1/§6.2/§6.3 permissive classifier.
- ``has_qc_statements`` — eIDAS QcStatements OID probe.

Full chain verification via :func:`verify_certificate_chain` is not
exposed as a conformance operation — it requires PEM chains and raw
key bytes, which are impractical to ship in YAML. Those paths are
covered exhaustively by the SDK's unit tests.

Spec-level cases for L2/L3 issuance and eIDAS integration
(``CERT-*`` in ARSIA-Identity §6) are recorded with
``skip_until: slice-4-identity`` until the identity workflow slice
lights up the end-to-end flow.
"""

from __future__ import annotations

from arsia_conformance.context import ConformanceContext
from arsia_conformance.loader import TestCase
from arsia_conformance.reporter import TestStatus


def _run_compute_trust_level(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.identity.certificates import compute_trust_level

    record = case.input.get("identity_record")
    if not isinstance(record, dict):
        return "error", "input.identity_record must be an object"
    got = compute_trust_level(record)
    want = case.expected.get("trust_level")
    if got != want:
        return "fail", f"compute_trust_level = {got!r}, want {want!r}"
    return "pass", None


def _run_has_qc_statements(case: TestCase) -> tuple[TestStatus, str | None]:
    from arsia_protocol.identity.certificates import has_qc_statements

    cert_pem = case.input.get("cert_pem")
    if not isinstance(cert_pem, str):
        return "error", "input.cert_pem must be a string"
    want_raises = bool(case.expected.get("raises", False))
    try:
        got = has_qc_statements(cert_pem)
    except ValueError as exc:
        if want_raises:
            return "pass", None
        return "fail", f"has_qc_statements raised unexpectedly: {exc}"
    if want_raises:
        return "fail", f"expected ValueError but got {got!r}"
    want = bool(case.expected.get("present"))
    if got != want:
        return "fail", f"has_qc_statements = {got}, want {want}"
    return "pass", None


_OPERATIONS = {
    "compute_trust_level": _run_compute_trust_level,
    "has_qc_statements": _run_has_qc_statements,
}


def execute(case: TestCase, context: ConformanceContext) -> tuple[TestStatus, str | None]:
    """Dispatch a ``certificates`` case to its handler."""
    try:
        import arsia_protocol.identity.certificates  # noqa: F401
    except ImportError as exc:  # pragma: no cover - defensive
        return "error", f"arsia_protocol.certificates import failed: {exc}"

    operation = case.input.get("operation")
    if not isinstance(operation, str):
        return "error", "input.operation is required for certificates cases"
    handler = _OPERATIONS.get(operation)
    if handler is None:
        return "error", f"unknown certificates operation: {operation!r}"
    return handler(case)


__all__ = ["execute"]
