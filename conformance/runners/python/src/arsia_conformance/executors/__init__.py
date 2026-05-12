# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Category-to-executor dispatch table.

Each executor is a callable with signature::

    def execute(case: TestCase, context: ConformanceContext) -> tuple[TestStatus, str | None]

where the return tuple is ``(status, message)``. Executors MUST NOT raise
— they must catch their own exceptions and return ``("error", str(exc))``.
The runner owns timing, skip handling, and result construction.
"""

from __future__ import annotations

from typing import Callable, TypeAlias

from arsia_conformance.context import ConformanceContext
from arsia_conformance.executors import (
    actions,
    assets,
    authorization,
    canonicalization,
    certificates,
    compliance,
    discovery,
    encryption,
    errors,
    identity,
    idempotency,
    onboarding,
    routing,
    schema_validation,
    signing,
    state,
    validation,
    version,
)
from arsia_conformance.loader import TestCase
from arsia_conformance.reporter import TestStatus

ExecutorResult: TypeAlias = tuple[TestStatus, str | None]
Executor: TypeAlias = Callable[[TestCase, ConformanceContext], ExecutorResult]

EXECUTORS: dict[str, Executor] = {
    "canonicalization": canonicalization.execute,
    "signing": signing.execute,
    "encryption": encryption.execute,
    "validation": validation.execute,
    "schema-validation": schema_validation.execute,
    "compliance": compliance.execute,
    "identity": identity.execute,
    "errors": errors.execute,
    "version": version.execute,
    "actions": actions.execute,
    "certificates": certificates.execute,
    "discovery": discovery.execute,
    "authorization": authorization.execute,
    "onboarding": onboarding.execute,
    "state": state.execute,
    "assets": assets.execute,
    "routing": routing.execute,
    "idempotency": idempotency.execute,
}


__all__ = ["EXECUTORS", "Executor", "ExecutorResult"]
