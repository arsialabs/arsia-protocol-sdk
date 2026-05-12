# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Conformance runner orchestrator.

Iterates the loaded suites, dispatches each case to the executor
registered for its category, collects :class:`TestResult` objects, and
returns a final :class:`ConformanceReport`.

The runner owns timing, skip handling, and exception safety. Executors
themselves are pure functions and never raise — any unexpected exception
bubbles up here and is captured as a ``TestResult`` with
``status="error"`` so a single broken case cannot abort a run.
"""

from __future__ import annotations

import time
from collections.abc import Iterable

from arsia_conformance.context import ConformanceContext
from arsia_conformance.executors import EXECUTORS
from arsia_conformance.loader import Suite, TestCase
from arsia_conformance.reporter import ConformanceReport, TestResult


def _get_sdk_target() -> str:
    """Return a human-readable identifier for the SDK under test."""
    try:
        from arsia_protocol.core.version import __version__
    except ImportError:  # pragma: no cover
        return "arsia-protocol (not installed)"
    return f"arsia-protocol {__version__}"


class TestRunner:
    """Executes conformance suites against an installed ARSIA SDK."""

    __test__ = False  # tell pytest this is not a test class

    def __init__(self, context: ConformanceContext) -> None:
        self.context = context

    def run(
        self,
        suites: Iterable[Suite],
        *,
        categories: list[str] | None = None,
        level: str | None = None,
    ) -> ConformanceReport:
        """Run the given suites and return an aggregate report.

        Args:
            suites: Iterable of :class:`Suite` objects to execute.
            categories: Optional allow-list of categories. Cases outside
                the list are skipped silently (not reported). ``None``
                runs every category.
            level: Optional conformance-level filter (``core``,
                ``compliance``, ``full``). ``None`` or ``"all"`` runs
                every level.

        Returns:
            A :class:`ConformanceReport` containing results in execution
            order.
        """
        report = ConformanceReport(
            target=_get_sdk_target(),
            level=level or "all",
        )
        start = time.perf_counter()
        for suite in suites:
            for case in suite.cases:
                if categories is not None and case.category not in categories:
                    continue
                if level not in (None, "all") and case.level != level:
                    continue
                report.results.append(self._run_case(suite, case))
        report.duration_ms = (time.perf_counter() - start) * 1000.0
        return report

    def _run_case(self, suite: Suite, case: TestCase) -> TestResult:
        if case.skip_until is not None:
            return TestResult(
                test_id=case.id,
                suite=suite.name,
                category=case.category,
                status="skip",
                duration_ms=0.0,
                message=f"skipped until {case.skip_until}",
                spec_ref=case.spec_ref,
                rtm_ids=case.rtm_ids,
            )

        executor = EXECUTORS.get(case.category)
        if executor is None:
            return TestResult(
                test_id=case.id,
                suite=suite.name,
                category=case.category,
                status="error",
                duration_ms=0.0,
                message=f"no executor registered for category {case.category!r}",
                spec_ref=case.spec_ref,
                rtm_ids=case.rtm_ids,
            )

        start = time.perf_counter()
        try:
            status, message = executor(case, self.context)
        except Exception as exc:  # pragma: no cover - defensive
            duration_ms = (time.perf_counter() - start) * 1000.0
            return TestResult(
                test_id=case.id,
                suite=suite.name,
                category=case.category,
                status="error",
                duration_ms=duration_ms,
                message=f"executor raised {type(exc).__name__}: {exc}",
                spec_ref=case.spec_ref,
                rtm_ids=case.rtm_ids,
            )
        duration_ms = (time.perf_counter() - start) * 1000.0
        return TestResult(
            test_id=case.id,
            suite=suite.name,
            category=case.category,
            status=status,
            duration_ms=duration_ms,
            message=message,
            spec_ref=case.spec_ref,
            rtm_ids=case.rtm_ids,
        )


__all__ = ["TestRunner"]
