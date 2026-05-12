# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Report dataclasses and serialization.

The runner produces a :class:`ConformanceReport` summarising every
executed :class:`TestResult`. Reports can be serialized to a
machine-readable JSON document (for CI pipelines) or a human-readable
text block (for interactive terminal use).
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict, dataclass, field
from typing import Literal

TestStatus = Literal["pass", "fail", "skip", "error"]


@dataclass
class TestResult:
    """Outcome of a single test case.

    Attributes:
        test_id: The case ID from the suite.
        suite: Name of the suite the case belongs to.
        category: Dispatch category (executor name).
        status: ``pass``, ``fail``, ``skip``, or ``error``.
        duration_ms: Wall-clock duration in milliseconds.
        message: Optional detail. Mandatory on ``fail``/``error``/``skip``.
        spec_ref: Spec reference copied from the case.
    """

    __test__ = False  # tell pytest this is not a test class

    test_id: str
    suite: str
    category: str
    status: TestStatus
    duration_ms: float
    message: str | None = None
    spec_ref: str = ""
    rtm_ids: tuple[str, ...] = ()


@dataclass
class ConformanceReport:
    """Aggregate result of a runner invocation.

    Attributes:
        target: Identifier of the SDK under test (package name + version).
        level: Conformance level filter that was requested (``core``,
            ``compliance``, ``full``, or ``all``).
        results: Individual test results in execution order.
        duration_ms: Total wall-clock duration in milliseconds.
    """

    target: str
    level: str
    results: list[TestResult] = field(default_factory=list)
    duration_ms: float = 0.0

    def count(self, status: TestStatus) -> int:
        """Return the number of results with ``status``."""
        return sum(1 for r in self.results if r.status == status)

    @property
    def summary(self) -> dict[str, int]:
        """Return ``{pass, fail, skip, error, total}`` keyed by status name."""
        return {
            "pass": self.count("pass"),
            "fail": self.count("fail"),
            "skip": self.count("skip"),
            "error": self.count("error"),
            "total": len(self.results),
        }

    @property
    def exit_code(self) -> int:
        """Return 0 iff no tests failed or errored. Skips do not fail."""
        return 0 if self.count("fail") == 0 and self.count("error") == 0 else 1

    def to_json(self, *, indent: int | None = 2) -> str:
        """Serialize to a JSON string for machine consumption."""
        payload = {
            "target": self.target,
            "level": self.level,
            "duration_ms": round(self.duration_ms, 2),
            "summary": self.summary,
            "results": [asdict(r) for r in self.results],
        }
        return json.dumps(payload, indent=indent, sort_keys=False)

    def to_text(self, *, verbose: bool = False, use_color: bool | None = None) -> str:
        """Serialize to a human-readable block.

        Args:
            verbose: When ``True``, each test's one-line status is printed
                in addition to the per-suite/global summary.
            use_color: Enable ANSI colors. Defaults to auto-detecting a
                terminal on ``sys.stdout``.
        """
        if use_color is None:
            use_color = sys.stdout.isatty()
        green = "\033[32m" if use_color else ""
        red = "\033[31m" if use_color else ""
        yellow = "\033[33m" if use_color else ""
        dim = "\033[90m" if use_color else ""
        reset = "\033[0m" if use_color else ""

        status_glyph = {
            "pass": f"{green}PASS{reset}",
            "fail": f"{red}FAIL{reset}",
            "skip": f"{yellow}SKIP{reset}",
            "error": f"{red}ERROR{reset}",
        }

        lines: list[str] = []
        lines.append(f"ARSIA Protocol Conformance — {self.target}")
        lines.append("=" * 60)
        lines.append("")

        # Per-suite summary
        suites_order: list[str] = []
        per_suite: dict[str, dict[str, int]] = {}
        for r in self.results:
            bucket = per_suite.setdefault(
                r.suite, {"pass": 0, "fail": 0, "skip": 0, "error": 0}
            )
            if r.suite not in suites_order:
                suites_order.append(r.suite)
            bucket[r.status] += 1

        for suite in suites_order:
            b = per_suite[suite]
            parts = [f"{b['pass']} passed"]
            if b["fail"]:
                parts.append(f"{red}{b['fail']} failed{reset}")
            if b["error"]:
                parts.append(f"{red}{b['error']} errors{reset}")
            if b["skip"]:
                parts.append(f"{yellow}{b['skip']} skipped{reset}")
            lines.append(f"  {suite:<24} {' · '.join(parts)}")

        if verbose:
            lines.append("")
            for r in self.results:
                msg = f" {dim}— {r.message}{reset}" if r.message else ""
                lines.append(
                    f"    {status_glyph[r.status]:<16} {r.test_id}"
                    f" {dim}({r.duration_ms:.1f} ms){reset}{msg}"
                )

        summary = self.summary
        lines.append("")
        lines.append("-" * 60)
        summary_bits = [f"{summary['pass']} passed"]
        if summary["fail"]:
            summary_bits.append(f"{red}{summary['fail']} failed{reset}")
        if summary["error"]:
            summary_bits.append(f"{red}{summary['error']} errors{reset}")
        if summary["skip"]:
            summary_bits.append(f"{yellow}{summary['skip']} skipped{reset}")
        lines.append(f"Total: {' · '.join(summary_bits)}")
        lines.append(f"Level: {self.level}")
        lines.append(f"Duration: {self.duration_ms:.0f} ms")
        return "\n".join(lines) + "\n"


__all__ = [
    "TestStatus",
    "TestResult",
    "ConformanceReport",
]
