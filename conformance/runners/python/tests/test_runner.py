# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Self-tests for the conformance runner infrastructure.

These tests validate the RUNNER, not the SDK. SDK correctness is proved
by executing the YAML suites against the installed SDK (which is what
``python -m arsia_conformance`` does). A passing run here plus a passing
suite run together prove both sides of the harness.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from click.testing import CliRunner

from arsia_conformance.cli import main
from arsia_conformance.context import ConformanceContext, resolve_repo_root
from arsia_conformance.executors import EXECUTORS
from arsia_conformance.loader import SuiteLoadError, load_suite, load_suite_dir
from arsia_conformance.reporter import ConformanceReport, TestResult
from arsia_conformance.runner import TestRunner


# ----------------------------------------------------------------------
# loader
# ----------------------------------------------------------------------


def _write_suite(path: Path, body: dict[str, Any]) -> Path:
    path.write_text(yaml.safe_dump(body, sort_keys=False))
    return path


def test_loader_parses_valid_yaml(tmp_path: Path) -> None:
    path = _write_suite(
        tmp_path / "mini.yaml",
        {
            "name": "mini",
            "description": "a tiny suite",
            "level": "core",
            "cases": [
                {
                    "id": "MINI-01",
                    "description": "one case",
                    "category": "stub",
                    "spec_ref": "ARSIA-Core §1",
                    "input": {"x": 1},
                    "expected": {"y": 2},
                },
            ],
        },
    )
    suite = load_suite(path)
    assert suite.name == "mini"
    assert len(suite.cases) == 1
    case = suite.cases[0]
    assert case.id == "MINI-01"
    assert case.category == "stub"
    assert case.level == "core"
    assert case.input == {"x": 1}
    assert case.expected == {"y": 2}
    assert case.skip_until is None


def test_loader_preserves_skip_until(tmp_path: Path) -> None:
    path = _write_suite(
        tmp_path / "skip.yaml",
        {
            "name": "skip",
            "level": "core",
            "cases": [
                {
                    "id": "SKIP-01",
                    "description": "future-slice",
                    "category": "stub",
                    "spec_ref": "x",
                    "skip_until": "slice-4+",
                    "input": {},
                    "expected": {},
                },
            ],
        },
    )
    suite = load_suite(path)
    assert suite.cases[0].skip_until == "slice-4+"


def test_loader_rejects_missing_id(tmp_path: Path) -> None:
    path = _write_suite(
        tmp_path / "bad.yaml",
        {
            "name": "bad",
            "level": "core",
            "cases": [
                {
                    "description": "no id",
                    "category": "stub",
                    "spec_ref": "x",
                    "input": {},
                    "expected": {},
                }
            ],
        },
    )
    with pytest.raises(SuiteLoadError, match="'id'"):
        load_suite(path)


def test_loader_load_suite_dir_sorted(tmp_path: Path) -> None:
    _write_suite(
        tmp_path / "b.yaml",
        {"name": "b", "level": "core", "cases": []},
    )
    _write_suite(
        tmp_path / "a.yaml",
        {"name": "a", "level": "core", "cases": []},
    )
    suites = load_suite_dir(tmp_path)
    assert [s.name for s in suites] == ["a", "b"]


# ----------------------------------------------------------------------
# context
# ----------------------------------------------------------------------


def test_context_resolve_repo_root_finds_repo() -> None:
    root = resolve_repo_root()
    assert (root / "shared").is_dir()
    assert (root / "conformance" / "suites").is_dir()


def test_context_loads_vectors_and_keypairs(real_context: ConformanceContext) -> None:
    test_vectors = real_context.shared_dir / "test-vectors"
    vectors = json.loads((test_vectors / "arsia-test-vectors.json").read_text())["vectors"]
    keypairs = json.loads((test_vectors / "keypairs.json").read_text())["keypairs"]
    assert vectors and keypairs
    assert len(real_context.vectors) == len(vectors)
    assert len(real_context.keypairs) == len(keypairs)
    assert "CTV-01" in real_context.vectors
    assert "agent:acme.echo-client" in real_context.keypairs


def test_context_get_vector_unknown_raises(real_context: ConformanceContext) -> None:
    with pytest.raises(KeyError, match="NOT-A-REAL-VECTOR"):
        real_context.get_vector("NOT-A-REAL-VECTOR")


# ----------------------------------------------------------------------
# runner dispatch
# ----------------------------------------------------------------------


def test_runner_dispatches_to_registered_executor(
    tmp_path: Path, real_context: ConformanceContext
) -> None:
    path = _write_suite(
        tmp_path / "dispatch.yaml",
        {
            "name": "dispatch",
            "level": "core",
            "cases": [
                {
                    "id": "DISPATCH-CANON-CTV-01",
                    "description": "real canon case",
                    "category": "canonicalization",
                    "spec_ref": "ARSIA-Core §5.1",
                    "input": {"vector_id": "CTV-01"},
                    "expected": {"match_vector_field": "canonical_bytes_hex"},
                }
            ],
        },
    )
    suite = load_suite(path)
    runner = TestRunner(real_context)
    report = runner.run([suite])
    assert len(report.results) == 1
    assert report.results[0].status == "pass"


def test_runner_unknown_category_errors_gracefully(
    tmp_path: Path, real_context: ConformanceContext
) -> None:
    path = _write_suite(
        tmp_path / "unknown.yaml",
        {
            "name": "unknown",
            "level": "core",
            "cases": [
                {
                    "id": "UNK-01",
                    "description": "category that does not exist",
                    "category": "not_a_real_category",
                    "spec_ref": "x",
                    "input": {},
                    "expected": {},
                }
            ],
        },
    )
    suite = load_suite(path)
    runner = TestRunner(real_context)
    report = runner.run([suite])
    assert report.results[0].status == "error"
    assert "no executor registered" in (report.results[0].message or "")


def test_runner_skip_until_is_respected(
    tmp_path: Path, real_context: ConformanceContext
) -> None:
    path = _write_suite(
        tmp_path / "skip.yaml",
        {
            "name": "skip",
            "level": "core",
            "cases": [
                {
                    "id": "SKIP-01",
                    "description": "future",
                    "category": "canonicalization",
                    "spec_ref": "x",
                    "skip_until": "slice-4+",
                    "input": {"vector_id": "CTV-01"},
                    "expected": {"match_vector_field": "canonical_bytes_hex"},
                }
            ],
        },
    )
    suite = load_suite(path)
    runner = TestRunner(real_context)
    report = runner.run([suite])
    assert report.results[0].status == "skip"
    assert report.results[0].message == "skipped until slice-4+"


def test_runner_category_filter_applies(
    tmp_path: Path, real_context: ConformanceContext
) -> None:
    path = _write_suite(
        tmp_path / "mix.yaml",
        {
            "name": "mix",
            "level": "core",
            "cases": [
                {
                    "id": "MIX-01",
                    "description": "canon",
                    "category": "canonicalization",
                    "spec_ref": "x",
                    "input": {"vector_id": "CTV-01"},
                    "expected": {"match_vector_field": "canonical_bytes_hex"},
                },
                {
                    "id": "MIX-02",
                    "description": "identity",
                    "category": "identity",
                    "spec_ref": "x",
                    "input": {"agent_id": "agent:acme.bot"},
                    "expected": {"valid": True},
                },
            ],
        },
    )
    suite = load_suite(path)
    runner = TestRunner(real_context)
    report = runner.run([suite], categories=["canonicalization"])
    assert len(report.results) == 1
    assert report.results[0].test_id == "MIX-01"


def test_executors_table_covers_all_categories() -> None:
    assert set(EXECUTORS.keys()) == {
        "canonicalization",
        "signing",
        "encryption",
        "validation",
        "schema-validation",
        "compliance",
        "identity",
        "errors",
        "version",
        "actions",
        "certificates",
        "discovery",
        "authorization",
        "onboarding",
        "state",
        "assets",
        "routing",
        "idempotency",
    }


# ----------------------------------------------------------------------
# reporter
# ----------------------------------------------------------------------


def _fake_report() -> ConformanceReport:
    report = ConformanceReport(target="arsia-protocol 1.0.0", level="core")
    report.results.extend(
        [
            TestResult("T1", "s1", "canonicalization", "pass", 1.0),
            TestResult("T2", "s1", "canonicalization", "fail", 1.0, "bad bytes"),
            TestResult("T3", "s2", "validation", "skip", 0.0, "skipped until slice-4+"),
            TestResult("T4", "s2", "validation", "error", 0.0, "boom"),
        ]
    )
    report.duration_ms = 42.5
    return report


def test_report_summary_counts() -> None:
    report = _fake_report()
    assert report.summary == {
        "pass": 1,
        "fail": 1,
        "skip": 1,
        "error": 1,
        "total": 4,
    }


def test_report_exit_code_nonzero_on_failure() -> None:
    assert _fake_report().exit_code == 1


def test_report_exit_code_zero_when_only_skips() -> None:
    report = ConformanceReport(target="x", level="core")
    report.results.append(TestResult("T", "s", "c", "skip", 0.0, "later"))
    assert report.exit_code == 0


def test_report_to_json_roundtrips() -> None:
    payload = json.loads(_fake_report().to_json())
    assert payload["target"] == "arsia-protocol 1.0.0"
    assert payload["summary"]["total"] == 4
    assert len(payload["results"]) == 4
    assert payload["results"][0]["status"] == "pass"


def test_report_to_text_contains_totals() -> None:
    text = _fake_report().to_text(use_color=False)
    assert "1 passed" in text
    assert "1 failed" in text
    assert "1 skipped" in text
    assert "1 errors" in text
    assert "Level: core" in text


def test_report_to_text_verbose_lists_cases() -> None:
    text = _fake_report().to_text(verbose=True, use_color=False)
    assert "T1" in text
    assert "T2" in text
    assert "bad bytes" in text


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------


def test_cli_runs_category_filter_and_exits_zero() -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["--category", "version", "--format", "text"],
    )
    assert result.exit_code == 0, result.output
    assert "passed" in result.output


def test_cli_json_format_parseable() -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["--category", "version", "--format", "json"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert "summary" in payload
    assert payload["summary"]["fail"] == 0
