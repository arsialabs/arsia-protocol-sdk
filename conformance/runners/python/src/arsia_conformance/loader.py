# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""YAML suite loader.

Parses the declarative test suite files in ``/conformance/suites/*.yaml``
into typed :class:`Suite` and :class:`TestCase` objects. The loader is
purely structural: it does not interpret ``input`` or ``expected`` blocks
— those are handed to the executor registered for the case's category.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class TestCase:
    """A single conformance test case parsed from a suite file.

    Attributes:
        id: Unique identifier within the suite (and across the suite set).
        description: Human-readable one-line summary.
        category: Dispatch key — which executor handles the case.
        level: Conformance level (``core``, ``compliance``, or ``full``).
        spec_ref: Spec section reference (e.g. ``"ARSIA-Core §5.1 Step 3"``).
        input: Input block, an opaque dict consumed by the executor.
        expected: Expected-outcome block, an opaque dict consumed by the
            executor.
        skip_until: If set, the case is skipped until the named gate lands
            (e.g. ``"slice-4+"``). The runner records a ``skip`` result
            rather than executing.
    """

    id: str
    description: str
    category: str
    level: str
    spec_ref: str
    input: dict[str, Any]
    expected: dict[str, Any]
    skip_until: str | None = None
    rtm_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class Suite:
    """A conformance suite loaded from a single YAML file.

    Attributes:
        name: Suite name as declared in the file.
        description: Suite description.
        level: Default conformance level declared at the suite top level
            (individual cases may override).
        path: Source file path, kept for error messages.
        cases: Ordered tuple of test cases.
    """

    name: str
    description: str
    level: str
    path: Path
    cases: tuple[TestCase, ...] = field(default_factory=tuple)


class SuiteLoadError(RuntimeError):
    """Raised when a suite YAML file cannot be parsed into a Suite."""


def _require(obj: dict[str, Any], key: str, *, where: str) -> Any:
    if key not in obj:
        raise SuiteLoadError(f"{where}: required key {key!r} is missing")
    return obj[key]


def _parse_case(raw: dict[str, Any], *, suite_path: Path, suite_level: str) -> TestCase:
    where = f"{suite_path.name}:{_require(raw, 'id', where=str(suite_path))!s}"
    case_id = str(_require(raw, "id", where=where))
    description = str(_require(raw, "description", where=where))
    category = str(_require(raw, "category", where=where))
    level = str(raw.get("level", suite_level))
    spec_ref = str(raw.get("spec_ref", ""))
    input_block = raw.get("input", {})
    expected_block = raw.get("expected", {})
    if not isinstance(input_block, dict):
        raise SuiteLoadError(f"{where}: 'input' must be a mapping")
    if not isinstance(expected_block, dict):
        raise SuiteLoadError(f"{where}: 'expected' must be a mapping")
    skip_until = raw.get("skip_until")
    if skip_until is not None and not isinstance(skip_until, str):
        raise SuiteLoadError(f"{where}: 'skip_until' must be a string when present")
    raw_rtm_ids = raw.get("rtm_ids", ())
    if not isinstance(raw_rtm_ids, (list, tuple)):
        raise SuiteLoadError(f"{where}: 'rtm_ids' must be a list when present")
    return TestCase(
        id=case_id,
        description=description,
        category=category,
        level=level,
        spec_ref=spec_ref,
        input=dict(input_block),
        expected=dict(expected_block),
        skip_until=skip_until,
        rtm_ids=tuple(str(r) for r in raw_rtm_ids),
    )


def load_suite(path: Path) -> Suite:
    """Load a single suite YAML file.

    Args:
        path: Absolute path to the ``.yaml`` file.

    Returns:
        The parsed :class:`Suite`.

    Raises:
        SuiteLoadError: if the file is missing required keys or has
            malformed structure.
        FileNotFoundError: if ``path`` does not exist.
    """
    with path.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    if not isinstance(raw, dict):
        raise SuiteLoadError(f"{path}: top-level YAML document must be a mapping")
    name = str(_require(raw, "name", where=str(path)))
    description = str(raw.get("description", ""))
    level = str(raw.get("level", "core"))
    raw_cases = raw.get("cases", [])
    if not isinstance(raw_cases, list):
        raise SuiteLoadError(f"{path}: 'cases' must be a list")
    cases: list[TestCase] = []
    for raw_case in raw_cases:
        if not isinstance(raw_case, dict):
            raise SuiteLoadError(f"{path}: each case must be a mapping")
        cases.append(_parse_case(raw_case, suite_path=path, suite_level=level))
    return Suite(
        name=name,
        description=description,
        level=level,
        path=path,
        cases=tuple(cases),
    )


def load_suite_dir(directory: Path) -> list[Suite]:
    """Load every ``*.yaml`` suite file in ``directory`` (sorted by name).

    Args:
        directory: Directory containing suite files.

    Returns:
        A list of :class:`Suite` objects, sorted by file name.

    Raises:
        FileNotFoundError: if ``directory`` does not exist.
        SuiteLoadError: if any suite file is malformed.
    """
    if not directory.is_dir():
        raise FileNotFoundError(f"suites directory does not exist: {directory}")
    suites: list[Suite] = []
    for path in sorted(directory.glob("*.yaml")):
        suites.append(load_suite(path))
    return suites


__all__ = [
    "TestCase",
    "Suite",
    "SuiteLoadError",
    "load_suite",
    "load_suite_dir",
]
