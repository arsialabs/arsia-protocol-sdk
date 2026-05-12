# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Shared pytest fixtures for runner self-tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from arsia_conformance.context import ConformanceContext, resolve_repo_root


@pytest.fixture(scope="session")
def repo_root() -> Path:
    """Return the absolute path to the ARSIA SDK repo root."""
    return resolve_repo_root()


@pytest.fixture(scope="session")
def real_context(repo_root: Path) -> ConformanceContext:
    """A real :class:`ConformanceContext` pointing at the repo's suites/shared."""
    return ConformanceContext.resolve()
