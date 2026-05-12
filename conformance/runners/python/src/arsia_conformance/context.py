# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Execution context for the conformance runner.

The runner lives outside ``python/src/`` and cannot rely on
:mod:`arsia_protocol._data_resolver`, which resolves paths for the
installed SDK package rather than for a standalone tool. This module
provides an independent path-resolution strategy:

- Explicit paths supplied on the command line always win.
- Otherwise, walk up from the current working directory (and from the
  runner's own file location) until we find a directory containing both
  ``shared/`` and ``conformance/suites/``. That is the repo root.

The :class:`ConformanceContext` object carries the resolved paths plus
the lazily-loaded test vectors and keypairs so executors can look up
vectors by ID without repeated disk I/O.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class ContextError(RuntimeError):
    """Raised when the runner cannot resolve the suites or shared directories."""


def _find_repo_root(start: Path) -> Path | None:
    """Walk up from ``start`` looking for a repo root.

    A directory qualifies as the repo root when it contains both
    ``shared/`` and ``conformance/suites/`` — the two locations the
    runner needs. Returns ``None`` if no ancestor qualifies.
    """
    current = start.resolve()
    for candidate in (current, *current.parents):
        if (candidate / "shared").is_dir() and (candidate / "conformance" / "suites").is_dir():
            return candidate
    return None


def resolve_repo_root(hint: Path | None = None) -> Path:
    """Return the ARSIA SDK repo root, or raise :class:`ContextError`.

    Args:
        hint: Optional path to begin the search from (for tests). Defaults
            to the current working directory, then this module's file
            location, then ``Path.home()``'s ancestors.

    Returns:
        The absolute path to the repo root.
    """
    candidates: list[Path] = []
    if hint is not None:
        candidates.append(hint)
    candidates.append(Path.cwd())
    candidates.append(Path(__file__).resolve())
    for start in candidates:
        found = _find_repo_root(start)
        if found is not None:
            return found
    raise ContextError(
        "could not locate the ARSIA repo root: expected an ancestor of "
        f"{Path.cwd()} or {Path(__file__).resolve()} containing both "
        "shared/ and conformance/suites/. Pass --suites-dir and "
        "--shared-dir explicitly if the runner is invoked outside the "
        "monorepo."
    )


@dataclass
class ConformanceContext:
    """Execution context shared by every executor in a run.

    Attributes:
        suites_dir: Directory containing suite YAML files.
        shared_dir: Directory containing ``schemas/``, ``test-vectors/``,
            and ``profiles/``.
        vectors: Lazily-loaded map of ``{vector_id: vector_object}``.
        keypairs: Lazily-loaded map of ``{agent_id: keypair_object}``.
    """

    suites_dir: Path
    shared_dir: Path
    vectors: dict[str, dict[str, Any]] = field(default_factory=dict)
    keypairs: dict[str, dict[str, Any]] = field(default_factory=dict)

    @classmethod
    def resolve(
        cls,
        *,
        suites_dir: Path | None = None,
        shared_dir: Path | None = None,
        repo_hint: Path | None = None,
    ) -> ConformanceContext:
        """Build a context, resolving any missing paths from the repo root.

        Args:
            suites_dir: Explicit suites directory, or ``None`` to derive
                from the repo root.
            shared_dir: Explicit shared directory, or ``None`` to derive
                from the repo root.
            repo_hint: Optional starting point for repo-root discovery.

        Returns:
            A fully populated context with vectors and keypairs loaded.
        """
        if suites_dir is None or shared_dir is None:
            root = resolve_repo_root(repo_hint)
            if suites_dir is None:
                suites_dir = root / "conformance" / "suites"
            if shared_dir is None:
                shared_dir = root / "shared"
        suites_dir = suites_dir.resolve()
        shared_dir = shared_dir.resolve()
        if not suites_dir.is_dir():
            raise ContextError(f"suites directory does not exist: {suites_dir}")
        if not shared_dir.is_dir():
            raise ContextError(f"shared directory does not exist: {shared_dir}")
        ctx = cls(suites_dir=suites_dir, shared_dir=shared_dir)
        ctx._load_vectors()
        ctx._load_keypairs()
        return ctx

    def _load_vectors(self) -> None:
        path = self.shared_dir / "test-vectors" / "arsia-test-vectors.json"
        with path.open("r", encoding="utf-8") as fh:
            raw = json.load(fh)
        for vector in raw.get("vectors", []):
            vid = vector.get("id")
            if isinstance(vid, str):
                self.vectors[vid] = vector

    def _load_keypairs(self) -> None:
        path = self.shared_dir / "test-vectors" / "keypairs.json"
        with path.open("r", encoding="utf-8") as fh:
            raw = json.load(fh)
        keypairs = raw.get("keypairs", {})
        if isinstance(keypairs, dict):
            self.keypairs = dict(keypairs)

    def get_vector(self, vector_id: str) -> dict[str, Any]:
        """Return the test vector with ID ``vector_id``.

        Raises:
            KeyError: if no such vector exists.
        """
        try:
            return self.vectors[vector_id]
        except KeyError as exc:
            raise KeyError(f"unknown test vector: {vector_id!r}") from exc


__all__ = [
    "ContextError",
    "ConformanceContext",
    "resolve_repo_root",
]
