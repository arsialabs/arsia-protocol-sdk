"""Hatch build hook — stage shared/ artifacts into src/arsia_protocol/_data/.

The SDK's schemas, test vectors, and compliance profiles live in
``/shared/`` at the monorepo root so that the Python and TypeScript
packages share a single source of truth (see CONTRIBUTING.md "Data artifacts").
Hatchling's ``force-include`` used to pull them into the wheel, but
that only works when building the wheel directly from source —
``python -m build`` chains sdist→wheel, and the extracted sdist has
no ``../shared/`` to reach.

This hook resolves the artifacts at build start and stages them
inside the Python package tree:

* **Source build** (``python -m build --sdist`` or ``--wheel`` run
  from the monorepo): ``../shared/`` exists; copy into ``_data/``.
  The staged copy is included in both targets.
* **Sdist-extracted build** (second stage of ``python -m build``):
  ``../shared/`` is absent because the sdist root is what used to be
  the ``python/`` directory. The sdist already carries ``_data/``
  from the first-stage copy, so the hook is a no-op.

``_data/`` is git-ignored and recreated on every build — never
commit it.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

_SUBDIRS = ("schemas", "test-vectors", "profiles")


class StageSharedHook(BuildHookInterface):
    PLUGIN_NAME = "stage-shared"

    def initialize(self, version: str, build_data: dict) -> None:
        root = Path(self.root)
        data_dir = root / "src" / "arsia_protocol" / "_data"
        shared_dir = root.parent / "shared"

        if shared_dir.is_dir():
            if data_dir.exists():
                shutil.rmtree(data_dir)
            data_dir.mkdir(parents=True, exist_ok=True)
            for sub in _SUBDIRS:
                src = shared_dir / sub
                if not src.is_dir():
                    raise FileNotFoundError(
                        f"Expected shared artifacts at {src}; "
                        f"monorepo layout may have changed."
                    )
                shutil.copytree(src, data_dir / sub)
            return

        missing = [sub for sub in _SUBDIRS if not (data_dir / sub).is_dir()]
        if missing:
            raise FileNotFoundError(
                f"Cannot build: neither ../shared/ nor src/arsia_protocol/_data/ "
                f"contains the required artifacts ({missing}). Run from a source "
                f"checkout or use a complete sdist."
            )
