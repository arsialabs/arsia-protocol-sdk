# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Resolve paths to bundled data artifacts (schemas, vectors, profiles).

``shared/`` at the repository root is the only tracked copy of the
artifacts (see ``shared/SOURCE.md``). ``_data/`` is not tracked: the build
hook (``python/hatch_build.py``) generates it from ``shared/`` on every
build, including editable installs, and Hatch ``force-include`` bundles
it into the wheel and sdist. ``shared/`` is the fallback when ``_data/``
has not been generated, e.g. when running from a source checkout.
"""

from __future__ import annotations

from pathlib import Path

_PACKAGE_ROOT = Path(__file__).resolve().parent
_BUNDLED_DATA = _PACKAGE_ROOT / "_data"
# _PACKAGE_ROOT = .../python/src/arsia_protocol
# parents[0] = .../python/src
# parents[1] = .../python
# parents[2] = .../ (repo root)
_REPO_SHARED = _PACKAGE_ROOT.parents[2] / "shared"


def data_root() -> Path:
    """Return the root directory containing bundled data artifacts.

    Prefers the build-generated ``_data/`` directory. Falls back to the
    repo-level ``shared/`` when ``_data/`` has not been generated.

    Raises:
        FileNotFoundError: if neither location is available.
    """
    if _BUNDLED_DATA.is_dir():
        return _BUNDLED_DATA
    if _REPO_SHARED.is_dir():
        return _REPO_SHARED
    raise FileNotFoundError(
        "Could not locate ARSIA data artifacts: neither "
        f"{_BUNDLED_DATA} nor {_REPO_SHARED} exists."
    )


def schemas_dir() -> Path:
    """Return the directory containing JSON Schemas."""
    return data_root() / "schemas"


def test_vectors_dir() -> Path:
    """Return the directory containing canonical test vectors."""
    return data_root() / "test-vectors"


def profiles_dir() -> Path:
    """Return the directory containing compliance profiles."""
    return data_root() / "profiles"


__all__ = [
    "data_root",
    "schemas_dir",
    "test_vectors_dir",
    "profiles_dir",
]
