# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Smoke test — the package imports and exposes a version string."""

from __future__ import annotations

import arsia_protocol


def test_package_exposes_version() -> None:
    assert isinstance(arsia_protocol.__version__, str)
    assert arsia_protocol.__version__
