# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""ARSIA Protocol conformance runner (Python harness).

This package is a development/CI tool. It is NOT part of the
``arsia-protocol`` SDK and MUST NOT be imported from it. The runner
consumes the SDK as an external dependency and executes the declarative
YAML suites in ``/conformance/suites/`` against the installed SDK.

See ``docs/suggested-sdk-approach.md §7.3`` for the rationale.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
