# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Import-boundary enforcement for the Layer 0-6 architecture.

Each source file under ``src/arsia_protocol/`` is parsed with
``ast.parse`` (not imported) and every ``Import`` / ``ImportFrom``
node is compared against a per-layer allow-list. Parsing rather than
importing means the tests catch illegal dependencies even if the
illegal import is inside a conditional block or a function body —
the AST walk ignores Python control flow.

Allow-lists come from the project's module-boundary rules
(see CONTRIBUTING.md). The layer assignments are:

- **Layer 0** — zero ``arsia_protocol`` imports:
  ``identity``, ``version``, ``hazmat/canonicalization``,
  ``hazmat/primitives/ed25519``, ``_data_resolver``.
- **Layer 1** — ``types/`` imports only ``arsia_protocol.identity``
  and other ``arsia_protocol.types.*`` submodules.
- **Layer 2** — ``message.py`` imports ``types/``, ``hazmat/``,
  ``identity``; ``errors.py`` imports ``types/`` and ``message``;
  ``compliance.py`` imports ``types/`` and ``_data_resolver``.
- **Layer 3** — ``validation.py`` imports ``types/``, ``identity``,
  ``compliance``, ``_data_resolver``.
- **Layer 4** — ``actions.py`` imports ``types/`` and ``validation``
  only. It does not need ``identity`` — capability strings are not
  agent IDs. ``certificates.py`` imports ``hazmat/`` only — it does
  NOT import ``types/`` or ``identity``, because its inputs are raw
  PEM strings and plain dicts. ``discovery.py`` imports ``types/``
  and ``hazmat/`` — it wraps :func:`public_key_to_jwk_dict` and
  produces dicts matching the :mod:`types` discovery models.
  ``authorization.py`` imports ``hazmat/`` only — it operates on
  JWTs as strings and plain dicts and deliberately does NOT depend
  on ``actions`` because token scope enforcement per ARSIA-Core.md
  §6.4 step 5 is exact string comparison, not the wildcard match
  implemented by :func:`arsia_protocol.actions.match_capability`.
  ``onboarding.py`` is the widest Layer 4 module: it imports
  ``types/``, ``identity``, ``actions``, ``compliance`` — everything
  it needs to model the §7 external-agent onboarding flow as data.
  It deliberately does NOT import ``audit`` even though Slice 5
  shipped the audit builders: onboarding is a decision producer, and
  audit records are assembled from the decision's envelope by the
  consumer (who feeds :data:`ONBOARDING_AUDIT_EVENTS` values into
  :func:`arsia_protocol.audit.build_audit_record`). Keeping the two
  modules uncoupled preserves the one-way Layer 4 → Layer 5 edge and
  lets a consumer that only wants the decision payload avoid pulling
  in the audit code path. It also does NOT import ``authorization``
  even though Phase 5 issues a token: the JWT is built out-of-band
  and not embedded in the decision payload.
- **Layer 4 state** — ``state.py`` imports ``types/``,
  ``validation``, ``compliance``, and ``hazmat`` (for the RFC 8785
  1 MiB size check in :func:`state.enforce_value_size_limit`). It
  does NOT import ``message``: state.py returns ``args`` dicts for
  each operation and the transport layer assembles the envelope via
  :func:`arsia_protocol.message.create_request`. It does NOT import
  ``actions`` either — the ``arsiaprotocol.state.*`` wildcard
  exclusion from §8.2 (``.purge`` / ``.snapshot`` require explicit
  grant) is implemented inline in
  :func:`state.wildcard_covers_state_capability`.
- **Layer 4 assets** — ``assets/assets.py`` imports ``types/``,
  ``validation``, ``compliance``, and ``actions`` (for the
  :data:`RESERVED_CAPABILITIES` membership assertion over the seven
  §5.1 capability strings). It does NOT import ``message``,
  ``hazmat``, ``audit``, ``identity``, ``authorization``,
  ``discovery``, ``certificates``, or ``onboarding``: the DORA
  incident builder returns a ``payload.data`` dict that the caller
  wraps via :func:`arsia_protocol.message.create_event`, and the
  MiFID audit builder receives ``payload_hash`` as a parameter so
  the module never needs the hazmat canonicalization primitive.
- **Layer 4 routing** — ``routing/routing.py`` imports ``types/``,
  ``validation``, and ``identity``. It does NOT import ``hazmat`` —
  callers that need ``payload_hash`` use
  :func:`arsia_protocol.audit.compute_payload_hash`. It does NOT
  import ``message``, ``actions``, ``compliance``, ``audit``,
  ``authorization``, ``onboarding``, ``certificates``, ``discovery``,
  ``assets``, or ``state``: the module produces decisions
  (topology, broker, priority, retry delay), validates structures
  (broker entries, relay preconditions, audit records), and drives
  the delivery state machine — all offline and transport-agnostic.
- **Layer 5 idempotency** — ``idempotency.py`` imports ``types/``
  only (for :class:`ArsiaIdempotency`). It does NOT import
  ``validation``, ``hazmat``, ``message``, ``errors``,
  ``compliance``, or any primitive: the module exposes a structural
  store protocol — no transport, no retry policy.
- **Layer 5 audit** — ``audit.py`` imports ``types/`` (for the
  :class:`ArsiaAuditRecord` model), ``hazmat`` (for the RFC 8785
  canonicalization used to derive ``payload_hash``), and
  ``validation`` (for :func:`validate_schema`, delegated by
  :func:`validate_audit_record` against
  ``arsia-audit-record.schema.json``). It does NOT depend on any
  other ``arsia_protocol`` module, keeping persistence, store
  mechanics, and transport out of the audit builder's surface.
- **Layer 6** — ``__main__.py`` is the CLI entry-point; it may
  import ``click`` and any Layer 0-5 symbol, but NOT
  ``fastapi``/``starlette``/``httpx`` (a CLI must not pull transport
  dependencies).

Forbidden imports (enforced globally):
- ``httpx``, ``fastapi``, ``websockets`` in any source module.
- ``click`` anywhere except ``__main__.py``.

Ref: CONTRIBUTING.md "Module boundaries".
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_SRC_ROOT = Path(__file__).resolve().parents[2] / "src" / "arsia_protocol"

# Modules whose imports MUST NOT touch anything inside arsia_protocol.
_LAYER_0_MODULES = {
    "_errors.py",
    "identity/agent_id.py",
    "core/version.py",
    "_data_resolver.py",
    "hazmat/canonicalization.py",
    "hazmat/primitives/ed25519.py",
}

# Allow-lists for higher layers. Each value is a set of
# ``arsia_protocol`` submodule prefixes that are legal; anything else
# is an illegal import. ``arsia_protocol`` (bare) is never allowed;
# sibling modules within the same subpackage are always allowed.
_LAYER_ALLOWLISTS: dict[str, set[str]] = {
    # Layer 2 — Core
    "core/message.py": {
        "arsia_protocol.types",
        "arsia_protocol.hazmat",
        "arsia_protocol.identity",
    },
    "core/errors.py": {
        "arsia_protocol.types",
        "arsia_protocol.core.message",
    },
    "core/compliance.py": {
        "arsia_protocol.types",
        "arsia_protocol._data_resolver",
    },
    # Layer 3 — Validation
    "core/validation.py": {
        "arsia_protocol.types",
        "arsia_protocol.identity",
        "arsia_protocol.core.compliance",
        "arsia_protocol._data_resolver",
        "arsia_protocol.core.version",
    },
    # Layer 4 — Primitives
    "actions/actions.py": {
        "arsia_protocol.types",
        "arsia_protocol.core.validation",
        "arsia_protocol.core.message",
    },
    "identity/certificates.py": {
        "arsia_protocol.hazmat",
        "arsia_protocol._errors",
    },
    "identity/discovery.py": {
        "arsia_protocol.types",
        "arsia_protocol.hazmat",
        "arsia_protocol._errors",
    },
    "core/authorization.py": {
        "arsia_protocol.hazmat",
        "arsia_protocol._errors",
    },
    "identity/onboarding.py": {
        "arsia_protocol.types",
        "arsia_protocol.identity",
        "arsia_protocol.actions",
        "arsia_protocol.core.compliance",
        "arsia_protocol._errors",
    },
    "state/state.py": {
        "arsia_protocol.types",
        "arsia_protocol.core.validation",
        "arsia_protocol.core.compliance",
        "arsia_protocol.hazmat",
    },
    "assets/assets.py": {
        "arsia_protocol.types",
        "arsia_protocol.core.validation",
        "arsia_protocol.core.compliance",
        "arsia_protocol.actions",
        "arsia_protocol.identity",
    },
    "routing/routing.py": {
        "arsia_protocol.types",
        "arsia_protocol.core.validation",
        "arsia_protocol.identity",
    },
    # Layer 5 — Cross-cutting
    "state/audit.py": {
        "arsia_protocol.types",
        "arsia_protocol.hazmat",
        "arsia_protocol.core.validation",
    },
    "core/idempotency.py": {
        "arsia_protocol._errors",
        "arsia_protocol.types",
    },
    # Layer 2 — Encryption
    "core/encryption.py": {
        "arsia_protocol.hazmat",
        "arsia_protocol.core.message",
    },
}

# Third-party modules that only the integrations layer may import.
_FORBIDDEN_TRANSPORT_MODULES = {"httpx", "fastapi", "websockets"}


def _parse(relpath: str) -> ast.Module:
    path = _SRC_ROOT / relpath
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _collect_imports(module: ast.Module) -> list[str]:
    """Return the fully qualified target of every import in ``module``.

    ``from arsia_protocol import message`` is expanded to
    ``arsia_protocol.message`` so that single-name imports from a
    package are classified the same way as dotted module imports.
    """
    out: list[str] = []
    for node in ast.walk(module):
        if isinstance(node, ast.Import):
            for alias in node.names:
                out.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.level > 0:
                # Relative imports are disallowed by convention.
                out.append(f".{'.' * (node.level - 1)}{node.module or ''}")
                continue
            if node.module is None:
                continue
            for alias in node.names:
                # Expand ``from pkg import x, y`` into ``pkg.x`` / ``pkg.y``.
                out.append(f"{node.module}.{alias.name}")
    return out


def _arsia_imports(imports: list[str]) -> list[str]:
    return [i for i in imports if i == "arsia_protocol" or i.startswith("arsia_protocol.")]


def _illegal_under_allowlist(imports: list[str], allowed: set[str]) -> list[str]:
    illegal: list[str] = []
    for imp in _arsia_imports(imports):
        if imp == "arsia_protocol":
            illegal.append(imp)
            continue
        if not any(imp == prefix or imp.startswith(prefix + ".") for prefix in allowed):
            illegal.append(imp)
    return illegal


# ----------------------------------------------------------------------
# Layer 0 — standalone
# ----------------------------------------------------------------------


_LAYER_0_ALLOWED = {f"arsia_protocol.{m.replace('/', '.').removesuffix('.py')}" for m in _LAYER_0_MODULES}


@pytest.mark.parametrize("relpath", sorted(_LAYER_0_MODULES))
def test_layer_0_module_has_no_sdk_imports(relpath: str) -> None:
    """Layer 0 modules may only import from other Layer 0 modules.

    Ref: CONTRIBUTING.md "Layer 0 — Standalone".
    """
    module = _parse(relpath)
    imports = _collect_imports(module)
    sdk_imports = _arsia_imports(imports)
    illegal = [i for i in sdk_imports if not any(i == p or i.startswith(p + ".") for p in _LAYER_0_ALLOWED)]
    assert illegal == [], (
        f"{relpath} is Layer 0 and may only import from other Layer 0 modules, "
        f"but imports: {illegal}"
    )


# ----------------------------------------------------------------------
# Layer 1 — types/ subpackage
# ----------------------------------------------------------------------


def _types_submodules() -> list[str]:
    return [
        str(p.relative_to(_SRC_ROOT))
        for p in sorted((_SRC_ROOT / "types").glob("*.py"))
        if p.name != "__init__.py"
    ]


@pytest.mark.parametrize("relpath", _types_submodules())
def test_layer_1_types_submodule_imports_are_within_layer(relpath: str) -> None:
    """``types/*.py`` may only import ``arsia_protocol.identity`` or other ``types.*``.

    Ref: CONTRIBUTING.md "Layer 1 — Foundation".
    """
    module = _parse(relpath)
    imports = _collect_imports(module)
    allowed = {"arsia_protocol.types", "arsia_protocol.identity", "arsia_protocol._errors"}
    illegal = _illegal_under_allowlist(imports, allowed)
    assert illegal == [], f"{relpath} has illegal imports: {illegal}"


def test_types_init_only_re_exports() -> None:
    """``types/__init__.py`` may only re-export its own submodules.

    Ref: CONTRIBUTING.md "Layer 1 — Foundation".
    """
    module = _parse("types/__init__.py")
    imports = _collect_imports(module)
    allowed = {"arsia_protocol.types"}
    illegal = _illegal_under_allowlist(imports, allowed)
    assert illegal == [], f"types/__init__.py has illegal imports: {illegal}"


# ----------------------------------------------------------------------
# Layer 2 / Layer 3 — per-module allow-lists
# ----------------------------------------------------------------------


@pytest.mark.parametrize("relpath", sorted(_LAYER_ALLOWLISTS.keys()))
def test_higher_layer_module_respects_allowlist(relpath: str) -> None:
    """Each Layer 2/3 module imports only from its allow-list.

    Ref: CONTRIBUTING.md "Layer 2 — Core" and "Layer 3 — Validation".
    """
    module = _parse(relpath)
    imports = _collect_imports(module)
    illegal = _illegal_under_allowlist(imports, _LAYER_ALLOWLISTS[relpath])
    assert illegal == [], (
        f"{relpath} has illegal imports {illegal}; "
        f"allow-list={sorted(_LAYER_ALLOWLISTS[relpath])}"
    )


# ----------------------------------------------------------------------
# Forbidden transport / integration imports
# ----------------------------------------------------------------------


def _all_source_files() -> list[str]:
    return [
        str(p.relative_to(_SRC_ROOT))
        for p in sorted(_SRC_ROOT.rglob("*.py"))
        if "__pycache__" not in p.parts
    ]


def test_no_module_imports_transport_libraries() -> None:
    """``httpx``/``fastapi``/``websockets`` not allowed in any source module.

    Ref: CONTRIBUTING.md "Module boundaries — Forbidden".
    """
    offenders: list[tuple[str, str]] = []
    for relpath in _all_source_files():
        module = _parse(relpath)
        for imp in _collect_imports(module):
            root = imp.split(".", 1)[0]
            if root in _FORBIDDEN_TRANSPORT_MODULES:
                offenders.append((relpath, imp))
    assert offenders == [], f"transport libs leaked into source: {offenders}"


def test_click_is_confined_to_cli_entrypoint() -> None:
    """Only ``__main__.py`` may import ``click``.

    Ref: CONTRIBUTING.md "Module boundaries — Forbidden".
    """
    offenders: list[tuple[str, str]] = []
    for relpath in _all_source_files():
        if relpath == "__main__.py":
            continue
        module = _parse(relpath)
        for imp in _collect_imports(module):
            if imp == "click" or imp.startswith("click."):
                offenders.append((relpath, imp))
    assert offenders == [], f"click leaked outside __main__: {offenders}"


def test_cli_entrypoint_does_not_import_transport_libs() -> None:
    """``__main__.py`` MUST NOT import fastapi/starlette/httpx/websockets.

    The CLI is meant to be usable from the base install (``pip install
    arsia-protocol``) without pulling transport dependencies.
    """
    module = _parse("__main__.py")
    illegal: list[str] = []
    for imp in _collect_imports(module):
        root = imp.split(".", 1)[0]
        if root in _FORBIDDEN_TRANSPORT_MODULES or root == "starlette":
            illegal.append(imp)
    assert illegal == [], f"__main__.py imports transport libs: {illegal}"


def test_no_vendor_sdk_imports() -> None:
    """No source file imports ``openai``/``anthropic``/``langchain``.

    Ref: CONTRIBUTING.md "No vendor SDK dependencies".
    """
    forbidden = {"openai", "anthropic", "langchain"}
    offenders: list[tuple[str, str]] = []
    for relpath in _all_source_files():
        module = _parse(relpath)
        for imp in _collect_imports(module):
            root = imp.split(".", 1)[0]
            if root in forbidden:
                offenders.append((relpath, imp))
    assert offenders == [], f"vendor SDK leaked in: {offenders}"


# ----------------------------------------------------------------------
# Sanity — every mapped file actually exists
# ----------------------------------------------------------------------


def test_all_described_source_files_exist() -> None:
    """Every file this test file makes claims about must exist on disk."""
    claimed = set(_LAYER_0_MODULES) | set(_LAYER_ALLOWLISTS.keys())
    missing = [rel for rel in claimed if not (_SRC_ROOT / rel).is_file()]
    assert missing == [], f"missing source files referenced by boundary tests: {missing}"
