# ARSIA Conformance Runner — Python harness

Language-agnostic conformance runner for the ARSIA Protocol SDK.

This is a **development/CI tool**, not part of the `arsia-protocol` package.
It lives in `/conformance/runners/python/` as a sibling project, consumes
the SDK as an external dependency, and executes the declarative suites in
`/conformance/suites/*.yaml` against the installed SDK.

The suites are language-agnostic: a future TypeScript runner reads the same
YAML files and asserts the same outcomes. The Python runner is the first
implementation of the harness.

## Why standalone?

Conformance runners are a different category of work from unit tests. They
validate what an implementation *does*, not what its internals *are*. The
`/conformance/` directory mirrors the pattern used by Protocol Buffers, gRPC
interop, WebAssembly `test/core/`, JSON Schema Test Suite, WPT and Test262:
declarative suites + harness per language, sitting outside the SDK package.

See `docs/suggested-sdk-approach.md §7.3` and §10.1 for the decision log.

## Install (editable dev mode)

```
cd conformance/runners/python
pip install -e .
```

The runner depends on `arsia-protocol`, `pyyaml`, and `click`. It does
**not** bring in FastAPI, httpx, or any transport dep.

## Run the full conformance suite

From anywhere inside the repo:

```
python -m arsia_conformance
```

The runner auto-detects `conformance/suites/` and `shared/` by walking up
from the current directory. Override with explicit flags:

```
python -m arsia_conformance \
  --suites-dir /path/to/conformance/suites \
  --shared-dir /path/to/shared \
  --verbose
```

## Filtering

Run a single category:

```
python -m arsia_conformance --category canonicalization
```

Filter by conformance level:

```
python -m arsia_conformance --level core
```

Emit a JSON report:

```
python -m arsia_conformance --format json > report.json
```

## Exit codes

- `0` — all tests passed (skipped tests do not fail the run)
- `1` — one or more tests failed or errored
- `2` — CLI usage error (click default)

## Runner self-tests

The runner has its own pytest suite that validates the harness itself
(loader, dispatch, reporter, CLI exit codes). These tests do **not** test
SDK correctness — SDK correctness is proved by executing the suites
against the installed SDK.

```
cd conformance/runners/python
pytest tests/ -v
```
