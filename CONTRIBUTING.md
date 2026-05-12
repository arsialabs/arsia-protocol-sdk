<!-- SPDX-License-Identifier: BUSL-1.1 -->
<!-- Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda) -->

# Contributing to the ARSIA Protocol SDK

Thank you for considering a contribution to the ARSIA Protocol SDK.

This repository contains the reference implementation of the ARSIA Protocol in Python (and, in the future, TypeScript), including source code, tests, conformance runner, documentation, and build configuration.

Contributions of every size are welcome, from bug fixes and test improvements to documentation updates and conformance runner enhancements.

This guide explains what you can contribute, how the review process works, and how to submit changes.

## 1. Licensing Overview

The ARSIA Protocol SDK repository contains materials under different licenses depending on their nature and location.

### 1.1 SDK Software

All files outside the `shared/` directory are licensed under the Business Source License 1.1 (BUSL-1.1).

This includes, unless otherwise stated:

- `python/src/` — SDK source code
- `python/tests/` — test suites
- `python/docs/` — Python-specific documentation
- `python/pyproject.toml` — build configuration
- `conformance/` — conformance runner and suites
- `docs/` — cross-language documentation
- `README.md`
- `CHANGELOG.md`
- `CONTRIBUTING.md`
- `CODE_OF_CONDUCT.md`
- `SECURITY.md`
- `VERSIONING.md`
- `CLA.md`
- `MAINTAINERS.md`

Each covered version converts to the Mozilla Public License Version 2.0 (MPL-2.0), without the Exhibit B "Incompatible With Secondary Licenses" notice, four years after that version's release.

See [python/LICENSE](python/LICENSE) for the applicable terms.

### 1.2 Technical Interoperability Artifacts

The `shared/` directory contains machine-readable technical artifacts (schemas, profiles, test vectors, keypairs) mirrored from the ARSIA Protocol specification repository. These are licensed under the Apache License 2.0.

See [shared/LICENSE-ARTIFACTS.md](shared/LICENSE-ARTIFACTS.md).

### 1.3 Specification Reference Materials

The `shared/rtm/` directory contains Requirements Traceability Matrix (RTM) files mirrored from the specification repository. These are licensed under the Creative Commons Attribution-ShareAlike 4.0 International License (CC BY-SA 4.0).

See [shared/LICENSE-SPEC.md](shared/LICENSE-SPEC.md).

### 1.4 The `shared/` Directory Is Read-Only

The contents of `shared/` are mirrored byte-for-byte from the [ARSIA Protocol specification repository](https://github.com/arsialabs/arsia-protocol). **Do not modify any file under `shared/` in this repository.** Contributions to schemas, profiles, test vectors, RTMs, or other specification artifacts belong in the specification repository, not here.

If SDK tests fail against `shared/` data, the bug is in the SDK, not in the specification data.

See [shared/SOURCE.md](shared/SOURCE.md) for provenance information.

See [LICENSE.md](LICENSE.md) for the complete licensing structure.

## 2. Contributor License Agreement

All contributions are accepted under the [ARSIA Protocol SDK Individual Contributor License Agreement](CLA.md) (the "CLA").

The CLA grants Arsia Labs (Arsia Tecnologia Unipessoal Lda) and recipients of the Project copyright and patent licenses to Your Contributions.

**You retain ownership of Your Contributions.** The CLA is a license grant, not a copyright assignment.

The CLA also allows Arsia Labs to use, sublicense, commercially license, and relicense Contributions as part of the Project, including under the Project License and commercial licensing terms.

You indicate acceptance of the CLA by adding a `Signed-off-by` line to every commit message.

The `git` command adds this automatically with the `-s` flag:

```bash
git commit -s -m "fix: correct kid prefix validation"
```

The resulting trailer looks like:

```
Signed-off-by: Your Name <your.email@example.com>
```

Pull requests without a `Signed-off-by` trailer on every commit cannot be merged.

If you forgot to sign off earlier commits, you can fix them with:

```bash
git commit --amend -s
```

for the most recent commit, or:

```bash
git rebase --signoff main
```

for a range of commits.

The name and email in the `Signed-off-by` trailer must correspond to your real identity. Pseudonymous contributions cannot be accepted.

## 3. What You Can Contribute

The following kinds of contributions are welcome and usually do not require prior discussion:

- **Bug fixes** — corrections to signing, verification, validation, compliance, or other SDK behavior.
- **Test improvements** — new unit, integration, property, adversarial, security, or smoke tests that improve coverage or catch regressions.
- **Type hint improvements** — stricter or more accurate type annotations, especially for `mypy --strict` compliance.
- **Documentation improvements** — corrections, clarifications, or additions to Python-specific documentation in `python/docs/` or cross-language documentation in `docs/`.
- **Conformance runner improvements** — enhancements to the conformance runner in `conformance/runners/python/`, including new executors, better error reporting, or performance improvements.
- **Lint and formatting fixes** — resolving `ruff` warnings or applying consistent formatting.
- **Error message improvements** — clearer, more actionable error messages and exception details.
- **Performance improvements** — optimizations that do not change the public API or correctness guarantees.

## 4. What Requires Discussion First

Please open a GitHub Issue before submitting a pull request for:

- new SDK modules or domain packages;
- changes to the module layering or dependency boundaries;
- changes to the signing, verification, or canonicalization pipeline;
- changes to the envelope factory or message builder;
- new dependencies or dependency upgrades that change the public API;
- changes to the Pydantic model structure or public types;
- changes to the conformance runner interface or suite format;
- changes to the `__init__.py` public API surface;
- changes to licensing files, CLA terms, or trademark language;
- changes that may affect backward compatibility.

Opening an issue first avoids wasted work and gives maintainers a chance to flag compatibility, governance, or licensing concerns early.

## 5. How to Contribute

1. **Fork** the repository at `https://github.com/arsialabs/arsia-protocol-sdk`.
2. **Create a branch** from `main`.
   Use a short, descriptive branch name, for example:
   - `fix-kid-prefix-validation`
   - `add-compliance-profile-tests`
   - `improve-error-messages`
3. **Make your changes.**
   Keep each pull request focused on one logical unit of work.
4. **Validate your changes locally.** See [Validation](#6-validation).
5. **Commit** using conventional commit messages and the `-s` sign-off flag.
6. **Open a pull request** against `main`.
   In the pull request description, include:
   - motivation for the change;
   - related issue, if any;
   - summary of changed files;
   - validation steps you ran;
   - any compatibility concerns.

## 6. Validation

Before opening a pull request, run the relevant checks below. These are the same checks that reviewers and CI will run.

### 6.1 Tests

Run the full test suite:

```bash
cd python
pytest tests/ -v
```

With coverage:

```bash
cd python
pytest tests/ --cov=arsia_protocol --cov-branch
```

### 6.2 Type Checking

Run mypy in strict mode:

```bash
cd python
mypy src/arsia_protocol/
```

New code must type-check cleanly under `mypy --strict`.

### 6.3 Linting and Formatting

Run ruff for linting and formatting:

```bash
cd python
ruff check src/
ruff format --check src/
```

Format before committing:

```bash
cd python
ruff format src/
```

### 6.4 Conformance Runner

If your change affects signing, verification, validation, compliance, or any behavior exercised by test vectors, run the conformance runner:

```bash
cd conformance/runners/python
pip install -e .
python -m arsia_conformance
```

### 6.5 Build

Verify that the package builds cleanly:

```bash
cd python
python -m build
```

## 7. SDK Conventions

### 7.1 Module Boundaries

The SDK is organized in strict dependency layers. Do not introduce imports that cross layers in the wrong direction, and never introduce circular imports.

- **Layer 0** — standalone modules with no SDK imports (`_errors.py`, `_data_resolver.py`, `hazmat/`, `identity/agent_id.py`, `identity/certificates.py`, `core/version.py`).
- **Layer 1** — `types/` (Pydantic v2 models). May import from Layer 0.
- **Layer 2** — `core/` (message, validation, compliance, encryption, authorization, idempotency, errors). May import from Layers 0--1.
- **Layer 3** — domain packages (`actions/`, `assets/`, `state/`, `routing/`, `identity/discovery.py`, `identity/onboarding.py`). May import from Layers 0--2.
- **Layer 4** — integration (`__init__.py`, `__main__.py`). May import from all layers.

### 7.2 Code Style

- **Python 3.12+** syntax — use `match`, `X | Y` unions, PEP 695 type aliases where appropriate.
- **Pydantic v2 only** — `model_config = ConfigDict(...)`, never `class Config:`.
- **`Literal["value"]` for enums** — never `StrEnum`.
- **Type hints everywhere** — on parameters, return types, and module attributes. No implicit `Any`.
- **Ed25519 only** for signing; **RFC 8785 (JCS)** for canonicalization.
- **No vendor SDK dependencies** — the SDK must not import `openai`, `anthropic`, `langchain`, or similar.

### 7.3 Test Conventions

- Unit tests mirror `src/arsia_protocol/` under `tests/unit/`.
- One concept per test function.
- Spec references go in docstrings, for example:

  ```python
  def test_kid_prefix_must_match_from() -> None:
      """Spec: ARSIA-Core.md S3.3 Rule 7."""
      ...
  ```

- No `@pytest.mark.spec(...)` markers. Conformance is defined by passing all schemas and test vectors, not by per-requirement coverage.
- Canonical test vectors live in `shared/test-vectors/` and are consumed via `tests/vectors/`.
- `tests/fixtures/` is for development-facing test data, not canonical vectors.

### 7.4 Commit Messages

Follow Conventional Commits:

- `feat:` — new functionality
- `fix:` — bug fix
- `docs:` — documentation
- `test:` — test additions or changes
- `chore:` — maintenance, dependencies
- `ci:` — CI/CD changes
- `refactor:` — code restructuring without behavior change

Keep the subject line under 72 characters, no period at the end.

### 7.5 The `shared/` Directory

The `shared/` directory is mirrored byte-for-byte from the specification repository. Do not modify, reorganize, rename, or delete any file under `shared/`. Provenance is tracked in [shared/SOURCE.md](shared/SOURCE.md) and relies on `diff -r` against the specification repository.

Any update to `shared/` must also update `shared/SOURCE.md` with the new provenance information.

## 8. SPDX Headers

Files should include SPDX headers where the file format permits comments.

For Python source files:

```python
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)
```

For Markdown documentation files outside `shared/`:

```html
<!-- SPDX-License-Identifier: BUSL-1.1 -->
<!-- Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda) -->
```

For TypeScript files:

```typescript
// SPDX-License-Identifier: BUSL-1.1
// Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)
```

For JSON files, do not add comments because JSON does not support comments. Licensing for JSON files is handled by [LICENSE.md](LICENSE.md), repository metadata, and any applicable REUSE/SPDX annotations.

Do not add or modify SPDX headers on files under `shared/`. Those files retain the headers from the specification repository.

## 9. Review Process

Every pull request is reviewed by a maintainer.

- Small bug fixes and test additions may be merged quickly.
- Changes touching the signing, verification, or validation pipeline require more review.
- Changes to the public API surface or Pydantic models require explicit sign-off from the Arsia Labs team.
- Changes must pass all validation checks (tests, mypy, ruff, conformance).
- Sign-off is verified on every commit.
- Licensing-sensitive changes may require additional review by Arsia Labs.

Maintainers may request changes, suggest alternatives, split a pull request, or decline a contribution.

If a contribution is declined, maintainers will try to explain the reason so you can decide whether to rework and resubmit.

## 10. Security Issues

Please do not report security vulnerabilities through public GitHub issues, pull requests, or discussions.

If you believe you have found a security vulnerability in the ARSIA Protocol SDK, please report it privately by email:

security@arsialabs.ai

See [SECURITY.md](SECURITY.md) for details.

## 11. Code of Conduct

All contributors, maintainers, and participants in ARSIA Protocol community spaces are expected to follow the [ARSIA Protocol Code of Conduct](CODE_OF_CONDUCT.md).

The Code of Conduct applies to issues, pull requests, discussions, reviews, community channels, and public representation of the project.

Instances of abusive, harassing, or otherwise unacceptable behavior may be reported to:

conduct@arsialabs.ai

If that address is not available, reports may be sent through the contact channels listed at:

https://arsialabs.ai

## 12. License

By contributing to the ARSIA Protocol SDK, you agree that your Contributions will be licensed under the Business Source License 1.1 (BUSL-1.1).

Software licensed under BUSL-1.1 converts to the Mozilla Public License Version 2.0 (MPL-2.0), without the Exhibit B "Incompatible With Secondary Licenses" notice, four years after each version's release.

All Contributions are subject to the [ARSIA Protocol SDK Individual Contributor License Agreement](CLA.md).

See [LICENSE.md](LICENSE.md) for the complete licensing structure. See [VERSIONING.md](VERSIONING.md) for the SDK's versioning policy.

---

_ARSIA Protocol ([arsiaprotocol.org](https://arsiaprotocol.org)) | by [Arsia Labs (Arsia Tecnologia Unipessoal Lda)](https://arsialabs.ai)_
