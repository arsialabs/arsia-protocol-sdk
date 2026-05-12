<!-- SPDX-License-Identifier: BUSL-1.1 -->
<!-- Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda) -->

# Versioning

The ARSIA Protocol SDK follows [Semantic Versioning](https://semver.org/) for package releases.

**Current version:** `1.0.0`

## SDK Version

The SDK version (`MAJOR.MINOR.PATCH`) reflects changes to the SDK's public API and behavior:

- **Major** (`X.0.0`) — breaking changes to the public API, removal of deprecated symbols, or changes to signing/verification behavior that affect existing consumers.
- **Minor** (`0.X.0`) — new modules, new public symbols, new domain packages, or support for a new spec draft version, without breaking existing consumers.
- **Patch** (`0.0.X`) — bug fixes, documentation corrections, test improvements, or performance improvements that do not change the public API.

Pre-release versions use the `.devN` suffix (e.g., `2.0.0.dev0`) following [PEP 440](https://peps.python.org/pep-0440/). Pre-release versions may include breaking changes between releases.

## Relationship to Spec Versions

Each SDK release targets a specific draft of the ARSIA Protocol specification. The targeted spec version is recorded in [CHANGELOG.md](CHANGELOG.md) and in [shared/SOURCE.md](shared/SOURCE.md).

A new spec draft may require a minor or major SDK version bump depending on whether the spec changes break the SDK's existing public API. Errata to a spec draft typically require only a patch bump, if any.

The SDK does not embed the spec draft version in its own version number. For example, SDK `0.2.0` might target spec `Draft-01.1`, and SDK `0.3.0` might target a later spec draft.

## Wire Version

The wire version (`v` field in the message envelope) is defined by the specification, not by the SDK. The current wire version is `1.0`. The SDK supports whichever wire versions are defined by the targeted spec draft.

---

_ARSIA Protocol ([arsiaprotocol.org](https://arsiaprotocol.org)) | by [Arsia Labs (Arsia Tecnologia Unipessoal Lda)](https://arsialabs.ai)_
