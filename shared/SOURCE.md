# shared/ — Source and Provenance

## Origin

These files are copied from the ARSIA Protocol specification
repository: `arsia-protocol`.

**Source repo:** `github.com/arsialabs/arsia-protocol`
**Source ref:** branch `fix/draft-01-vector-signatures`, commit
`9c1316a87b70571d0f5664bc7ed65d6384dfdec2`
**Copied on:** 2026-09-29
**Spec version:** Draft-01.1 (wire version `1.0`)

The source is a branch commit, not yet merged into the protocol's `main`.
After the protocol pull request is merged, and before the SDK release,
the content of this directory must be re-verified against the merged
`main` (SHA-256 per file), and the commit reference above updated if it
changes.

Copied byte-for-byte: `schemas/*.json`, `profiles/arsia-compliance-profiles.json`,
`test-vectors/arsia-test-vectors.json`, `test-vectors/keypairs.json`, and
`rtm/` (from the protocol's `docs/rtm/`).

## Rule

**Do NOT modify any file in this directory.**

These artifacts are the source of truth for the SDK. If SDK tests
fail against this data, the bug is in the SDK — not in the spec.

To update: copy fresh from the protocol repo and re-run tests.

## Contents

| Directory | Files | Description |
|-----------|-------|-------------|
| schemas/ | 31 | JSON Schemas (Draft 2020-12) for all protocol data structures |
| test-vectors/ | 2 files: 613 vectors (413 valid, 125 invalid, 75 runtime-only, as reported by the protocol's `scripts/validate_vectors.py`); 55 keypairs (51 Ed25519, 2 ES256, 2 RS256) | Conformance test vectors with reference keypairs |
| profiles/ | 1 file, 7 profiles (GDPR, EU AI Act High-Risk, EU AI Act Limited-Risk, MiFID II, PAC, DSA, DORA) | Compliance profiles |
| rtm/ | 6 RTMs + README | Requirements Traceability Matrices (one per spec) |

## What was excluded

README.md files from schemas/, test-vectors/, and profiles/ were
excluded during copy. They contain links relative to the protocol
repo that don't resolve in the SDK context. The RTM README
(rtm/README.md) was kept — it documents the RTM column format.

## Adapted files

`LICENSE-ARTIFACTS.md` and `LICENSE-SPEC.md` are the only files in this
directory that are not byte-for-byte copies. They come from the protocol's
`licenses/` directory, with the reference to the code licence changed to
`../LICENSE.md` so that it resolves in the SDK.

## Licensing

The contents of this directory retain the licenses from the source repository:

- **Schemas, profiles, test vectors, keypairs** (`schemas/`, `profiles/`,
  `test-vectors/`): Apache License 2.0. See `LICENSE-ARTIFACTS.md` in this
  directory.

- **RTM files** (`rtm/`): Creative Commons Attribution-ShareAlike 4.0
  International (CC BY-SA 4.0). See `LICENSE-SPEC.md` in this directory.

These licenses are separate from the SDK's Business Source License 1.1,
which applies to all files outside of this directory.
