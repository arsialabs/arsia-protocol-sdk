# shared/ — Source and Provenance

## Origin

These files are copied from the ARSIA Protocol specification
repository: `arsia-protocol`.

**Source repo:** `github.com/arsialabs/arsia-protocol`
**Copied on:** 2026-05-11
**Spec version:** v1.0

## Rule

**Do NOT modify any file in this directory.**

These artifacts are the source of truth for the SDK. If SDK tests
fail against this data, the bug is in the SDK — not in the spec.

To update: copy fresh from the protocol repo and re-run tests.

## Contents

| Directory | Files | Description |
|-----------|-------|-------------|
| schemas/ | 31 | JSON Schemas (Draft 2020-12) for all protocol data structures |
| test-vectors/ | 2 files, 613 vectors (514 valid, 99 invalid), 9 keypairs | Conformance test vectors with reference keypairs |
| profiles/ | 1 file, 7 profiles (GDPR, EU AI Act High-Risk, EU AI Act Limited-Risk, MiFID II, PAC, DSA, DORA) | Compliance profiles |
| rtm/ | 6 RTMs + README | Requirements Traceability Matrices (one per spec) |

## What was excluded

README.md files from schemas/, test-vectors/, and profiles/ were
excluded during copy. They contain links relative to the protocol
repo that don't resolve in the SDK context. The RTM README
(rtm/README.md) was kept — it documents the RTM column format.

## Licensing

The contents of this directory retain the licenses from the source repository:

- **Schemas, profiles, test vectors, keypairs** (`schemas/`, `profiles/`,
  `test-vectors/`): Apache License 2.0. See `LICENSE-ARTIFACTS.md` in this
  directory.

- **RTM files** (`rtm/`): Creative Commons Attribution-ShareAlike 4.0
  International (CC BY-SA 4.0). See `LICENSE-SPEC.md` in this directory.

These licenses are separate from the SDK's Business Source License 1.1,
which applies to all files outside of this directory.
