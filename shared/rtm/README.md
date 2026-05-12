<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda) -->
# Requirements Traceability Matrix (RTM)

This directory contains per-spec RTM files that trace every normative requirement to its schema coverage and test vector coverage.

## Files

| File | Spec | Description |
|------|------|-------------|
| `ARSIA-Core.rtm.md` | Core | Foundation — envelope, signing, discovery, authorization, transport |
| `ARSIA-Actions.rtm.md` | Actions | Capabilities, human oversight, explainability |
| `ARSIA-Routing.rtm.md` | Routing | Message routing, broker topology, data residency |
| `ARSIA-State.rtm.md` | State | State lifecycle, GDPR, compliance profiles, audit trail |
| `ARSIA-Identity.rtm.md` | Identity | Agent identity, certificates, onboarding |
| `ARSIA-Assets.rtm.md` | Assets | Transactions, escrow, MiFID II / DORA / PSD2 |

## Format

Each RTM uses an 8-column table:

| Column | Description |
|--------|-------------|
| ID | Requirement identifier (e.g., `CORE-§4.1.3-01`) |
| § | Spec section reference |
| Modal | BCP 14 keyword (MUST, SHOULD, MAY, etc.) |
| Layer | Implementation layer (sdk, deployment, external, etc.) |
| Kind | Requirement type (structural, behavioural, procedural, etc.) |
| Requirement | Normative text |
| Schema | Schema coverage status |
| Vector | Test vector coverage (vector ID or gap marker) |
