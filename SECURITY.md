# Security Policy

The ARSIA Protocol SDK is cryptographic infrastructure for autonomous AI
agents. We take security reports seriously.

## Supported versions

| Version  | Supported |
|----------|-----------|
| `1.0.x`  | Yes       |

Only the current minor series receives security fixes.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately through either of these channels:

1. **Email:** <security@arsialabs.ai> — PGP key available on request.
2. **GitHub private advisory:** open a draft advisory at
   <https://github.com/arsialabs/arsia-protocol-sdk/security/advisories/new>.

Please include:

- A description of the vulnerability and the affected component.
- Reproduction steps or a proof-of-concept if possible.
- The version / commit hash you tested against.
- Any known mitigations or workarounds.
- Whether you wish to be credited in the fix advisory.

## Response timeline

| Stage | Target |
|-------|--------|
| Acknowledgement of the report | Within 72 hours |
| Triage and severity assessment | Within 7 days |
| Fix or mitigation for confirmed issues | Within 30 days |
| Coordinated public disclosure | After a fix ships, with reporter credit |

If a report is not actionable (out of scope, already known, not a
vulnerability) we will still reply with the reasoning.

## Scope

The following classes of issues are in scope:

- **Cryptographic vulnerabilities** — non-constant-time operations,
  side-channel leaks, signature malleability, weak randomness, replay
  attacks, nonce reuse.
- **Envelope integrity violations** — any way to modify a signed ARSIA
  envelope without invalidating the signature, or to craft an envelope
  that passes verification but deviates from the canonical form defined
  by RFC 8785 (JCS).
- **Authentication / authorization bypass** — `kid` confusion, agent ID
  spoofing, trust-level escalation, JWT / DPoP bypass, capability
  checks that can be defeated.
- **Compliance-field tampering** — any way to strip or mutate the
  `compliance` object without invalidating the signature.
- **Denial-of-service in parsers** — pathological inputs that cause
  excessive memory or CPU use in schema validation, canonicalization,
  or signature verification.
- **Dependency vulnerabilities** — issues in `cryptography`, `pydantic`,
  `jsonschema`, or `rfc8785` that affect the SDK's security properties.

Out of scope:

- Issues in transport protocols (HTTP, WebSocket, MCP, A2A) — the SDK
  is transport-agnostic.
- Issues in agent frameworks or user applications built on top of the SDK.
- Social-engineering attacks against agent operators.
- Vulnerabilities requiring a compromised signing key.

## Disclosure policy

We practice **coordinated disclosure**:

- Reporters are credited in the CHANGELOG and security advisory unless
  anonymity is requested.
- We aim to publish the advisory at the same time as the fix release.
- If a vulnerability is being actively exploited we may accelerate
  disclosure to protect users.
- We will not pursue legal action against researchers who act in good
  faith, stay within the scope above, and give us reasonable time to
  fix issues before going public.

## Hall of fame

No reports yet. This section will list reporters who have contributed
to the security of the ARSIA Protocol SDK.

---

*ARSIA Protocol ([arsiaprotocol.org](https://arsiaprotocol.org)) | by
[Arsia Labs](https://arsialabs.ai)*
