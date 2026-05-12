<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda) -->
# ARSIA-Core — Requirements Traceability Matrix

| ID | § | Modal | Layer | Kind | Requirement | Schema | Vector |
|----|---|-------|-------|------|-------------|--------|--------|
| CORE-§1.3-01 | 1.3 | MAY | sdk_enabled | interoperability | MCP/A2A agents MAY add ARSIA compliance by including the compliance field in the envelope | — | — |
| CORE-§2.2-01 | 2.2 | MUST | sdk | behavioural_positive | Agents MUST produce/consume ARSIA envelopes, verify signatures, and respond to discovery | arsia-message | — |
| CORE-§2.2-02 | 2.2 | MUST | sdk | behavioural_positive | Receiving agent MUST apply profile defaults for unset compliance fields when profile is referenced | arsia-compliance-field | — |
| CORE-§2.2-03 | 2.2 | MUST_NOT | external | behavioural_negative | Compliance broker MUST NOT modify message envelope contents | — | — |
| CORE-§2.2-04 | 2.2 | MUST | external | behavioural_positive | Compliance broker MUST append an audit record for every relayed message | arsia-broker-relay-audit | — |
| CORE-§2.2-05 | 2.2 | MAY | external | informational | A single authorization server MAY serve multiple agents within an organisation | — | — |
| CORE-§2.2-06 | 2.2 | MAY | deployment | informational | Each agent MAY use a dedicated authorization server | — | — |
| CORE-§2.2-07 | 2.2 | MUST | sdk | behavioural_positive | Each agent MUST expose exactly one inbox endpoint for receiving messages | arsia-discovery-response | — |
| CORE-§2.2-08 | 2.2 | MUST | sdk | behavioural_positive | Response/error/pending_approval/approval_decision messages MUST include correlation_id matching the original request id | arsia-message | CTV-08 |
| CORE-§2.2-09 | 2.2 | MUST | sdk | behavioural_positive | Servers MUST store idempotency keys for the duration in idempotency.expires_at | — | — |
| CORE-§2.2-10 | 2.2 | MUST | sdk | behavioural_positive | Servers MUST return the original response for any duplicate idempotency key within the retention window | — | — |
| CORE-§2.2-11 | 2.2 | MUST | deployment | structural | Data residency zone MUST be an ISO 3166-1 alpha-2 code or supranational ID where processing occurs | arsia-compliance-field | ITV-23 |
| CORE-§2.2-12 | 2.2 | MUST | deployment | procedural | Messages with data_residency MUST route through a compliance broker within the declared zone | — | — |
| CORE-§3.1-01 | 3.1 | MUST | sdk | structural | Agent ID org-segment MUST contain only ASCII letters, digits, or hyphens | arsia-message | — |
| CORE-§3.1-02 | 3.1 | MUST_NOT | sdk | structural | Agent ID org-segment MUST NOT begin or end with a hyphen | arsia-message | — |
| CORE-§3.3-01 | 3.3 | MUST_NOT | sdk | structural | Agent identifier MUST NOT exceed 256 characters including the agent: prefix | arsia-message | ITV-178 |
| CORE-§3.3-02 | 3.3 | MUST | operational_policy | behavioural_positive | Agent identifier MUST be globally unique within a deployment | — | — |
| CORE-§3.3-03 | 3.3 | SHOULD | operational_policy | behavioural_positive | Implementations SHOULD use a registry or namespace authority to prevent ID collisions | — | — |
| CORE-§3.3-04 | 3.3 | MUST_NOT | operational_policy | behavioural_negative | Agent identifier MUST NOT contain personally identifiable information (PII) | — | — |
| CORE-§3.3-05 | 3.3 | SHOULD | sdk | interoperability | Implementations SHOULD use lowercase agent identifiers to avoid confusion | arsia-message | ITV-430 |
| CORE-§3.3-06 | 3.3 | MUST_NOT | sdk | behavioural_negative | Implementations MUST NOT normalise case when comparing agent identifiers | — | — |
| CORE-§3.3-07 | 3.3 | MUST | sdk | structural | The agent: prefix MUST be present in all contexts — envelope fields, token claims, discovery, and errors | arsia-message | INV-04 |
| CORE-§3.3-08 | 3.3 | MAY | sdk | structural | Neither org-segment nor any sub-segment MAY begin or end with a hyphen | arsia-message | — |
| CORE-§3.3-09 | 3.3 | MUST_NOT | sdk | structural | Agent ID resource-segment, if present, MUST NOT be empty (no trailing slash) | arsia-message | — |
| CORE-§3.3-10 | 3.3 | MAY | sdk | informational | Implementations MAY use the specified regex for agent identifier validation | — | — |
| CORE-§4.1-01 | 4.1 | MUST | sdk | structural | Every ARSIA envelope MUST include v, id, ts, from, to, and intent fields | arsia-message | INV-01 |
| CORE-§4.1-02 | 4.1 | MUST | sdk | behavioural_negative | Messages missing any required field MUST be rejected with error invalid_request | arsia-message | INV-01, INV-02, INV-03 |
| CORE-§4.1.1-01 | 4.1.1 | MUST | sdk | behavioural_negative | Implementations MUST reject messages with unsupported major version | — | ITV-404 |
| CORE-§4.1.1-02 | 4.1.1 | MUST | sdk | behavioural_positive | Minor version differences within the same major version MUST be handled gracefully | — | ITV-405 |
| CORE-§4.1.1-03 | 4.1.1 | SHOULD | sdk | interoperability | Unknown fields from a later minor version SHOULD be ignored | — | ITV-406 |
| CORE-§4.1.2-01 | 4.1.2 | MUST | sdk | structural | Message id MUST be a UUID v4 in canonical 8-4-4-4-12 hexadecimal format | arsia-message | INV-02, ITV-407 |
| CORE-§4.1.2-02 | 4.1.2 | SHOULD | sdk | interoperability | Message id hex digits SHOULD be lowercase | arsia-message | ITV-407 |
| CORE-§4.1.2-03 | 4.1.2 | MUST | sdk | behavioural_positive | Message id UUID MUST be generated using a CSPRNG | — | — |
| CORE-§4.1.2-04 | 4.1.2 | MUST_NOT | sdk | behavioural_negative | Message identifiers MUST NOT be sequential or predictable | — | — |
| CORE-§4.1.3-01 | 4.1.3 | MUST | sdk | structural | Timestamp ts MUST be RFC 3339 UTC with exactly millisecond precision (Z suffix) | arsia-message | INV-03 |
| CORE-§4.1.3-02 | 4.1.3 | MUST_NOT | sdk | behavioural_negative | Timestamp ts MUST NOT use local timezone offsets | arsia-message | — |
| CORE-§4.1.3-03 | 4.1.3 | MAY | sdk | behavioural_negative | Recipients MAY reject messages with ts exceeding ±300 seconds clock skew tolerance | — | ITV-408 |
| CORE-§4.1.4-01 | 4.1.4 | MUST | sdk | structural | The from field MUST be a valid agent identifier per §3.1 grammar | arsia-message | — |
| CORE-§4.1.4-02 | 4.1.4 | MUST | sdk | behavioural_positive | The from field MUST match the access token sub claim | — | ITV-409 |
| CORE-§4.1.4-03 | 4.1.4 | MUST | sdk | behavioural_negative | Mismatched from vs. token sub MUST cause rejection with error unauthorized | — | ITV-409 |
| CORE-§4.1.5-01 | 4.1.5 | MUST | sdk | structural | The to field MUST be a valid agent identifier per §3.1 grammar | arsia-message | — |
| CORE-§4.1.5-02 | 4.1.5 | MUST | sdk | behavioural_positive | The to field MUST match the access token aud claim | — | ITV-410 |
| CORE-§4.1.5-03 | 4.1.5 | MUST | sdk | behavioural_negative | Mismatched to vs. token aud MUST cause rejection with error unauthorized | — | ITV-410 |
| CORE-§4.1.6-01 | 4.1.6 | SHOULD_NOT | sdk | informational | Event intent sender SHOULD NOT expect a response | arsia-message | CTV-06, CTV-07 |
| CORE-§4.1.6-02 | 4.1.6 | MUST | sdk | structural | Error intent messages MUST include payload.error object | arsia-message | CTV-05 |
| CORE-§4.2-01 | 4.2 | REQUIRED | sdk | structural | Conditional fields (correlation_id, expires_at, capabilities) are REQUIRED when their condition holds | arsia-message | — |
| CORE-§4.2-02 | 4.2 | MUST | sdk | behavioural_negative | Messages missing a conditionally required field MUST be rejected with error invalid_request | arsia-message | — |
| CORE-§4.2.1-01 | 4.2.1 | REQUIRED | sdk | structural | correlation_id is REQUIRED when intent is response, error, pending_approval, or approval_decision | arsia-message | CTV-04, CTV-05, CTV-08, CTV-09, CTV-10, INV-14 |
| CORE-§4.2.1-02 | 4.2.1 | MUST | sdk | behavioural_positive | correlation_id MUST equal the original request message id | — | CTV-04, CTV-10 |
| CORE-§4.2.1-03 | 4.2.1 | SHOULD | sdk_enabled | behavioural_positive | Agents SHOULD log unmatched correlation_id in response/error messages | — | — |
| CORE-§4.2.1-04 | 4.2.1 | MAY | sdk_enabled | behavioural_negative | Agents MAY discard response/error messages with unmatched correlation_id | — | — |
| CORE-§4.2.2-01 | 4.2.2 | REQUIRED | sdk | structural | expires_at is REQUIRED when intent is request or pending_approval | arsia-message | CTV-01, CTV-08, INV-05 |
| CORE-§4.2.2-02 | 4.2.2 | MUST_NOT | sdk | behavioural_negative | Messages MUST NOT be processed after their expires_at timestamp | — | — |
| CORE-§4.2.2-03 | 4.2.2 | MUST | sdk | structural | expires_at value MUST be strictly greater than the message ts value | — | CTV-01 |
| CORE-§4.2.2-04 | 4.2.2 | MUST | sdk | behavioural_negative | Recipients MUST reject messages with past expires_at (±300s skew tolerance) as invalid_request | — | ITV-411 |
| CORE-§4.2.3-01 | 4.2.3 | REQUIRED | sdk | structural | capabilities array is REQUIRED when intent is request or approval_decision | arsia-message | CTV-01, ITV-532, ITV-533 |
| CORE-§4.2.3-02 | 4.2.3 | MUST | sdk | structural | capabilities array MUST contain at least one element | arsia-message | — |
| CORE-§4.2.3-03 | 4.2.3 | MUST | sdk | structural | Each capability string MUST be unique within the capabilities array | arsia-message | — |
| CORE-§4.2.3-04 | 4.2.3 | MUST | sdk | behavioural_positive | Receiving agent MUST verify that the access token scope covers all listed capabilities | — | ITV-412 |
| CORE-§4.2.3-05 | 4.2.3 | MUST | sdk | behavioural_negative | Uncovered capabilities in token scope MUST cause rejection with error forbidden | — | ITV-412 |
| CORE-§4.2.3-06 | 4.2.3 | MUST | sdk | structural | Each capability string MUST be a concrete capability (concrete-cap per Actions §1.1); wildcard capabilities are not permitted in the message capabilities field | arsia-message | — |
| CORE-§4.3-01 | 4.3 | OPTIONAL | sdk | structural | Envelope optional fields (min_v, idempotency, context, payload, security, compliance) MAY be absent | arsia-message | — |
| CORE-§4.3-02 | 4.3 | MUST | sdk | structural | Optional fields, when present, MUST conform to their defined format and constraints | arsia-message | ITV-176 |
| CORE-§4.3.1-01 | 4.3.1 | MUST | sdk | behavioural_negative | Recipients MUST reject with not_implemented if their max version is below min_v | — | ITV-413 |
| CORE-§4.3.2-01 | 4.3.2 | REQUIRED | sdk | structural | idempotency.key field (string) is REQUIRED within the idempotency object | arsia-message | CTV-02 |
| CORE-§4.3.2-02 | 4.3.2 | MUST | sdk | structural | idempotency.key MUST be 1–128 characters in length | arsia-message | ITV-177 |
| CORE-§4.3.2-03 | 4.3.2 | MUST | sdk | behavioural_positive | idempotency.key MUST be unique per (from, to, payload.type) tuple | — | — |
| CORE-§4.3.2-04 | 4.3.2 | MAY | sdk | structural | idempotency.key MAY contain any printable ASCII (0x20–0x7E) | arsia-message | — |
| CORE-§4.3.2-05 | 4.3.2 | REQUIRED | sdk | structural | idempotency.expires_at field (string) is REQUIRED within the idempotency object | arsia-message | — |
| CORE-§4.3.2-06 | 4.3.2 | MAY | sdk | behavioural_positive | Server MAY discard idempotency record after idempotency.expires_at timestamp | — | — |
| CORE-§4.3.2-07 | 4.3.2 | MUST | sdk | structural | idempotency.expires_at MUST be strictly greater than the message ts | — | ITV-414 |
| CORE-§4.3.3-01 | 4.3.3 | OPTIONAL | sdk | structural | All fields within the context object (trace_id, span_id, flags, locale, priority) are OPTIONAL | arsia-message | ITV-66 |
| CORE-§4.3.3-02 | 4.3.3 | MUST | sdk | structural | context.trace_id MUST be a 32-char lowercase hex string (W3C 128-bit trace ID) | arsia-message | ITV-24 |
| CORE-§4.3.3-03 | 4.3.3 | MUST | sdk | structural | context.span_id MUST be a 16-char lowercase hex string (W3C 64-bit span ID) | arsia-message | ITV-25 |
| CORE-§4.3.3-04 | 4.3.3 | MUST | sdk | structural | context.flags MUST be an integer 0–255 (8-bit W3C trace flags) | arsia-message | ITV-26 |
| CORE-§4.3.3-05 | 4.3.3 | MAY | sdk | informational | Implementations MAY use context.locale to select error/output language | — | — |
| CORE-§4.3.3-06 | 4.3.3 | MAY | sdk | informational | Implementations MAY use context.priority for queue ordering without guarantee | — | ITV-27 |
| CORE-§4.3.5-01 | 4.3.5 | REQUIRED | sdk | structural | security object, when present, MUST include alg, kid, and sig fields | arsia-message | — |
| CORE-§4.3.5-02 | 4.3.5 | MUST | sdk | structural | security.alg MUST be one of EdDSA, ES256, or RS256 | arsia-message | ITV-548, ITV-549, ITV-550 |
| CORE-§4.3.5-03 | 4.3.5 | MUST | sdk | interoperability | Conformant implementations MUST support EdDSA (Ed25519) | — | — |
| CORE-§4.3.5-04 | 4.3.5 | SHOULD | sdk | interoperability | Conformant implementations SHOULD support ES256 (ECDSA P-256) | — | ITV-548 |
| CORE-§4.3.5-05 | 4.3.5 | MAY | sdk | interoperability | Conformant implementations MAY support RS256 for legacy interoperability only | — | ITV-549 |
| CORE-§4.3.5-06 | 4.3.5 | MUST | sdk | behavioural_positive | security.kid MUST correspond to a key in the sender JWKS endpoint | — | INV-11 |
| CORE-§4.3.5-07 | 4.3.5 | MUST | sdk | structural | security.kid format MUST be {agent-id}#{keyN} | arsia-jwk-entry | — |
| CORE-§4.3.5-08 | 4.3.5 | REQUIRED | sdk | structural | security.enc_alg is REQUIRED when security.encrypted is true | arsia-message | ITV-12, ITV-13, ITV-163 |
| CORE-§4.3.5-09 | 4.3.5 | REQUIRED | sdk | structural | security.enc_method is REQUIRED when security.encrypted is true | arsia-message | ITV-12, ITV-163 |
| CORE-§4.3.5-10 | 4.3.5 | OPTIONAL | sdk | structural | security.encrypted (boolean, OPTIONAL) indicates payload encryption; defaults to false | arsia-message | — |
| CORE-§4.3.6-01 | 4.3.6 | OPTIONAL | sdk | structural | The compliance object is OPTIONAL in every ARSIA message envelope | arsia-message, arsia-compliance-field | ITV-135, ITV-137 |
| CORE-§4.3.6.1-01 | 4.3.6.1 | SHOULD | sdk | behavioural_positive | Unknown compliance profile names SHOULD trigger a compliance warning | — | ITV-415 |
| CORE-§4.3.6.1-02 | 4.3.6.1 | MUST | sdk | behavioural_negative | In strict mode, unknown profile names MUST be rejected with invalid_request | — | ITV-416 |
| CORE-§4.3.6.2-01 | 4.3.6.2 | MUST | deployment | behavioural_positive | data_residency declares the geographic zone where the message MUST be processed and stored | arsia-compliance-field | — |
| CORE-§4.3.6.2-02 | 4.3.6.2 | MUST | deployment | procedural | data_residency, when set, MUST trigger brokered routing through an in-zone Compliance Broker | — | — |
| CORE-§4.3.6.3-01 | 4.3.6.3 | MUST | sdk | behavioural_positive | audit_required declares whether the message MUST generate an ArsiaAuditRecord | arsia-compliance-field | — |
| CORE-§4.3.6.3-02 | 4.3.6.3 | MUST | sdk_enabled | behavioural_positive | When audit_required is true, receiver MUST persist an audit record before acknowledging | — | — |
| CORE-§4.3.6.3-03 | 4.3.6.3 | OPTIONAL | sdk | informational | When audit_required is false, audit record generation is OPTIONAL | arsia-compliance-field | — |
| CORE-§4.3.6.4-01 | 4.3.6.4 | MUST | sdk | behavioural_positive | retention_days specifies the minimum days the audit record MUST be retained | arsia-compliance-field | ITV-419, ITV-28 |
| CORE-§4.3.6.4-02 | 4.3.6.4 | MUST_NOT | sdk | behavioural_negative | Per-message retention_days MUST NOT be less than the profile minimum | arsia-compliance-field | — |
| CORE-§4.3.6.4-03 | 4.3.6.4 | MUST | sdk | behavioural_positive | Receiving agent MUST use the profile minimum when per-message retention_days is lower | — | — |
| CORE-§4.3.6.4-04 | 4.3.6.4 | SHOULD | sdk | behavioural_positive | Receiving agent SHOULD log a compliance warning when overriding retention_days | — | — |
| CORE-§4.3.6.5-01 | 4.3.6.5 | MAY | sdk | informational | human_oversight not_required: agent MAY execute actions autonomously | arsia-compliance-field | ITV-134 |
| CORE-§4.3.6.5-02 | 4.3.6.5 | MUST_NOT | sdk_enabled | behavioural_negative | human_oversight required_before_execution: action MUST NOT execute until human approves | arsia-compliance-field | CTV-02 |
| CORE-§4.3.6.5-03 | 4.3.6.5 | MUST | sdk_enabled | procedural | Agent MUST respond with pending_approval and await approval_decision for pre-execution oversight | — | CTV-08, CTV-09 |
| CORE-§4.3.6.5-04 | 4.3.6.5 | MAY | sdk_enabled | behavioural_positive | human_oversight required_within_24h: action MAY execute immediately | arsia-compliance-field | — |
| CORE-§4.3.6.5-05 | 4.3.6.5 | MUST | operational_policy | procedural | A human MUST review the action and results within 24 hours of execution | — | — |
| CORE-§4.3.6.5-06 | 4.3.6.5 | MUST | sdk | behavioural_positive | Missing 24-hour review MUST trigger a compliance warning with event oversight_timeout | — | — |
| CORE-§4.3.6.6-01 | 4.3.6.6 | MUST | sdk | behavioural_positive | explainability_required declares whether responses MUST include payload.explanation | arsia-compliance-field | — |
| CORE-§4.3.6.6-02 | 4.3.6.6 | MUST | sdk | behavioural_positive | When explainability_required is true, response MUST include reasoning, confidence, and inputs_used | arsia-explanation | — |
| CORE-§4.3.6.7-01 | 4.3.6.7 | MUST | sdk | structural | When pii_involved is true, legal_basis MUST be set | arsia-message, arsia-compliance-field | INV-06, ITV-420 |
| CORE-§4.3.6.7-02 | 4.3.6.7 | MUST | sdk | behavioural_positive | Agents MUST apply GDPR Art. 5(1)(f) data protection for pii_involved messages | — | — |
| CORE-§4.3.6.7-03 | 4.3.6.7 | SHOULD | sdk | behavioural_positive | PII data SHOULD be encrypted in transit and at rest | — | — |
| CORE-§4.3.6.8-01 | 4.3.6.8 | REQUIRED | sdk | structural | legal_basis field is REQUIRED when pii_involved is true | arsia-compliance-field | CTV-02, ITV-18, ITV-19, ITV-161, ITV-162 |
| CORE-§4.3.6.8-02 | 4.3.6.8 | MUST | sdk | behavioural_negative | When pii_classification is "sensitive", legal_basis MUST be an Art. 9(2) ground | arsia-compliance-field | ITV-555, INV-20 |
| CORE-§4.3.6.9-01 | 4.3.6.9 | MAY | sdk | informational | High-risk agent MAY send a minimal-risk message (downgrade allowed) | arsia-compliance-field | ITV-136 |
| CORE-§4.3.6.9-02 | 4.3.6.9 | MUST_NOT | sdk | behavioural_negative | Minimal-risk agent MUST NOT send a high-risk message (escalation prohibited) | — | ITV-418 |
| CORE-§4.3.7-01 | 4.3.7 | MUST | sdk | behavioural_negative | Classification escalation MUST cause rejection with invalid_request and classification_escalation detail | — | ITV-418 |
| CORE-§4.3.7-02 | 4.3.7 | MUST | sdk | behavioural_positive | Per-message retention_days below profile minimum MUST default to the profile minimum | — | — |
| CORE-§4.3.7-03 | 4.3.7 | SHOULD | sdk | behavioural_positive | Implementations SHOULD log a compliance warning when retention_days override occurs | — | — |
| CORE-§4.3.8-01 | 4.3.8 | MUST | sdk | procedural | Receiving agents MUST validate the compliance field before processing | — | — |
| CORE-§4.3.8-02 | 4.3.8 | MUST | sdk | procedural | Compliance validation MUST occur after signature verification and before payload processing | — | — |
| CORE-§4.3.8-03 | 4.3.8 | MUST | sdk | behavioural_negative | Messages failing compliance validation MUST be rejected with the rule-specific error code | — | — |
| CORE-§4.3.8-04 | 4.3.8 | MUST | sdk | behavioural_positive | Rule 1: compliance.profile MUST be a known name from ARSIA-State.md §6 | arsia-compliance-profiles | CTV-03, ITV-415 |
| CORE-§4.3.8-05 | 4.3.8 | MUST | sdk | behavioural_positive | Non-strict mode: unknown profile MUST log warning and apply GDPR-STANDARD defaults | — | ITV-415 |
| CORE-§4.3.8-06 | 4.3.8 | MUST | sdk | behavioural_negative | Strict mode: unknown profile MUST reject with invalid_request | — | ITV-416 |
| CORE-§4.3.8-07 | 4.3.8 | MUST | sdk | behavioural_negative | Rule 2: pii_involved=true without legal_basis MUST reject with invalid_request | arsia-message, arsia-compliance-field | INV-06, ITV-420 |
| CORE-§4.3.8-08 | 4.3.8 | MUST_NOT | sdk | behavioural_negative | Rule 3: high-risk classification MUST have human_oversight set (not null) | arsia-message | CTV-03, ITV-421 |
| CORE-§4.3.8-09 | 4.3.8 | MUST | sdk | behavioural_negative | High-risk message without human_oversight MUST be rejected with invalid_request | — | ITV-421 |
| CORE-§4.3.8-10 | 4.3.8 | MUST | sdk | behavioural_positive | Rule 4: MIFID-II profile MUST have effective retention_days >= 1827 (5 years) | arsia-compliance-field | CTV-03, ITV-417 |
| CORE-§4.3.8-11 | 4.3.8 | MUST | sdk | behavioural_negative | MIFID-II retention_days below 1827 MUST reject with invalid_request and insufficient_retention | arsia-compliance-field | ITV-417 |
| CORE-§4.3.8-12 | 4.3.8 | MUST | deployment | procedural | Rule 5: data_residency MUST trigger routing through an in-zone Compliance Broker | — | — |
| CORE-§4.3.8-13 | 4.3.8 | MUST_NOT | sdk | behavioural_negative | Rule 6: per-message ai_system_classification MUST NOT exceed agent-level classification | — | ITV-418 |
| CORE-§4.3.8-14 | 4.3.8 | MUST | sdk | behavioural_negative | Classification escalation MUST reject with invalid_request and classification_escalation detail | — | ITV-418 |
| CORE-§4.3.8-15 | 4.3.8 | MUST | sdk | behavioural_positive | Rule 7: when pii_involved is true, effective audit_required MUST be true (silent override) | arsia-compliance-field | ITV-553, ITV-554 |
| CORE-§4.3.8-16 | 4.3.8 | SHOULD | sdk | behavioural_positive | Rule 7: when audit_required is overridden, agent SHOULD log a compliance_warning event | — | ITV-553 |
| CORE-§4.3.8-17 | 4.3.8 | MUST | sdk | behavioural_negative | Rule 8: SET with pii_classification "sensitive" MUST have Art. 9(2) legal_basis in the compliance envelope | arsia-compliance-field, arsia-state-operations | ITV-555, INV-20 |
| CORE-§4.3.8-18 | 4.3.8 | MUST | sdk | behavioural_negative | Rule 8: Art. 6(1) legal_basis for a sensitive entry MUST be rejected with invalid_request and sensitive_requires_art9_basis | — | INV-20 |
| CORE-§4.4-01 | 4.4 | MUST | sdk | structural | Payload object, when present, MUST contain a type field | arsia-message | CTV-07 |
| CORE-§4.4-02 | 4.4 | MAY | sdk | structural | Payload MAY contain additional intent-dependent fields (args, result, data, error) | arsia-message | — |
| CORE-§4.4.1-01 | 4.4.1 | REQUIRED | sdk | structural | payload.type field is REQUIRED within the payload object | arsia-message | — |
| CORE-§4.4.1-02 | 4.4.1 | MAY | sdk | structural | payload.type MAY use additional /-separated segments for sub-actions | arsia-message | — |
| CORE-§4.4.1-03 | 4.4.1 | MUST | sdk | behavioural_negative | Unrecognised payload.type MUST be rejected with error not_implemented | — | ITV-422 |
| CORE-§4.4.2-01 | 4.4.2 | SHOULD | sdk | interoperability | Senders SHOULD include payload.version when recipient may support multiple schema versions | arsia-message | — |
| CORE-§4.4.3-01 | 4.4.3 | SHOULD | sdk | structural | payload.args SHOULD be present when intent is request or pending_approval | arsia-message | — |
| CORE-§4.4.4-01 | 4.4.4 | SHOULD | sdk | structural | payload.result SHOULD be present when intent is response | arsia-message | CTV-04 |
| CORE-§4.4.5-01 | 4.4.5 | SHOULD | sdk | structural | payload.data SHOULD be present when intent is event | arsia-message | CTV-06, CTV-07 |
| CORE-§4.4.6-01 | 4.4.6 | REQUIRED | sdk | structural | payload.error object is REQUIRED when intent is error | arsia-message | — |
| CORE-§4.4.6-02 | 4.4.6 | REQUIRED | sdk | structural | payload.error.code (string) is REQUIRED; must be a standard error code from §11.2 | arsia-message | — |
| CORE-§4.4.6-03 | 4.4.6 | REQUIRED | sdk | structural | payload.error.description (string) is REQUIRED; human-readable error description | arsia-message | — |
| CORE-§4.4.6-04 | 4.4.6 | MUST_NOT | sdk | behavioural_negative | Error description MUST NOT contain stack traces, DB queries, or credentials | — | — |
| CORE-§4.4.6-05 | 4.4.6 | MUST | sdk | structural | Forbidden error details MUST include required_capabilities and provided_capabilities arrays | arsia-message | CTV-05 |
| CORE-§4.4.6-06 | 4.4.6 | MUST | sdk | structural | not_implemented error details MUST include supported_versions | arsia-message | — |
| CORE-§4.4.6-07 | 4.4.6 | SHOULD | sdk | structural | rate_limited error details SHOULD include retry_after_seconds | arsia-message | — |
| CORE-§4.4.6-08 | 4.4.6 | OPTIONAL | sdk | structural | payload.error.details (object, OPTIONAL) provides structured error context | arsia-message | — |
| CORE-§4.4.7-01 | 4.4.7 | SHOULD | sdk | structural | Only one of args, result, data, or error SHOULD be present per message | arsia-message | ITV-423 |
| CORE-§4.4.7-02 | 4.4.7 | SHOULD | sdk | behavioural_positive | Implementations SHOULD log a warning if multiple content fields are present | — | — |
| CORE-§4.4.7-03 | 4.4.7 | MUST | sdk | behavioural_positive | Implementations MUST process the content field matching the message intent | — | — |
| CORE-§4.4.7-04 | 4.4.7 | MUST | sdk | behavioural_positive | Implementations MUST ignore content fields not matching the message intent | — | — |
| CORE-§4.5-01 | 4.5 | MAY | sdk | behavioural_positive | Implementations MAY increase the 1 MiB default message size limit | — | — |
| CORE-§4.5-02 | 4.5 | MUST | sdk | behavioural_positive | Agent max message size MUST be advertised via max_message_bytes in discovery | arsia-discovery-response | — |
| CORE-§4.5-03 | 4.5 | SHOULD | sdk_enabled | behavioural_positive | Senders SHOULD check recipient max_message_bytes before sending large messages | — | — |
| CORE-§4.5-04 | 4.5 | MUST | sdk | behavioural_negative | Messages exceeding the advertised size limit MUST be rejected with payload_too_large | — | ITV-424 |
| CORE-§4.5-05 | 4.5 | SHOULD | sdk_enabled | interoperability | Large payloads SHOULD use a reference pattern (URL/ID) instead of embedding content | — | — |
| CORE-§5.1-01 | 5.1 | MUST | sdk | interoperability | Implementations MUST use a standards-compliant Ed25519 implementation | — | — |
| CORE-§5.1-02 | 5.1 | MUST | sdk | procedural | Message signing MUST follow the normative 6-step procedure (clone, strip security, JCS, sign, b64url, populate) | — | CTV-01, ITV-551, ITV-552 |
| CORE-§5.1-03 | 5.1 | MUST | sdk | interoperability | All conformant implementations MUST support Ed25519 signature generation and verification | — | — |
| CORE-§5.1-04 | 5.1 | RECOMMENDED | sdk | interoperability | ES256 support is RECOMMENDED for ECDSA interoperability | — | ITV-551, INV-18 |
| CORE-§5.1-05 | 5.1 | MUST_NOT | sdk | behavioural_negative | RS256 MUST NOT be used for new deployments; legacy interoperability only | — | ITV-552, INV-19 |
| CORE-§5.1-06 | 5.1 | MUST | sdk | behavioural_positive | RS256 key MUST be at least 2048 bits | — | ITV-425, ITV-552 |
| CORE-§5.2-01 | 5.2 | MUST | sdk | behavioural_positive | Receivers MUST verify signatures on request, response, pending_approval, and approval_decision intents | arsia-message | CTV-08, CTV-09, CTV-10, INV-15, INV-16, INV-17 |
| CORE-§5.2-02 | 5.2 | RECOMMENDED | sdk | behavioural_positive | Signature verification on event messages is RECOMMENDED but not required | — | CTV-06 |
| CORE-§5.2-03 | 5.2 | RECOMMENDED | sdk | behavioural_positive | Signature verification on error messages is RECOMMENDED | — | — |
| CORE-§5.2-04 | 5.2 | MUST | sdk | procedural | Signature verification MUST follow the normative 6-step procedure (extract, resolve key, clone-strip, JCS, verify, accept/reject) | — | ITV-551, ITV-552 |
| CORE-§5.2-05 | 5.2 | MUST | sdk | behavioural_positive | Ed25519 signature decoding MUST produce exactly 64 bytes | — | ITV-426 |
| CORE-§5.2-06 | 5.2 | SHOULD | sdk_enabled | behavioural_positive | Implementations SHOULD cache JWKS responses per Cache-Control headers | — | — |
| CORE-§5.2-07 | 5.2 | MUST | sdk | behavioural_negative | Failed signature verification MUST reject with error unauthorized | — | INV-11, ITV-426, INV-18, INV-19 |
| CORE-§5.2-08 | 5.2 | SHOULD_NOT | sdk | behavioural_negative | Signature failure error SHOULD NOT include verification failure details | — | — |
| CORE-§5.2-09 | 5.2 | SHOULD | sdk | behavioural_positive | Signature failure SHOULD be logged with kid, algorithm, and sender for debugging | — | — |
| CORE-§5.2-10 | 5.2 | MAY | sdk_enabled | behavioural_positive | Implementations MAY cache JWKS lookups and public key resolution | — | — |
| CORE-§5.2-11 | 5.2 | MUST | sdk_enabled | behavioural_positive | Cached JWKS MUST be refreshed on unknown kid, expired max-age, or every 24 hours | — | — |
| CORE-§5.3-01 | 5.3 | MUST | sdk | structural | Payload encryption requires security.encrypted MUST be set to true | arsia-message | — |
| CORE-§5.3-02 | 5.3 | MUST | sdk | structural | security.enc_alg and security.enc_method MUST be present when payload is encrypted | arsia-message | — |
| CORE-§5.3-03 | 5.3 | MUST | sdk | structural | Encrypted payload MUST be a JWE Compact Serialization string per RFC 7516 | arsia-message | ITV-428 |
| CORE-§5.3-04 | 5.3 | MUST | sdk | behavioural_positive | JWE MUST use the algorithms in security.enc_alg and security.enc_method | — | ITV-427 |
| CORE-§5.3-05 | 5.3 | RECOMMENDED | sdk | interoperability | ECDH-ES is the RECOMMENDED key encryption algorithm for payload encryption | — | ITV-12 |
| CORE-§5.3-06 | 5.3 | RECOMMENDED | sdk | interoperability | A256GCM is the RECOMMENDED content encryption method for payload encryption | — | ITV-12 |
| CORE-§5.3-07 | 5.3 | MUST | sdk | behavioural_positive | Recipient encryption key MUST be obtained from their JWKS endpoint (use: enc) | — | — |
| CORE-§5.3-08 | 5.3 | MUST | sdk | procedural | Decryption: receiver MUST verify signature before decrypting payload | — | — |
| CORE-§5.3-09 | 5.3 | MUST | sdk | procedural | Receiver MUST decrypt payload JWE using their private key and specified algorithms | — | — |
| CORE-§5.3-10 | 5.3 | MUST | sdk | behavioural_positive | Decrypted payload MUST be parsed as a JSON object conforming to §4.4 | — | — |
| CORE-§5.3-11 | 5.3 | MUST | sdk | behavioural_negative | Failed decryption MUST reject with error unauthorized | — | ITV-429 |
| CORE-§5.3-12 | 5.3 | MAY | sdk | interoperability | ECDH-ES+A256KW with A256GCM MAY be used for multi-recipient encryption | — | ITV-64 |
| CORE-§5.3-13 | 5.3 | MAY | sdk | interoperability | RSA-OAEP-256 with A256GCM MAY be used for legacy encryption interoperability | — | ITV-63 |
| CORE-§5.3.1-01 | 5.3.1 | MUST | sdk | structural | payload_hash MUST be SHA-256(UTF-8(payload)) where payload is the JWE Compact Serialization string when security.encrypted is true | arsia-audit-record | ITV-525 |
| CORE-§5.3.1-02 | 5.3.1 | SHOULD | sdk | behavioural_positive | Sender SHOULD include plaintext_hash in its audit record when security.encrypted is true | arsia-audit-record | ITV-525 |
| CORE-§5.3.1-03 | 5.3.1 | SHOULD | sdk | behavioural_positive | Recipient SHOULD include plaintext_hash in its audit record after decryption | arsia-audit-record | — |
| CORE-§5.3.1-04 | 5.3.1 | MUST_NOT | sdk | behavioural_negative | plaintext_hash MUST NOT be present when security.encrypted is false or absent | — | ITV-526 |
| CORE-§6.1-01 | 6.1 | REQUIRED | external | structural | JWT iss claim MUST identify the Authorization Server that issued the token | arsia-jwt-claims | — |
| CORE-§6.1-02 | 6.1 | REQUIRED | sdk | structural | JWT sub claim MUST contain the requesting agent's identifier per §3 | arsia-jwt-claims | — |
| CORE-§6.1-03 | 6.1 | REQUIRED | sdk | structural | JWT aud claim MUST contain the target agent's identifier per §3 | arsia-jwt-claims | — |
| CORE-§6.1-04 | 6.1 | REQUIRED | sdk | structural | JWT exp claim MUST be a NumericDate expiration time per RFC 7519 §2 | arsia-jwt-claims | — |
| CORE-§6.1-05 | 6.1 | REQUIRED | sdk | structural | JWT iat claim MUST be a NumericDate issued-at time per RFC 7519 §2 | arsia-jwt-claims | — |
| CORE-§6.1-06 | 6.1 | REQUIRED | sdk | structural | JWT jti claim MUST be a UUID v4 unique token identifier | arsia-jwt-claims | ITV-31 |
| CORE-§6.1-07 | 6.1 | REQUIRED | sdk | structural | JWT scope claim MUST be a space-separated list of capability strings | arsia-jwt-claims | ITV-32 |
| CORE-§6.1-08 | 6.1 | OPTIONAL | sdk | structural | JWT cnf claim MAY contain a proof-of-possession confirmation per RFC 9449 | arsia-jwt-claims | ITV-31 |
| CORE-§6.1-09 | 6.1 | MUST | sdk | behavioural_positive | Access token sub claim MUST match the from field of messages presented with that token | — | ITV-431 |
| CORE-§6.1-10 | 6.1 | MUST | sdk | behavioural_positive | Access token aud claim MUST match the to field of messages presented with that token | — | ITV-432 |
| CORE-§6.1-11 | 6.1 | MUST | sdk | behavioural_positive | Access token scope MUST cover all capabilities listed in the message capabilities field | — | ITV-433 |
| CORE-§6.1-12 | 6.1 | SHOULD | sdk | behavioural_positive | Access token lifetime SHOULD be short (max 3600 seconds recommended) | — | — |
| CORE-§6.1-13 | 6.1 | RECOMMENDED | sdk | behavioural_positive | Access token lifetime of 3600 seconds (1 hour) maximum is RECOMMENDED | — | — |
| CORE-§6.1-14 | 6.1 | RECOMMENDED | sdk | behavioural_positive | High-risk compliance profiles SHOULD use a token lifetime of 300 seconds (5 minutes) maximum | — | — |
| CORE-§6.1-15 | 6.1 | MUST | external | behavioural_positive | Authorization Server MUST sign access tokens using EdDSA, ES256, or RS256 per §5.1 | — | — |
| CORE-§6.1-16 | 6.1 | MUST | external | behavioural_positive | Authorization Server signing key MUST be discoverable via a standard JWKS endpoint | — | — |
| CORE-§6.1-17 | 6.1 | MUST | sdk | procedural | Token recipients MUST verify the JWT signature before extracting claims | — | — |
| CORE-§6.2-01 | 6.2 | MUST | sdk | structural | Token request grant_type parameter MUST be "client_credentials" | arsia-jwt-claims | — |
| CORE-§6.2-02 | 6.2 | REQUIRED | sdk | structural | Token request MUST include client_id with the requesting agent's identifier, URL-encoded | arsia-jwt-claims | — |
| CORE-§6.2-03 | 6.2 | REQUIRED | sdk | structural | Token request MUST include scope with space-separated requested capabilities | arsia-jwt-claims | — |
| CORE-§6.2-04 | 6.2 | REQUIRED | sdk | structural | Token request MUST include audience with the target agent's identifier, URL-encoded | arsia-jwt-claims | — |
| CORE-§6.2-05 | 6.2 | RECOMMENDED | sdk | interoperability | Private key JWT per RFC 7523 §2.2 is RECOMMENDED for client authentication | — | — |
| CORE-§6.2-06 | 6.2 | REQUIRED | external | structural | Token response MUST include access_token containing the JWT | arsia-jwt-claims | ITV-125 |
| CORE-§6.2-07 | 6.2 | MUST | external | structural | Token response token_type MUST be "Bearer" or "DPoP" | arsia-jwt-claims | — |
| CORE-§6.2-08 | 6.2 | REQUIRED | external | structural | Token response MUST include expires_in with the token lifetime in seconds | arsia-jwt-claims | — |
| CORE-§6.2-09 | 6.2 | REQUIRED | external | structural | Token response MUST include scope with granted capabilities (may differ from requested) | arsia-jwt-claims | — |
| CORE-§6.3-01 | 6.3 | RECOMMENDED | sdk | interoperability | DPoP proof-of-possession is RECOMMENDED for high-security deployments or intermediary traversal | arsia-dpop-proof | ITV-33, ITV-34, ITV-126 |
| CORE-§6.3-02 | 6.3 | SHOULD | sdk | interoperability | Implementations SHOULD use DPoP when the compliance profile requires high-risk controls | arsia-dpop-proof | — |
| CORE-§6.4-01 | 6.4 | MUST | sdk | procedural | Receiving agent MUST enforce capability-based authorization for every request message | — | — |
| CORE-§6.4-02 | 6.4 | MUST | sdk | behavioural_positive | Token exp claim MUST be in the future (±300 seconds clock skew tolerance) | — | ITV-434 |
| CORE-§6.4-03 | 6.4 | MUST | sdk | behavioural_positive | Token iat claim MUST be in the past (±300 seconds clock skew tolerance) | — | ITV-435, ITV-447, ITV-448 |
| CORE-§6.4-04 | 6.4 | MUST | sdk | behavioural_positive | Token sub claim MUST equal the message from field during enforcement | — | ITV-436 |
| CORE-§6.4-05 | 6.4 | MUST | sdk | behavioural_positive | Token aud claim MUST equal the message to field (receiving agent's identifier) | — | ITV-437 |
| CORE-§6.4-06 | 6.4 | MUST | sdk | structural | Capability-denied error MUST include required_capabilities and provided_capabilities in details | arsia-message | — |
| CORE-§7.1-01 | 7.1 | MUST | sdk | behavioural_positive | Every ARSIA agent MUST expose a discovery endpoint at GET /.well-known/arsia | arsia-discovery-response | ITV-45, ITV-46 |
| CORE-§7.1-02 | 7.1 | SHOULD | sdk | behavioural_positive | Discovery endpoint SHOULD set Cache-Control, ETag, Content-Type, and CORS headers | — | — |
| CORE-§7.1-03 | 7.1 | SHOULD | sdk | behavioural_positive | Discovery Cache-Control SHOULD use a max-age appropriate for metadata change rate | — | — |
| CORE-§7.1-04 | 7.1 | RECOMMENDED | sdk | behavioural_positive | Discovery endpoint Cache-Control max-age=3600 (1 hour) is RECOMMENDED | — | — |
| CORE-§7.1-05 | 7.1 | SHOULD | sdk | behavioural_positive | Discovery endpoint SHOULD set an ETag header to enable conditional requests | — | — |
| CORE-§7.1-06 | 7.1 | SHOULD | deployment | behavioural_positive | Discovery clients SHOULD use If-None-Match to avoid unnecessary data transfer | — | — |
| CORE-§7.1-07 | 7.1 | MUST | sdk | behavioural_positive | Discovery endpoint Content-Type MUST be application/json | — | — |
| CORE-§7.1-08 | 7.1 | SHOULD | deployment | behavioural_positive | Discovery endpoint SHOULD set Access-Control-Allow-Origin for browser-based agents | — | — |
| CORE-§7.1-09 | 7.1 | SHOULD | deployment | behavioural_positive | Restricted agents SHOULD list specific origins in Access-Control-Allow-Origin | — | — |
| CORE-§7.2-01 | 7.2 | SHOULD | sdk | behavioural_positive | Agents SHOULD expose a capability discovery endpoint at GET /.well-known/arsia/capabilities | arsia-capability-descriptor | — |
| CORE-§7.2-02 | 7.2 | REQUIRED | sdk | structural | Capability descriptor MUST include capability as the identifier string | arsia-capability-descriptor | ITV-57 |
| CORE-§7.2-03 | 7.2 | OPTIONAL | sdk | structural | Capability descriptor MAY include rate_limit as requests per minute | arsia-capability-descriptor | — |
| CORE-§7.2-04 | 7.2 | MUST | sdk | behavioural_positive | Prerequisite capabilities listed in requires MUST be present in the request capabilities array | arsia-capability-descriptor | — |
| CORE-§7.2-05 | 7.2 | SHOULD | sdk_enabled | behavioural_positive | Senders SHOULD handle pending_approval responses when human_oversight_required is true | arsia-capability-descriptor | — |
| CORE-§7.2-06 | 7.2 | REQUIRED | sdk | structural | Capability descriptor MUST include description as a human-readable string | arsia-capability-descriptor | — |
| CORE-§7.2-07 | 7.2 | REQUIRED | sdk | structural | Capability descriptor MUST include risk_level as an integer from 0 (no risk) to 10 (critical) | arsia-capability-descriptor | ITV-58 |
| CORE-§7.2-08 | 7.2 | OPTIONAL | sdk | structural | Capability descriptor MAY include requires as an array of prerequisite capability strings | arsia-capability-descriptor | — |
| CORE-§7.2-09 | 7.2 | REQUIRED | sdk | structural | Capability descriptor MUST include human_oversight_required as a boolean | arsia-capability-descriptor | — |
| CORE-§7.3-01 | 7.3 | MUST | sdk | behavioural_positive | Every ARSIA agent MUST expose a JWKS endpoint at GET /.well-known/arsia/jwks.json | arsia-jwk-entry | — |
| CORE-§7.3-02 | 7.3 | REQUIRED | sdk | structural | Ed25519 JWK kty field MUST be "OKP" (Octet Key Pair) | arsia-jwk-entry | ITV-35, ITV-37 |
| CORE-§7.3-03 | 7.3 | REQUIRED | sdk | structural | P-256 JWK kty field MUST be "EC" | arsia-jwk-entry | ITV-127 |
| CORE-§7.3-04 | 7.3 | MUST | sdk | structural | JWK kid format MUST be {agent-id}#{keyN} for global uniqueness | arsia-jwk-entry | — |
| CORE-§7.3-05 | 7.3 | MUST | sdk | behavioural_positive | Agents supporting encryption MUST publish encryption public keys in JWKS with use "enc" | arsia-jwk-entry | ITV-36, ITV-129 |
| CORE-§7.3-06 | 7.3 | MUST | sdk | procedural | Agents MUST support key rotation to limit key compromise impact | — | — |
| CORE-§7.3-07 | 7.3 | MUST | sdk_enabled | procedural | Key rotation MUST publish both old and new keys in JWKS for minimum 24-hour overlap | — | — |
| CORE-§7.3-08 | 7.3 | MAY | sdk | behavioural_positive | Old signing key MAY be removed from JWKS after the 24-hour overlap period | — | — |
| CORE-§7.3-09 | 7.3 | SHOULD | operational_policy | procedural | Agents SHOULD generate new signing keys at least every 90 days | — | — |
| CORE-§7.3-10 | 7.3 | MUST | sdk_enabled | procedural | Compromised key MUST be removed from JWKS immediately, overriding the 24-hour overlap | — | — |
| CORE-§7.3-11 | 7.3 | MUST | sdk_enabled | behavioural_negative | Tokens and signatures produced with a compromised key MUST be considered invalid | — | — |
| CORE-§7.3-12 | 7.3 | SHOULD | sdk | behavioural_positive | JWKS endpoint SHOULD set Cache-Control: max-age=3600 for caching efficiency | — | — |
| CORE-§7.3-13 | 7.3 | SHOULD | sdk | behavioural_positive | Emergency key rotation SHOULD temporarily reduce the JWKS Cache-Control max-age | — | — |
| CORE-§7.3-14 | 7.3 | REQUIRED | sdk | structural | Ed25519 JWK crv field MUST be "Ed25519" | arsia-jwk-entry | — |
| CORE-§7.3-15 | 7.3 | REQUIRED | sdk | structural | Ed25519 JWK kid field MUST be a unique key identifier within the JWKS | arsia-jwk-entry | — |
| CORE-§7.3-16 | 7.3 | REQUIRED | sdk | structural | Ed25519 JWK x field MUST be a base64url-encoded 32-byte public key without padding | arsia-jwk-entry | — |
| CORE-§7.3-17 | 7.3 | REQUIRED | sdk | structural | Ed25519 signing JWK use field MUST be "sig" | arsia-jwk-entry | — |
| CORE-§7.3-18 | 7.3 | REQUIRED | sdk | structural | P-256 JWK crv field MUST be "P-256" | arsia-jwk-entry | ITV-127, ITV-128 |
| CORE-§7.3-19 | 7.3 | REQUIRED | sdk | structural | P-256 JWK kid field MUST be a unique key identifier | arsia-jwk-entry | — |
| CORE-§7.3-20 | 7.3 | REQUIRED | sdk | structural | P-256 JWK x field MUST be the base64url-encoded x-coordinate | arsia-jwk-entry | — |
| CORE-§7.3-21 | 7.3 | REQUIRED | sdk | structural | P-256 JWK y field MUST be the base64url-encoded y-coordinate | arsia-jwk-entry | — |
| CORE-§7.3-22 | 7.3 | REQUIRED | sdk | structural | P-256 signing JWK use field MUST be "sig" | arsia-jwk-entry | — |
| CORE-§7.4-01 | 7.4 | MUST | sdk | behavioural_negative | Version negotiation failure MUST return not_implemented error with supported_versions in details | arsia-message | — |
| CORE-§7.4-02 | 7.4 | MUST | sdk | behavioural_positive | Agents MUST accept messages with v within their supported range, ignoring unknown fields | — | ITV-438 |
| CORE-§7.4-03 | 7.4 | MUST | sdk | interoperability | Unknown fields from a later minor version MUST be preserved when forwarding messages | — | ITV-439 |
| CORE-§7.4-04 | 7.4 | SHOULD | sdk | interoperability | Unknown fields from a later minor version SHOULD be ignored during processing | — | ITV-438, ITV-439 |
| CORE-§7.4-05 | 7.4 | MUST_NOT | sdk_enabled | behavioural_negative | Agents MUST NOT send messages with v higher than the recipient's server_max | — | — |
| CORE-§7.4-06 | 7.4 | SHOULD | sdk_enabled | behavioural_positive | Senders SHOULD query the recipient's discovery endpoint before first contact and cache it | — | — |
| CORE-§8-01 | 8 | REQUIRED | deployment | interoperability | HTTP/2 transport binding is REQUIRED for all ARSIA implementations | — | — |
| CORE-§8-02 | 8 | OPTIONAL | sdk_enabled | interoperability | WebSocket transport binding is OPTIONAL for ARSIA implementations | arsia-websocket-frame | — |
| CORE-§8-03 | 8 | MAY | sdk_enabled | interoperability | Additional transport bindings MAY be defined if they preserve the envelope and enforce §5/§6 security | — | — |
| CORE-§8.1-01 | 8.1 | MUST | deployment | interoperability | All conformant implementations MUST support the HTTP/2 transport binding | — | — |
| CORE-§8.1-02 | 8.1 | MUST | sdk | behavioural_negative | Requests with unsupported Content-Type MUST be rejected with HTTP 415 | — | — |
| CORE-§8.1-03 | 8.1 | MUST | sdk | behavioural_positive | HTTP response body MUST be an ARSIA envelope with intent response/error/pending_approval | arsia-message | CTV-08 |
| CORE-§8.1-04 | 8.1 | MUST | sdk_enabled | behavioural_positive | Async status endpoint MUST return 202 (in-progress), 200 (complete), or 410 (expired) | — | — |
| CORE-§8.1-05 | 8.1 | MUST | deployment | interoperability | All ARSIA HTTP connections MUST use TLS 1.3 or later | — | — |
| CORE-§8.1-06 | 8.1 | MAY | deployment | interoperability | TLS 1.2 MAY be accepted as a fallback for HTTP connections | — | — |
| CORE-§8.1-07 | 8.1 | MUST | deployment | interoperability | TLS 1.3 MUST be preferred over TLS 1.2 when both are supported | — | — |
| CORE-§8.1-08 | 8.1 | RECOMMENDED | deployment | interoperability | HTTP Strict Transport Security (HSTS) per RFC 6797 is RECOMMENDED | — | — |
| CORE-§8.1-09 | 8.1 | SHOULD | deployment | behavioural_positive | HSTS header SHOULD include max-age=31536000 and includeSubDomains | — | — |
| CORE-§8.1-10 | 8.1 | MUST_NOT | deployment | behavioural_negative | Plaintext HTTP connections MUST NOT be accepted for any ARSIA endpoint | — | — |
| CORE-§8.2-01 | 8.2 | MUST | deployment | interoperability | WebSocket connections MUST use the wss:// scheme (TLS-encrypted) | — | — |
| CORE-§8.2-02 | 8.2 | MUST_NOT | deployment | behavioural_negative | Plaintext ws:// connections MUST NOT be used for ARSIA | — | — |
| CORE-§8.2-03 | 8.2 | MUST | deployment | interoperability | WebSocket sub-protocol "arsia-v1" MUST be declared during the HTTP upgrade handshake | — | — |
| CORE-§8.2-04 | 8.2 | MUST | deployment | behavioural_positive | Server MUST respond with "arsia-v1" as the selected WebSocket sub-protocol | — | — |
| CORE-§8.2-05 | 8.2 | MUST | sdk_enabled | procedural | WebSocket client MUST authenticate via auth frame before sending ARSIA messages | arsia-websocket-frame | ITV-59, ITV-62, ITV-141 |
| CORE-§8.2-06 | 8.2 | MUST | deployment | behavioural_negative | Failed WebSocket auth MUST close connection with code 4001 within 5 seconds | arsia-websocket-frame | ITV-61 |
| CORE-§8.2-07 | 8.2 | MUST_NOT | deployment | behavioural_negative | Binary WebSocket frames MUST NOT be used for ARSIA messages | — | — |
| CORE-§8.2-08 | 8.2 | MUST | deployment | procedural | WebSocket client MUST send a ping heartbeat frame every 30 seconds | arsia-websocket-frame | ITV-142 |
| CORE-§8.2-09 | 8.2 | MUST | deployment | behavioural_positive | Server MUST respond to WebSocket ping with pong within 5 seconds | arsia-websocket-frame | ITV-143 |
| CORE-§8.2-10 | 8.2 | SHOULD | deployment | behavioural_positive | Server SHOULD close WebSocket with code 4002 if no ping received within 60 seconds | — | — |
| CORE-§8.2-11 | 8.2 | SHOULD | deployment | behavioural_positive | Client SHOULD close and reconnect if no pong received within 10 seconds of ping | — | — |
| CORE-§8.2-12 | 8.2 | SHOULD | sdk_enabled | procedural | Lost WebSocket connections SHOULD reconnect using exponential backoff (max 30 seconds) | — | — |
| CORE-§8.2-13 | 8.2 | RECOMMENDED | sdk_enabled | interoperability | Reconnection backoff jitter of ±25% is RECOMMENDED to avoid thundering herd | — | — |
| CORE-§8.2-14 | 8.2 | MUST | sdk_enabled | procedural | WebSocket client MUST re-authenticate after every reconnection | — | — |
| CORE-§8.2-15 | 8.2 | MUST_NOT | deployment | behavioural_negative | Server MUST NOT assume a reconnected WebSocket client retains prior auth state | — | — |
| CORE-§8.2-16 | 8.2 | MUST | deployment | behavioural_negative | Oversized WebSocket frames MUST cause closure with code 4003 (Message Too Large) | — | — |
| CORE-§8.2-17 | 8.2 | MUST | sdk_enabled | procedural | WebSocket agents MUST use idempotency.key envelope field (not HTTP header) as sole idempotency mechanism | arsia-message | ITV-543 |
| CORE-§8.2-18 | 8.2 | MUST | deployment | behavioural_positive | WebSocket duplicate detection MUST return stored response envelope as JSON text frame | — | ITV-544 |
| CORE-§8.3-01 | 8.3 | SHOULD | sdk_enabled | behavioural_positive | Senders SHOULD set their client timeout to match the recipient's request_timeout_ms | — | — |
| CORE-§8.3-02 | 8.3 | SHOULD | sdk_enabled | behavioural_positive | Sender SHOULD treat request as failed if no synchronous response within the timeout period | — | — |
| CORE-§8.3-03 | 8.3 | SHOULD_NOT | sdk_enabled | behavioural_negative | Sender SHOULD NOT retry immediately after a request timeout (see §11.3) | — | — |
| CORE-§8.3-04 | 8.3 | MAY | sdk_enabled | behavioural_positive | Sender MAY check the async status URL after timeout if one was provided | — | — |
| CORE-§8.3-05 | 8.3 | SHOULD | deployment | behavioural_positive | Idle WebSocket connections (no frames for 60 seconds) SHOULD be closed by the server | — | — |
| CORE-§8.3-06 | 8.3 | MAY | sdk | behavioural_positive | Messages with ts differing more than ±300 seconds (default, may be overridden by compliance profile) from recipient time MAY be rejected | — | ITV-440 |
| CORE-§8.3-07 | 8.3 | SHOULD | deployment | behavioural_positive | Implementations SHOULD synchronise clocks using NTP or equivalent time protocol | — | — |
| CORE-§8.3-08 | 8.3 | SHOULD | deployment | behavioural_positive | Compliance-sensitive agents SHOULD use multiple NTP sources and log drift exceeding 10 seconds | — | — |
| CORE-§8.3-09 | 8.3 | MUST | sdk | behavioural_positive | When compliance profile defines clock_skew_seconds, that value MUST be used instead of the 300s default | arsia-compliance-profiles | ITV-545, ITV-546, ITV-547 |
| CORE-§8.3-10 | 8.3 | MUST_NOT | schema | constraint | Profile clock_skew_seconds MUST NOT exceed 300 seconds (maximum: 300 in schema enforces this) | arsia-compliance-profiles | — |
| CORE-§9.1-01 | 9.1 | MUST | sdk | interoperability | Direct routing alone MUST be sufficient for Core conformance (§12.1) | — | — |
| CORE-§9.1-02 | 9.1 | MUST | sdk_enabled | procedural | Sender MUST resolve the recipient's inbox URL via the discovery endpoint (§7.1) | — | — |
| CORE-§9.1-03 | 9.1 | MUST | sdk_enabled | procedural | Sender MUST present a valid access token per §6.3 with each request | — | — |
| CORE-§9.1-04 | 9.1 | MUST | sdk | procedural | Sender MUST sign every outgoing message per §5.1 | — | — |
| CORE-§9.1-05 | 9.1 | MUST | sdk | procedural | Receiver MUST verify signature (§5.2), validate access token (§6.4), and process the message | — | — |
| CORE-§9.1-06 | 9.1 | MUST | sdk | behavioural_positive | Receiver MUST return response synchronously (HTTP 200) or accept async (HTTP 202) | — | — |
| CORE-§9.2-01 | 9.2 | OPTIONAL | sdk | informational | Compliance brokers are OPTIONAL in the ARSIA protocol | — | — |
| CORE-§9.2-02 | 9.2 | REQUIRED | sdk | behavioural_positive | Broker routing is REQUIRED when compliance.data_residency is set in the message | — | — |
| CORE-§9.2-03 | 9.2 | MUST | sdk_enabled | procedural | Sender MUST route through a broker whose servers reside in the declared residency zone | — | — |
| CORE-§9.2-04 | 9.2 | MUST_NOT | sdk_enabled | behavioural_negative | Sender MUST NOT bypass broker routing even if direct connectivity is available | — | — |
| CORE-§9.2-05 | 9.2 | MUST_NOT | external | behavioural_negative | Compliance brokers MUST NOT modify message envelope contents | — | — |
| CORE-§9.2-06 | 9.2 | MUST | external | interoperability | Broker-forwarded message MUST be byte-identical to original after JSON canonicalization | — | — |
| CORE-§9.2-07 | 9.2 | MUST | external | procedural | Compliance brokers MUST append an audit record for every relayed message | arsia-broker-relay-audit | — |
| CORE-§9.2-08 | 9.2 | MUST | external | behavioural_positive | Broker audit record MUST include message id, from, to, ts, broker id, relay timestamp, and zone | arsia-broker-relay-audit | — |
| CORE-§9.2-09 | 9.2 | MAY | deployment | informational | Broker discovery endpoint MAY be hosted by any ARSIA infrastructure service | — | — |
| CORE-§9.2-10 | 9.2 | MUST_NOT | sdk_enabled | behavioural_negative | Sender MUST NOT send the message if no broker is available for the required residency zone | — | — |
| CORE-§9.2-11 | 9.2 | MUST | sdk | behavioural_negative | Missing broker MUST produce service_unavailable error with data_residency_violation details | arsia-message | — |
| CORE-§9.3-01 | 9.3 | MUST | external | behavioural_positive | Compliance broker servers MUST physically reside within the declared residency zone | arsia-broker-entry | — |
| CORE-§9.3-02 | 9.3 | OPTIONAL | sdk | informational | Federated (multi-hop) routing topology is OPTIONAL and out of scope for ARSIA v1.0 | — | — |
| CORE-§9.4-01 | 9.4 | MUST | sdk | procedural | Sending agents MUST implement the topology determination procedure defined in ARSIA-Routing §1.3 (or equivalent) for routing | — | — |
| CORE-§9.4-02 | 9.4 | MAY | sdk | behavioural_positive | Broker selection MAY use advanced strategies (load balancing, failover) if within required zone | — | — |
| CORE-§10.1-01 | 10.1 | MUST | sdk | behavioural_positive | Idempotency key MUST be unique within the (from, to, payload.type) tuple scope | arsia-message | — |
| CORE-§10.1-02 | 10.1 | MAY | sdk | structural | Idempotency key MAY contain any printable ASCII character (0x20–0x7E), 1–128 chars | arsia-message | — |
| CORE-§10.1-03 | 10.1 | SHOULD | sdk_enabled | behavioural_positive | Idempotency keys SHOULD be domain-meaningful identifiers (invoice number, UUID, etc.) | — | — |
| CORE-§10.2-01 | 10.2 | MUST | sdk | procedural | Idempotency support is REQUIRED for Core conformance; agents MUST implement key storage | — | — |
| CORE-§10.2-02 | 10.2 | MUST | sdk | behavioural_positive | Server MUST store the idempotency key-to-response mapping scoped by (from, to, payload.type) | — | — |
| CORE-§10.2-03 | 10.2 | MUST | sdk | behavioural_positive | Stored idempotency mapping MUST be retained until idempotency.expires_at | — | — |
| CORE-§10.2-04 | 10.2 | MUST | sdk | behavioural_positive | Header-only idempotency key MUST be retained for a minimum of 24 hours | — | — |
| CORE-§10.2-05 | 10.2 | MUST | deployment | behavioural_positive | Idempotency storage MUST survive server restarts within the retention window in production | — | — |
| CORE-§10.2-06 | 10.2 | MAY | sdk | behavioural_positive | Server MAY delete stored idempotency mappings after the retention window expires | — | — |
| CORE-§10.3-01 | 10.3 | MUST | sdk | behavioural_positive | Duplicate idempotency key MUST return the stored response without re-executing | — | — |
| CORE-§10.3-02 | 10.3 | MUST | sdk | behavioural_positive | Duplicate response HTTP status code MUST be identical to the original response | — | — |
| CORE-§10.3-03 | 10.3 | MUST | sdk | behavioural_positive | Duplicate response body MUST be the exact ARSIA envelope from original processing | — | — |
| CORE-§10.3-04 | 10.3 | SHOULD | sdk | behavioural_positive | In-progress duplicate SHOULD return HTTP 409 (Conflict) with Retry-After header | — | — |
| CORE-§10.4-01 | 10.4 | MUST | sdk | behavioural_positive | HTTP Idempotency-Key header takes precedence over envelope idempotency.key for detection (HTTP transport only) | — | — |
| CORE-§10.4-02 | 10.4 | SHOULD | sdk | behavioural_positive | Server SHOULD log discrepancies between header and envelope idempotency key values | — | — |
| CORE-§11.1-01 | 11.1 | MUST | sdk | structural | Error response envelope intent field MUST be "error" | arsia-message | — |
| CORE-§11.1-02 | 11.1 | MUST | sdk | behavioural_positive | Error response correlation_id MUST match the id of the original message | arsia-message | — |
| CORE-§11.1-03 | 11.1 | SHOULD | sdk | behavioural_positive | Error payload.type SHOULD match the original request type, or default to "arsiaprotocol.error" | — | ITV-441 |
| CORE-§11.1-04 | 11.1 | MUST | sdk | structural | Error response envelope MUST include a payload.error object per §4.4.6 | arsia-message | — |
| CORE-§11.1-05 | 11.1 | REQUIRED | sdk | structural | payload.error.code (string) is REQUIRED; MUST be a standard error code from §11.2 | arsia-message | — |
| CORE-§11.1-06 | 11.1 | REQUIRED | sdk | structural | payload.error.description (string) is REQUIRED; human-readable error message | arsia-message | — |
| CORE-§11.1-07 | 11.1 | OPTIONAL | sdk | structural | payload.error.details (object) is OPTIONAL; provides structured error context | arsia-message | — |
| CORE-§11.1-08 | 11.1 | MUST | sdk | behavioural_positive | Error description text MUST be written in English | — | — |
| CORE-§11.1-09 | 11.1 | MUST_NOT | sdk | behavioural_negative | Error description MUST NOT contain stack traces, DB queries, file paths, or credentials | — | — |
| CORE-§11.1.1-01 | 11.1.1 | MAY | sdk_enabled | interoperability | Transport-level HTTP errors (401, 403) MAY use plain JSON without ARSIA envelope or signing | arsia-message | — |
| CORE-§11.1.1-02 | 11.1.1 | SHOULD | sdk | behavioural_positive | Transport-level error responses SHOULD include at least a status and reason field | arsia-message | — |
| CORE-§11.2-01 | 11.2 | MUST | sdk | interoperability | Implementations MUST use the standard error codes for their defined conditions | arsia-message | ITV-73, ITV-74, ITV-75, ITV-79, ITV-83, ITV-84, ITV-148, ITV-149, ITV-150, ITV-151, ITV-152, ITV-153, ITV-154, ITV-155, ITV-156, ITV-157, ITV-158, ITV-159, ITV-160, ITV-14 |
| CORE-§11.2-02 | 11.2 | MAY | sdk | interoperability | Implementations MAY define custom error codes using reverse domain notation | — | — |
| CORE-§11.2-03 | 11.2 | MUST_NOT | sdk | behavioural_negative | Implementations MUST NOT redefine the meaning of standard ARSIA error codes | — | — |
| CORE-§11.2-04 | 11.2 | MUST | sdk | structural | Forbidden (403) error details MUST include required_capabilities and provided_capabilities | arsia-message | — |
| CORE-§11.2-05 | 11.2 | MUST | sdk | structural | not_implemented (501) error details MUST include supported_versions with min and max | arsia-message | ITV-15, ITV-155 |
| CORE-§11.2-06 | 11.2 | SHOULD | sdk | structural | not_implemented caused by unsupported payload type SHOULD include unsupported_type in details | arsia-message | ITV-155 |
| CORE-§11.2-07 | 11.2 | SHOULD | sdk | structural | rate_limited (429) error details SHOULD include retry_after_seconds, limit, remaining, and reset_at | arsia-message | ITV-83, ITV-153, ITV-534 |
| CORE-§11.2-08 | 11.2 | SHOULD | sdk | structural | payload_too_large (413) error details SHOULD include max_message_bytes and actual_bytes | arsia-message | ITV-84, ITV-152, ITV-535 |
| CORE-§11.2-09 | 11.2 | MUST | sdk | structural | service_unavailable from data residency violation MUST include data_residency_violation and required_zone | arsia-message | ITV-156 |
| CORE-§11.3-01 | 11.3 | MUST_NOT | sdk_enabled | behavioural_negative | Agents MUST NOT retry non-retryable errors (4xx except 429) without modifying the request. Exception: conflict (409) with Retry-After header for idempotent in-progress requests — agent SHOULD retry identical request per §10.3 | — | — |
| CORE-§11.3-02 | 11.3 | MUST_NOT | sdk_enabled | behavioural_negative | Agent MUST NOT retry immediately after receiving a rate_limited (429) error | — | — |
| CORE-§11.3-03 | 11.3 | MUST | sdk_enabled | behavioural_positive | Agent MUST honour the Retry-After header before retrying a rate_limited error | — | — |
| CORE-§11.3-04 | 11.3 | SHOULD | sdk_enabled | behavioural_positive | Agent SHOULD use retry_after_seconds from error details when no Retry-After header is present | — | — |
| CORE-§11.3-05 | 11.3 | SHOULD | sdk_enabled | behavioural_positive | Agent SHOULD wait at least 60 seconds before retrying when no retry timing is provided | — | — |
| CORE-§11.3-06 | 11.3 | SHOULD | sdk | behavioural_positive | 5xx errors SHOULD be retried using exponential backoff (1s base, 2x multiplier, 32s max, 3 retries) | — | — |
| CORE-§11.3-07 | 11.3 | RECOMMENDED | sdk_enabled | behavioural_positive | Retry jitter of ±25% of the computed delay is RECOMMENDED for exponential backoff | — | — |
| CORE-§11.3-08 | 11.3 | MUST | sdk | behavioural_positive | Agent MUST abandon the request and report failure after 3 failed retries | — | — |
| CORE-§11.3-09 | 11.3 | SHOULD | sdk_enabled | behavioural_positive | Failure report SHOULD include the error code and description from the last retry attempt | — | — |
| CORE-§11.3-10 | 11.3 | RECOMMENDED | sdk_enabled | behavioural_positive | Retry jitter is RECOMMENDED to prevent thundering herd on a recovering server | — | — |
| CORE-§11.3-11 | 11.3 | SHOULD | sdk_enabled | behavioural_positive | Implementations SHOULD use uniform random jitter: base_delay × (0.75 + random() × 0.5) | — | — |
| CORE-§12.1-01 | 12.1 | MUST | external | interoperability | Core conformance MUST implement agent-id, envelope, EdDSA, auth, discovery, JWKS, HTTP/2, routing, idempotency, and errors | — | — |
| CORE-§12.2-01 | 12.2 | MUST | external | interoperability | Compliance conformance MUST meet Core plus compliance fields, profiles, audit trail, oversight, and broker routing | — | — |
| CORE-§12.3-01 | 12.3 | MUST | external | interoperability | Full conformance MUST implement Compliance requirements plus all 5 primitives, WebSocket, encryption, and ES256 | — | — |
| CORE-§12.4-01 | 12.4 | MUST | external | interoperability | Compliance-level implementations MUST pass all compliance field conformance tests in §12.4 | — | — |
| CORE-§13.3-01 | 13.3 | MUST_NOT | deployment | behavioural_negative | Distributed tracing infrastructure MUST NOT be required for protocol compliance | — | — |
| CORE-§13.3-02 | 13.3 | MUST_NOT | operational_policy | behavioural_negative | Agent identifiers MUST NOT contain personally identifiable information | — | — |
| CORE-§13.3-03 | 13.3 | OPTIONAL | sdk | structural | context.trace_id and context.span_id fields are OPTIONAL; agents MAY omit them | arsia-message | — |
| CORE-§14.1-01 | 14.1 | MUST | sdk | behavioural_positive | Recipients MUST verify the Content-Type v parameter equals the major version component of the envelope v field | — | ITV-442 |
| CORE-§14.1-02 | 14.1 | SHOULD | sdk | behavioural_negative | Content-Type v parameter mismatch SHOULD be treated as an invalid_request error | — | ITV-442, ITV-443 |

---

## Coverage Gaps

Generated: 2026-05-04 (audited)

### Summary

| Metric | Count |
|--------|------:|
| Total requirements | 388 |
| Schema ≠ — | 165 |
| Vector ≠ — | 132 |
| Both ≠ — | 71 |
| Both = — (gaps) | 162 |

### Per-section breakdown

| § | Total | Schema ≠ — | Vector ≠ — | Both ≠ — | Both = — |
|---|-------|-----------|-----------|---------|---------|
| 1 | 1 | 0 | 0 | 0 | 1 |
| 2 | 12 | 6 | 2 | 2 | 6 |
| 3 | 12 | 7 | 3 | 3 | 5 |
| 4 | 131 | 70 | 68 | 37 | 30 |
| 5 | 34 | 7 | 19 | 4 | 12 |
| 6 | 34 | 19 | 12 | 5 | 8 |
| 7 | 46 | 25 | 10 | 7 | 18 |
| 8 | 41 | 9 | 9 | 7 | 30 |
| 9 | 21 | 4 | 0 | 0 | 17 |
| 10 | 15 | 2 | 0 | 0 | 13 |
| 11 | 31 | 15 | 7 | 6 | 15 |
| 12 | 4 | 0 | 0 | 0 | 4 |
| 13 | 3 | 1 | 0 | 0 | 2 |
| 14 | 2 | 0 | 2 | 0 | 0 |
| 16 | 1 | 0 | 0 | 0 | 1 |
