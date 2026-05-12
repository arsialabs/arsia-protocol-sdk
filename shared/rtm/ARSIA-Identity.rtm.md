<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda) -->
# ARSIA-Identity — Requirements Traceability Matrix

| ID | § | Modal | Layer | Kind | Requirement | Schema | Vector |
|----|---|-------|-------|------|-------------|--------|--------|
| IDENT-§1.1-01 | 1.1 | MUST | sdk | behavioural_positive | Identity three layers (technical, cryptographic, compliance) MUST all be present and consistent for full identification | arsia-identity-record, arsia-jwk-entry | — |
| IDENT-§1.1-02 | 1.1 | MUST | sdk | behavioural_positive | Identity layers MUST be consistent: agent-id, signing key kid prefix, and IdentityRecord owner MUST all correspond | — | — |
| IDENT-§1.1-03 | 1.1 | MUST | sdk | behavioural_positive | Message signature kid prefix MUST match the sending agent's agent-id | arsia-jwk-entry | ITV-444, ITV-445 |
| IDENT-§1.1-04 | 1.1 | MUST | deployment | behavioural_positive | Agent signing key MUST be published at the JWKS endpoint on the same domain infrastructure | — | — |
| IDENT-§1.1-05 | 1.1 | MUST | sdk | behavioural_positive | IdentityRecord MUST declare the owning legal entity via owner_id and owner_name fields | arsia-identity-record | — |
| IDENT-§1.1-06 | 1.1 | MUST | sdk | behavioural_positive | High-risk agents MUST include compliance metadata in all outbound request and response messages | arsia-message | — |
| IDENT-§1.1-07 | 1.1 | MUST | sdk | behavioural_negative | Receiving agent MUST reject or log a compliance warning when identity layer inconsistency is detected | — | ITV-445 |
| IDENT-§1.2-01 | 1.2 | REQUIRED | sdk | structural | IdentityRecord agent_id field (string) is REQUIRED | arsia-identity-record | — |
| IDENT-§1.2-02 | 1.2 | REQUIRED | sdk | structural | IdentityRecord owner_id field (string) is REQUIRED as a verifiable legal entity identifier | arsia-identity-record | — |
| IDENT-§1.2-03 | 1.2 | MAY | sdk | informational | Agents MAY be owned by entities registered in any jurisdiction | — | — |
| IDENT-§1.2-04 | 1.2 | MUST | sdk | structural | owner_id MUST be a verifiable legal entity ID (EU VAT, US EIN, LEI, DUNS, national registration, or URN) | arsia-identity-record | — |
| IDENT-§1.2-05 | 1.2 | SHOULD | sdk_enabled | informational | Implementations SHOULD prefer LEI for owner_id when the entity has one | — | ITV-02 |
| IDENT-§1.2-06 | 1.2 | REQUIRED | sdk | structural | IdentityRecord owner_name field (string) is REQUIRED | arsia-identity-record | — |
| IDENT-§1.2-07 | 1.2 | MUST | sdk_enabled | structural | owner_name MUST be the registered legal name, not a trading name or brand | — | — |
| IDENT-§1.2-08 | 1.2 | REQUIRED | sdk | structural | IdentityRecord jurisdiction field (string, ISO 3166-1 alpha-2) is REQUIRED | arsia-identity-record | — |
| IDENT-§1.2-09 | 1.2 | REQUIRED | sdk | structural | IdentityRecord ai_system_classification field (string) is REQUIRED | arsia-identity-record | — |
| IDENT-§1.2-10 | 1.2 | MUST | sdk | structural | ai_system_classification MUST be one of: minimal-risk, limited-risk, high-risk, or unacceptable-risk | arsia-identity-record | — |
| IDENT-§1.2-11 | 1.2 | MAY | sdk | informational | Per-message ai_system_classification MAY equal or be lower than the IdentityRecord value | arsia-compliance-field | — |
| IDENT-§1.2-12 | 1.2 | MUST | sdk | behavioural_negative | Per-message ai_system_classification MUST NOT exceed the IdentityRecord-level classification | — | ITV-418, ITV-446 |
| IDENT-§1.2-13 | 1.2 | OPTIONAL | sdk | structural | IdentityRecord deployer_id field (string) is OPTIONAL for split-responsibility deployments | arsia-identity-record | ITV-124 |
| IDENT-§1.2-14 | 1.2 | OPTIONAL | sdk | structural | IdentityRecord deployer_name field (string) is OPTIONAL but REQUIRED when deployer_id is set | arsia-identity-record | ITV-522 |
| IDENT-§1.2-15 | 1.2 | MUST | sdk | behavioural_negative | deployer_name MUST be present whenever deployer_id is present | arsia-identity-record | ITV-01, ITV-522 |
| IDENT-§1.2-16 | 1.2 | REQUIRED | sdk | structural | deployer_name is conditionally REQUIRED when deployer_id is set | arsia-identity-record | ITV-522 |
| IDENT-§1.2-17 | 1.2 | REQUIRED | sdk | structural | IdentityRecord created_at field (string, RFC 3339 with ms precision) is REQUIRED | arsia-identity-record | ITV-124 |
| IDENT-§1.2-18 | 1.2 | OPTIONAL | sdk | structural | IdentityRecord valid_until field (string, RFC 3339 with ms precision) is OPTIONAL | arsia-identity-record | ITV-124 |
| IDENT-§1.2-19 | 1.2 | MUST | operational_policy | procedural | Agent operator MUST refresh the IdentityRecord after valid_until timestamp expires | — | — |
| IDENT-§1.2-20 | 1.2 | RECOMMENDED | operational_policy | informational | valid_until RECOMMENDED value is 90 days from created_at | — | — |
| IDENT-§1.2-21 | 1.2 | OPTIONAL | sdk | structural | IdentityRecord contact_email field (string) is OPTIONAL, RECOMMENDED for high-risk agents | arsia-identity-record | ITV-124 |
| IDENT-§1.2-22 | 1.2 | RECOMMENDED | sdk_enabled | informational | contact_email is RECOMMENDED for agents classified as high-risk | — | — |
| IDENT-§1.2-23 | 1.2 | MUST | sdk_enabled | structural | contact_email MUST be a role-based address, not a personal address | arsia-identity-record | — |
| IDENT-§1.3-01 | 1.3 | MUST | deployment | behavioural_positive | Agent MUST serve IdentityRecord at GET /.well-known/arsia/identity | — | — |
| IDENT-§1.3-02 | 1.3 | MUST | deployment | behavioural_positive | Identity endpoint MUST be available alongside the ARSIA-Core §7.1 discovery endpoint | — | — |
| IDENT-§1.3-03 | 1.3 | MUST | deployment | behavioural_positive | Identity endpoint MUST be served over TLS 1.3 or higher | — | — |
| IDENT-§1.3-04 | 1.3 | MUST | deployment | behavioural_positive | Identity endpoint response MUST include X-ARSIA-Sig header with Ed25519 signature over SHA-256 of body | — | — |
| IDENT-§1.3-05 | 1.3 | MUST | sdk | behavioural_negative | IdentityRecord MUST be treated as untrusted if X-ARSIA-Sig verification fails | — | — |
| IDENT-§1.3-06 | 1.3 | SHOULD | deployment | informational | Identity endpoint response SHOULD include Cache-Control and ETag headers | — | — |
| IDENT-§1.3-07 | 1.3 | SHOULD | deployment | behavioural_positive | Clients SHOULD respect identity endpoint caching headers | — | — |
| IDENT-§1.3-08 | 1.3 | SHOULD | deployment | behavioural_positive | Clients SHOULD refetch IdentityRecord on message signature verification failure | — | — |
| IDENT-§2.1-01 | 2.1 | REQUIRED | sdk | behavioural_positive | Ed25519 (EdDSA over Curve25519) is the REQUIRED signing algorithm for ARSIA Protocol v1.0 | arsia-jwk-entry | ITV-35 |
| IDENT-§2.1-02 | 2.1 | REQUIRED | sdk | behavioural_positive | Ed25519 is the only REQUIRED signing algorithm; no other algorithm is mandatory | arsia-jwk-entry | — |
| IDENT-§2.1-03 | 2.1 | MAY | sdk | informational | Implementations MAY support additional signing algorithms listed in ARSIA-Core §5.1 | — | ITV-127, ITV-551, ITV-552 |
| IDENT-§2.1-04 | 2.1 | MUST | sdk | behavioural_positive | All implementations MUST support Ed25519 signing | arsia-jwk-entry | ITV-35 |
| IDENT-§2.1-05 | 2.1 | MUST_NOT | deployment | behavioural_negative | Private keys MUST NOT be stored in plaintext on disk in production | — | — |
| IDENT-§2.1-06 | 2.1 | RECOMMENDED | deployment | informational | HSM or cloud KMS (AWS KMS, GCP Cloud KMS, Azure Key Vault) is RECOMMENDED for private key storage | — | — |
| IDENT-§2.1-07 | 2.1 | MAY | deployment | informational | Development environments MAY use environment variables for private key storage | — | — |
| IDENT-§2.1-08 | 2.1 | MUST_NOT | deployment | behavioural_negative | Environment-variable private key storage MUST NOT be used in production | — | — |
| IDENT-§2.1-09 | 2.1 | MUST | deployment | behavioural_positive | Agent public key MUST be published at /.well-known/arsia/jwks.json per ARSIA-Core §7.3 | — | — |
| IDENT-§2.2-01 | 2.2 | MUST | sdk | structural | JWK kid field MUST follow the pattern {agent-id}#{key-index} | arsia-jwk-entry | — |
| IDENT-§2.2-02 | 2.2 | MUST | sdk | structural | kid MUST be globally unique within the agent's JWKS | arsia-jwk-entry | — |
| IDENT-§2.2-03 | 2.2 | MUST_NOT | deployment | behavioural_negative | kid MUST NOT be reused after the corresponding key is retired, even with identical key material | — | — |
| IDENT-§2.2-04 | 2.2 | SHOULD | sdk | informational | Generating a new key with identical material as a retired key SHOULD be avoided | — | — |
| IDENT-§2.3-01 | 2.3 | MUST | sdk | structural | Each Ed25519 JWK entry MUST contain kty, crv, kid, x, and use fields | arsia-jwk-entry | ITV-35, ITV-37 |
| IDENT-§2.3-02 | 2.3 | REQUIRED | sdk | structural | JWK use field value sig is REQUIRED for Ed25519 key entries | arsia-jwk-entry | ITV-35 |
| IDENT-§2.4-01 | 2.4 | MUST | deployment | procedural | Key rotation MUST follow the prescribed procedure: generate, add to JWKS, overlap, switch signing, remove old key | — | — |
| IDENT-§2.4-02 | 2.4 | MUST | operational_policy | procedural | Both old and new keys MUST be present in the JWKS simultaneously during the overlap period | — | — |
| IDENT-§2.4-03 | 2.4 | MUST | operational_policy | behavioural_positive | Key rotation overlap period MUST be at least 24 hours | — | — |
| IDENT-§2.4-04 | 2.4 | RECOMMENDED | operational_policy | informational | 72-hour key rotation overlap period is RECOMMENDED | — | — |
| IDENT-§2.4-05 | 2.4 | MUST | sdk | behavioural_positive | Recipients MUST accept signatures from both old and new keys during the overlap period | — | — |
| IDENT-§2.4-06 | 2.4 | SHOULD | operational_policy | informational | Key rotation SHOULD be automated via triggers such as age, compromise, or policy change | — | — |
| IDENT-§2.4-07 | 2.4 | RECOMMENDED | operational_policy | informational | Maximum key lifetime of 90 days is RECOMMENDED as a rotation trigger | — | — |
| IDENT-§2.5-01 | 2.5 | SHOULD | sdk_enabled | procedural | Implementations SHOULD achieve key revocation by removing the compromised key from JWKS and rotating immediately | — | — |
| IDENT-§2.5-02 | 2.5 | RECOMMENDED | operational_policy | informational | Short key validity periods (90 days RECOMMENDED) limit revocation exposure | — | — |
| IDENT-§2.5-03 | 2.5 | SHOULD | deployment | behavioural_positive | JWKS-caching recipients SHOULD refetch on signature verification failure for near-immediate revocation propagation | — | — |
| IDENT-§2.5-04 | 2.5 | RECOMMENDED | sdk | behavioural_positive | JWKS cache TTL RECOMMENDED maximum is 1 hour | — | — |
| IDENT-§2.5-05 | 2.5 | MAY | sdk | informational | Future protocol versions MAY define a formal key revocation mechanism (CRL or OCSP-like) | — | — |
| IDENT-§3.1-01 | 3.1 | MUST | sdk | structural | Every ARSIA message MUST carry a security object with alg, kid, and sig fields | arsia-message | — |
| IDENT-§3.1-02 | 3.1 | MUST | sdk | procedural | Recipient MUST verify message signature using the 10-step EdDSA verification procedure | — | — |
| IDENT-§3.1-03 | 3.1 | SHOULD | sdk | behavioural_positive | Recipients SHOULD cache JWKS responses for up to 1 hour, respecting Cache-Control headers | — | — |
| IDENT-§3.1-04 | 3.1 | SHOULD | sdk | behavioural_positive | Recipient SHOULD refetch JWKS once on verification failure before rejecting the message | — | — |
| IDENT-§3.1-05 | 3.1 | MAY | sdk | behavioural_positive | Sandbox/development implementations MAY relax EdDSA verification for non-production environments | — | — |
| IDENT-§3.1-06 | 3.1 | MUST | sdk | behavioural_positive | Relaxed-verification implementations MUST log a warning for each unverified request | — | — |
| IDENT-§3.1-07 | 3.1 | MUST_NOT | deployment | behavioural_negative | Production deployments MUST NOT use open registration mode | — | — |
| IDENT-§3.2-01 | 3.2 | MUST | sdk | behavioural_positive | Request-intent messages MUST include a Bearer or DPoP-bound access token per ARSIA-Core §6 | arsia-jwt-claims | — |
| IDENT-§3.2-02 | 3.2 | MUST | sdk | procedural | Receiving agent MUST verify access tokens using the 7-step OAuth 2.0 verification procedure | — | — |
| IDENT-§3.2-03 | 3.2 | MUST | external | behavioural_positive | Access token MUST be issued by a trusted Authorization Server | — | — |
| IDENT-§3.2-04 | 3.2 | MUST_NOT | sdk | behavioural_negative | Access token exp claim MUST NOT be expired at verification time | arsia-jwt-claims | — |
| IDENT-§3.2-05 | 3.2 | MUST_NOT | sdk | behavioural_negative | Access token iat claim MUST NOT be in the future beyond ±300-second clock skew tolerance per ARSIA-Core.md §8.3 | — | ITV-447, ITV-448 |
| IDENT-§3.2-06 | 3.2 | MUST_NOT | sdk | behavioural_negative | Access token MUST NOT be used before the nbf (not-before) claim time | — | ITV-449, ITV-450 |
| IDENT-§3.3-01 | 3.3 | RECOMMENDED | sdk_enabled | interoperability | DPoP (RFC 9449) is RECOMMENDED for all token presentations to prevent theft and replay | arsia-dpop-proof | — |
| IDENT-§3.3-02 | 3.3 | MUST | sdk | behavioural_negative | Receiving agent MUST reject requests with error unauthorized when any DPoP verification check fails | — | ITV-451 |
| IDENT-§4.1-01 | 4.1 | MUST | deployment | behavioural_positive | Both sender and receiver owner_id MUST be retrievable via /.well-known/arsia/identity when audit_required is true | — | — |
| IDENT-§4.1-02 | 4.1 | MUST | sdk | behavioural_positive | Both parties' owner_id MUST be included in the corresponding audit record | arsia-audit-record | — |
| IDENT-§4.1-03 | 4.1 | SHOULD | sdk | behavioural_positive | Implementations SHOULD cache identity records for up to 1 hour, same policy as JWKS | — | — |
| IDENT-§4.1-04 | 4.1 | MUST | deployment | behavioural_positive | Audit records MUST use the identity record retrieved at message processing time, not a stale cache | — | — |
| IDENT-§4.2-01 | 4.2 | MUST | sdk | behavioural_positive | High-risk agent outbound request/response messages MUST set compliance.profile to at least EU-AI-ACT-HIGH-RISK | arsia-compliance-field | INV-07 |
| IDENT-§4.2-02 | 4.2 | SHOULD | sdk_enabled | behavioural_positive | Receiving agent SHOULD log a compliance warning when a high-risk agent omits the expected compliance profile | — | — |
| IDENT-§4.2-03 | 4.2 | MAY | sdk | behavioural_negative | Receiving agent MAY reject classification-mismatched messages with invalid_request and classification_mismatch detail | — | ITV-452 |
| IDENT-§4.2-04 | 4.2 | MUST_NOT | operational_policy | behavioural_negative | Agents classified as unacceptable-risk MUST NOT be deployed | — | — |
| IDENT-§4.2-05 | 4.2 | MUST | sdk | behavioural_negative | Receiving agent MUST reject all messages from agents classified as unacceptable-risk with error forbidden | arsia-identity-record | — |
| IDENT-§4.3-01 | 4.3 | MUST | deployment | behavioural_positive | Cross-border agents' IdentityRecords MUST be independently verifiable via their respective endpoints | — | — |
| IDENT-§4.4-01 | 4.4 | MUST | sdk | behavioural_positive | Both deployer_id and owner_id MUST be recorded in audit events for split-responsibility agents | — | ITV-453 |
| IDENT-§5-01 | 5 | MUST | sdk | interoperability | Conformant implementations MUST pass all identity conformance tests at their applicable level | — | — |
| IDENT-§5-02 | 5 | MAY | sdk | behavioural_positive | Receiving agent MAY reject high-risk classification-mismatched messages with invalid_request error | — | ITV-454 |
| IDENT-§6-01 | 6 | MUST | sdk | behavioural_positive | All implementations MUST support Level 1 (self-signed) certificate trust | — | ITV-455 |
| IDENT-§6-02 | 6 | SHOULD | sdk | behavioural_positive | Implementations SHOULD support Level 2 (CA-signed) certificate trust | — | ITV-456 |
| IDENT-§6-03 | 6 | MAY | sdk | informational | Implementations MAY support Level 3 (eIDAS qualified) certificate trust | — | — |
| IDENT-§6.2-01 | 6.2 | MUST | sdk | structural | Leaf certificate in the chain MUST satisfy all Level 2 structural requirements | — | ITV-457 |
| IDENT-§6.2-02 | 6.2 | MUST | sdk | structural | Leaf certificate SAN MUST contain the agent's agent_id as a URI (format agent:{domain}.{name}) | — | ITV-458 |
| IDENT-§6.2-03 | 6.2 | MUST | sdk | structural | Leaf certificate Subject Organization (O) MUST match the IdentityRecord owner_name or owner_id | arsia-identity-record | — |
| IDENT-§6.2-04 | 6.2 | MUST | sdk | structural | Leaf certificate Key Usage digitalSignature bit MUST be set | — | ITV-459 |
| IDENT-§6.2-05 | 6.2 | MUST_NOT | sdk | behavioural_negative | Leaf certificate Key Usage keyCertSign bit MUST NOT be set (end-entity only) | — | ITV-460 |
| IDENT-§6.2-06 | 6.2 | MUST | sdk | structural | Leaf certificate Basic Constraints MUST set CA:FALSE with the critical flag | — | ITV-461 |
| IDENT-§6.2-07 | 6.2 | MUST | sdk | behavioural_positive | Certificate public key MUST be identical to the Ed25519 key at the agent's JWKS endpoint | — | ITV-462 |
| IDENT-§6.2-08 | 6.2 | OPTIONAL | sdk | informational | Extended Key Usage id-kp-serverAuth is OPTIONAL in leaf certificates | — | — |
| IDENT-§6.2-09 | 6.2 | SHOULD_NOT | sdk | informational | Implementations SHOULD NOT require id-kp-serverAuth Extended Key Usage | — | — |
| IDENT-§6.2-10 | 6.2 | MUST | sdk | behavioural_positive | Raw 32-byte certificate public key MUST equal the base64url-decoded JWKS x field value | — | ITV-463 |
| IDENT-§6.3-01 | 6.3 | MUST | external | structural | Level 3 leaf certificate MUST include QcStatements extension per ETSI EN 319 412-5 | — | ITV-02 |
| IDENT-§6.3-02 | 6.3 | MUST | external | behavioural_positive | Level 3 issuing CA MUST be a QTSP listed on a Member State Trusted List | — | ITV-02 |
| IDENT-§6.3-03 | 6.3 | MUST | external | behavioural_positive | Level 3 owner_id MUST be verifiable against official registers (VIES for VAT, GLEIF for LEI) | — | ITV-02 |
| IDENT-§6.4.1-01 | 6.4.1 | MUST | sdk | procedural | Verifier MUST execute the step-by-step verification procedure for every peer message | — | — |
| IDENT-§6.4.1-02 | 6.4.1 | MUST | sdk | behavioural_positive | Certificate and JWKS raw 32-byte Ed25519 public keys MUST be identical (step 4d) | — | ITV-464 |
| IDENT-§6.4.1-03 | 6.4.1 | MUST | sdk | behavioural_positive | Leaf certificate SAN URI MUST match the peer's IdentityRecord agent_id (step 4e) | — | ITV-465 |
| IDENT-§6.4.1-04 | 6.4.1 | MUST | deployment | procedural | Verifier MUST check Level 3 certificate revocation status via OCSP or CRL (step 4h) | — | — |
| IDENT-§6.4.1-05 | 6.4.1 | RECOMMENDED | deployment | informational | OCSP stapling is RECOMMENDED to reduce Level 3 revocation-check latency | — | — |
| IDENT-§6.4.1-06 | 6.4.1 | SHOULD | sdk | behavioural_positive | Verifier SHOULD treat a certificate as potentially revoked when OCSP and CRL are both unavailable | — | — |
| IDENT-§6.4.1-07 | 6.4.1 | MAY | sdk | behavioural_positive | Verifier MAY downgrade a Level 3 certificate to Level 2 when revocation status is unavailable | — | — |
| IDENT-§6.4.2-01 | 6.4.2 | MUST | deployment | behavioural_positive | Agents supporting Level 2+ verification MUST maintain a local trust store of CA certificates | — | — |
| IDENT-§6.4.2-02 | 6.4.2 | SHOULD | sdk_enabled | behavioural_positive | Trust store SHOULD support PEM directory, OS trust store, or config-based CA certificates | — | — |
| IDENT-§6.4.2-03 | 6.4.2 | MAY | sdk_enabled | behavioural_positive | Agent MAY enforce a minimum trust level policy, rejecting below-threshold agents | — | — |
| IDENT-§6.4.2-04 | 6.4.2 | MUST_NOT | sdk | behavioural_negative | Agent MUST NOT reject Level 1 messages unless a minimum trust level policy is explicitly configured | — | ITV-466 |
| IDENT-§6.4.2-05 | 6.4.2 | MUST | sdk | behavioural_positive | Default behaviour MUST accept messages at all trust levels | — | ITV-467 |
| IDENT-§6.4.3-01 | 6.4.3 | MUST | sdk | structural | Certificate error responses MUST include a details object with a human-readable reason string | arsia-message | ITV-14, ITV-76, ITV-77, ITV-78, ITV-468, ITV-469, ITV-470 |
| IDENT-§6.4.3-02 | 6.4.3 | SHOULD | sdk | behavioural_positive | Certificate error responses SHOULD be signed with the receiving agent's own key | — | — |
| IDENT-§6.5.1-01 | 6.5.1 | OPTIONAL | sdk | structural | IdentityRecord certificate_chain field (array of PEM strings) is OPTIONAL | arsia-identity-record | ITV-01 |
| IDENT-§6.5.1-02 | 6.5.1 | MUST | sdk | structural | certificate_chain MUST be ordered: leaf at index 0, intermediates next, root last | arsia-identity-record | ITV-01 |
| IDENT-§6.5.1-03 | 6.5.1 | MAY | sdk | informational | Root CA certificate MAY be omitted if it is well-known and expected in verifier trust stores | — | — |
| IDENT-§6.5.1-04 | 6.5.1 | MUST | sdk | structural | Each certificate_chain entry MUST be complete PEM with BEGIN/END CERTIFICATE markers | arsia-identity-record | ITV-01 |
| IDENT-§6.5.1-05 | 6.5.1 | MUST | deployment | behavioural_positive | All certificates in the chain MUST be valid when the IdentityRecord is served | — | — |
| IDENT-§6.5.1-06 | 6.5.1 | MUST_NOT | deployment | behavioural_negative | Agent MUST NOT serve an IdentityRecord containing expired certificates | — | — |
| IDENT-§6.5.1-07 | 6.5.1 | SHOULD | operational_policy | behavioural_positive | Agent SHOULD update its IdentityRecord when any certificate is within 30 days of expiry | — | — |
| IDENT-§6.5.2-01 | 6.5.2 | MUST_NOT | sdk | behavioural_negative | Agents MUST NOT include a trust_level field in their IdentityRecord | arsia-identity-record | — |
| IDENT-§6.5.2-02 | 6.5.2 | MAY | sdk | behavioural_positive | Verifier MAY cache computed trust level for the IdentityRecord Cache-Control duration | — | — |
| IDENT-§6.5.2-03 | 6.5.2 | MUST | deployment | behavioural_positive | Verifier MUST recompute trust level when the IdentityRecord is refreshed | — | — |
| IDENT-§6.5.3-01 | 6.5.3 | OPTIONAL | sdk | structural | certificate_chain schema property is OPTIONAL; the required array is unchanged | arsia-identity-record | — |
| IDENT-§6.6-01 | 6.6 | MUST | sdk | interoperability | Level 2 conformant implementations MUST pass tests IDENTITY-09 through IDENTITY-12 | — | — |
| IDENT-§6.7.1-01 | 6.7.1 | MUST_NOT | deployment | behavioural_negative | Sandbox CA certificates MUST NOT be trusted outside the sandbox environment | — | — |
| IDENT-§6.7.1-02 | 6.7.1 | MUST | deployment | behavioural_positive | Production deployments MUST use a properly operated CA with appropriate certificate policies | — | — |
| IDENT-§6.8-01 | 6.8 | SHOULD_NOT | deployment | informational | Level 1 (self-signed) SHOULD NOT be relied upon for identity verification in production | — | — |
| IDENT-§6.8-02 | 6.8 | SHOULD | operational_policy | informational | Level 2 relying agents SHOULD understand their CA's issuance practices | — | — |
| IDENT-§6.8-03 | 6.8 | RECOMMENDED | deployment | informational | Certificate pinning is RECOMMENDED for Level 2 production deployments | — | — |
| IDENT-§6.8-04 | 6.8 | MUST_NOT | sdk | behavioural_negative | Private key MUST NOT be transmitted or included in any protocol message or IdentityRecord | arsia-jwk-entry | ITV-471 |
| IDENT-§6.8-05 | 6.8 | RECOMMENDED | deployment | informational | OCSP stapling is RECOMMENDED for Level 3 to reduce privacy risk and verification latency | — | — |
| IDENT-§6.8-06 | 6.8 | SHOULD | operational_policy | procedural | Agents SHOULD monitor certificate validity and initiate renewal before expiry | — | — |
| IDENT-§6.8-07 | 6.8 | SHOULD | operational_policy | procedural | Agents SHOULD update IdentityRecord with the new certificate chain before the old one expires | — | — |
| IDENT-§7.1.1-01 | 7.1.1 | MUST | deployment | behavioural_positive | External agent MUST serve all ARSIA-Core §7 discovery endpoints (discovery, JWKS, identity) | — | — |
| IDENT-§7.1.1-02 | 7.1.1 | MUST | sdk | behavioural_positive | External agent MUST have a valid IdentityRecord with all REQUIRED fields including ai_system_classification | arsia-identity-record | — |
| IDENT-§7.1.1-03 | 7.1.1 | SHOULD | deployment | behavioural_positive | External agent SHOULD expose an audit trail query endpoint at /v1/arsia/audit | — | — |
| IDENT-§7.1.1-04 | 7.1.1 | MUST | sdk | behavioural_positive | Onboarding gateway MUST declare arsiaprotocol.onboarding.evaluate in its discovery response | arsia-capability-descriptor | — |
| IDENT-§7.1.1-05 | 7.1.1 | MUST | deployment | behavioural_positive | Onboarding gateway MUST be authorized to issue scoped access tokens for the organization | — | ITV-03 |
| IDENT-§7.1.1-06 | 7.1.1 | MUST | sdk | procedural | Gateway MUST record all onboarding decisions as ArsiaAuditRecords | arsia-audit-record | — |
| IDENT-§7.1.1-07 | 7.1.1 | MUST | deployment | procedural | Infrastructure router MUST verify Bearer tokens via the gateway's /v1/arsia/verify-token endpoint | — | — |
| IDENT-§7.1.1-08 | 7.1.1 | MUST | deployment | behavioural_negative | Router MUST reject requests whose capabilities are not present in the token scope with error forbidden | — | ITV-472 |
| IDENT-§7.1.1-09 | 7.1.1 | MUST_NOT | sdk | behavioural_negative | Router MUST NOT accept messages from agents that have not completed onboarding | — | ITV-473 |
| IDENT-§7.1.1-10 | 7.1.1 | REQUIRED | sdk | behavioural_positive | External agent IdentityRecord MUST include ai_system_classification among all REQUIRED fields | arsia-identity-record | — |
| IDENT-§7.1.2-01 | 7.1.2 | MUST_NOT | sdk | behavioural_negative | Gateway MUST NOT grant trust based on out-of-band information (email, verbal, manual config) | — | — |
| IDENT-§7.1.2-02 | 7.1.2 | MUST | sdk | procedural | All onboarding trust decisions MUST be traceable through the audit trail | — | — |
| IDENT-§7.1.3-01 | 7.1.3 | MAY | sdk_enabled | informational | Implementations MAY extend onboarding with additional checks if the six normative phases execute in order | — | — |
| IDENT-§7.2-01 | 7.2 | MUST | sdk | procedural | Gateway MUST proceed to Phase 5 denial if any of Phases 1–4 fails | arsia-onboarding-decision | ITV-04 |
| IDENT-§7.2-02 | 7.2 | MUST_NOT | sdk | procedural | Onboarding phases MUST NOT be reordered or skipped | — | — |
| IDENT-§7.2-03 | 7.2 | MUST | sdk | procedural | Gateway MUST perform Phase 1 identity verification steps in order | — | — |
| IDENT-§7.2-04 | 7.2 | MUST | sdk | structural | Discovery response MUST include agent_id, protocol_version, and capabilities fields | arsia-discovery-response | — |
| IDENT-§7.2-05 | 7.2 | MUST | sdk | behavioural_negative | Gateway MUST deny with discovery_failed when discovery fetch fails or response is invalid | — | ITV-474 |
| IDENT-§7.2-06 | 7.2 | MUST | deployment | behavioural_positive | Identity endpoint response MUST include the X-ARSIA-Sig header | — | — |
| IDENT-§7.2-07 | 7.2 | MUST | sdk | behavioural_negative | Gateway MUST deny with identity_verification_failed when identity fetch fails or schema is invalid | arsia-identity-record | — |
| IDENT-§7.2-08 | 7.2 | MUST | sdk | behavioural_negative | Gateway MUST deny with identity_verification_failed when JWKS fetch fails or no Ed25519 key found | arsia-jwk-entry | ITV-04 |
| IDENT-§7.2-09 | 7.2 | MUST | sdk | behavioural_negative | Gateway MUST deny with identity_verification_failed when X-ARSIA-Sig verification fails | — | ITV-475 |
| IDENT-§7.2-10 | 7.2 | MUST | sdk | behavioural_negative | Gateway MUST deny with identity_verification_failed when no JWKS kid prefix matches the agent_id | — | ITV-476 |
| IDENT-§7.2-11 | 7.2 | MUST | sdk | behavioural_negative | Gateway MUST deny with unacceptable_risk_classification when agent is classified unacceptable-risk | arsia-identity-record | — |
| IDENT-§7.2-12 | 7.2 | MUST_NOT | operational_policy | behavioural_negative | Agents classified as unacceptable-risk MUST NOT be deployed | — | — |
| IDENT-§7.3-01 | 7.3 | MUST | sdk | structural | Conformance check status field MUST be one of pass, fail, or skip | arsia-onboarding-decision | — |
| IDENT-§7.3-02 | 7.3 | MAY | sdk | behavioural_positive | Conformance check MAY be skipped only when its preconditions are not met | arsia-onboarding-decision | — |
| IDENT-§7.3-03 | 7.3 | MUST | sdk | structural | CHECK-01: response MUST have intent set to response | arsia-message | — |
| IDENT-§7.3-04 | 7.3 | MUST | sdk | behavioural_positive | CHECK-01: response MUST have correlation_id set to the request's id | arsia-message | — |
| IDENT-§7.3-05 | 7.3 | MUST | sdk | structural | CHECK-01: response id field MUST be a valid UUID | arsia-message | — |
| IDENT-§7.3-06 | 7.3 | MUST | sdk | structural | CHECK-01: response MUST include v, ts, from, and to fields | arsia-message | — |
| IDENT-§7.3-07 | 7.3 | MUST | deployment | behavioural_positive | CHECK-01: response from field MUST match the external agent's agent_id | — | ITV-477 |
| IDENT-§7.3-08 | 7.3 | MUST | sdk | behavioural_positive | CHECK-03: external agent MUST respond with pending_approval for oversight-required capabilities | — | ITV-478 |
| IDENT-§7.3-09 | 7.3 | MUST | sdk | structural | CHECK-03: pending_approval message MUST have intent set to pending_approval | arsia-message | — |
| IDENT-§7.3-10 | 7.3 | MUST | sdk | behavioural_positive | CHECK-03: pending_approval correlation_id MUST match the request's id | — | ITV-479 |
| IDENT-§7.3-11 | 7.3 | SHOULD | sdk | structural | CHECK-03: pending_approval payload.type SHOULD be arsiaprotocol.oversight/pending | arsia-message | ITV-480 |
| IDENT-§7.3-12 | 7.3 | MUST | sdk | behavioural_positive | CHECK-03: pending_approval expires_at MUST be present and set to a future timestamp | arsia-message | ITV-481 |
| IDENT-§7.3-13 | 7.3 | MUST | sdk | structural | CHECK-04: audit endpoint response MUST be a JSON array of audit records | arsia-audit-record | — |
| IDENT-§7.3-14 | 7.3 | MUST | sdk | structural | CHECK-04: each audit record MUST include all ArsiaAuditRecord-defined fields | arsia-audit-record | — |
| IDENT-§7.3-15 | 7.3 | MUST | sdk | behavioural_positive | CHECK-04: audit records MUST use payload_hash, not raw payload content | arsia-audit-record | — |
| IDENT-§7.3-16 | 7.3 | RECOMMENDED | sdk_enabled | informational | Audit trail endpoint is RECOMMENDED but not REQUIRED at Core Conformance level | — | — |
| IDENT-§7.3-17 | 7.3 | MUST | sdk | procedural | All conformance checks MUST achieve pass or skip status for Phase 2 to pass | arsia-onboarding-decision | — |
| IDENT-§7.3-18 | 7.3 | MUST | sdk | behavioural_negative | Gateway MUST deny with conformance_failed when any conformance check has fail status | arsia-onboarding-decision | ITV-131 |
| IDENT-§7.4-01 | 7.4 | MAY | sdk | informational | Allowed-status capabilities MAY be invoked without additional oversight | arsia-capability-policy | — |
| IDENT-§7.4-02 | 7.4 | MAY | sdk | behavioural_positive | Oversight-required capabilities MAY be invoked but MUST trigger pending_approval first | arsia-capability-policy | — |
| IDENT-§7.4-03 | 7.4 | MUST | sdk | behavioural_positive | Each oversight-required invocation MUST trigger a pending_approval flow before execution | arsia-capability-policy | — |
| IDENT-§7.4-04 | 7.4 | MUST_NOT | sdk | behavioural_negative | Prohibited-status capabilities MUST NOT be invoked by the agent | arsia-capability-policy | — |
| IDENT-§7.4-05 | 7.4 | MUST | sdk | behavioural_negative | Infrastructure router MUST reject prohibited-capability requests with error forbidden | arsia-capability-policy | — |
| IDENT-§7.4-06 | 7.4 | MUST | sdk | procedural | Gateway MUST partition effective capabilities into freely_allowed and oversight_required lists | arsia-onboarding-decision | — |
| IDENT-§7.5-01 | 7.5 | MUST | sdk | procedural | Gateway MUST record identity_created_at, earliest_audit_record, and provenance_verified | arsia-onboarding-decision | ITV-130 |
| IDENT-§7.5-02 | 7.5 | SHOULD | sdk | behavioural_positive | Gateway SHOULD log a warning when provenance_verified is false | arsia-onboarding-decision | ITV-130 |
| IDENT-§7.5-03 | 7.5 | MUST_NOT | sdk | behavioural_negative | Failed provenance verification MUST NOT automatically deny onboarding | — | — |
| IDENT-§7.5-04 | 7.5 | MAY | operational_policy | informational | Organization's human oversight process MAY use provenance as an input to approval | — | — |
| IDENT-§7.6-01 | 7.6 | MUST | sdk | structural | Onboarding decision message MUST conform to the approval_decision envelope structure | arsia-onboarding-decision | ITV-03, ITV-04, ITV-38, ITV-130 |
| IDENT-§7.6-02 | 7.6 | REQUIRED | sdk | structural | Decision message compliance field is REQUIRED with the organization's applicable profile | arsia-onboarding-decision | — |
| IDENT-§7.6-03 | 7.6 | REQUIRED | sdk | behavioural_positive | Decision message security field is REQUIRED, signed with the gateway's Ed25519 key | arsia-message | ITV-482 |
| IDENT-§7.6-04 | 7.6 | MUST | sdk | behavioural_positive | Approval token MUST be a valid JWT with scope matching effective_capabilities | arsia-jwt-claims, arsia-onboarding-decision | ITV-38, ITV-130 |
| IDENT-§7.6-05 | 7.6 | MUST | sdk | structural | Approval decision token_expires_at MUST be present in RFC 3339 format | arsia-onboarding-decision | ITV-130 |
| IDENT-§7.6-06 | 7.6 | MUST | sdk | structural | Approval decision effective_capabilities, freely_allowed, and oversight_required MUST be non-empty | arsia-onboarding-decision | ITV-130 |
| IDENT-§7.6-07 | 7.6 | MUST | sdk | structural | Denial decision denial_reason field MUST be present | arsia-onboarding-decision | ITV-04, ITV-131 |
| IDENT-§7.6-08 | 7.6 | MUST_NOT | sdk | behavioural_negative | Denial decision MUST NOT include a token field | arsia-onboarding-decision | ITV-04, ITV-131 |
| IDENT-§7.6-09 | 7.6 | SHOULD | sdk | behavioural_positive | Denial decision SHOULD include conformance_result for operator feedback | arsia-onboarding-decision | ITV-131 |
| IDENT-§7.6-10 | 7.6 | MUST | sdk | procedural | Gateway MUST record the onboarding decision as an ArsiaAuditRecord with event_type approval_decision | arsia-audit-record | — |
| IDENT-§7.7-01 | 7.7 | MUST | sdk | behavioural_positive | External agent MUST present the onboarding token as a Bearer token in the Authorization header | arsia-jwt-claims | — |
| IDENT-§7.7-02 | 7.7 | MUST | sdk_enabled | procedural | Infrastructure router MUST verify the token on every request via the gateway's verify-token endpoint | — | — |
| IDENT-§7.7-03 | 7.7 | MUST | deployment | structural | Token verification request body MUST contain the token to be verified | arsia-jwt-claims | ITV-483, ITV-484 |
| IDENT-§7.7-04 | 7.7 | MUST | sdk | behavioural_negative | Router MUST reject with error unauthorized when the token is invalid, expired, or revoked | — | ITV-485 |
| IDENT-§7.7-05 | 7.7 | MUST | sdk | behavioural_positive | Router MUST verify that requested message capabilities are a subset of the token scope | arsia-jwt-claims | — |
| IDENT-§7.7-06 | 7.7 | MUST | sdk | behavioural_negative | Router MUST reject with error forbidden when message requests out-of-scope capabilities | — | ITV-486 |
| IDENT-§7.7-06a | 7.7 | MUST | sdk | behavioural_positive | Router MUST verify that the invoked action's risk_level does not exceed the capability's max_risk_level constraint | arsia-capability-policy | — |
| IDENT-§7.7-06b | 7.7 | MUST | sdk | behavioural_negative | Router MUST reject with error forbidden and details.risk_level_exceeded when action risk_level exceeds max_risk_level | — | — |
| IDENT-§7.7-07 | 7.7 | SHOULD | sdk_enabled | behavioural_positive | Router SHOULD signal to the internal agent when oversight is required for a capability | — | — |
| IDENT-§7.7-08 | 7.7 | MUST | deployment | behavioural_positive | Receiving internal agent MUST respond with pending_approval before executing oversight-required actions | — | — |
| IDENT-§7.7-09 | 7.7 | SHOULD | sdk_enabled | interoperability | External agents SHOULD use DPoP when presenting tokens to the infrastructure router | arsia-dpop-proof | — |
| IDENT-§7.7-10 | 7.7 | SHOULD | sdk_enabled | behavioural_positive | Router SHOULD verify DPoP proofs when presented by external agents | — | — |
| IDENT-§7.7-11 | 7.7 | MAY | sdk | informational | External agent MAY re-initiate onboarding to obtain a new token before expiry | — | — |
| IDENT-§7.7-12 | 7.7 | MAY | sdk_enabled | informational | Implementations MAY provide a lightweight token renewal skipping Phases 1–4 | — | — |
| IDENT-§8.1-01 | 8.1 | MUST | sdk | structural | CapabilityPolicy MUST include policy_version, token_lifetime_seconds, and capabilities fields | arsia-capability-policy | ITV-10 |
| IDENT-§8.1-02 | 8.1 | REQUIRED | sdk | structural | CapabilityPolicy policy_version field (string) is REQUIRED | arsia-capability-policy | — |
| IDENT-§8.1-03 | 8.1 | SHOULD | sdk_enabled | informational | policy_version SHOULD use a semantically meaningful version string | — | — |
| IDENT-§8.1-04 | 8.1 | REQUIRED | sdk | structural | CapabilityPolicy token_lifetime_seconds field (integer) is REQUIRED | arsia-capability-policy | ITV-03, ITV-10 |
| IDENT-§8.1-05 | 8.1 | RECOMMENDED | sdk_enabled | informational | token_lifetime_seconds RECOMMENDED minimum is 900 seconds (15 minutes) | — | — |
| IDENT-§8.1-06 | 8.1 | RECOMMENDED | sdk_enabled | informational | token_lifetime_seconds RECOMMENDED maximum is 86400 seconds (24 hours) | — | ITV-65 |
| IDENT-§8.1-07 | 8.1 | MUST_NOT | sdk | behavioural_negative | Tokens MUST NOT be issued with lifetime exceeding token_lifetime_seconds | arsia-capability-policy | — |
| IDENT-§8.1-08 | 8.1 | REQUIRED | sdk | structural | CapabilityPolicy capabilities field (array of CapabilityRule) is REQUIRED | arsia-capability-policy | — |
| IDENT-§8.2-01 | 8.2 | REQUIRED | sdk | structural | CapabilityRule capability field (string) is REQUIRED | arsia-capability-policy | — |
| IDENT-§8.2-02 | 8.2 | MUST | sdk | structural | CapabilityRule MUST specify an exact capability string, no wildcards | arsia-capability-policy | ITV-11 |
| IDENT-§8.2-03 | 8.2 | REQUIRED | sdk | structural | CapabilityRule status field (string: allowed, oversight_required, or prohibited) is REQUIRED | arsia-capability-policy | — |
| IDENT-§8.2-04 | 8.2 | OPTIONAL | sdk | structural | CapabilityRule max_risk_level field (integer 0–10) is OPTIONAL | arsia-capability-policy | — |
| IDENT-§8.2-05 | 8.2 | MUST | sdk | behavioural_negative | Invocation MUST be treated as prohibited when action risk level exceeds max_risk_level | arsia-capability-policy | — |
| IDENT-§8.2-06 | 8.2 | OPTIONAL | sdk | structural | CapabilityRule conditions field (string, human-readable) is OPTIONAL and not machine-enforced | arsia-capability-policy | — |
| IDENT-§8.3-01 | 8.3 | MUST | sdk | procedural | Gateway MUST evaluate CapabilityPolicy against the agent's declared capabilities using the evaluation procedure defined in §8.3; output includes max_risk_level constraints per capability | arsia-capability-policy, arsia-capability-descriptor | — |
| IDENT-§8.3-02 | 8.3 | SHOULD | sdk | behavioural_negative | Gateway SHOULD deny with no_permitted_capabilities when effective capabilities is empty | arsia-onboarding-decision | — |
| IDENT-§9.1-01 | 9.1 | MUST | sdk | behavioural_positive | Gateway tokens MUST be scoped to exactly the effective_capabilities from Phase 3 | arsia-jwt-claims, arsia-onboarding-decision | ITV-03 |
| IDENT-§9.1-02 | 9.1 | MUST | sdk | behavioural_positive | Token scope claim MUST contain the union of freely_allowed and oversight_required capabilities | arsia-jwt-claims | — |
| IDENT-§9.1-03 | 9.1 | MUST | sdk | behavioural_positive | Tokens MUST have exp claim set to current time plus policy.token_lifetime_seconds | arsia-jwt-claims | — |
| IDENT-§9.1-04 | 9.1 | MUST_NOT | sdk | behavioural_negative | Tokens MUST NOT be issued without an expiry time | arsia-jwt-claims | — |
| IDENT-§9.1-05 | 9.1 | MUST | sdk | behavioural_positive | Token sub claim MUST be the external agent's agent-id | arsia-jwt-claims | — |
| IDENT-§9.1-06 | 9.1 | MUST | sdk | behavioural_positive | Token iss claim MUST be the gateway's agent-id | arsia-jwt-claims | — |
| IDENT-§9.1-07 | 9.1 | SHOULD | sdk | behavioural_positive | Token aud claim SHOULD be the infrastructure router's agent-id or a wildcard audience | arsia-jwt-claims | — |
| IDENT-§9.2-01 | 9.2 | RECOMMENDED | sdk_enabled | interoperability | DPoP per RFC 9449 is RECOMMENDED for all external agent token presentations | arsia-dpop-proof | — |
| IDENT-§9.2-02 | 9.2 | MUST | sdk | behavioural_positive | External agent MUST present a DPoP proof JWT alongside the access token when DPoP is in use | arsia-dpop-proof | — |
| IDENT-§9.2-03 | 9.2 | MUST | sdk | behavioural_positive | Infrastructure router MUST verify the DPoP proof before accepting the request | — | — |
| IDENT-§9.2-04 | 9.2 | MUST | sdk | behavioural_positive | DPoP-bound token MUST contain a cnf claim binding it to the agent's Ed25519 key | arsia-jwt-claims | — |
| IDENT-§9.2-05 | 9.2 | SHOULD | sdk_enabled | behavioural_positive | High-security organizations SHOULD mandate DPoP for all external agents | — | — |
| IDENT-§9.3-01 | 9.3 | MUST | sdk | procedural | All onboarding events MUST be recorded as ArsiaAuditRecord entries | arsia-audit-record | — |
| IDENT-§9.3-02 | 9.3 | MUST | sdk | procedural | Onboarding initiation, identity, conformance, capabilities, decision, and revocation MUST be audited | arsia-audit-record | — |
| IDENT-§9.3-03 | 9.3 | MUST | sdk | behavioural_positive | Onboarding audit records MUST use payload_hash, not raw payload content | arsia-audit-record | — |
| IDENT-§9.3-04 | 9.3 | MUST | deployment | behavioural_positive | Onboarding audit records MUST be retained for at least the compliance profile's retention_days | — | — |
| IDENT-§9.4-01 | 9.4 | MAY | operational_policy | informational | Organization MAY revoke an external agent's token at any time | — | — |
| IDENT-§9.4-02 | 9.4 | MUST | deployment | procedural | Gateway MUST record an arsiaprotocol.onboarding/revocation audit event on token revocation | arsia-audit-record | — |
| IDENT-§9.4-03 | 9.4 | MUST | deployment | behavioural_positive | Gateway verify-token endpoint MUST return invalid/revoked status for revoked tokens | — | ITV-487 |
| IDENT-§9.4-04 | 9.4 | MUST | deployment | behavioural_negative | Router MUST reject requests presenting a revoked token with error unauthorized | — | ITV-488 |
| IDENT-§9.4-05 | 9.4 | MUST | deployment | behavioural_positive | Audit trail for an agent's operational period MUST be retained after token revocation | — | — |
| IDENT-§10-01 | 10 | MUST | sdk | interoperability | Conformant implementations MUST pass all onboarding conformance tests (IDENTITY-13 through IDENTITY-20) | — | — |

## Coverage Gaps

| Metric | Count |
|--------|-------|
| Total requirements | 257 |
| Schema ≠ — | 114 |
| Vector ≠ — | 78 |
| Both ≠ — | 39 |
| Both = — (gaps) | 104 |

### Gaps by section

| Section | Gaps | Total |
|---------|------|-------|
| §1 (Identity) | 15 | 38 |
| §2 (Cryptographic) | 20 | 27 |
| §3 (Verification) | 8 | 15 |
| §4 (Compliance) | 6 | 11 |
| §5 (Conformance L1) | 1 | 2 |
| §6 (Certificate Trust) | 27 | 51 |
| §7 (Onboarding) | 19 | 75 |
| §8 (Capability Policy) | 2 | 16 |
| §9 (Token & Audit) | 5 | 21 |
| §10 (Conformance L2) | 1 | 1 |
