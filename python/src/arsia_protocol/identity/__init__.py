# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""ARSIA Identity — agent identifiers, certificates, onboarding, and discovery."""

from __future__ import annotations

import importlib
from typing import Any

from arsia_protocol.identity.agent_id import (
    AGENT_ID_PATTERN,
    AgentId,
    is_identity_record_expired,
    is_valid_agent_id,
    parse_agent_id,
    validate_agent_id,
)

_LAZY_SUBMODULES = {
    "certificates": "arsia_protocol.identity.certificates",
    "discovery": "arsia_protocol.identity.discovery",
    "onboarding": "arsia_protocol.identity.onboarding",
}

_LAZY_SYMBOLS: dict[str, str] = {
    # certificates
    "CertificateVerificationResult": "certificates",
    "QC_STATEMENTS_OID": "certificates",
    "TrustLevel": "certificates",
    "compute_trust_level": "certificates",
    "extract_public_key_from_cert": "certificates",
    "has_qc_statements": "certificates",
    "is_certificate_chain_expired": "certificates",
    "verify_certificate_chain": "certificates",
    # discovery
    "JWKS_MAX_CACHE_SECONDS": "discovery",
    "JWKSCachePolicy": "discovery",
    "ROTATION_OVERLAP_HOURS": "discovery",
    "RSA_MINIMUM_KEY_BITS": "discovery",
    "build_capability_listing": "discovery",
    "build_discovery_document": "discovery",
    "build_ec_jwk": "discovery",
    "build_encryption_jwks": "discovery",
    "build_identity_record_signature": "discovery",
    "build_jwk": "discovery",
    "build_jwks": "discovery",
    "build_rotation_jwks": "discovery",
    "filter_compromised_keys": "discovery",
    "is_kid_revoked": "discovery",
    "public_key_from_jwk": "discovery",
    "select_jwk_from_jwks": "discovery",
    "validate_capability_prerequisites": "discovery",
    "validate_rsa_key_size": "discovery",
    "verify_identity_record_signature": "discovery",
    "verify_jwks_agent_id_consistency": "discovery",
    # onboarding
    "CLASSIFICATION_HIERARCHY": "onboarding",
    "CapabilityEvaluationResult": "onboarding",
    "CapabilityStatus": "onboarding",
    "CheckResult": "onboarding",
    "DenialReason": "onboarding",
    "ONBOARDING_AUDIT_EVENTS": "onboarding",
    "ONBOARDING_EVALUATE_CAPABILITY": "onboarding",
    "OnboardingDecision": "onboarding",
    "OnboardingOutcome": "onboarding",
    "OnboardingPhase": "onboarding",
    "ProvenanceResult": "onboarding",
    "build_decision_payload": "onboarding",
    "build_onboarding_decision": "onboarding",
    "check_audit_payload_hash": "onboarding",
    "check_audit_record_fields": "onboarding",
    "check_audit_records_array": "onboarding",
    "is_classification_consistent": "onboarding",
    "check_discovery_response": "onboarding",
    "check_envelope_id": "onboarding",
    "check_envelope_required_fields": "onboarding",
    "check_expires_at": "onboarding",
    "check_pending_approval": "onboarding",
    "validate_profile_requirement": "onboarding",
    "evaluate_capability_policy": "onboarding",
    "evaluate_phase2_checks": "onboarding",
    "validate_capability_policy": "onboarding",
    "verify_provenance": "onboarding",
}


def __getattr__(name: str) -> Any:
    if name in _LAZY_SUBMODULES:
        return importlib.import_module(_LAZY_SUBMODULES[name])
    submod = _LAZY_SYMBOLS.get(name)
    if submod is not None:
        mod = importlib.import_module(_LAZY_SUBMODULES[submod])
        return getattr(mod, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    eager = [
        "AGENT_ID_PATTERN",
        "AgentId",
        "is_identity_record_expired",
        "is_valid_agent_id",
        "parse_agent_id",
        "validate_agent_id",
    ]
    return eager + list(_LAZY_SYMBOLS) + list(_LAZY_SUBMODULES)


__all__ = [
    # agent_id
    "AGENT_ID_PATTERN",
    "AgentId",
    "is_identity_record_expired",
    "is_valid_agent_id",
    "parse_agent_id",
    "validate_agent_id",
    # certificates
    "CertificateVerificationResult",
    "QC_STATEMENTS_OID",
    "TrustLevel",
    "compute_trust_level",
    "extract_public_key_from_cert",
    "has_qc_statements",
    "is_certificate_chain_expired",
    "verify_certificate_chain",
    # discovery
    "JWKS_MAX_CACHE_SECONDS",
    "JWKSCachePolicy",
    "ROTATION_OVERLAP_HOURS",
    "RSA_MINIMUM_KEY_BITS",
    "build_capability_listing",
    "build_discovery_document",
    "build_ec_jwk",
    "build_encryption_jwks",
    "build_identity_record_signature",
    "build_jwk",
    "build_jwks",
    "build_rotation_jwks",
    "filter_compromised_keys",
    "is_kid_revoked",
    "public_key_from_jwk",
    "select_jwk_from_jwks",
    "validate_capability_prerequisites",
    "validate_rsa_key_size",
    "verify_identity_record_signature",
    "verify_jwks_agent_id_consistency",
    # onboarding
    "CLASSIFICATION_HIERARCHY",
    "CapabilityEvaluationResult",
    "CapabilityStatus",
    "CheckResult",
    "DenialReason",
    "ONBOARDING_AUDIT_EVENTS",
    "ONBOARDING_EVALUATE_CAPABILITY",
    "OnboardingDecision",
    "OnboardingOutcome",
    "OnboardingPhase",
    "ProvenanceResult",
    "build_decision_payload",
    "build_onboarding_decision",
    "check_audit_payload_hash",
    "check_audit_record_fields",
    "check_audit_records_array",
    "is_classification_consistent",
    "check_discovery_response",
    "check_envelope_id",
    "check_envelope_required_fields",
    "check_expires_at",
    "check_pending_approval",
    "validate_profile_requirement",
    "evaluate_capability_policy",
    "evaluate_phase2_checks",
    "validate_capability_policy",
    "verify_provenance",
]
