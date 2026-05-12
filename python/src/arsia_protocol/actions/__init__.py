# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""ARSIA Actions — capability model, action descriptors, and execution lifecycle."""

from arsia_protocol.actions.actions import (
    CAPABILITY_MAX_LENGTH,
    CAPABILITY_PATTERN,
    EXPLICIT_GRANT_ONLY,
    ExecutionState,
    RESERVED_CAPABILITIES,
    RESERVED_PREFIX,
    RISK_LEVEL_CLASSIFICATION,
    RiskClassification,
    VALID_TRANSITIONS,
    attach_effective_capabilities,
    build_partial_execution_audit,
    build_partial_rollback_response,
    build_rollback_audit_record,
    build_timeout_error,
    is_explanation_required,
    create_rollback_request,
    build_version_not_supported_error,
    downgrade_capabilities,
    find_unsatisfied_capabilities,
    get_risk_classification,
    is_approval_expired,
    is_major_version_bump,
    is_reserved_capability,
    is_reserved_prefix_misuse,
    is_terminal_state,
    is_valid_capability,
    is_valid_transition,
    match_capabilities,
    match_capability,
    resolve_action_version,
    validate_action_descriptor,
    validate_capability,
    validate_explanation,
    validate_explanation_timestamp,
    validate_response_explanation,
    validate_rollback,
    validate_timeout_cancellation,
)

__all__ = [
    # §1
    "CAPABILITY_MAX_LENGTH",
    "CAPABILITY_PATTERN",
    "RESERVED_PREFIX",
    "RESERVED_CAPABILITIES",
    "EXPLICIT_GRANT_ONLY",
    "validate_capability",
    "is_valid_capability",
    "is_reserved_capability",
    "is_reserved_prefix_misuse",
    "match_capability",
    "match_capabilities",
    "find_unsatisfied_capabilities",
    "downgrade_capabilities",
    "attach_effective_capabilities",
    # §2
    "RiskClassification",
    "RISK_LEVEL_CLASSIFICATION",
    "get_risk_classification",
    "validate_action_descriptor",
    # §2.4
    "is_major_version_bump",
    "resolve_action_version",
    "build_version_not_supported_error",
    # §3.4
    "is_approval_expired",
    # §4.1
    "ExecutionState",
    "VALID_TRANSITIONS",
    "is_valid_transition",
    "is_terminal_state",
    # §4.2
    "create_rollback_request",
    "validate_rollback",
    "build_rollback_audit_record",
    "build_partial_rollback_response",
    # §4.3
    "build_timeout_error",
    "validate_timeout_cancellation",
    "build_partial_execution_audit",
    # §5.1
    "is_explanation_required",
    "validate_response_explanation",
    # §5.2
    "validate_explanation",
    "validate_explanation_timestamp",
]
