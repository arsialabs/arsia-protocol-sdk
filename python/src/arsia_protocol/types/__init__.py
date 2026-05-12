# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Pydantic v2 models for ARSIA envelopes and domain types.

Models are split by domain across the following submodules and
re-exported here for convenience:

- ``envelope``      — ``ArsiaMessage`` and its sub-objects
- ``security``      — ``ArsiaSecurity``, ``SignatureAlgorithm``
- ``compliance``    — ``ArsiaCompliance`` and related enums
- ``errors``        — ``ArsiaError``, ``ArsiaErrorCode``
- ``identity``      — ``IdentityRecord``, JWKS, discovery document
- ``actions``       — ``ActionDescriptor``, ``Explanation``
- ``state``         — ``StateEntry``, ``ArsiaAuditRecord``
- ``assets``        — transfer request/receipt/reversal, escrow
- ``routing``       — ``BrokerEntry``, ``CapabilityPolicy``
- ``breach``        — ``BreachNotificationPayload``

This package is Layer 1 in the SDK dependency graph. Submodules may
import from ``arsia_protocol.identity`` (Layer 0) for agent-id
validation, but not from any other SDK module.
"""

from __future__ import annotations

from arsia_protocol.types.breach import (
    BreachNotificationPayload,
    NotificationTarget,
)
from arsia_protocol.types.actions import (
    ActionCategory,
    ActionDescriptor,
    AlternativeConsidered,
    Explanation,
)
from arsia_protocol.types.assets import (
    AssetTransferReceiptResult,
    AssetTransferRequestArgs,
    AssetTransferReversalArgs,
    AssetType,
    EscrowConditions,
    TransferStatus,
)
from arsia_protocol.types.compliance import (
    AISystemClassification,
    ArsiaCompliance,
    GDPRLegalBasis,
    HumanOversightLevel,
)
from arsia_protocol.types.envelope import (
    ArsiaContext,
    ArsiaIdempotency,
    ArsiaIntent,
    ArsiaMessage,
    ArsiaPayload,
)
from arsia_protocol.types.errors import ArsiaError, ArsiaErrorCode, ValidationError
from arsia_protocol.types.identity import (
    ArsiaCapabilityDescriptor,
    ArsiaDiscoveryDocument,
    ArsiaFeatures,
    ArsiaJWK,
    ArsiaJWKS,
    ArsiaRateLimits,
    IdentityRecord,
)
from arsia_protocol.types.routing import (
    BrokerCapacity,
    BrokerEntry,
    BrokerHealth,
    CapabilityPolicy,
    CapabilityRule,
    CapabilityRuleStatus,
)
from arsia_protocol.types.security import ArsiaSecurity, SignatureAlgorithm
from arsia_protocol.types.state import (
    ArsiaAuditRecord,
    AuditEventType,
    LegalBasis,
    OversightStatus,
    PiiClassification,
    PiiSpecialCategory,
    StateEntry,
    StateScope,
)

__all__ = [
    # breach
    "BreachNotificationPayload",
    "NotificationTarget",
    # actions
    "ActionCategory",
    "ActionDescriptor",
    "AlternativeConsidered",
    "Explanation",
    # assets
    "AssetType",
    "TransferStatus",
    "EscrowConditions",
    "AssetTransferRequestArgs",
    "AssetTransferReceiptResult",
    "AssetTransferReversalArgs",
    # compliance
    "AISystemClassification",
    "ArsiaCompliance",
    "GDPRLegalBasis",
    "HumanOversightLevel",
    # envelope
    "ArsiaContext",
    "ArsiaIdempotency",
    "ArsiaIntent",
    "ArsiaMessage",
    "ArsiaPayload",
    # errors
    "ArsiaError",
    "ArsiaErrorCode",
    "ValidationError",
    # identity
    "ArsiaCapabilityDescriptor",
    "ArsiaDiscoveryDocument",
    "ArsiaFeatures",
    "ArsiaJWK",
    "ArsiaJWKS",
    "ArsiaRateLimits",
    "IdentityRecord",
    # routing
    "BrokerCapacity",
    "BrokerEntry",
    "BrokerHealth",
    "CapabilityPolicy",
    "CapabilityRule",
    "CapabilityRuleStatus",
    # security
    "ArsiaSecurity",
    "SignatureAlgorithm",
    # state
    "ArsiaAuditRecord",
    "AuditEventType",
    "LegalBasis",
    "OversightStatus",
    "PiiClassification",
    "PiiSpecialCategory",
    "StateEntry",
    "StateScope",
]
