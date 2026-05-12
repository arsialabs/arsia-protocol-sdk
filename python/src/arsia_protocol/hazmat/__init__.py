# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Low-level cryptographic and canonicalization primitives.

Reach for anything in ``hazmat`` only when you need raw Ed25519 or raw
RFC 8785 (JCS) canonicalization. High-level APIs in
``arsia_protocol.message`` apply envelope rules automatically and should
be preferred.
"""
