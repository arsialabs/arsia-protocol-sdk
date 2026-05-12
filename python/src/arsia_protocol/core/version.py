# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Package version and ARSIA wire-protocol version helpers.

This module is Layer 0 in the SDK dependency graph: it imports nothing
from other ``arsia_protocol`` modules. It exposes two distinct
version concepts:

- :data:`__version__` — the installed Python package version, resolved
  via :mod:`importlib.metadata`. This is the SDK's release version.
- :data:`PROTOCOL_VERSION` — the ARSIA wire protocol version this SDK
  implements. This is what goes into the envelope ``v`` field and
  what :func:`is_compatible` compares against a peer's supported range.

The wire-version helpers (:func:`parse_version`, :func:`compare_versions`,
:func:`is_compatible`) implement the negotiation procedure from
ARSIA-Core.md §7.4.
"""

from __future__ import annotations

import re
from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("arsia-protocol")
except PackageNotFoundError:  # pragma: no cover - only hit in uninstalled checkouts
    __version__ = "0.0.0+unknown"


PROTOCOL_VERSION: str = "1.0"
"""The ARSIA wire protocol version implemented by this SDK.

This is the value the SDK writes into the envelope ``v`` field and uses
as its ``server_min`` / ``server_max`` when answering discovery queries.

Spec: ARSIA-Core.md §4.1.1, §7.4.
"""


_VERSION_RE = re.compile(r"^\d+\.\d+$")


def parse_version(version_str: str) -> tuple[int, int]:
    """Parse a wire version string into a ``(major, minor)`` tuple.

    The ARSIA wire version grammar is ``MAJOR.MINOR`` where both
    components are non-negative integers (Core §4.1.1). Leading zeros,
    pre-release suffixes, and patch components are all rejected.

    Args:
        version_str: The candidate version string (e.g. ``"1.0"``).

    Returns:
        A ``(major, minor)`` tuple of integers.

    Raises:
        ValueError: if ``version_str`` does not match the
            ``^\\d+\\.\\d+$`` pattern.

    Spec: ARSIA-Core.md §4.1.1, §7.4.
    """
    if not isinstance(version_str, str) or not _VERSION_RE.fullmatch(version_str):
        raise ValueError(
            f"invalid ARSIA wire version {version_str!r}: "
            "expected 'MAJOR.MINOR' with integer components"
        )
    major_str, minor_str = version_str.split(".", 1)
    return int(major_str), int(minor_str)


def compare_versions(a: str, b: str) -> int:
    """Compare two wire version strings.

    Args:
        a: Left-hand version string.
        b: Right-hand version string.

    Returns:
        ``-1`` if ``a < b``, ``0`` if ``a == b``, ``1`` if ``a > b``.
        Ordering is by major version first, then minor.

    Raises:
        ValueError: if either argument is not a valid wire version.

    Spec: ARSIA-Core.md §7.4.
    """
    ta = parse_version(a)
    tb = parse_version(b)
    if ta < tb:
        return -1
    if ta > tb:
        return 1
    return 0


def is_compatible(
    our_version: str,
    their_version: str,
    their_min_v: str | None = None,
) -> bool:
    """Decide whether an incoming message is version-compatible with us.

    Implements the negotiation rule from ARSIA-Core.md §7.4 from the
    perspective of the *receiver*:

    1. Major versions MUST match. ARSIA treats major-version changes
       as wire-incompatible.
    2. If the sender set ``min_v`` (its minimum acceptable response
       version), ``our_version`` MUST be at least ``their_min_v``;
       otherwise we cannot produce a response the sender will accept.

    Args:
        our_version: This SDK's wire version (typically
            :data:`PROTOCOL_VERSION`).
        their_version: The envelope ``v`` field from the incoming
            message.
        their_min_v: The envelope ``min_v`` field, if present.

    Returns:
        ``True`` if the exchange can proceed, ``False`` otherwise.

    Raises:
        ValueError: if any supplied version string is malformed.

    Spec: ARSIA-Core.md §4.3.1, §7.4.
    """
    ours = parse_version(our_version)
    theirs = parse_version(their_version)
    if ours[0] != theirs[0]:
        return False
    if their_min_v is not None:
        min_required = parse_version(their_min_v)
        if ours < min_required:
            return False
    return True


def validate_outbound_version(
    envelope_v: str,
    server_max: str,
) -> None:
    """Reject outbound messages with v higher than the recipient's server_max.

    Per §7.4, agents MUST NOT send messages with a ``v`` value higher
    than the recipient's ``server_max`` as advertised in their discovery
    endpoint.

    Args:
        envelope_v: The ``v`` field of the envelope being sent.
        server_max: The recipient's ``server_max`` from discovery.

    Raises:
        ValueError: if ``envelope_v`` exceeds ``server_max``.

    Spec: ARSIA-Core.md §7.4.
    """
    v = parse_version(envelope_v)
    s_max = parse_version(server_max)
    if v > s_max:
        raise ValueError(
            f"envelope v={envelope_v!r} exceeds recipient's "
            f"server_max={server_max!r} (Core §7.4)"
        )


def extract_content_type_version(header_value: str | None) -> str | None:
    """Return the ``v=`` parameter value from a Content-Type header.

    Spec: ARSIA-Core.md §14.1 — the ``v`` parameter indicates the major
    protocol version. Returns ``None`` when the header is absent or
    does not carry a ``v`` parameter.
    """
    if not header_value:
        return None
    parts = [p.strip() for p in header_value.split(";") if p.strip()]
    for param in parts[1:]:
        key, _, value = param.partition("=")
        if key.strip().lower() == "v":
            return value.strip() or None
    return None


__all__ = [
    "__version__",
    "PROTOCOL_VERSION",
    "parse_version",
    "compare_versions",
    "is_compatible",
    "validate_outbound_version",
    "extract_content_type_version",
]
