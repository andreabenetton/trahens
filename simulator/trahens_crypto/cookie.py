# SPDX-License-Identifier: Apache-2.0
"""Trahens B1.2 stateless admission cookie reference.

`network-bootstrap-b1.md` section 7: before allocating a handshake object, a
responder may require a stateless cookie bound to the observed source, the time
window, and the parameters offered so far. It is a denial-of-service control,
**not** an identity proof, and ADR 0045 records it as the floor under whichever
identity model is selected rather than as the thing that authenticates.

What it buys is that a responder allocates nothing, and performs no public-key
operation, for a sender that has not demonstrated return routability. What it
does not buy is any statement about who that sender is.

This reference exists to publish vectors. It is not independently audited and
MUST NOT be used as production security code.
"""

from __future__ import annotations

import hashlib
import hmac

from trahens_spec.generated import (
    BYTES_B12_COOKIE,
    DOMAIN_B12_COOKIE,
    LIMIT_COOKIE_WINDOWS_ACCEPTED,
    LIMIT_COOKIE_WINDOW_MS,
)

SECRET_BYTES = 32


class CookieError(ValueError):
    """Any failure. A sender is never told which check refused it."""


def _lp16(value: bytes) -> bytes:
    if len(value) > 0xFFFF:
        raise CookieError("field too long to length-prefix")
    return len(value).to_bytes(2, "big") + value


def window_id(now_ms: int, window_ms: int = LIMIT_COOKIE_WINDOW_MS) -> int:
    """Which window a moment falls in.

    Windows are absolute rather than relative to any node's start, so two
    responders that disagree about uptime still agree about which window a
    cookie belongs to.
    """
    if now_ms < 0:
        raise CookieError("time must not be negative")
    if window_ms <= 0:
        raise CookieError("window must be positive")
    return now_ms // window_ms


def issue(secret: bytes, source: bytes, port: int, window: int, offer: bytes) -> bytes:
    """Compute the cookie for one (source, port, window, offer).

    Every variable-length field is length-prefixed, so no two different inputs
    can produce the same message: without that, a source address and an offer
    could be split differently and collide.

    The window is inside the MAC rather than carried beside it. A cookie
    therefore cannot be replayed into a later window, and nothing has to be
    stored per issued cookie for that to hold.
    """
    if len(secret) != SECRET_BYTES:
        raise CookieError("responder secret must be 32 bytes")
    if not 0 <= port <= 0xFFFF:
        raise CookieError("port out of range")
    if window < 0:
        raise CookieError("window must not be negative")
    message = (
        DOMAIN_B12_COOKIE
        + _lp16(source)
        + port.to_bytes(2, "big")
        + window.to_bytes(8, "big")
        + _lp16(offer)
    )
    return hmac.new(secret, message, hashlib.sha256).digest()[:BYTES_B12_COOKIE]


def verify(
    secrets: list[bytes],
    cookie: bytes,
    source: bytes,
    port: int,
    offer: bytes,
    now_ms: int,
    windows_accepted: int = LIMIT_COOKIE_WINDOWS_ACCEPTED,
    window_ms: int = LIMIT_COOKIE_WINDOW_MS,
) -> bool:
    """Whether `cookie` is one this responder issued and still accepts.

    `secrets` is newest first: the current window's secret, then the retained
    previous ones. A cookie issued just before a boundary must still verify
    just after it, or every rotation would reject the senders mid-exchange;
    that is the whole reason more than one secret is kept.

    Comparison is constant time. The number of windows accepted is what bounds
    a cookie's life, and it is a registry value rather than a local choice.
    """
    if windows_accepted < 1:
        raise CookieError("at least one window must be accepted")
    if len(cookie) != BYTES_B12_COOKIE:
        return False
    current = window_id(now_ms, window_ms)
    accepted = False
    # Every candidate is evaluated: returning early on the first match would
    # make the time taken depend on which window the cookie came from.
    for index in range(min(windows_accepted, len(secrets))):
        window = current - index
        if window < 0:
            continue
        expected = issue(secrets[index], source, port, window, offer)
        accepted |= hmac.compare_digest(expected, cookie)
    return accepted
