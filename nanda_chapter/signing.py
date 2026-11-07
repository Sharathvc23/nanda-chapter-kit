"""Signed-request verification for both wire schemes (spec/0.2 §3, spec/0.3 §3).

``ed25519``        — canonical ``body:agent_id:timestamp``             (v0.2)
``ed25519+nonce``  — canonical ``method:url_path:body:agent_id:timestamp:nonce`` (v0.3)

The verifier fails closed: any missing header, unknown scheme, skewed clock,
replayed nonce, key mismatch or bad signature is a 401 with a reason from the
closed set the spec names. Nothing here knows what endpoint it is protecting.
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sm_server import signing as _sm_signing
from sm_server.store.base import Member, ServerStore

TIMESTAMP_WINDOW_S = 300
SCHEME_V02 = "ed25519"
SCHEME_V03 = "ed25519+nonce"
REASONS = frozenset(
    {
        "missing_agent_id",
        "missing_signature",
        "missing_timestamp",
        "missing_nonce",
        "unknown_sig_scheme",
        "invalid_timestamp",
        "expired_timestamp",
        "invalid_did_key",
        "key_mismatch",
        "no_stored_key",
        "nonce_replay",
        "invalid_signature",
    }
)


class SignatureError(Exception):
    """Verification failed. ``reason`` is always one of ``REASONS``."""

    def __init__(self, reason: str) -> None:
        assert reason in REASONS, reason
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Verified:
    agent_id: str
    did_key: str
    public_key_b64: str
    scheme: str
    bootstrapped: bool  # True when this request TOFU-registered the caller


def canonical_v02(body: str, agent_id: str, timestamp: str) -> str:
    return f"{body}:{agent_id}:{timestamp}"


def canonical_v03(method: str, url_path: str, body: str, agent_id: str, timestamp: str, nonce: str) -> str:
    return f"{method.upper()}:{url_path}:{body}:{agent_id}:{timestamp}:{nonce}"


def _verify_ed25519(pubkey32: bytes, signature: bytes, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pubkey32).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_headers(
    headers: dict[str, str],
    *,
    method: str,
    url_path: str,
    body: bytes,
    store: ServerStore,
    tofu: bool,
    now: float | None = None,
) -> Verified:
    """Verify one signed request against the members on file.

    ``headers`` is case-insensitive in practice; callers pass lower-cased keys.
    ``url_path`` is the request-line path including the query string.
    ``tofu`` lets an unknown agent register itself by signing (spec §3.1 bootstrap);
    the directory read allows it, mutations on protected resources do not.
    """
    h = {k.lower(): v for k, v in headers.items()}
    agent_id = h.get("x-agent-id", "")
    if not agent_id:
        raise SignatureError("missing_agent_id")
    sig_b64 = h.get("x-agent-signature", "")
    if not sig_b64:
        raise SignatureError("missing_signature")
    ts = h.get("x-agent-timestamp", "")
    if not ts:
        raise SignatureError("missing_timestamp")
    scheme = h.get("x-agent-sig-scheme", SCHEME_V02)
    if scheme not in (SCHEME_V02, SCHEME_V03):
        raise SignatureError("unknown_sig_scheme")
    try:
        ts_int = int(ts)
    except ValueError:
        raise SignatureError("invalid_timestamp") from None
    if abs(int(now if now is not None else time.time()) - ts_int) > TIMESTAMP_WINDOW_S:
        raise SignatureError("expired_timestamp")

    did_key_hdr = h.get("x-agent-did-key", "")
    try:
        claimed_pub = _sm_signing.parse_did_key(did_key_hdr) if did_key_hdr else b""
        signature = base64.b64decode(sig_b64, validate=True)
    except (ValueError, TypeError, KeyError, IndexError):
        raise SignatureError("invalid_did_key" if did_key_hdr else "invalid_signature") from None

    member = store.get_member(agent_id)
    if member is not None:
        stored_pub = base64.b64decode(member.public_key)
        if claimed_pub and claimed_pub != stored_pub:
            raise SignatureError("key_mismatch")
        pub = stored_pub
        did_key = member.did_key
    else:
        if not tofu or not claimed_pub:
            raise SignatureError("no_stored_key")
        pub = claimed_pub
        did_key = did_key_hdr

    body_str = body.decode("utf-8", "strict")
    if scheme == SCHEME_V03:
        nonce = h.get("x-agent-nonce", "")
        if not nonce:
            raise SignatureError("missing_nonce")
        canonical = canonical_v03(method, url_path, body_str, agent_id, ts, nonce)
    else:
        canonical = canonical_v02(body_str, agent_id, ts)

    if not _verify_ed25519(pub, signature, canonical.encode()):
        raise SignatureError("invalid_signature")

    # Replay store is consulted only after the signature verifies, so an attacker
    # cannot burn a victim's nonce with a forged request.
    if scheme == SCHEME_V03 and not store.consume_nonce(agent_id, h["x-agent-nonce"]):
        raise SignatureError("nonce_replay")

    bootstrapped = False
    if member is None:
        store.put_member(Member(agent_id, agent_id, "sovereign", base64.b64encode(pub).decode(), did_key))
        bootstrapped = True
    return Verified(agent_id, did_key, base64.b64encode(pub).decode(), scheme, bootstrapped)
