"""Client-side helpers for council reviewers (humans, or their delegated agents).

A reviewer never talks to the chapter database. They receive a proposal (JSON
from ``GET /api/council/proposals/{id}``), sign a gesture receipt with their own
key, collect co-witness signatures from other reviewers until the quorum is
met, and POST the receipt. The chapter verifies; it never signs on their behalf.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from typing import Any

from sm_arp import Identity
from sm_oversight import (
    APPROVED,
    DENIED,
    ESCALATED,
    add_witness,
    build_oversight_approval,
    build_oversight_decision,
)


def reviewer_identity(seed_b64: str) -> Identity:
    return Identity.from_seed(base64.b64decode(seed_b64))


def new_reviewer_seed() -> str:
    import secrets

    return base64.b64encode(secrets.token_bytes(32)).decode()


def build_gesture(
    reviewer: Identity,
    proposal: dict[str, Any],
    *,
    decision: str,
    reviewers: list[str] | None = None,
    summary: str = "",
    grant_days: int = 30,
) -> dict[str, Any]:
    """One reviewer's signed answer to a proposal.

    The approve gesture is an ``authority_granted`` receipt scoped to the
    proposal's category for the proposal's subject; deny/escalate are
    ``decision_made`` receipts. Pass the resulting dict to ``add_witness`` for
    each further reviewer, then POST it to ``/api/council/proposals/{id}/gestures``.
    """
    gesture = _build(reviewer, proposal, decision=decision, reviewers=reviewers, summary=summary, grant_days=grant_days)
    # sm-oversight counts witness signatures, not the issuer signature, toward
    # quorum — so the builder co-signs its own gesture: one reviewer, one vote.
    return add_witness(gesture, reviewer)


def _build(
    reviewer: Identity,
    proposal: dict[str, Any],
    *,
    decision: str,
    reviewers: list[str] | None,
    summary: str,
    grant_days: int,
) -> dict[str, Any]:
    if decision == APPROVED:
        expires = (datetime.now(UTC) + timedelta(days=grant_days)).isoformat(timespec="seconds").replace("+00:00", "Z")
        return build_oversight_approval(
            reviewer,
            principal_did=proposal["proposer_did"],
            agent_did=proposal.get("subject_did") or proposal["proposer_did"],
            reviews_receipt_id=proposal["receipt_id"],
            action_category=proposal.get("category", "record_filed"),
            grant_expires_at=expires,
            reviewers=reviewers,
            human_summary=summary or f"Approved {proposal['kind']} for {proposal['subject']}",
        )
    if decision in (DENIED, ESCALATED):
        return build_oversight_decision(
            reviewer,
            decision=decision,
            principal_did=proposal["proposer_did"],
            reviews_receipt_id=proposal["receipt_id"],
            reviewers=reviewers,
            human_summary=summary or f"{decision} {proposal['kind']} for {proposal['subject']}",
        )
    raise ValueError(f"decision must be one of {APPROVED!r}, {DENIED!r}, {ESCALATED!r}")


def co_sign(gesture: dict[str, Any], reviewer: Identity) -> dict[str, Any]:
    """Add one more reviewer's witness signature. Order-independent, idempotent per DID."""
    return add_witness(gesture, reviewer)
