"""The council: human quorum over chapter decisions, as signed receipts.

A chapter has decisions with collective blast radius — admitting a member,
chartering the chapter itself, admitting a peer chapter, promoting a leader.
Each becomes a *proposal*: an ARP receipt the chapter issues with outcome
``pending``. Reviewers answer with *gestures*: ``sm-oversight`` receipts they
sign themselves (approve / deny / escalate), co-witnessed until the configured
M-of-N quorum is met. The chapter verifies every gesture against the trusted
reviewer set and only then executes the effect.

Nothing here is an LLM. A reviewer may be a human with a key, or an agent
holding a bounded ``sm-dat`` grant from that human — the chapter cannot tell
and does not need to; the quorum is over signatures.
"""

from __future__ import annotations

import copy
import secrets
from collections.abc import Callable
from typing import Any

from sm_arp import Identity, build_action, issue_receipt, verify_receipt
from sm_oversight import APPROVED, DENIED, ESCALATED, OVERSIGHT_KEY, verify_quorum
from sm_server.store.base import ServerStore

from .config import ChapterConfig
from .state import PROPOSAL_KINDS, ChapterState, Proposal

# What a proposal of each kind does when approved. Kept small and explicit:
# the set is closed, like the umbrella's APPROVAL_KINDS.
PROPOSAL_CATEGORY = {
    "member_admission": "record_filed",
    "member_revocation": "decision_made",
    "chapter_charter": "commitment_entered",
    "peer_admission": "record_filed",
    "role_promotion": "record_filed",
}


class CouncilError(Exception):
    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


class Council:
    def __init__(
        self,
        cfg: ChapterConfig,
        state: ChapterState,
        store: ServerStore,
        identity: Identity,
        *,
        on_approved: Callable[[Proposal], None],
    ) -> None:
        self.cfg = cfg
        self.state = state
        self.store = store
        self.identity = identity
        self._configured_reviewers = set(cfg.council_reviewers)
        self._operator_revoked = set(cfg.council_revoked_reviewers)
        self.required_m = max(1, cfg.council_required_m)
        self._on_approved = on_approved

    @property
    def reviewers(self) -> set[str]:
        """Trusted reviewers right now: configured minus revoked (operator env or state)."""
        return self._configured_reviewers - self._operator_revoked - self.state.revoked_reviewers()

    def revoke_reviewer(self, did: str, reason: str) -> None:
        self.state.revoke_reviewer(did, reason)

    # ── read ──────────────────────────────────────────────────────────
    def describe(self) -> dict[str, Any]:
        return {
            "chapter_id": self.cfg.chapter_id,
            "chapter_did": self.identity.did,
            "reviewers": sorted(self.reviewers),
            "revoked_reviewers": sorted(self._operator_revoked | self.state.revoked_reviewers()),
            "required_m": self.required_m,
            "quorum": f"{self.required_m}-of-{len(self.reviewers)}" if self.reviewers else "no council configured",
            "kinds": list(PROPOSAL_KINDS),
            "pending": len(self.state.list_proposals("pending")),
        }

    # ── propose ───────────────────────────────────────────────────────
    def propose(self, *, kind: str, subject: str, proposer_did: str, summary: str) -> Proposal:
        if kind not in PROPOSAL_KINDS:
            raise CouncilError(400, f"unknown kind {kind!r}; one of {list(PROPOSAL_KINDS)}")
        if not subject:
            raise CouncilError(400, "subject required")
        existing = self.state.pending_for_subject(kind, subject)
        if existing:
            return existing
        pid = f"prop-{secrets.token_hex(6)}"
        action = build_action(
            category=PROPOSAL_CATEGORY[kind],
            human_summary=(summary or f"{kind} for {subject}")[:280],
            outcome="pending",
            machine_payload={"proposal": {"id": pid, "kind": kind, "subject": subject}},
        )
        receipt = issue_receipt(self.identity, principal_did=proposer_did, action=action)
        self.store.append_receipt(receipt)
        return self.state.create_proposal(
            id=pid, kind=kind, subject=subject, proposer_did=proposer_did, summary=summary, receipt_id=receipt["receipt_id"]
        )

    # ── gesture ───────────────────────────────────────────────────────
    def gesture(self, proposal_id: str, receipt: dict[str, Any]) -> Proposal:
        """Accept one reviewer gesture receipt; execute when quorum is reached."""
        p = self.state.get_proposal(proposal_id)
        if p is None:
            raise CouncilError(404, "unknown proposal")
        if p.status != "pending":
            raise CouncilError(409, f"proposal already {p.status}")
        if not self.reviewers:
            raise CouncilError(409, "no council configured; set COUNCIL_REVIEWERS")

        vr = verify_receipt(_without_witnesses(receipt))
        if not vr.ok:
            raise CouncilError(401, f"gesture receipt invalid: {vr.detail}")
        issuer = receipt.get("issuer_did")
        if issuer not in self.reviewers:
            raise CouncilError(403, "gesture issuer is not a trusted reviewer")
        osp = receipt.get("action", {}).get("machine_payload", {}).get(OVERSIGHT_KEY, {})
        if osp.get("reviews_receipt_id") != p.receipt_id:
            raise CouncilError(400, "gesture does not review this proposal's receipt")
        decision = osp.get("decision")
        if decision not in (APPROVED, DENIED, ESCALATED):
            raise CouncilError(400, "gesture carries no recognised decision")

        self.store.append_receipt(receipt)
        self.state.add_gesture(proposal_id, receipt, decision)

        if decision == DENIED:
            self.state.decide(proposal_id, "denied")
        elif decision == ESCALATED:
            self.state.decide(proposal_id, "escalated")
        else:
            q = verify_quorum(receipt, m=self.required_m, trusted=self.reviewers)
            if q.ok:
                self.state.decide(proposal_id, "approved")
                p = self.state.get_proposal(proposal_id)
                assert p is not None
                self._on_approved(p)
        p = self.state.get_proposal(proposal_id)
        assert p is not None
        return p


def _without_witnesses(receipt: dict[str, Any]) -> dict[str, Any]:
    """The receipt as its issuer signed it.

    ``sm-oversight`` co-signatures are appended to ``evidence.witness_signatures``
    AFTER the issuer signed, over bytes that exclude that list — so the issuer's
    signature must be checked on the receipt with the list stripped, exactly as
    the witnesses' own signatures are.
    """
    g = copy.deepcopy(receipt)
    ev = g.get("evidence")
    if isinstance(ev, dict):
        ev.pop("witness_signatures", None)
        if not ev:
            g.pop("evidence", None)
    return g


def proposal_json(p: Proposal) -> dict[str, Any]:
    return {
        "id": p.id,
        "kind": p.kind,
        "subject": p.subject,
        "proposer_did": p.proposer_did,
        "summary": p.summary,
        "receipt_id": p.receipt_id,
        "status": p.status,
        "created_at": p.created_at,
        "decided_at": p.decided_at,
        "gestures": [
            {
                "receipt_id": g.get("receipt_id"),
                "issuer_did": g.get("issuer_did"),
                "decision": g.get("action", {}).get("machine_payload", {}).get(OVERSIGHT_KEY, {}).get("decision"),
                "witnesses": [w.get("signer_did") or w.get("witness_did") for w in g.get("evidence", {}).get("witness_signatures", [])],
            }
            for g in p.gestures
        ],
    }
