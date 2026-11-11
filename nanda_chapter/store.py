"""The chapter's store: sm-org-server's SQLite store plus one chapter rule.

sm-org-server >= 0.2.0 makes the receipt log append-only itself (identical
bytes idempotent, ``receipt_rewrite`` / ``chain_fork`` → ``ReceiptConflict``) and
exposes ``last_receipt_for_issuer``. What the chapter adds is the genesis rule for
chains it controls: an issuer in ``chain_enforced_issuers`` (the chapter's own
DID) may not start a second chain. External issuers (reviewers, members) may
start a new chain — their clients decide how they chain — but can never rewrite
or fork what they already published here.
"""

from __future__ import annotations

from typing import Any

from sm_arp import Identity, chain_link, issue_receipt
from sm_server.store.base import ReceiptConflict
from sm_server.store.sqlite import SqliteStore

__all__ = ["ChapterStore", "ReceiptConflict", "issue_chained"]


class ChapterStore(SqliteStore):
    def __init__(self, path: str = ":memory:") -> None:
        super().__init__(path)
        self.chain_enforced_issuers: set[str] = set()

    def _issuer_has_receipts(self, issuer_did: str) -> bool:
        return self.last_receipt_for_issuer(issuer_did) is not None

    def append_receipt(self, receipt: dict[str, Any]) -> str:
        issuer = str(receipt.get("issuer_did"))
        if (
            not receipt.get("previous_receipt_hash")
            and issuer in self.chain_enforced_issuers
            and self.get_receipt(str(receipt.get("receipt_id"))) is None
            and self._issuer_has_receipts(issuer)
        ):
            raise ReceiptConflict("second_genesis")
        return super().append_receipt(receipt)


def issue_chained(store: ChapterStore, identity: Identity, *, principal_did: str, action: dict[str, Any], **kw: Any) -> dict[str, Any]:
    """Issue a receipt as the next link in ``identity``'s per-issuer hash chain and append it.

    ARP §6.4: the genesis receipt omits ``previous_receipt_hash``; every later one
    carries the chain link of its predecessor.
    """
    head = store.last_receipt_for_issuer(identity.did)
    receipt = issue_receipt(
        identity,
        principal_did=principal_did,
        action=action,
        previous_receipt_hash=chain_link(head) if head else None,
        **kw,
    )
    store.append_receipt(receipt)
    return receipt
