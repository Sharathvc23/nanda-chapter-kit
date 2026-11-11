"""The chapter's store: sm-org-server's SQLite store with an immutable receipt log.

Upstream ``SqliteStore.append_receipt`` is ``INSERT OR REPLACE``: an issuer can
re-sign different content under an existing ``receipt_id`` and rewrite history,
orphaning every successor and invalidating published checkpoints. An issuer log
that the issuer can edit is not evidence. This subclass makes the log append-only:

* the same receipt again → idempotent, returns the existing chain link;
* a different receipt under an existing id → ``ReceiptConflict``;
* a second child of the same predecessor (a fork) → ``ReceiptConflict``;
* a new genesis receipt from an issuer in ``chain_enforced_issuers`` that already
  has a chain → ``ReceiptConflict``. The chapter registers its own DID there: it
  controls its chain, so it must never fork it. External issuers (reviewers,
  members) may start a new chain — their clients decide how they chain — but can
  never rewrite or fork what they already published here.
"""

from __future__ import annotations

import json
from typing import Any

from sm_arp import Identity, canonical_bytes, chain_link, issue_receipt
from sm_server.store.sqlite import SqliteStore


class ReceiptConflict(Exception):
    def __init__(self, reason: str, receipt_id: str) -> None:
        super().__init__(f"{reason}: {receipt_id}")
        self.reason = reason
        self.receipt_id = receipt_id


class ChapterStore(SqliteStore):
    def __init__(self, path: str = ":memory:") -> None:
        super().__init__(path)
        self.chain_enforced_issuers: set[str] = set()
        if path != ":memory:":
            with self._lock:
                self._conn.execute("PRAGMA journal_mode=WAL")

    def _issuer_has_receipts(self, issuer_did: str) -> bool:
        with self._lock:
            row = self._conn.execute("SELECT 1 FROM receipts WHERE issuer_did=? LIMIT 1", (issuer_did,)).fetchone()
        return row is not None

    def _child_of(self, issuer_did: str, previous_hash: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT receipt_id FROM receipts WHERE issuer_did=? AND previous_receipt_hash=? LIMIT 1",
                (issuer_did, previous_hash),
            ).fetchone()
        return row[0] if row else None

    def append_receipt(self, receipt: dict[str, Any]) -> str:
        rid = str(receipt.get("receipt_id"))
        issuer = str(receipt.get("issuer_did"))
        existing = self.get_receipt(rid)
        if existing is not None:
            if canonical_bytes(existing, include_signature=True) == canonical_bytes(receipt, include_signature=True):
                return self._link_of(rid)
            raise ReceiptConflict("receipt_rewrite", rid)
        prev = receipt.get("previous_receipt_hash")
        if prev:
            sibling = self._child_of(issuer, str(prev))
            if sibling is not None and sibling != rid:
                raise ReceiptConflict("chain_fork", rid)
        elif issuer in self.chain_enforced_issuers and self._issuer_has_receipts(issuer):
            raise ReceiptConflict("second_genesis", rid)
        return super().append_receipt(receipt)

    def _link_of(self, receipt_id: str) -> str:
        with self._lock:
            row = self._conn.execute("SELECT chain_link FROM receipts WHERE receipt_id=?", (receipt_id,)).fetchone()
        return str(row[0]) if row else ""

    def last_receipt_for_issuer(self, issuer_did: str) -> dict[str, Any] | None:
        """The issuer's chain head. Ordered by issued_at then rowid, so two receipts
        in the same second cannot fork the chain on resume (upstream had no tiebreak)."""
        with self._lock:
            row = self._conn.execute(
                "SELECT receipt_json FROM receipts WHERE issuer_did=? ORDER BY issued_at DESC, rowid DESC LIMIT 1",
                (issuer_did,),
            ).fetchone()
        return json.loads(row[0]) if row else None

    def receipt_json(self, receipt_id: str) -> str | None:
        r = self.get_receipt(receipt_id)
        return json.dumps(r, sort_keys=True) if r else None


def issue_chained(store: ChapterStore, identity: Identity, *, principal_did: str, action: dict[str, Any], **kw: Any) -> dict[str, Any]:
    """Issue a receipt as the next link in ``identity``'s per-issuer hash chain and append it.

    ARP §6.4: the genesis receipt omits ``previous_receipt_hash``; every later one
    carries the chain link of its predecessor. The chapter's own receipts obey the
    same rule the store enforces on everyone else's.
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
