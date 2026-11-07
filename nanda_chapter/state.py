"""The kit's own durable state — what the conformant floor does not persist.

``sm-org-server``'s ``ServerStore`` holds members, nonces, trust events and the
ARP issuer log. The chapter adds three things on top, kept in one SQLite file
under ``CHAPTER_HOME``: admission decisions, council proposals with their
gesture receipts, and the store-and-forward inbox for members with no public
endpoint. Each is a plain table; nothing here is protocol.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROPOSAL_KINDS = ("member_admission", "chapter_charter", "peer_admission", "role_promotion")
PROPOSAL_STATUSES = ("pending", "approved", "denied", "escalated", "expired")


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class Proposal:
    id: str
    kind: str
    subject: str
    proposer_did: str
    summary: str
    receipt_id: str
    status: str
    created_at: str
    decided_at: str | None
    gestures: list[dict[str, Any]]


class ChapterState:
    def __init__(self, path: str | Path) -> None:
        self._path = str(path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._init()

    def _init(self) -> None:
        with self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS admissions (
                    agent_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,          -- admitted | pending | denied
                    via TEXT NOT NULL,             -- open | council:<proposal_id> | parc | operator
                    decided_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS proposals (
                    id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    proposer_did TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    receipt_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    decided_at TEXT
                );
                CREATE TABLE IF NOT EXISTS gestures (
                    receipt_id TEXT PRIMARY KEY,
                    proposal_id TEXT NOT NULL REFERENCES proposals(id),
                    decision TEXT NOT NULL,
                    receipt_json TEXT NOT NULL,
                    received_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS inbox (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    sender TEXT NOT NULL,
                    message_json TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    delivered_at TEXT
                );
                CREATE INDEX IF NOT EXISTS inbox_agent ON inbox(agent_id, delivered_at);
                CREATE TABLE IF NOT EXISTS roles (
                    agent_id TEXT PRIMARY KEY,
                    role TEXT NOT NULL,            -- member | leader | admin
                    set_at TEXT NOT NULL
                );
                """
            )

    # ── admissions ────────────────────────────────────────────────────
    def admission(self, agent_id: str) -> tuple[str, str] | None:
        row = self._conn.execute("SELECT status, via FROM admissions WHERE agent_id=?", (agent_id,)).fetchone()
        return (row[0], row[1]) if row else None

    def set_admission(self, agent_id: str, status: str, via: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO admissions(agent_id,status,via,decided_at) VALUES(?,?,?,?) "
                "ON CONFLICT(agent_id) DO UPDATE SET status=excluded.status, via=excluded.via, "
                "decided_at=excluded.decided_at",
                (agent_id, status, via, now_iso()),
            )

    def admitted_ids(self) -> set[str]:
        return {r[0] for r in self._conn.execute("SELECT agent_id FROM admissions WHERE status='admitted'")}

    # ── proposals ─────────────────────────────────────────────────────
    def create_proposal(self, *, id: str, kind: str, subject: str, proposer_did: str, summary: str, receipt_id: str) -> Proposal:
        if kind not in PROPOSAL_KINDS:
            raise ValueError(f"unknown proposal kind {kind!r}")
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO proposals(id,kind,subject,proposer_did,summary,receipt_id,status,created_at) "
                "VALUES(?,?,?,?,?,?,'pending',?)",
                (id, kind, subject, proposer_did, summary, receipt_id, now_iso()),
            )
        p = self.get_proposal(id)
        assert p is not None
        return p

    def get_proposal(self, id: str) -> Proposal | None:
        row = self._conn.execute(
            "SELECT id,kind,subject,proposer_did,summary,receipt_id,status,created_at,decided_at FROM proposals WHERE id=?",
            (id,),
        ).fetchone()
        if not row:
            return None
        gestures = [
            json.loads(g[0])
            for g in self._conn.execute(
                "SELECT receipt_json FROM gestures WHERE proposal_id=? ORDER BY received_at", (id,)
            )
        ]
        return Proposal(*row, gestures=gestures)

    def pending_for_subject(self, kind: str, subject: str) -> Proposal | None:
        row = self._conn.execute(
            "SELECT id FROM proposals WHERE kind=? AND subject=? AND status='pending' ORDER BY created_at DESC LIMIT 1",
            (kind, subject),
        ).fetchone()
        return self.get_proposal(row[0]) if row else None

    def list_proposals(self, status: str | None = None, limit: int = 100) -> list[Proposal]:
        q = "SELECT id FROM proposals"
        args: tuple[Any, ...] = ()
        if status:
            q += " WHERE status=?"
            args = (status,)
        q += " ORDER BY created_at DESC LIMIT ?"
        rows = self._conn.execute(q, (*args, limit)).fetchall()
        return [p for r in rows if (p := self.get_proposal(r[0])) is not None]

    def add_gesture(self, proposal_id: str, receipt: dict[str, Any], decision: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO gestures(receipt_id,proposal_id,decision,receipt_json,received_at) VALUES(?,?,?,?,?)",
                (receipt["receipt_id"], proposal_id, decision, json.dumps(receipt, sort_keys=True), now_iso()),
            )

    def decide(self, proposal_id: str, status: str) -> None:
        if status not in PROPOSAL_STATUSES:
            raise ValueError(status)
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE proposals SET status=?, decided_at=? WHERE id=?", (status, now_iso(), proposal_id)
            )

    # ── inbox ─────────────────────────────────────────────────────────
    def enqueue(self, agent_id: str, sender: str, message: dict[str, Any]) -> int:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "INSERT INTO inbox(agent_id,sender,message_json,received_at) VALUES(?,?,?,?)",
                (agent_id, sender, json.dumps(message, sort_keys=True), now_iso()),
            )
            return int(cur.lastrowid)

    def drain(self, agent_id: str, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT id,sender,message_json,received_at FROM inbox WHERE agent_id=? AND delivered_at IS NULL "
            "ORDER BY id LIMIT ?",
            (agent_id, limit),
        ).fetchall()
        if rows:
            with self._lock, self._conn:
                self._conn.execute(
                    f"UPDATE inbox SET delivered_at=? WHERE id IN ({','.join('?' * len(rows))})",
                    (now_iso(), *[r[0] for r in rows]),
                )
        return [
            {"id": r[0], "sender": r[1], "message": json.loads(r[2]), "received_at": r[3]} for r in rows
        ]

    def inbox_depth(self, agent_id: str) -> int:
        return int(
            self._conn.execute(
                "SELECT COUNT(*) FROM inbox WHERE agent_id=? AND delivered_at IS NULL", (agent_id,)
            ).fetchone()[0]
        )

    # ── roles ─────────────────────────────────────────────────────────
    def role(self, agent_id: str) -> str:
        row = self._conn.execute("SELECT role FROM roles WHERE agent_id=?", (agent_id,)).fetchone()
        return row[0] if row else "member"

    def set_role(self, agent_id: str, role: str) -> None:
        if role not in ("member", "leader", "admin"):
            raise ValueError(role)
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO roles(agent_id,role,set_at) VALUES(?,?,?) ON CONFLICT(agent_id) DO UPDATE SET role=excluded.role, set_at=excluded.set_at",
                (agent_id, role, now_iso()),
            )
