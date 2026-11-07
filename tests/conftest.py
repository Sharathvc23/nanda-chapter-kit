from __future__ import annotations

import base64
import secrets
import time
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sm_arp import Identity
from sm_server.signing import derive_did_key
from sm_server.store.sqlite import SqliteStore

from nanda_chapter.app import create_app
from nanda_chapter.config import ChapterConfig
from nanda_chapter.state import ChapterState


@dataclass
class Agent:
    agent_id: str
    seed: bytes
    pub: bytes

    @property
    def pub_b64(self) -> str:
        return base64.b64encode(self.pub).decode()

    @property
    def did_key(self) -> str:
        return derive_did_key(self.pub)

    def _sign(self, canonical: str) -> str:
        sig = Ed25519PrivateKey.from_private_bytes(self.seed).sign(canonical.encode())
        return base64.b64encode(sig).decode()

    def headers_v02(self, body: str = "") -> dict[str, str]:
        ts = str(int(time.time()))
        return {
            "X-Agent-ID": self.agent_id,
            "X-Agent-DID-Key": self.did_key,
            "X-Agent-Timestamp": ts,
            "X-Agent-Sig-Scheme": "ed25519",
            "X-Agent-Signature": self._sign(f"{body}:{self.agent_id}:{ts}"),
        }

    def headers_v03(self, method: str, path: str, body: str = "", nonce: str | None = None) -> dict[str, str]:
        ts = str(int(time.time()))
        nonce = nonce or base64.b64encode(secrets.token_bytes(32)).decode()
        return {
            "X-Agent-ID": self.agent_id,
            "X-Agent-DID-Key": self.did_key,
            "X-Agent-Timestamp": ts,
            "X-Agent-Nonce": nonce,
            "X-Agent-Sig-Scheme": "ed25519+nonce",
            "X-Agent-Signature": self._sign(f"{method.upper()}:{path}:{body}:{self.agent_id}:{ts}:{nonce}"),
        }


def make_agent(prefix: str = "agent") -> Agent:
    seed = secrets.token_bytes(32)
    pub = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    return Agent(f"{prefix}-{secrets.token_hex(3)}", seed, pub)


def make_cfg(tmp_path: Path, **over) -> ChapterConfig:
    env = {
        "CHAPTER_HOME": str(tmp_path),
        "CHAPTER_ID": "test-chapter",
        "CHAPTER_NAME": "Test Chapter",
        "PUBLIC_URL": "https://chapter.example.org",
        "CHAPTER_DOMAIN": "chapter.example.org",
        "CHAPTER_FOCUS": "testing, agents",
        "ADMISSION_MODE": "open",
        "CONTACT_EMAIL": "council@example.org",
        # Tests assert catalog contents; production default is opt-in (off).
        "CATALOG_DEFAULT_LISTED": "true",
    }
    env.update({k: str(v) for k, v in over.items()})
    return ChapterConfig.from_env(env)


def make_client(cfg: ChapterConfig) -> TestClient:
    app = create_app(cfg, store=SqliteStore(":memory:"), state=ChapterState(":memory:"))
    return TestClient(app)


@pytest.fixture
def reviewers() -> list[Identity]:
    return [Identity.generate() for _ in range(3)]


@pytest.fixture
def open_client(tmp_path: Path) -> TestClient:
    return make_client(make_cfg(tmp_path))


@pytest.fixture
def council_client(tmp_path: Path, reviewers: list[Identity]) -> TestClient:
    cfg = make_cfg(
        tmp_path,
        ADMISSION_MODE="council",
        COUNCIL_REVIEWERS=",".join(r.did for r in reviewers),
        COUNCIL_REQUIRED_M="2",
    )
    return make_client(cfg)


def register(client: TestClient, agent: Agent, origin: str = "sovereign") -> dict:
    r = client.post("/api/members", json={"agent_id": agent.agent_id, "name": agent.agent_id, "origin": origin, "public_key": agent.pub_b64})
    assert r.status_code == 200, r.text
    return r.json()
