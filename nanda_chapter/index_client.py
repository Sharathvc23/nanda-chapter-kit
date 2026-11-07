"""NANDA Index v2 client (api.nandaindex.org) — operator-triggered, never at boot.

The Index holds one entry per organisation. A chapter registers as a
``registry`` org: ``urn:air:<domain>:catalog:root`` whose ``registry_url`` is
this chapter, where the AI Catalog lists every admitted member. Activation is a
DNS TXT record on the chapter's domain, so only the domain holder can make a
chapter resolvable — that is the Index's authority evidence, and it is why a
chapter needs a domain, not just a Railway hostname.

Registration ≠ discoverability. ``POST /api/v1/orgs`` creates a ``pending`` row
nobody can resolve; only ``verify-domain`` flips it ``active``. ``resolve()`` is
the one check that proves a stranger can find the chapter.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import httpx

from .config import ChapterConfig


def sanitize_org_id(raw: str) -> str:
    s = re.sub(r"[^a-z0-9-]", "-", raw.lower())
    s = re.sub(r"-+", "-", s).strip("-")
    return s or "chapter"


@dataclass
class IndexClient:
    cfg: ChapterConfig
    http: httpx.Client | None = None
    _token: str | None = None

    def _client(self) -> httpx.Client:
        if self.http is None:
            self.http = httpx.Client(base_url=self.cfg.index_url, timeout=20.0)
        return self.http

    # ── pure helpers (tested without a network) ───────────────────────
    @property
    def org_id(self) -> str:
        return sanitize_org_id(self.cfg.chapter_id)

    @property
    def locator(self) -> str:
        return f"urn:air:{self.cfg.domain.lower()}:catalog:root"

    def org_payload(self) -> dict[str, Any]:
        tags = ["nanda-chapter", *[t.strip().lower() for t in self.cfg.focus.split(",") if t.strip()]]
        return {
            "org_id": self.org_id,
            "display_name": self.cfg.name,
            "hosting_path": "registry",
            "domain": self.cfg.domain.lower(),
            "contact_email": self.cfg.contact_email,
            "registry_url": self.cfg.public_url,
            "description": self.cfg.description or f"NANDA chapter {self.cfg.chapter_id}: a home network for personal agents.",
            "tags": tags[:10],
        }

    def preflight(self) -> list[str]:
        problems = []
        if not self.cfg.public_url.startswith("https://"):
            problems.append("registry_url must be https:// (the Index refuses http)")
        if "." not in self.cfg.domain or self.cfg.domain.startswith("localhost"):
            problems.append("CHAPTER_DOMAIN must be a real DNS name you control (DNS-TXT activation)")
        if not self.cfg.contact_email:
            problems.append("CONTACT_EMAIL (or INDEX_ACCOUNT_EMAIL) is required by the Index")
        if not (self.cfg.index_email and self.cfg.index_password):
            problems.append("INDEX_ACCOUNT_EMAIL + INDEX_ACCOUNT_PASSWORD are needed to write to the Index")
        return problems

    # ── network ───────────────────────────────────────────────────────
    def login(self) -> str:
        if self._token:
            return self._token
        creds = {"email": self.cfg.index_email, "password": self.cfg.index_password}
        r = self._client().post("/auth/login", json=creds)
        if r.status_code == 200:
            self._token = r.json()["token"]
            return self._token
        r = self._client().post("/auth/register", json=creds)
        if r.status_code == 201:
            self._token = r.json()["token"]
            return self._token
        raise RuntimeError(f"index auth failed: {r.status_code} {r.text[:200]}")

    def _auth(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.login()}"}

    def register(self, *, dry_run: bool = False) -> dict[str, Any]:
        payload = self.org_payload()
        if dry_run:
            return {"dry_run": True, "would_post": f"{self.cfg.index_url}/api/v1/orgs", "payload": payload, "locator": self.locator, "problems": self.preflight()}
        r = self._client().post("/api/v1/orgs", json=payload, headers=self._auth())
        return {"status_code": r.status_code, "body": _json(r), "locator": self.locator}

    def domain_challenge(self) -> dict[str, Any]:
        r = self._client().post(f"/api/v1/orgs/{self.org_id}/domain-challenge", headers=self._auth())
        return {"status_code": r.status_code, "body": _json(r)}

    def verify_domain(self) -> dict[str, Any]:
        r = self._client().post(f"/api/v1/orgs/{self.org_id}/verify-domain", headers=self._auth())
        return {"status_code": r.status_code, "body": _json(r)}

    def resolve(self) -> dict[str, Any]:
        """Unauthenticated. The only evidence a stranger can find this chapter."""
        r = self._client().get("/api/v1/resolve", params={"locator": self.locator})
        body = _json(r)
        resolves_here = (
            r.status_code == 200
            and isinstance(body, dict)
            and (body.get("entry") or {}).get("url", "").rstrip("/") == self.cfg.public_url.rstrip("/")
        )
        return {"status_code": r.status_code, "locator": self.locator, "resolves_to_this_chapter": resolves_here, "body": body}


def _json(r: httpx.Response) -> Any:
    try:
        return r.json()
    except ValueError:
        return {"raw": r.text[:500]}
