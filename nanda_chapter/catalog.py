"""The chapter's discovery surface: what the NANDA Index resolves to.

The Index is a switchboard. It holds ONE entry per organisation, the chapter's
``urn:air:<domain>:catalog:root``, whose ``registry_url`` points here. A
resolver then reads this chapter's AI Catalog and finds every admitted member
as its own entry with its own A2A agent card. That is how "every member on the
Index" works without the Index hosting agents.

Shapes come from ``sm-bridge``; this module only decides *which* members are
listed (admitted, not withheld) and *what* a member's card points at. A
personal agent usually has no inbound URL of its own, so its card points at the
chapter-hosted mailbox (``/a2a/@<agent_id>``) — the chapter is the network edge
that makes the agent reachable.
"""

from __future__ import annotations

from collections.abc import Callable

from fastapi import APIRouter, HTTPException
from sm_bridge import (
    CatalogDocument,
    CatalogEntry,
    SmAgentFacts,
    SmAuthentication,
    SmCapabilities,
    SmEndpoints,
    SmProvider,
    SmSkill,
)
from sm_bridge.gateway import to_a2a_card, to_catalog_entry
from sm_server.store.base import Member, ServerStore

from .config import ChapterConfig
from .state import now_iso

WITHHELD_PREFIXES = ("TEST-", "demo-agent-")


def is_withheld(agent_id: str) -> bool:
    """Probe and demo identities never reach a public directory."""
    return agent_id.startswith(WITHHELD_PREFIXES)


def member_facts(cfg: ChapterConfig, m: Member) -> SmAgentFacts:
    base = cfg.public_url
    mailbox = f"{base}/a2a/@{m.agent_id}"
    return SmAgentFacts(
        id=f"did:web:{cfg.domain}:agents:{m.agent_id}",
        handle=f"@{m.agent_id}@{cfg.domain}",
        agent_name=m.agent_id,
        label=m.name,
        description=f"Member of {cfg.name}",
        version="0.1.0",
        provider=SmProvider(name=cfg.name, url=base, did=m.did_key),
        endpoints=SmEndpoints(static=[mailbox], dynamic=[]),
        capabilities=SmCapabilities(
            modalities=["text"],
            skills=[],
            authentication=SmAuthentication(methods=["ed25519"]),
        ),
        skills=[SmSkill(id="chapter-member", description="Reachable through the chapter mailbox", inputModes=["text"], outputModes=["text"])],
        metadata={"origin": m.origin, "did_key": m.did_key, "chapter_id": cfg.chapter_id, "mailbox": mailbox},
    )


def a2a_v1_card(card: dict, m: Member, cfg: ChapterConfig) -> dict:
    """Lift sm-bridge's v0.2-era card to the A2A v1.0 shape the NANDA Index validates.

    Adds ``supportedInterfaces``, ``securitySchemes``, ``defaultInputModes`` /
    ``defaultOutputModes`` and gives every skill an ``id`` and ``tags``; drops the
    retired ``authentication`` block. The legacy top-level ``url`` is kept because
    the Index still accepts it as a fallback.
    """
    mailbox = card.get("url") or f"{cfg.public_url}/a2a/@{m.agent_id}"
    skills = []
    for i, s in enumerate(card.get("skills") or []):
        skills.append(
            {
                "id": s.get("id") or (s.get("name") or f"skill-{i}").lower().replace(" ", "-"),
                "name": s.get("name") or s.get("id") or f"skill {i}",
                "description": s.get("description") or "",
                "tags": s.get("tags") or ["chapter-member"],
                "inputModes": s.get("inputModes") or ["text/plain"],
                "outputModes": s.get("outputModes") or ["text/plain"],
            }
        )
    card.pop("authentication", None)
    card.update(
        {
            "protocolVersion": "1.0",
            "url": mailbox,
            "supportedInterfaces": [{"url": mailbox, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}],
            "securitySchemes": {"ed25519": {"type": "httpSignature", "description": "X-Agent-* Ed25519 headers, scheme ed25519+nonce"}},
            "securityRequirements": [{}, {"ed25519": []}],
            "defaultInputModes": ["text/plain", "application/json"],
            "defaultOutputModes": ["text/plain", "application/json"],
            "skills": skills or [{"id": "chapter-member", "name": "Chapter member", "description": "Reachable through the chapter mailbox", "tags": ["chapter-member"], "inputModes": ["text/plain"], "outputModes": ["text/plain"]}],
        }
    )
    return card


def chapter_card(cfg: ChapterConfig, server_did: str, member_count: int) -> dict:
    """The chapter's own A2A agent card at ``/.well-known/agent.json``."""
    base = cfg.public_url
    return {
        "name": cfg.name,
        "description": cfg.description or f"NANDA chapter {cfg.chapter_id}",
        "url": f"{base}/a2a",
        "version": "0.1.0",
        "protocolVersion": "1.0",
        "supportedInterfaces": [{"url": f"{base}/a2a", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}],
        "capabilities": {"streaming": False, "pushNotifications": False},
        "securitySchemes": {"ed25519": {"type": "httpSignature", "description": "X-Agent-* Ed25519 headers, scheme ed25519+nonce"}},
        "securityRequirements": [{}, {"ed25519": []}],
        "defaultInputModes": ["text/plain", "application/json"],
        "defaultOutputModes": ["text/plain", "application/json"],
        "skills": [
            {"id": "join", "name": "Join the chapter", "description": "POST /api/members — did:key TOFU registration", "tags": ["membership"]},
            {"id": "directory", "name": "Member directory", "description": "Signed GET /api/members", "tags": ["discovery"]},
            {"id": "mailbox", "name": "Member mailbox", "description": "POST /a2a/@<agent_id> store-and-forward", "tags": ["messaging"]},
            {"id": "council", "name": "Council", "description": "Charter and admission proposals with M-of-N human quorum", "tags": ["governance"]},
        ],
        "provider": {"organization": "Project NANDA chapter", "url": base},
        "_meta": {
            "chapter_id": cfg.chapter_id,
            "did": server_did,
            "focus": cfg.focus,
            "members": member_count,
            "identifier": f"urn:air:{cfg.domain}:catalog:root",
            "catalog": f"{base}/.well-known/ai-catalog.json",
            "nanda": f"{base}/.well-known/nanda-agent.json",
        },
    }


def create_catalog_router(
    cfg: ChapterConfig,
    store: ServerStore,
    *,
    is_listed: Callable[[str], bool],
    is_resolvable: Callable[[str], bool],
    server_did: Callable[[], str],
) -> APIRouter:
    """``is_listed`` gates the enumerable catalog; ``is_resolvable`` gates exact-id
    card lookups. A member may be resolvable by whoever already knows its id
    without being enumerable by anyone — listing is the member's choice."""
    router = APIRouter()
    base = cfg.public_url

    def _listed_members() -> list[Member]:
        return [
            m
            for m in store.list_members(10_000)
            if not is_withheld(m.agent_id) and is_listed(m.agent_id)
        ]

    def _entries() -> list[CatalogEntry]:
        root = CatalogEntry(
            identifier=cfg.chapter_id,
            displayName=cfg.name,
            mediaType="application/a2a-agent-card+json",
            url=f"{base}/.well-known/agent.json",
            description=cfg.description or f"NANDA chapter {cfg.chapter_id}",
            tags=["nanda-chapter", *[t.strip().lower() for t in cfg.focus.split(",") if t.strip()]],
            version="0.1.0",
            updatedAt=now_iso(),
        )
        members = [to_catalog_entry(member_facts(cfg, m), m.agent_id, base) for m in _listed_members()]
        return [root, *members]

    @router.get("/.well-known/ai-catalog.json", response_model=CatalogDocument)
    def ai_catalog() -> CatalogDocument:
        return CatalogDocument(host=cfg.domain, entries=_entries())

    @router.get("/.well-known/agent.json")
    @router.get("/.well-known/agent-card.json")
    def agent_card() -> dict:
        return chapter_card(cfg, server_did(), len(_listed_members()))

    @router.get("/agents/{slug}", response_model=CatalogEntry)
    def get_agent(slug: str) -> CatalogEntry:
        for e in _entries():
            if e.identifier == slug:
                return e
        raise HTTPException(status_code=404, detail="unknown agent")

    @router.get("/cards/{slug}.json")
    def get_card(slug: str) -> dict:
        if slug == cfg.chapter_id:
            return chapter_card(cfg, server_did(), len(_listed_members()))
        m = store.get_member(slug)
        if m is None or is_withheld(slug) or not is_resolvable(slug):
            raise HTTPException(status_code=404, detail="unknown agent")
        return a2a_v1_card(to_a2a_card(member_facts(cfg, m), slug, cfg.domain, base).model_dump(by_alias=True), m, cfg)

    @router.get("/.well-known/nanda.json")
    def nanda_well_known() -> dict:
        """sm-bridge peers read this to learn the chapter's registry surfaces."""
        return {
            "registry_id": cfg.chapter_id,
            "registry_did": server_did(),
            "namespaces": [f"did:web:{cfg.domain}:*"],
            "index_url": f"{base}/.well-known/ai-catalog.json",
            "resolve_url": f"{base}/agents",
            "deltas_url": None,
            "tools_url": None,
            "a2a_send_url": f"{base}/a2a",
            "provider": {"name": cfg.name, "url": base, "did": server_did()},
            "capabilities": ["ai-catalog", "a2a-agent-card", "chapter"],
            "peers": list(cfg.known_peers) or None,
        }

    return router
