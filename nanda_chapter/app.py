"""Compose a chapter from the published primitives.

``create_app`` takes ``sm-org-server``'s conformant floor and adds what a
*chapter* is on top of a *server*:

* the signed-request gate on the member directory, both wire schemes;
* admission (open / council / PARC) deciding who is *listed*, distinct from
  who is *registered*;
* the council: proposals + M-of-N gesture receipts;
* the AI Catalog + A2A cards the NANDA Index resolves to;
* a store-and-forward mailbox so a personal agent with no public endpoint is
  still reachable through its chapter.

No LLM anywhere. The chapter is infrastructure; the members think.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from sm_arp import Identity, build_action, verify_receipt
from sm_server import trust as sm_trust
from sm_server.app import _surface
from sm_server.app import create_app as sm_create_app
from sm_server.store.base import ServerStore
from starlette.middleware.base import BaseHTTPMiddleware

from . import __version__
from .catalog import create_catalog_router, is_withheld
from .config import ChapterConfig
from .council import PROPOSAL_CATEGORY, Council, CouncilError, proposal_json
from .join import JOIN_DOC_PATH, JOIN_TEXT, build_join_document
from .ratelimit import RateLimitMiddleware
from .signing import SignatureError, Verified, verify_headers
from .state import ChapterState, Proposal
from .store import ChapterStore, issue_chained

MAX_MESSAGE_BYTES = 16 * 1024
AGENT_SUBJECT_KINDS = ("member_admission", "member_revocation", "role_promotion")
REPLACED_ROUTES = {
    ("GET", "/health"),
    ("GET", "/api/member/{agent_id}/profile"),
    ("GET", "/api/version"),
    ("GET", "/api/members"),
    ("GET", "/api/federation"),
    ("GET", "/api/federation/{peer_id}/members"),
    ("POST", "/api/feedback"),
    ("GET", "/.well-known/nanda-agent.json"),
}


class AuthError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class RevokedError(Exception):
    """A correctly signed request from a member this chapter has revoked."""


def _drop_routes(app: FastAPI, keys: set[tuple[str, str]]) -> None:
    kept = []
    for r in app.router.routes:
        if isinstance(r, APIRoute) and any((m, r.path) in keys for m in r.methods):
            continue
        kept.append(r)
    app.router.routes[:] = kept


def create_app(cfg: ChapterConfig, store: ServerStore | None = None, state: ChapterState | None = None) -> FastAPI:
    # sm-org-server reads its public URL and signing seed from the environment;
    # hand it the chapter's so the server DID and the chapter DID are one identity.
    os.environ["SERVER_PUBLIC_URL"] = cfg.public_url
    os.environ["SERVER_SEED"] = cfg.seed_b64
    store = store or ChapterStore(str(cfg.home / "store.sqlite"))
    state = state or ChapterState(cfg.home / "chapter.sqlite")
    identity = Identity.from_seed(cfg.seed_bytes)
    if isinstance(store, ChapterStore):
        store.chain_enforced_issuers.add(identity.did)

    app = sm_create_app(
        store=store,
        chapter_id=cfg.chapter_id,
        origins=set(cfg.origins),
        nonrotatable_origins=set(cfg.nonrotatable_origins),
    )
    app.title = f"nanda-chapter {cfg.chapter_id}"
    _drop_routes(app, REPLACED_ROUTES)
    base = cfg.public_url

    # ── admission ─────────────────────────────────────────────────────
    def is_admitted(agent_id: str) -> bool:
        """Registered, admitted under the chapter's mode, and not revoked."""
        if state.is_revoked(agent_id):
            return False
        if cfg.admission_mode == "open":
            return True
        a = state.admission(agent_id)
        return a is not None and a[0] == "admitted"

    def is_listed(agent_id: str) -> bool:
        """Appears in the enumerable catalog: admitted AND opted in (or default-on)."""
        if not is_admitted(agent_id):
            return False
        choice = state.listed(agent_id)
        return cfg.catalog_default_listed if choice is None else choice

    def on_approved(p: Proposal) -> None:
        if p.kind == "member_admission":
            state.set_admission(p.subject, "admitted", f"council:{p.id}")
        elif p.kind == "member_revocation":
            state.revoke_member(p.subject, p.summary or "revoked by council", f"council:{p.id}")
        elif p.kind == "role_promotion":
            state.set_role(p.subject, "leader")
        # chapter_charter / peer_admission leave a receipt; federation wiring lands with peers.

    council = Council(cfg, state, store, identity, on_approved=on_approved)

    def admit_or_propose(agent_id: str, did_key: str) -> None:
        """Called once a registration succeeds. Never raises into the registration."""
        if is_withheld(agent_id):
            return
        if cfg.admission_mode == "open":
            state.set_admission(agent_id, "admitted", "open")
            return
        if state.admission(agent_id) is not None:
            return
        state.set_admission(agent_id, "pending", cfg.admission_mode)
        if cfg.admission_mode == "council" and council.reviewers:
            council.propose(
                kind="member_admission",
                subject=agent_id,
                proposer_did=did_key or identity.did,
                summary=f"{agent_id} asked to join {cfg.name}",
            )

    class AdmissionHook(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next: Callable) -> Any:
            response = await call_next(request)
            if request.method == "POST" and request.url.path.rstrip("/") == "/api/members" and response.status_code == 200:
                body = b"".join([chunk async for chunk in response.body_iterator])
                try:
                    import json

                    data = json.loads(body)
                    if data.get("registered"):
                        m = store.get_member(data["agent_id"])
                        admit_or_propose(data["agent_id"], m.did_key if m else "")
                except (ValueError, KeyError, TypeError, CouncilError):
                    # The hook must never turn a successful registration into an
                    # error; a failed proposal is retried on the member's first
                    # signed read (``signed`` calls ``admit_or_propose`` again).
                    pass
                from starlette.responses import Response

                return Response(content=body, status_code=response.status_code, headers=dict(response.headers), media_type=response.media_type)
            return response

    app.add_middleware(AdmissionHook)
    # Outermost: runs before any body is read or any handler is resolved.
    app.add_middleware(
        RateLimitMiddleware,
        register_per_min=cfg.rate_register_per_min,
        mailbox_per_min=cfg.rate_mailbox_per_min,
        writes_per_min=cfg.rate_writes_per_min,
        reads_per_min=cfg.rate_reads_per_min,
        trust_proxy_headers=cfg.trust_proxy_headers,
    )
    if not cfg.seed_encrypted:
        print(
            f"[custody] chapter seed at {cfg.home / 'seed.b64'} is PLAINTEXT (mode 0600). "
            "Set CHAPTER_SEED_PASSPHRASE to encrypt it at rest, or supply CHAPTER_SEED from a secret store."
        )

    # ── signed requests ───────────────────────────────────────────────
    async def signed(req: Request, *, tofu: bool) -> Verified:
        raw = await req.body()
        path = req.url.path + (f"?{req.url.query}" if req.url.query else "")
        try:
            v = verify_headers(dict(req.headers), method=req.method, url_path=path, body=raw, store=store, tofu=tofu)
        except SignatureError as e:
            raise AuthError(e.reason) from None
        if state.is_revoked(v.agent_id):
            raise RevokedError(v.agent_id)
        if v.bootstrapped:
            admit_or_propose(v.agent_id, v.did_key)
        return v

    @app.exception_handler(AuthError)
    async def _auth_error(_: Request, exc: AuthError) -> JSONResponse:
        return JSONResponse({"error": exc.reason, "detail": exc.reason}, status_code=401)

    @app.exception_handler(RevokedError)
    async def _revoked(_: Request, exc: RevokedError) -> JSONResponse:
        return JSONResponse({"error": "revoked", "agent_id": str(exc)}, status_code=403)

    @app.exception_handler(CouncilError)
    async def _council_error(_: Request, exc: CouncilError) -> JSONResponse:
        return JSONResponse({"error": exc.detail}, status_code=exc.status)

    # ── identity & versions ───────────────────────────────────────────
    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "agent_id": cfg.chapter_id,
            "slug": cfg.chapter_id.replace("-chapter", "").replace("TEST-", "").lower(),
            "display_name": cfg.name,
            "did": identity.did,
            "members": store.member_count(),
            "admitted": len(state.admitted_ids()) if cfg.admission_mode != "open" else store.member_count(),
            "admission_mode": cfg.admission_mode,
            "council": {"reviewers": len(council.reviewers), "required_m": council.required_m, "pending": len(state.list_proposals("pending"))},
            "federation": len(cfg.known_peers),
            "revoked": len(state.revoked_members()),
            "seed_encrypted": cfg.seed_encrypted,
            "rate_limits_per_min": {
                "register": cfg.rate_register_per_min,
                "mailbox": cfg.rate_mailbox_per_min,
                "writes": cfg.rate_writes_per_min,
                "reads": cfg.rate_reads_per_min,
            },
            "kit_version": __version__,
        }

    @app.get("/api/version")
    def version() -> dict[str, Any]:
        return {
            "chapter_id": cfg.chapter_id,
            "protocol_versions": ["0.2", "0.3"],
            "preferred_version": "0.3",
            "a2ui_versions": ["0.9", "0.10"],
            "preferred_a2ui_version": "0.10",
            "arp_versions": ["0.1", "0.2"],
            "preferred_arp_version": "0.2",
            "kit": {"name": "nanda-chapter-kit", "version": __version__},
        }

    @app.get("/.well-known/nanda-agent.json")
    def well_known() -> dict[str, Any]:
        return {
            "agent_id": cfg.chapter_id,
            "did": identity.did,
            "facts_url": f"{base}/.well-known/ai-catalog.json",
            "agent_card": f"{base}/.well-known/agent.json",
            "a2a_url": f"{base}/a2a",
            "checkpoint": f"{base}/api/checkpoint",
            "council": f"{base}/api/council",
            "join": f"{base}{JOIN_DOC_PATH}",
            "registries": {"nanda_index": {"locator": f"urn:air:{cfg.domain}:catalog:root"}},
            "protocol_versions": ["0.2", "0.3"],
            "conformance": f"{base}/.well-known/conformance.json",
        }

    # ── directory (spec §4.12: signed reads only) ─────────────────────
    def _member_row(m: Any) -> dict[str, Any]:
        return {"agent_id": m.agent_id, "name": m.name, "origin": m.origin, "did_key": m.did_key, "admitted": is_admitted(m.agent_id)}

    @app.get("/api/members")
    @app.get("/api/members/", include_in_schema=False)
    async def list_members(req: Request, limit: int = Query(50, ge=1, le=1000), skill: str | None = None) -> dict[str, Any]:
        await signed(req, tofu=True)
        rows = [_member_row(m) for m in store.list_members(limit) if is_admitted(m.agent_id)]
        return {"chapter": cfg.chapter_id, "members": rows, "total": len(rows), "registered": store.member_count()}

    @app.get("/api/federation")
    def federation() -> dict[str, Any]:
        peers = {p.rstrip("/").split("://", 1)[-1]: {"endpoint": p, "status": "configured", "endpoint_source": "allowlist"} for p in cfg.known_peers}
        return {"self": {"agent_id": cfg.chapter_id, "did": identity.did, "name": cfg.name}, "chapters": peers, "total": len(peers)}

    @app.get("/api/federation/{peer_id}/members")
    async def federation_members(peer_id: str, req: Request) -> dict[str, Any]:
        await signed(req, tofu=True)
        if peer_id != cfg.chapter_id:
            raise HTTPException(status_code=404, detail=f"unknown peer: {peer_id}")
        rows = [{"agent_id": m.agent_id, "did_key": m.did_key} for m in store.list_members(1000) if is_admitted(m.agent_id)]
        return {"chapter": peer_id, "members": rows, "total": len(rows)}

    @app.get("/api/member/{agent_id}/profile")
    def member_profile(agent_id: str) -> dict[str, Any]:
        """Exact-match lookup stays public (§4.12): one agent, by id, is not enumeration."""
        m = store.get_member(agent_id)
        if m is None:
            raise HTTPException(status_code=404, detail="unknown agent")
        score = store.trust_score(agent_id)
        tier = sm_trust.tier_for(score)["tier"]
        return _surface(
            f"profile:{agent_id}",
            {"id": "h", "component": "Heading", "text": m.name, "level": 1},
            {"id": "id", "component": "Text", "text": f"@{m.agent_id}@{cfg.domain}"},
            {"id": "did", "component": "Text", "text": m.did_key},
            {"id": "origin", "component": "Text", "text": f"origin: {m.origin} · admitted: {is_admitted(agent_id)}"},
            {"id": "trust", "component": "Text", "text": f"trust: {score:g} ({tier})"},
            {"id": "mailbox", "component": "Text", "text": f"mailbox: {base}/a2a/@{m.agent_id}"},
        )

    # ── the signed join document (a protocol, not prose) ──────────────
    @app.get(JOIN_DOC_PATH)
    def join_document() -> dict[str, Any]:
        return build_join_document(cfg, identity, council_quorum=council.describe()["quorum"])

    @app.get("/join")
    def join_text() -> Any:
        from starlette.responses import PlainTextResponse

        return PlainTextResponse(
            JOIN_TEXT.format(
                name=cfg.name,
                chapter_id=cfg.chapter_id,
                base=base,
                path=JOIN_DOC_PATH,
                locator=f"urn:air:{cfg.domain}:catalog:root",
            )
        )

    # ── listing is the member's choice (enumeration is opt-in) ────────
    @app.post("/api/me/listing")
    async def set_listing(req: Request) -> dict[str, Any]:
        v = await signed(req, tofu=False)
        import json

        body = json.loads(await req.body() or b"{}")
        listed = body.get("listed")
        if not isinstance(listed, bool):
            raise HTTPException(status_code=400, detail="body must be {\"listed\": true|false}")
        state.set_listed(v.agent_id, listed)
        return {"agent_id": v.agent_id, "listed": listed, "admitted": is_admitted(v.agent_id)}

    @app.get("/api/me")
    async def me(req: Request) -> dict[str, Any]:
        v = await signed(req, tofu=False)
        a = state.admission(v.agent_id)
        return {
            "agent_id": v.agent_id,
            "did_key": v.did_key,
            "admitted": is_admitted(v.agent_id),
            "admission": {"status": a[0], "via": a[1]} if a else {"status": "admitted" if cfg.admission_mode == "open" else "unknown", "via": cfg.admission_mode},
            "listed": is_listed(v.agent_id),
            "role": state.role(v.agent_id),
            "inbox_depth": state.inbox_depth(v.agent_id),
        }

    @app.get("/api/revocations")
    def revocations() -> dict[str, Any]:
        """Public: which ids no longer speak for this chapter. Reasons stay internal."""
        return {"revoked": [{"agent_id": r["agent_id"], "revoked_at": r["revoked_at"]} for r in state.revoked_members()]}

    # ── feedback (signed mutation, both schemes) ──────────────────────
    @app.post("/api/feedback")
    async def feedback(req: Request) -> dict[str, Any]:
        """A member vouches for ANOTHER member's useful response.

        Upstream credited the caller +1 trust per call with TOFU on the way in, so
        anyone could mint unlimited trust for themselves. Here trust is credited to
        the named subject only when the subject is a different admitted member and
        the voucher is admitted, and one (voucher, subject) credit counts per day.
        Self-feedback is recorded as a receipt with no trust effect.

        Spec v0.2 deliberately has no replay protection and the conformance suite
        asserts an identical v0.2 request is accepted twice (R2), so no signature
        dedupe here: the defence is that no replayable request has a cumulative
        effect. v0.3 callers get nonce replay protection from the verifier.
        """
        v = await signed(req, tofu=True)
        raw = await req.body()
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            body = {}
        subject = body.get("agent_id") if isinstance(body, dict) else None
        credited = False
        if (
            isinstance(subject, str)
            and subject != v.agent_id
            and is_admitted(v.agent_id)
            and store.get_member(subject) is not None
            and is_admitted(subject)
            and store.consume_nonce(f"vouch:{v.agent_id}:{subject}", time.strftime("%Y-%m-%d", time.gmtime()))
        ):
            store.record_trust_event(subject, "intent_response_useful", sm_trust.EVENT_DELTAS["intent_response_useful"])
            credited = True
        action = build_action(
            category="attestation_issued",
            human_summary=(f"{v.agent_id} vouched for {subject}" if credited else f"feedback recorded from {v.agent_id}")[:280],
            counterparty_did=v.did_key,
            counterparty_label=v.agent_id,
            machine_payload={"feedback": {"from": v.agent_id, "subject": subject, "credited": credited}},
        )
        receipt = issue_chained(store, identity, principal_did=identity.did, action=action)  # type: ignore[arg-type]
        return {"recorded": True, "agent_id": v.agent_id, "subject": subject, "credited": credited, "receipt_id": receipt["receipt_id"], "scheme": v.scheme}

    # ── admission by PARC credential ──────────────────────────────────
    @app.post("/api/admission/parc")
    async def admit_by_parc(req: Request) -> dict[str, Any]:
        v = await signed(req, tofu=False)
        import json

        from sm_parc import AdmissionPolicy, admit

        body = json.loads(await req.body() or b"{}")
        vc = body.get("credential")
        ledger = body.get("ledger")
        if not isinstance(vc, dict) or not isinstance(ledger, dict):
            raise HTTPException(status_code=400, detail="credential (PARC VC) and ledger required")
        if not cfg.parc_trusted_issuers:
            raise HTTPException(status_code=403, detail="parc admission disabled: no PARC_TRUSTED_ISSUERS configured")
        # sm-parc >= 0.3.0 binds the presenter, uses a real clock and caps the ledger
        # itself; the chapter keeps its own checks as defence in depth.
        subject = (vc.get("credentialSubject") or {}).get("id")
        if subject != v.did_key:
            raise HTTPException(status_code=403, detail="parc rejected: credential subject is not the presenting key")
        receipts = ledger.get("receipts") if isinstance(ledger.get("receipts"), list) else []
        if len(receipts) > cfg.parc_max_ledger_receipts:
            raise HTTPException(status_code=413, detail=f"parc rejected: ledger exceeds {cfg.parc_max_ledger_receipts} receipts")
        for r in receipts:
            if not isinstance(r, dict) or r.get("issuer_did") != subject:
                raise HTTPException(status_code=403, detail="parc rejected: ledger contains receipts not issued by the subject")
        policy = AdmissionPolicy(
            trusted_issuers=set(cfg.parc_trusted_issuers),
            min_reputation_score=cfg.parc_min_score,
            required_anchors=set(cfg.parc_required_anchors),
            max_ledger_receipts=cfg.parc_max_ledger_receipts,
        )
        result = admit(vc, policy=policy, presenter_did=v.did_key, ledger=ledger, is_valid=lambda r: verify_receipt(r).ok)
        if not result.ok:
            raise HTTPException(status_code=403, detail=f"parc rejected: {result.stage}: {result.detail}")
        state.set_admission(v.agent_id, "admitted", "parc")
        return {"admitted": True, "agent_id": v.agent_id, "via": "parc", "score": (vc.get("credentialSubject") or {}).get("reputation_score")}

    # ── council ───────────────────────────────────────────────────────
    @app.get("/api/council")
    def council_info() -> dict[str, Any]:
        return council.describe()

    @app.get("/api/council/proposals")
    async def council_list(req: Request, status: str | None = None) -> dict[str, Any]:
        await signed(req, tofu=False)
        return {"proposals": [proposal_json(p) for p in state.list_proposals(status)]}

    @app.post("/api/council/proposals")
    async def council_propose(req: Request) -> dict[str, Any]:
        v = await signed(req, tofu=False)
        import json

        body = json.loads(await req.body() or b"{}")
        p = council.propose(kind=str(body.get("kind", "")), subject=str(body.get("subject", "")), proposer_did=v.did_key, summary=str(body.get("summary", ""))[:280])
        return proposal_json(p)

    @app.get("/api/council/proposals/{proposal_id}/public")
    def council_proposal_public(proposal_id: str) -> dict[str, Any]:
        """What a reviewer needs to sign a gesture: ids and DIDs, nothing more."""
        p = state.get_proposal(proposal_id)
        if p is None:
            raise HTTPException(status_code=404, detail="unknown proposal")
        # Every kind whose subject is a member id resolves that member's DID, so a
        # reviewer's approval is scoped to the right key (sm-oversight needs it).
        m = store.get_member(p.subject) if p.kind in AGENT_SUBJECT_KINDS else None
        return {
            "id": p.id,
            "kind": p.kind,
            "subject": p.subject,
            "subject_did": m.did_key if m else None,
            "proposer_did": p.proposer_did,
            "receipt_id": p.receipt_id,
            "category": PROPOSAL_CATEGORY[p.kind],
            "status": p.status,
            "chapter_did": identity.did,
            "required_m": council.required_m,
        }

    @app.post("/api/council/proposals/{proposal_id}/gestures")
    async def council_gesture(proposal_id: str, req: Request) -> dict[str, Any]:
        import json

        receipt = json.loads(await req.body() or b"{}")
        if not isinstance(receipt, dict) or "receipt_id" not in receipt:
            raise HTTPException(status_code=400, detail="body must be a signed oversight receipt")
        return proposal_json(council.gesture(proposal_id, receipt))

    # ── mailbox: the chapter as the member's network edge ─────────────
    def _normalise_message(payload: dict[str, Any]) -> dict[str, Any]:
        if payload.get("jsonrpc") == "2.0":
            params = payload.get("params") or {}
            msg = params.get("message") or params
            return {"format": "a2a-jsonrpc", "method": payload.get("method"), "id": payload.get("id"), "message": msg}
        return {"format": "nanda-adapter", "message": payload}

    @app.post("/a2a/@{agent_id}")
    async def mailbox_post(agent_id: str, req: Request) -> dict[str, Any]:
        raw = await req.body()
        if len(raw) > MAX_MESSAGE_BYTES:
            raise HTTPException(status_code=413, detail="message too large")
        m = store.get_member(agent_id)
        if m is None or not is_admitted(agent_id):
            raise HTTPException(status_code=404, detail="unknown agent")
        import json

        try:
            payload = json.loads(raw or b"{}")
        except ValueError:
            raise HTTPException(status_code=400, detail="body must be JSON") from None
        sender = "anonymous"
        if req.headers.get("x-agent-signature") or not cfg.mailbox_allow_anonymous:
            v = await signed(req, tofu=False)
            sender = v.did_key
        item = _normalise_message(payload if isinstance(payload, dict) else {"text": payload})
        mid = state.enqueue(agent_id, sender, item)
        result = {"queued": True, "message_id": mid, "to": agent_id, "depth": state.inbox_depth(agent_id)}
        if item["format"] == "a2a-jsonrpc":
            return {"jsonrpc": "2.0", "id": item.get("id"), "result": {"id": str(mid), "status": {"state": "submitted"}, **result}}
        return result

    @app.get("/api/inbox")
    async def inbox_drain(req: Request, limit: int = Query(50, ge=1, le=500)) -> dict[str, Any]:
        v = await signed(req, tofu=False)
        items = state.drain(v.agent_id, limit)
        return {"agent_id": v.agent_id, "messages": items, "remaining": state.inbox_depth(v.agent_id)}

    @app.post("/a2a")
    @app.post("/a2a/")
    async def chapter_a2a(req: Request) -> dict[str, Any]:
        import json

        payload = json.loads(await req.body() or b"{}")
        text = (
            f"{cfg.name} is a NANDA chapter: a home network for personal agents. "
            f"Join: POST {base}/api/members. Directory: signed GET {base}/api/members. "
            f"Catalog: {base}/.well-known/ai-catalog.json. Council: {base}/api/council. "
            f"Reach a member: POST {base}/a2a/@<agent_id>."
        )
        if isinstance(payload, dict) and payload.get("jsonrpc") == "2.0":
            return {"jsonrpc": "2.0", "id": payload.get("id"), "result": {"message": {"role": "agent", "parts": [{"type": "text", "text": text}]}}}
        return {"role": "assistant", "content": {"type": "text", "text": text}, "conversation_id": (payload or {}).get("conversation_id", ""), "message_id": ""}

    # ── discovery surface the Index resolves to ───────────────────────
    app.include_router(
        create_catalog_router(cfg, store, is_listed=is_listed, is_resolvable=is_admitted, server_did=lambda: identity.did)
    )

    app.state.cfg = cfg
    app.state.store = store
    app.state.chapter_state = state
    app.state.council = council
    app.state.identity = identity
    return app


def app_from_env() -> FastAPI:
    return create_app(ChapterConfig.from_env())
