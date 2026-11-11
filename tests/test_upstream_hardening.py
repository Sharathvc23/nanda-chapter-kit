"""Regressions for defects found in the upstream libraries (audit 2026-11) that were
reachable through the kit. Each test reproduces the hole, then asserts it is closed."""

import base64
import copy
import json
import secrets
import time
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sm_arp import Identity, build_action, issue_receipt
from sm_server.signing import derive_did_key

from nanda_chapter.store import ChapterStore, ReceiptConflict

from .conftest import make_agent, make_cfg, make_client, register


# ── sm-org-server F1: identity hijack by re-registration ───────────────
def test_reregistration_with_a_different_key_is_refused(open_client):
    victim = make_agent()
    register(open_client, victim)
    attacker = make_agent()
    r = open_client.post("/api/members", json={"agent_id": victim.agent_id, "name": "evil", "origin": "sovereign", "public_key": attacker.pub_b64})
    assert r.status_code == 401 and r.json()["error"] == "key_mismatch"
    attacker.agent_id = victim.agent_id
    assert open_client.get("/api/me", headers=victim.headers_v02("")).status_code == 200
    assert open_client.get("/api/me", headers=attacker.headers_v02("")).status_code == 401
    # Same key again is idempotent, not an error.
    r = open_client.post("/api/members", json={"agent_id": victim.agent_id, "name": "renamed", "origin": "sovereign", "public_key": victim.pub_b64})
    assert r.status_code == 200 and r.json()["idempotent"] is True


# ── sm-org-server F5: garbage keys ─────────────────────────────────────
def test_registration_requires_a_real_ed25519_key(open_client):
    for bad in ("", "!!!notb64", base64.b64encode(b"short").decode(), None):
        body = {"agent_id": f"g-{secrets.token_hex(2)}", "name": "g", "origin": "sovereign"}
        if bad is not None:
            body["public_key"] = bad
        r = open_client.post("/api/members", json=body)
        assert r.status_code == 400, (bad, r.text)
    assert open_client.post("/api/members", content=b"[1,2]", headers={"Content-Type": "application/json"}).status_code == 400
    assert open_client.post("/api/members", content=b"not json", headers={"Content-Type": "application/json"}).status_code == 400


# ── sm-org-server F2: self-minted trust and replay ─────────────────────
def test_feedback_cannot_mint_trust_for_the_caller(open_client):
    a, b = make_agent(), make_agent()
    register(open_client, a)
    register(open_client, b)
    body = json.dumps({"agent_id": a.agent_id, "signal": "positive"})
    h = {**a.headers_v02(body), "Content-Type": "application/json"}
    r1 = open_client.post("/api/feedback", content=body, headers=h)
    assert r1.status_code == 200 and r1.json()["recorded"] is True and r1.json()["credited"] is False
    # Spec v0.2 has no replay protection (suite R2), so the replay is accepted —
    # but it still mints nothing.
    r2 = open_client.post("/api/feedback", content=body, headers=h)
    assert r2.status_code == 200 and r2.json()["credited"] is False
    assert open_client.get(f"/api/agents/{a.agent_id}/trust").json()["score"] == 0
    # Vouching for another admitted member credits that member, once per day.
    vouch = json.dumps({"agent_id": b.agent_id, "signal": "positive"})
    r3 = open_client.post("/api/feedback", content=vouch, headers={**a.headers_v03("POST", "/api/feedback", vouch), "Content-Type": "application/json"})
    assert r3.status_code == 200 and r3.json()["credited"] is True
    r4 = open_client.post("/api/feedback", content=vouch, headers={**a.headers_v03("POST", "/api/feedback", vouch), "Content-Type": "application/json"})
    assert r4.status_code == 200 and r4.json()["credited"] is False
    assert open_client.get(f"/api/agents/{b.agent_id}/trust").json()["score"] == 1.0
    assert open_client.get(f"/api/agents/{a.agent_id}/trust").json()["score"] == 0


def test_unknown_agent_bootstrapping_via_feedback_gets_no_trust(council_client):
    stranger = make_agent()
    body = json.dumps({"agent_id": stranger.agent_id})
    r = council_client.post("/api/feedback", content=body, headers={**stranger.headers_v03("POST", "/api/feedback", body), "Content-Type": "application/json"})
    assert r.status_code == 200 and r.json()["credited"] is False
    assert council_client.get(f"/api/agents/{stranger.agent_id}/trust").json()["score"] == 0


# ── sm-org-server F3: issuer-mutable receipt log ───────────────────────
def test_receipt_log_is_append_only():
    store = ChapterStore(":memory:")
    iss = Identity.generate()
    store.chain_enforced_issuers.add(iss.did)  # the chapter registers its own DID here
    r1 = issue_receipt(iss, principal_did=iss.did, action=build_action(category="record_filed", human_summary="original"))
    link = store.append_receipt(r1)
    assert store.append_receipt(copy.deepcopy(r1)) == link  # idempotent
    r2 = issue_receipt(iss, principal_did=iss.did, action=build_action(category="record_filed", human_summary="REWRITTEN"), receipt_id=r1["receipt_id"])
    try:
        store.append_receipt(r2)
        raise AssertionError("rewrite must be refused")
    except ReceiptConflict as e:
        assert e.reason == "receipt_rewrite"
    assert store.get_receipt(r1["receipt_id"])["action"]["human_summary"] == "original"
    # A second genesis from the same issuer, and a fork of the same predecessor, are refused.
    g2 = issue_receipt(iss, principal_did=iss.did, action=build_action(category="record_filed", human_summary="genesis again"))
    try:
        store.append_receipt(g2)
        raise AssertionError("second genesis must be refused")
    except ReceiptConflict as e:
        assert e.reason == "second_genesis"
    from sm_arp import chain_link

    child_a = issue_receipt(iss, principal_did=iss.did, action=build_action(category="record_filed", human_summary="a"), previous_receipt_hash=chain_link(r1))
    child_b = issue_receipt(iss, principal_did=iss.did, action=build_action(category="record_filed", human_summary="b"), previous_receipt_hash=chain_link(r1))
    store.append_receipt(child_a)
    try:
        store.append_receipt(child_b)
        raise AssertionError("fork must be refused")
    except ReceiptConflict as e:
        assert e.reason == "chain_fork"


def test_receipt_ingestion_endpoint_returns_409_on_rewrite(open_client):
    iss = Identity.generate()
    r1 = issue_receipt(iss, principal_did=iss.did, action=build_action(category="record_filed", human_summary="one"))
    assert open_client.post("/api/receipts", json=r1).json()["accepted"] is True
    r2 = issue_receipt(iss, principal_did=iss.did, action=build_action(category="record_filed", human_summary="two"), receipt_id=r1["receipt_id"])
    r = open_client.post("/api/receipts", json=r2)
    assert r.status_code == 409 and r.json()["error"] == "receipt_rewrite"
    assert open_client.get(f"/api/receipts/{r1['receipt_id']}").json()["action"]["human_summary"] == "one"


# ── sm-org-server F6: rotation nonce scope and client-set did ──────────
def _rotate(client, agent, nonce, claimed_did=None):
    new_seed = secrets.token_bytes(32)
    new_pub = Ed25519PrivateKey.from_private_bytes(new_seed).public_key().public_bytes_raw()
    new_b64 = base64.b64encode(new_pub).decode()
    ts = str(int(time.time()))
    msg = f"ROTATE:test-chapter:{agent.agent_id}:{new_b64}:{ts}:{nonce}".encode()
    sig = base64.b64encode(Ed25519PrivateKey.from_private_bytes(agent.seed).sign(msg)).decode()
    body = {"agent_id": agent.agent_id, "chapter_id": "test-chapter", "new_public_key_b64": new_b64, "timestamp": ts, "nonce": nonce, "signature": sig}
    if claimed_did:
        body["new_did_key"] = claimed_did
    r = client.post("/api/members/rotate", json=body).json()
    return r, new_seed, new_pub


def test_rotation_nonce_is_per_agent_and_did_is_server_derived(open_client):
    v, a = make_agent(), make_agent()
    register(open_client, v)
    register(open_client, a)
    nonce = secrets.token_hex(16)
    ra, _, _ = _rotate(open_client, a, nonce, claimed_did="did:key:zBOGUS")
    assert ra.get("rotated") is True
    rv, _, _ = _rotate(open_client, v, nonce)  # same nonce, different agent: fine (per-agent scope)
    assert rv.get("rotated") is True
    rv2, _, _ = _rotate(open_client, v, nonce)  # reuse by the same agent: refused
    assert rv2.get("error") in ("nonce replay", "invalid signature (old key did not sign this attestation)")
    # The stored did for the attacker-claimed rotation is derived, not "zBOGUS".
    stored = open_client.app.state.store.get_member(a.agent_id)
    assert stored.did_key.startswith("did:key:z6Mk") and stored.did_key != "did:key:zBOGUS"
    assert stored.did_key == derive_did_key(base64.b64decode(stored.public_key))


# ── sm-bridge: A2A card must be v1.0-shaped for the Index ──────────────
def test_member_and_chapter_cards_are_a2a_v1_shaped(open_client):
    a = make_agent()
    register(open_client, a)
    for path in (f"/cards/{a.agent_id}.json", "/.well-known/agent-card.json"):
        card = open_client.get(path).json()
        assert card["protocolVersion"] == "1.0", path
        assert card["supportedInterfaces"][0]["protocolBinding"] == "JSONRPC"
        assert card["defaultInputModes"] and card["defaultOutputModes"]
        assert "authentication" not in card and "securitySchemes" in card
        for s in card["skills"]:
            assert s["id"] and s["name"] and s["description"] is not None and s["tags"], s


# ── sm-parc: real credential end to end, with the kit's bindings ────────
def _ledger_and_credential(agent: Identity, issuer: Identity, *, counterparties=3, subject_did=None):
    from sm_arp import verify_receipt
    from sm_arp.vrp import SCORING_METHOD_V2, build_ledger, cosign_receipt
    from sm_parc import build_reputation_credential

    human = Identity.generate()
    receipts = []
    for i in range(counterparties):
        cp = Identity.generate()
        act = build_action(category="record_filed", human_summary=f"filed {i}", counterparty_did=cp.did)
        rid, ts = str(uuid.uuid4()), f"2026-10-0{i + 1}T00:00:00Z"
        r0 = issue_receipt(agent, principal_did=human.did, action=act, issued_at=ts, receipt_id=rid)
        cosig = cosign_receipt(r0, signing_key_bytes=cp.sk_bytes)
        receipts.append(issue_receipt(agent, principal_did=human.did, action=act, issued_at=ts, receipt_id=rid, evidence={"witness_signatures": [cosig]}))
    is_valid = lambda r: verify_receipt(r).ok
    ledger = build_ledger(subject=subject_did or agent.did, receipts=receipts, is_valid=is_valid, as_of="2026-10-10T00:00:00Z", method=SCORING_METHOD_V2)
    vc = build_reputation_credential(ledger=ledger, issuer_sk=issuer.sk_bytes, valid_from="2026-10-10T00:00:00Z", valid_until="2099-01-01T00:00:00Z", credential_id=f"urn:parc:{uuid.uuid4()}")
    return ledger, vc


def test_parc_admission_end_to_end(tmp_path):
    issuer, other = Identity.generate(), Identity.generate()
    client = make_client(make_cfg(tmp_path, ADMISSION_MODE="parc", PARC_TRUSTED_ISSUERS=issuer.did, PARC_MIN_SCORE="1.0", CATALOG_DEFAULT_LISTED="true"))
    # The presenting member's key must be the credential subject: reuse the agent identity for both.
    agent = Identity.generate()
    seed = agent.sk_bytes
    pub = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    from .conftest import Agent

    me = Agent(f"parc-{secrets.token_hex(3)}", seed, pub)
    register(client, me)
    assert client.get("/api/me", headers=me.headers_v02("")).json()["admitted"] is False
    ledger, vc = _ledger_and_credential(agent, issuer)

    def present(vc_, ledger_):
        body = json.dumps({"credential": vc_, "ledger": ledger_})
        return client.post("/api/admission/parc", content=body, headers={**me.headers_v03("POST", "/api/admission/parc", body), "Content-Type": "application/json"})

    # Wrong issuer, tampered score, stripped proof, foreign subject: all refused.
    _, vc_other = _ledger_and_credential(agent, other)
    assert present(vc_other, ledger).status_code == 403
    t = copy.deepcopy(vc)
    t["credentialSubject"]["reputation_score"] = 999.0
    assert present(t, ledger).status_code == 403
    np_ = copy.deepcopy(vc)
    del np_["proof"]
    assert present(np_, ledger).status_code == 403
    stranger = Identity.generate()
    s_ledger, s_vc = _ledger_and_credential(stranger, issuer)
    r = present(s_vc, s_ledger)
    assert r.status_code == 403 and "not the presenting key" in r.json()["detail"]
    # The genuine credential admits.
    r = present(vc, ledger)
    assert r.status_code == 200 and r.json()["admitted"] is True, r.text
    assert client.get("/api/me", headers=me.headers_v02("")).json()["admitted"] is True
    # An expired credential is refused even though sm-parc itself has no clock.
    from sm_parc import build_reputation_credential

    fresh_agent = Identity.generate()
    fresh = Agent(f"parc-{secrets.token_hex(3)}", fresh_agent.sk_bytes, Ed25519PrivateKey.from_private_bytes(fresh_agent.sk_bytes).public_key().public_bytes_raw())
    register(client, fresh)
    l3, _ = _ledger_and_credential(fresh_agent, issuer)
    vc3_expired = build_reputation_credential(ledger=l3, issuer_sk=issuer.sk_bytes, valid_from="2019-01-01T00:00:00Z", valid_until="2020-01-01T00:00:00Z", credential_id="urn:parc:old2")
    body = json.dumps({"credential": vc3_expired, "ledger": l3})
    r = client.post("/api/admission/parc", content=body, headers={**fresh.headers_v03("POST", "/api/admission/parc", body), "Content-Type": "application/json"})
    assert r.status_code == 403, r.text
    assert "stale" in r.json()["detail"] or "expired" in r.json()["detail"], r.json()
