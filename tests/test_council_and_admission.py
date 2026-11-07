import json

from sm_arp import Identity

from nanda_chapter.reviewer import build_gesture, co_sign

from .conftest import make_agent, register


def _pending_for(client, agent_id):
    cfg = client.app.state.chapter_state
    p = cfg.pending_for_subject("member_admission", agent_id)
    assert p is not None
    return p


def test_registration_files_admission_proposal_and_hides_until_quorum(council_client, reviewers):
    a = make_agent()
    register(council_client, a)
    assert council_client.get("/health").json()["council"]["pending"] == 1
    p = _pending_for(council_client, a.agent_id)
    # Not listed yet: directory and catalog hide pending members.
    listing = council_client.get("/api/members", headers=a.headers_v02("")).json()
    assert a.agent_id not in {m["agent_id"] for m in listing["members"]}
    assert a.agent_id not in [e["identifier"] for e in council_client.get("/.well-known/ai-catalog.json").json()["entries"]]
    assert council_client.post(f"/a2a/@{a.agent_id}", json={"text": "hi"}).status_code == 404

    pub = council_client.get(f"/api/council/proposals/{p.id}/public").json()
    assert pub["receipt_id"] == p.receipt_id and pub["required_m"] == 2

    # One reviewer alone is below quorum.
    g1 = build_gesture(reviewers[0], pub, decision="approved")
    r = council_client.post(f"/api/council/proposals/{p.id}/gestures", json=g1)
    assert r.status_code == 200 and r.json()["status"] == "pending", r.text

    # Co-witnessed 2-of-3 reaches quorum and executes admission.
    g2 = co_sign(build_gesture(reviewers[1], pub, decision="approved"), reviewers[2])
    r = council_client.post(f"/api/council/proposals/{p.id}/gestures", json=g2)
    assert r.status_code == 200 and r.json()["status"] == "approved", r.text
    assert set(r.json()["gestures"][-1]["witnesses"]) == {reviewers[1].did, reviewers[2].did}

    listing = council_client.get("/api/members", headers=a.headers_v02("")).json()
    assert a.agent_id in {m["agent_id"] for m in listing["members"]}
    assert council_client.post(f"/a2a/@{a.agent_id}", json={"text": "hi"}).status_code == 200
    # The gesture is in the chapter's issuer log alongside the proposal receipt.
    assert council_client.get(f"/api/receipts/{g2['receipt_id']}").status_code == 200
    assert council_client.get(f"/api/receipts/{p.receipt_id}").status_code == 200


def test_untrusted_reviewer_and_wrong_proposal_are_rejected(council_client, reviewers):
    a = make_agent()
    register(council_client, a)
    p = _pending_for(council_client, a.agent_id)
    pub = council_client.get(f"/api/council/proposals/{p.id}/public").json()
    stranger = Identity.generate()
    r = council_client.post(f"/api/council/proposals/{p.id}/gestures", json=build_gesture(stranger, pub, decision="approved"))
    assert r.status_code == 403
    wrong = dict(pub, receipt_id="rcpt-not-this-one")
    r = council_client.post(f"/api/council/proposals/{p.id}/gestures", json=build_gesture(reviewers[0], wrong, decision="approved"))
    assert r.status_code == 400
    tampered = build_gesture(reviewers[0], pub, decision="approved")
    tampered["action"]["human_summary"] = "edited after signing"
    r = council_client.post(f"/api/council/proposals/{p.id}/gestures", json=tampered)
    assert r.status_code == 401


def test_deny_closes_the_proposal(council_client, reviewers):
    a = make_agent()
    register(council_client, a)
    p = _pending_for(council_client, a.agent_id)
    pub = council_client.get(f"/api/council/proposals/{p.id}/public").json()
    r = council_client.post(f"/api/council/proposals/{p.id}/gestures", json=build_gesture(reviewers[0], pub, decision="denied"))
    assert r.status_code == 200 and r.json()["status"] == "denied"
    r = council_client.post(f"/api/council/proposals/{p.id}/gestures", json=build_gesture(reviewers[1], pub, decision="approved"))
    assert r.status_code == 409


def test_member_can_propose_and_list_signed(council_client, reviewers):
    a = make_agent()
    register(council_client, a)
    body = json.dumps({"kind": "chapter_charter", "subject": "test-chapter", "summary": "charter this chapter"})
    r = council_client.post("/api/council/proposals", content=body, headers={**a.headers_v03("POST", "/api/council/proposals", body), "Content-Type": "application/json"})
    assert r.status_code == 200 and r.json()["kind"] == "chapter_charter", r.text
    assert council_client.get("/api/council/proposals").status_code == 401
    listed = council_client.get("/api/council/proposals?status=pending", headers=a.headers_v02("")).json()["proposals"]
    assert {p["kind"] for p in listed} == {"member_admission", "chapter_charter"}
    info = council_client.get("/api/council").json()
    assert info["quorum"] == "2-of-3" and info["pending"] == 2


def test_mailbox_store_and_forward(open_client):
    a, b = make_agent(), make_agent()
    register(open_client, a)
    register(open_client, b)
    rpc = {"jsonrpc": "2.0", "id": "7", "method": "message/send", "params": {"message": {"role": "user", "parts": [{"type": "text", "text": "hello"}]}}}
    body = json.dumps(rpc)
    r = open_client.post(f"/a2a/@{a.agent_id}", content=body, headers={**b.headers_v03("POST", f"/a2a/@{a.agent_id}", body), "Content-Type": "application/json"})
    assert r.status_code == 200 and r.json()["result"]["status"]["state"] == "submitted"
    assert open_client.post(f"/a2a/@{a.agent_id}", json={"role": "user", "content": {"type": "text", "text": "anon"}}).status_code == 200
    assert open_client.get("/api/inbox").status_code == 401
    inbox = open_client.get("/api/inbox", headers=a.headers_v02("")).json()
    assert len(inbox["messages"]) == 2 and inbox["messages"][0]["sender"] == b.did_key and inbox["remaining"] == 0
    assert open_client.get("/api/inbox", headers=a.headers_v02("")).json()["messages"] == []
