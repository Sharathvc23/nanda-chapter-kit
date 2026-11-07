import json

from .conftest import make_agent, register


def test_health_and_version(open_client):
    h = open_client.get("/health").json()
    assert h["status"] == "ok" and h["agent_id"] == "test-chapter" and h["did"].startswith("did:key:z6Mk")
    v = open_client.get("/api/version").json()
    assert v["protocol_versions"] == ["0.2", "0.3"] and v["preferred_version"] == "0.3"


def test_anonymous_directory_read_is_rejected(open_client):
    for path in ("/api/members", "/api/members/", "/api/members?skill=python", "/api/federation/test-chapter/members"):
        r = open_client.get(path)
        assert r.status_code == 401, (path, r.text)
        assert r.json()["error"] in ("missing_agent_id",)


def test_junk_scheme_fails_closed(open_client):
    r = open_client.get("/api/members", headers={"X-Agent-ID": "x", "X-Agent-Signature": "AAAA", "X-Agent-Timestamp": "1", "X-Agent-Sig-Scheme": "nope"})
    assert r.status_code == 401 and r.json()["error"] == "unknown_sig_scheme"


def test_signed_v02_read_bootstraps_and_lists(open_client):
    a = make_agent()
    r = open_client.get("/api/members", headers=a.headers_v02(""))
    assert r.status_code == 200, r.text
    ids = {m["agent_id"] for m in r.json()["members"]}
    assert a.agent_id in ids  # TOFU bootstrap on first signed read
    assert r.json()["chapter"] == "test-chapter"


def test_signed_v03_read_and_nonce_replay(open_client):
    a = make_agent()
    register(open_client, a)
    h = a.headers_v03("GET", "/api/members?limit=5")
    assert open_client.get("/api/members?limit=5", headers=h).status_code == 200
    r = open_client.get("/api/members?limit=5", headers=h)
    assert r.status_code == 401 and r.json()["error"] == "nonce_replay"


def test_v03_path_binding(open_client):
    a = make_agent()
    register(open_client, a)
    h = a.headers_v03("GET", "/api/members")
    r = open_client.get("/api/federation/test-chapter/members", headers=h)
    assert r.status_code == 401 and r.json()["error"] == "invalid_signature"


def test_key_mismatch_after_tofu(open_client):
    a = make_agent()
    register(open_client, a)
    impostor = make_agent()
    impostor.agent_id = a.agent_id
    r = open_client.get("/api/members", headers=impostor.headers_v02(""))
    assert r.status_code == 401 and r.json()["error"] == "key_mismatch"


def test_feedback_accepts_both_schemes_and_emits_receipt(open_client):
    a = make_agent()
    register(open_client, a)
    body = json.dumps({"agent_id": a.agent_id, "useful": True})
    r2 = open_client.post("/api/feedback", content=body, headers={**a.headers_v02(body), "Content-Type": "application/json"})
    assert r2.status_code == 200 and r2.json()["recorded"] and r2.json()["scheme"] == "ed25519"
    r3 = open_client.post("/api/feedback", content=body, headers={**a.headers_v03("POST", "/api/feedback", body), "Content-Type": "application/json"})
    assert r3.status_code == 200 and r3.json()["scheme"] == "ed25519+nonce"
    rid = r3.json()["receipt_id"]
    assert open_client.get(f"/api/receipts/{rid}").status_code == 200
    trust = open_client.get(f"/api/agents/{a.agent_id}/trust").json()
    assert trust["score"] > 0 and len(trust["history"]) == 2


def test_openclaw_origin_admitted_and_profile_public(open_client):
    a = make_agent()
    assert register(open_client, a, origin="openclaw")["origin"] == "openclaw"
    r = open_client.get(f"/api/member/{a.agent_id}/profile")
    assert r.status_code == 200 and r.json()["updateComponents"]["components"][0]["text"] == a.agent_id
    assert open_client.get("/api/member/nobody/profile").status_code == 404
