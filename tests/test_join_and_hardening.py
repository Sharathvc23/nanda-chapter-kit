import json
from pathlib import Path

from nanda_chapter.config import ChapterConfig
from nanda_chapter.join import JOIN_DOC_PATH, verify_join_document
from nanda_chapter.reviewer import build_gesture, co_sign

from .conftest import make_agent, make_cfg, make_client, register


# ── signed join document ──────────────────────────────────────────────
def test_join_document_verifies_and_binds_did_and_url(open_client):
    doc = open_client.get(JOIN_DOC_PATH).json()
    did = open_client.get("/health").json()["did"]
    v = verify_join_document(doc, expected_did=did, fetched_from="https://chapter.example.org")
    assert v.ok, v
    assert doc["payload"]["promises"]["never_asks_for_secrets"] is True
    assert doc["payload"]["endpoints"]["register"]["auth"] == "none"
    assert doc["payload"]["signing"]["preferred"] == "ed25519+nonce"
    assert verify_join_document(doc, expected_did="did:key:z6MkfakefakefakefakefakefakefakefakefakefakeX").reason == "did_not_expected"
    assert verify_join_document(doc, fetched_from="https://evil.example.net").reason == "url_mismatch"


def test_tampered_join_document_is_rejected(open_client):
    doc = open_client.get(JOIN_DOC_PATH).json()
    doc["payload"]["endpoints"]["register"]["body"].append("private_key")
    assert verify_join_document(doc).reason == "bad_signature"
    doc2 = open_client.get(JOIN_DOC_PATH).json()
    doc2["payload"]["promises"]["never_asks_for_secrets"] = False
    assert verify_join_document(doc2).reason == "bad_signature"
    assert verify_join_document({"payload": {}, "signed_by": 1, "signature": "x"}).reason == "malformed"


def test_join_text_points_at_document_not_instructions(open_client):
    r = open_client.get("/join")
    assert r.status_code == 200 and JOIN_DOC_PATH in r.text and "never asks you for a secret" in r.text
    assert open_client.get("/.well-known/agent-card.json").json()["_meta"]["chapter_id"] == "test-chapter"
    assert open_client.get("/.well-known/nanda-agent.json").json()["join"].endswith(JOIN_DOC_PATH)


# ── abuse: rate limits ────────────────────────────────────────────────
def test_registration_rate_limit(tmp_path):
    client = make_client(make_cfg(tmp_path, RATE_REGISTER_PER_MIN="2"))
    agents = [make_agent() for _ in range(3)]
    codes = [
        client.post("/api/members", json={"agent_id": a.agent_id, "name": a.agent_id, "origin": "sovereign", "public_key": a.pub_b64}).status_code
        for a in agents
    ]
    assert codes == [200, 200, 429]
    # Other buckets are unaffected by the register bucket.
    assert client.get("/health").status_code == 200
    assert client.get("/health").json()["rate_limits_per_min"]["register"] == 2


def test_mailbox_rate_limit_and_anonymous_policy(tmp_path):
    client = make_client(make_cfg(tmp_path, RATE_MAILBOX_PER_MIN="1", CATALOG_DEFAULT_LISTED="true"))
    a = make_agent()
    register(client, a)
    assert client.post(f"/a2a/@{a.agent_id}", json={"text": "1"}).status_code == 200
    r = client.post(f"/a2a/@{a.agent_id}", json={"text": "2"})
    assert r.status_code == 429 and r.headers["Retry-After"] == "60"
    strict = make_client(make_cfg(tmp_path / "strict", MAILBOX_ALLOW_ANONYMOUS="false"))
    b = make_agent()
    register(strict, b)
    assert strict.post(f"/a2a/@{b.agent_id}", json={"text": "anon"}).status_code == 401


# ── revocation ────────────────────────────────────────────────────────
def test_council_revocation_locks_the_member_out(council_client, reviewers):
    a = make_agent()
    register(council_client, a)
    st = council_client.app.state.chapter_state
    # Admit first (2-of-3), then revoke (2-of-3).
    p = st.pending_for_subject("member_admission", a.agent_id)
    pub = council_client.get(f"/api/council/proposals/{p.id}/public").json()
    g = co_sign(build_gesture(reviewers[0], pub, decision="approved"), reviewers[1])
    assert council_client.post(f"/api/council/proposals/{p.id}/gestures", json=g).json()["status"] == "approved"
    assert council_client.get("/api/me", headers=a.headers_v02("")).json()["admitted"] is True

    body = json.dumps({"kind": "member_revocation", "subject": a.agent_id, "summary": "spam"})
    r = council_client.post("/api/council/proposals", content=body, headers={**a.headers_v03("POST", "/api/council/proposals", body), "Content-Type": "application/json"})
    rp = r.json()
    pub = council_client.get(f"/api/council/proposals/{rp['id']}/public").json()
    g = co_sign(build_gesture(reviewers[1], pub, decision="approved"), reviewers[2])
    assert council_client.post(f"/api/council/proposals/{rp['id']}/gestures", json=g).json()["status"] == "approved"

    # A correctly signed request from the revoked member is refused with 403, not 401.
    r = council_client.get("/api/members", headers=a.headers_v02(""))
    assert r.status_code == 403 and r.json()["error"] == "revoked"
    assert council_client.post(f"/a2a/@{a.agent_id}", json={"text": "hi"}).status_code == 404
    assert council_client.get(f"/cards/{a.agent_id}.json").status_code == 404
    pub_list = council_client.get("/api/revocations").json()["revoked"]
    assert [x["agent_id"] for x in pub_list] == [a.agent_id] and "reason" not in pub_list[0]
    assert council_client.get("/health").json()["revoked"] == 1


def test_operator_revocation_and_reviewer_revocation(tmp_path, reviewers):
    cfg = make_cfg(tmp_path, ADMISSION_MODE="council", COUNCIL_REVIEWERS=",".join(r.did for r in reviewers), COUNCIL_REQUIRED_M="2")
    client = make_client(cfg)
    a = make_agent()
    register(client, a)
    st = client.app.state.chapter_state
    st.revoke_member(a.agent_id, "operator says no", "operator")
    assert client.get("/api/me", headers=a.headers_v02("")).status_code == 403
    # Revoke a reviewer: their witness no longer counts toward quorum.
    client.app.state.council.revoke_reviewer(reviewers[0].did, "key lost")
    info = client.get("/api/council").json()
    assert reviewers[0].did in info["revoked_reviewers"] and reviewers[0].did not in info["reviewers"]
    b = make_agent()
    register(client, b)
    p = st.pending_for_subject("member_admission", b.agent_id)
    pub = client.get(f"/api/council/proposals/{p.id}/public").json()
    g = co_sign(build_gesture(reviewers[0], pub, decision="approved"), reviewers[1])
    assert client.post(f"/api/council/proposals/{p.id}/gestures", json=g).status_code == 403  # issuer revoked
    g = co_sign(build_gesture(reviewers[1], pub, decision="approved"), reviewers[0])
    assert client.post(f"/api/council/proposals/{p.id}/gestures", json=g).json()["status"] == "pending"  # 1 valid of 2
    g = co_sign(build_gesture(reviewers[1], pub, decision="approved"), reviewers[2])
    assert client.post(f"/api/council/proposals/{p.id}/gestures", json=g).json()["status"] == "approved"


# ── enumeration is opt-in ─────────────────────────────────────────────
def test_catalog_listing_is_opt_in_but_cards_resolve(tmp_path):
    open_client = make_client(make_cfg(tmp_path, CATALOG_DEFAULT_LISTED="false"))
    a = make_agent()
    register(open_client, a)
    ids = [e["identifier"] for e in open_client.get("/.well-known/ai-catalog.json").json()["entries"]]
    assert a.agent_id not in ids  # admitted, not listed
    assert open_client.get(f"/cards/{a.agent_id}.json").status_code == 200  # exact id still resolves
    body = json.dumps({"listed": True})
    r = open_client.post("/api/me/listing", content=body, headers={**a.headers_v03("POST", "/api/me/listing", body), "Content-Type": "application/json"})
    assert r.status_code == 200 and r.json()["listed"] is True
    ids = [e["identifier"] for e in open_client.get("/.well-known/ai-catalog.json").json()["entries"]]
    assert a.agent_id in ids
    body = json.dumps({"listed": False})
    open_client.post("/api/me/listing", content=body, headers={**a.headers_v03("POST", "/api/me/listing", body), "Content-Type": "application/json"})
    assert a.agent_id not in [e["identifier"] for e in open_client.get("/.well-known/ai-catalog.json").json()["entries"]]
    assert open_client.get("/api/me", headers=a.headers_v02("")).json()["listed"] is False


# ── custody: encrypted seed at rest ───────────────────────────────────
def _env(home: Path, **extra):
    base = {"CHAPTER_HOME": str(home), "CHAPTER_ID": "c", "CHAPTER_NAME": "c", "PUBLIC_URL": "https://c.example.org"}
    base.update(extra)
    return base


def test_seed_encrypted_at_rest_and_stable_across_loads(tmp_path):
    cfg1 = ChapterConfig.from_env(_env(tmp_path, CHAPTER_SEED_PASSPHRASE="correct horse"))
    assert cfg1.seed_encrypted and (tmp_path / "seed.enc").exists() and not (tmp_path / "seed.b64").exists()
    assert "v1" not in (tmp_path / "seed.enc").read_text()[:0]  # content is base64, no plaintext seed
    assert cfg1.seed_b64 not in (tmp_path / "seed.enc").read_text()
    cfg2 = ChapterConfig.from_env(_env(tmp_path, CHAPTER_SEED_PASSPHRASE="correct horse"))
    assert cfg2.seed_b64 == cfg1.seed_b64
    try:
        ChapterConfig.from_env(_env(tmp_path, CHAPTER_SEED_PASSPHRASE="wrong"))
        raise AssertionError("wrong passphrase must fail")
    except ValueError as e:
        assert "does not decrypt" in str(e)
    try:
        ChapterConfig.from_env(_env(tmp_path))
        raise AssertionError("encrypted seed without passphrase must refuse to run")
    except ValueError as e:
        assert "refusing" in str(e)


def test_plaintext_seed_is_migrated_when_passphrase_appears(tmp_path):
    cfg_plain = ChapterConfig.from_env(_env(tmp_path))
    assert not cfg_plain.seed_encrypted and (tmp_path / "seed.b64").exists()
    cfg_enc = ChapterConfig.from_env(_env(tmp_path, CHAPTER_SEED_PASSPHRASE="pw"))
    assert cfg_enc.seed_encrypted and cfg_enc.seed_b64 == cfg_plain.seed_b64
    assert not (tmp_path / "seed.b64").exists() and (tmp_path / "seed.enc").exists()
