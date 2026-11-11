"""Drive a running chapter from the outside, as a stranger agent would.

Plain httpx + Ed25519, no kit imports on the agent side: this is what any agent
does. Boot a council-mode chapter first, e.g.

    R=$(nanda-chapter council new-reviewer)   # three times; collect dids + seeds
    COUNCIL_REVIEWERS=did1,did2,did3 COUNCIL_REQUIRED_M=2 ADMISSION_MODE=council \
      CHAPTER_ID=demo CHAPTER_NAME=Demo PUBLIC_URL=http://localhost:7810 nanda-chapter run --port 7810

    python examples/walkthrough.py http://localhost:7810 <seed1> <seed2> <seed3>

Steps: verify the signed join document offline; register with a fresh key; see
the pending member hidden from directory, catalog and mailbox; one reviewer
below quorum; a stranger rejected; two reviewers co-sign to quorum; the
approval receipt in the public log; opt into the catalog; receive and drain
mail; a replayed signature refused; council revocation; 403 / 404 afterwards.
"""
import base64
import json
import secrets
import sys
import time

import base58
import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sm_arp import Identity
from sm_oversight import add_witness, build_oversight_approval

BASE = sys.argv[1]
REVIEWER_SEEDS = sys.argv[2:5]  # the three humans on the council
h = httpx.Client(base_url=BASE, timeout=10)

def show(step, resp, keys=None):
    try: body = resp.json()
    except ValueError: body = resp.text[:200]
    if keys and isinstance(body, dict): body = {k: body.get(k) for k in keys if k in body}
    print(f"\n[{step}]  HTTP {resp.status_code}\n  {json.dumps(body, default=str)[:700]}")

# ── 0. The chapter as the Index would see it
show("0a health", h.get("/health"), ["agent_id","did","members","admitted","admission_mode","council","seed_encrypted"])
doc = h.get("/.well-known/nanda-chapter-join.json")
show("0b signed join document", doc, ["signed_by","signed_at"])
import jcs
from sm_arp import pubkey_from_did

payload = doc.json()["payload"]
pubkey_from_did(doc.json()["signed_by"]).verify(base64.b64decode(doc.json()["signature"]), bytes(jcs.canonicalize(payload)))
print("  signature verifies offline ✓ ; promises:", payload["promises"])
print("  register endpoint:", payload["endpoints"]["register"])

# ── 1. A brand-new agent with its own key
seed = secrets.token_bytes(32); sk = Ed25519PrivateKey.from_private_bytes(seed); pub = sk.public_key().public_bytes_raw()
pub_b64 = base64.b64encode(pub).decode(); did = "did:key:z" + base58.b58encode(b"\xed\x01" + pub).decode()
agent_id = f"ada-{secrets.token_hex(3)}"
print(f"\n[1] agent generates key locally: {agent_id}  {did}")

def signed(method, path, body=""):
    ts = str(int(time.time())); nonce = base64.b64encode(secrets.token_bytes(32)).decode()
    canonical = f"{method}:{path}:{body}:{agent_id}:{ts}:{nonce}"
    sig = base64.b64encode(sk.sign(canonical.encode())).decode()
    return {"X-Agent-ID": agent_id, "X-Agent-DID-Key": did, "X-Agent-Timestamp": ts, "X-Agent-Nonce": nonce,
            "X-Agent-Sig-Scheme": "ed25519+nonce", "X-Agent-Signature": sig, "Content-Type": "application/json"}

show("2 register (public key only, nothing secret sent)", h.post("/api/members", json={"agent_id": agent_id, "name": "Ada", "origin": "sovereign", "public_key": pub_b64}))
show("3 who am I (signed)", h.get("/api/me", headers=signed("GET", "/api/me")))
show("4 anonymous directory read", h.get("/api/members"))
cat = h.get("/.well-known/ai-catalog.json").json()
print(f"\n[5] catalog while pending: {[e['identifier'] for e in cat['entries']]}  (agent hidden)")
show("6 mail to a pending member", h.post(f"/a2a/@{agent_id}", json={"text": "hi"}))

# ── 7. The council
council = h.get("/api/council").json(); print(f"\n[7] council: quorum {council['quorum']}, pending {council['pending']}")
props = h.get("/api/council/proposals?status=pending", headers=signed("GET", "/api/council/proposals?status=pending")).json()["proposals"]
p = next(x for x in props if x["subject"] == agent_id); print(f"  proposal {p['id']} kind={p['kind']} receipt={p['receipt_id'][:16]}…")
pub_view = h.get(f"/api/council/proposals/{p['id']}/public").json()
reviewers = [Identity.from_seed(base64.b64decode(s)) for s in REVIEWER_SEEDS]
expires = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 86400))
def gesture(r):
    g = build_oversight_approval(r, principal_did=pub_view["proposer_did"], agent_did=pub_view["subject_did"], reviews_receipt_id=pub_view["receipt_id"], action_category=pub_view["category"], grant_expires_at=expires, human_summary=f"approve {agent_id}")
    return add_witness(g, r)
show("8a reviewer 1 approves alone (1 of 2)", h.post(f"/api/council/proposals/{p['id']}/gestures", json=gesture(reviewers[0])), ["status","gestures"])
stranger = Identity.generate()
show("8b a non-reviewer tries to approve", h.post(f"/api/council/proposals/{p['id']}/gestures", json=gesture(stranger)))
g2 = add_witness(gesture(reviewers[1]), reviewers[2])
show("8c reviewers 2+3 co-sign (quorum)", h.post(f"/api/council/proposals/{p['id']}/gestures", json=g2), ["status","decided_at"])
show("8d the approval receipt is in the public log", h.get(f"/api/receipts/{g2['receipt_id']}"), ["receipt_id","issuer_did","action"])

# ── 9. Admitted
show("9 who am I now", h.get("/api/me", headers=signed("GET", "/api/me")), ["admitted","admission","listed"])
show("10 opt into the public catalog", h.post("/api/me/listing", content=json.dumps({"listed": True}), headers=signed("POST", "/api/me/listing", json.dumps({"listed": True}))))
cat = h.get("/.well-known/ai-catalog.json").json(); print(f"\n[11] catalog now: {[e['identifier'] for e in cat['entries']]}")
card = h.get(f"/cards/{agent_id}.json").json(); print(f"  card url={card['url']}  identifier={card['_meta']['identifier']}")
show("12 someone mails the agent (A2A message/send)", h.post(f"/a2a/@{agent_id}", json={"jsonrpc": "2.0", "id": "1", "method": "message/send", "params": {"message": {"role": "user", "parts": [{"type": "text", "text": "welcome to the chapter"}]}}}))
show("13 agent drains its inbox (signed)", h.get("/api/inbox", headers=signed("GET", "/api/inbox")))
hdr = signed("GET", "/api/me"); h.get("/api/me", headers=hdr); show("14 replaying the same signed request", h.get("/api/me", headers=hdr))

# ── 15. Revocation by council
body = json.dumps({"kind": "member_revocation", "subject": agent_id, "summary": "demo: revoke"})
rp = h.post("/api/council/proposals", content=body, headers=signed("POST", "/api/council/proposals", body)).json()
pv = h.get(f"/api/council/proposals/{rp['id']}/public").json()
g = build_oversight_approval(reviewers[0], principal_did=pv["proposer_did"], agent_did=pv["subject_did"], reviews_receipt_id=pv["receipt_id"], action_category=pv["category"], grant_expires_at=expires)
g = add_witness(add_witness(g, reviewers[0]), reviewers[2])
show("15 council revokes (2 of 3)", h.post(f"/api/council/proposals/{rp['id']}/gestures", json=g), ["status"])
show("16 revoked agent, correctly signed request", h.get("/api/me", headers=signed("GET", "/api/me")))
show("17 its card", h.get(f"/cards/{agent_id}.json"))
show("18 public revocation list", h.get("/api/revocations"))
show("19 final health", h.get("/health"), ["members","admitted","revoked","council"])
