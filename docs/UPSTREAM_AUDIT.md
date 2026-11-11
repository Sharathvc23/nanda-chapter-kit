# Upstream library audit — 2026-11-11

> **Resolved upstream, same day.** Every finding below was fixed in its library
> through a reviewed, CI-green, squash-merged pull request. The kit now pins
> those merged commits (see `pyproject.toml`) and has dropped the handlers it
> had replaced where upstream now does the job. Status per library:
>
> | Library | PR | Merged | Version | Own tests |
> |---|---|---|---|---|
> | sm-arp | [#17](https://github.com/Sharathvc23/sm-arp/pull/17) | `f182c0c` | 0.4.0 | 179 → 244, 25 vectors |
> | sm-org-server | [#11](https://github.com/Sharathvc23/sm-org-server/pull/11) | `e71497e` | 0.2.0 | 75 → 148; umbrella conformance 68/68 on its own |
> | sm-org-agent | [#8](https://github.com/Sharathvc23/sm-org-agent/pull/8) | `a232c93` | 0.2.0 | 34 → 64 |
> | sm-bridge | [#31](https://github.com/Sharathvc23/sm-bridge/pull/31) | `bbcd9f2` | 0.11.0 | 371 → 410 |
> | sm-conformance | [#14](https://github.com/Sharathvc23/sm-conformance/pull/14) | `48e9166` | 0.4.0 | 100 → 142 |
> | sm-oversight | [#9](https://github.com/Sharathvc23/sm-oversight/pull/9) | `a60a5dd` | 0.3.0 | 13 → 34 |
> | sm-parc | [#5](https://github.com/Sharathvc23/sm-parc/pull/5) | `1561ae2` | 0.3.0 | 74 → 105 |
> | sm-dat | [#10](https://github.com/Sharathvc23/sm-dat/pull/10) | `b3174b5` | 0.3.0 | 66 → 197, 60 vectors |
>
> Still to do by a human: publish these versions to PyPI and tag them (the kit
> and three downstream CIs install sm-arp from its commit until 0.4.0 is
> published); delete the merged `fix/audit-2026-11` branches, which the
> session's proxy could not remove; re-sign the stale conformance badges in
> sm-org-server and sm-org-agent with the runtime key.
>
> **What the kit dropped** after the merges: its own registration, rotation and
> receipt-ingestion handlers (sm-org-server 0.2.0 refuses re-registration with
> a different key, validates keys, scopes rotation nonces per agent, derives
> DIDs server-side, and keeps the receipt log append-only); its duplicate
> rewrite/fork detection in `ChapterStore` (only the chapter-chain genesis rule
> remains); its clock and presenter binding for PARC (sm-parc 0.3.0 requires
> `presenter_did` and uses a real clock; the kit's subject and cap checks stay
> as defence in depth); and the hand-built A2A v1.0 card (sm-bridge 0.11.0
> emits it; the kit only fills gaps). The record below is kept as written on
> the day of the audit.

The kit composes eight `sm-*` libraries. Each was audited in a clean virtualenv:
its own test suite run, README and SPEC claims checked against code with
file:line evidence, cryptography reviewed, the published PyPI artifact diffed
against the repo, and a reproduction attempted for every suspected defect.
Findings that were reachable through the kit were then reproduced **through the
kit** and closed in `nanda_chapter/`. This file records what was found, what the
kit does about it, and what must change upstream. Versions: sm-arp 0.3.4,
sm-oversight 0.2.0 (git, not on PyPI), sm-org-server 0.1.0, sm-org-agent 0.1.0,
sm-bridge 0.10.0, sm-conformance 0.3.2, sm-parc 0.2.3, sm-dat 0.2.1.

| Library | Own tests | Verdict for the kit's use |
|---|---|---|
| sm-arp | 179 pass | Signature / structure / did:key sound. `verify_authority_chain` is NOT an authentication (see below). |
| sm-oversight | 13 pass | `verify_quorum` sound; `add_witness` breaks the issuer signature; `verify_oversight` is a stub. Kit works around both. |
| sm-org-server | 75 pass | Not safe as a bare wire floor: identity hijack, self-minted trust, mutable receipt log, garbage keys accepted. Kit replaces those handlers. |
| sm-org-agent | 34 pass | Canonical strings correct; no nonce/timestamp helpers; `Identity` does not check pub/seed match. |
| sm-bridge | 371 pass | Catalog builder fine. A2A card is v0.2-era and fails Index validation. Kit lifts it to v1.0. |
| sm-conformance | 100 pass | Signing core sound. Pass gate lives only in the CLI; no future-timestamp guard. |
| sm-parc | 74 pass | Proof verification sound. Gate has unsafe defaults: no clock, no presenter binding, forgeable with 3 fresh DIDs. Kit supplies all bindings. |
| sm-dat | 66 pass | Correct for one human→agent grant. Chains ignore revoked / not-yet-valid ancestors. Kit must forbid sub-delegation when it adopts DAT. |

Every published artifact matched its repo at HEAD byte-for-byte, except: sm-bridge
HEAD has one unreleased commit; sm-org-server's 0.1.0 artifact contains features
its CHANGELOG lists as unreleased. sm-oversight has no tags and is not on PyPI; the
kit pins it to a commit.

## Reachable through the kit, now closed

| # | Defect (upstream location) | Reproduced through the kit | Kit fix |
|---|---|---|---|
| 1 | **Identity hijack**: re-registering an existing `agent_id` with a different key overwrote the pinned key (`sm_server/app.py` register, `INSERT OR REPLACE`) | Yes: attacker authenticates, victim locked out | Own `POST /api/members`: differing key → 401 `key_mismatch`; same key idempotent; did derived server-side |
| 2 | **Self-minted trust**: `/api/feedback` credited the caller +1 per call, TOFU on the way in | Yes: unknown agent reached score 3.0 in 3 calls | Trust goes only to a *different* admitted subject, once per (voucher, subject) per day; self-feedback records a receipt and nothing else |
| 3 | **Mutable receipt log**: `append_receipt` was `INSERT OR REPLACE` | Yes: stored summary rewritten under the same id | `ChapterStore`: idempotent on identical bytes, 409 on rewrite, 409 on chain fork, second genesis refused for the chapter's own chain |
| 4 | **Garbage keys accepted** at registration → later 500 | Yes: handler raised on `b64decode` | Key must be 32 Ed25519 bytes (400 otherwise); verifier treats an undecodable stored key as `no_stored_key` |
| 5 | **Rotation**: nonce scope chapter-wide; client-supplied `new_did_key` stored unvalidated | Scope reproduced upstream; did confirmed through kit | Own rotate handler: nonce scoped per agent; did derived from the new key |
| 6 | **A2A card rejected by Index** (`sm_bridge.gateway.to_a2a_card` emits v0.2 shape) | Shape confirmed | `catalog.a2a_v1_card` adds `supportedInterfaces`, `securitySchemes`, default modes, skill `id`/`tags`; drops `authentication` |
| 7 | **sm-oversight `add_witness` invalidates the issuer signature**; `verify_oversight` never verifies the gesture receipt | Yes | Council verifies the issuer signature on the gesture with the witness list stripped, requires the issuer in the trusted set, then counts witnesses |
| 8 | **sm-parc unsafe defaults**: no clock → expired credential admitted; no presenter binding; subject ≠ receipt issuer admitted; no inline ledger cap; anchors off | Yes (auditor E2E) | `POST /api/admission/parc` passes UTC `now`, requires `credentialSubject.id == presenting did:key`, requires every receipt's issuer to be the subject, caps ledger size, passes `PARC_REQUIRED_ANCHORS`, uses the real `verify_receipt` |

Also chained: the chapter's own receipts now form a proper per-issuer hash chain
(ARP §6.4); upstream emitted every server receipt as a fresh genesis.

Not changed, by spec: v0.2 has no replay protection and the conformance suite
asserts an identical v0.2 request is accepted twice (R2). The kit therefore makes
every replayable request idempotent instead of refusing replays.

## Not yet reachable, noted for when the kit adopts the path

- **sm-dat chains**: ancestor revocation and `not_before` are not checked in the
  chain walk; `max_depth` is read from the leaf; `not_before`, `predicate`,
  `amount_currency` are not attenuated. The kit will accept only single-hop
  grants (`parent_grant_id` forbidden), require `revocation` to be declared,
  always pass `agent_did`, and bind `grantor_did` to the reviewer's registered DID.
- **sm-arp `verify_authority_chain`** does not verify the grant's signature, does
  not require issuer == principal, and admits an absent `granted_to_did`. Use
  `verify_direct_grant` or pre-verify grants.
- **sm-conformance**: `verify_envelope` returns a payload for a failed badge; the
  refusal is in the CLI. Add a future-`completed_at` guard when gating freshness.
- **sm-bridge trust profiles**: `ans-txt` returns VERIFIED without DNSSEC;
  `nanda-delegation` takes `now` and revocation status from the evidence bundle.
  Not used by the kit.

## What must change upstream

- **sm-org-server**: reject re-registration with a different key; validate
  public keys and derive did:key server-side; implement v0.3 verification and
  honour `X-Agent-Sig-Scheme`; gate the directory and federation views; bind
  feedback to a verified body and stop crediting the caller; make
  `append_receipt` append-only; file-backed store by default; nonce TTL; bump
  the version and re-mint badges against the current corpus.
- **sm-oversight**: carry witness signatures outside the signed receipt or
  re-sign after witnessing; verify the gesture receipt in `verify_quorum` /
  `inspect_legacy`; implement or strike SPEC §5; unify `signer_did` /
  `witness_did` with sm-arp; tag and publish.
- **sm-arp**: make `verify_authority_chain` authenticate the grant or document
  that it does not; implement or strike spec §3 unknown-member rejection and
  §11.2 freshness from `verify_receipt`'s contract.
- **sm-bridge**: emit A2A v1.0 cards; `ans-txt` → NOT_VERIFIED without DNSSEC;
  take delegation `now`/status from a trusted source; release the pending commit.
- **sm-parc**: require `now`; add presenter binding and issuer == subject check;
  mandatory credential `id`; apply `max_ledger_receipts` inline; tests with the
  real verifier.
- **sm-dat**: check ancestor revocation and window; take `max_depth` from the
  root; attenuate all bounds; return `VIOLATED(malformed)` instead of raising.
- **sm-conformance**: future-timestamp rejection; wrap jcs errors; library-level
  pass gate.
