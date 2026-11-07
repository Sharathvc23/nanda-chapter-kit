# nanda-chapter-kit

**A chapter is the home network a personal agent joins.**

Personal agents are becoming real: one per person, holding its own keys, acting
under its owner's authority. An agent that only talks to one other agent is a
phone with one number. The useful unit is a *network* the agent belongs to: a
place that vouches for who is in it, makes its members findable from outside,
routes messages to members that have no public address, and decides, with
humans in the loop, who gets in. That is what a NANDA chapter is, and this kit
is how you stand one up.

```
pip install nanda-chapter-kit
nanda-chapter init --id tokyo --name "Tokyo Chapter" --url https://tokyo.chapters.example --admission council
nanda-chapter run
```

No LLM. No vendor account. One process, one SQLite file, one domain.

## What a chapter provides

| To a member (a personal agent) | How |
|---|---|
| **A home identity that is yours** | You register your own Ed25519 `did:key`; the chapter pins it on first use and can never sign as you. |
| **A name strangers can resolve** | You appear in the chapter's AI Catalog as `urn:air:<chapter-domain>:agent:<you>`, resolvable from the NANDA Index through the chapter's org entry. |
| **A mailbox when you have no public endpoint** | Your A2A card points at `POST /a2a/@<you>` on the chapter; the chapter stores and you drain with a signed `GET /api/inbox`. |
| **A directory of peers** | Signed `GET /api/members` lists admitted members only; anonymous enumeration is refused. |
| **A reputation that travels** | Every chapter action is an ARP receipt in the issuer log; `sm-parc` turns them into a credential another chapter can verify at admission. |
| **A governed door** | Admission is open, council (M-of-N human quorum), or by presented reputation credential. |

| To the network (Project NANDA, the council, peer chapters) | How |
|---|---|
| **One Index entry per chapter, not per agent** | `nanda-chapter index register` creates `urn:air:<domain>:catalog:root` with `registry_url` = this chapter; the Index resolves to the catalog, the catalog to the member. |
| **Human-in-the-loop governance as receipts** | Proposals (member admission, chapter charter, peer admission, role promotion) are ARP receipts; reviewers answer with `sm-oversight` gestures, co-witnessed to quorum, verified offline. |
| **Delegable oversight** | A reviewer may be a human key or an agent holding a bounded `sm-dat` grant from that human; the quorum is over signatures and does not care which. |
| **Mechanical conformance** | The kit is a NANDA chapter iff the `Nanda_Chapter_Protocol` server conformance suite passes against it. `scripts/conformance.sh` runs it; CI runs it on every push. |

## How a personal agent connects

```
 personal agent (did:key, local keys)
        │ POST /api/members  (TOFU: chapter pins your public key)
        ▼
 ┌──────────────── chapter ────────────────┐      ┌──────────── NANDA Index ───────────┐
 │ directory · mailbox · council · receipts │◄─────│ urn:air:<domain>:catalog:root       │
 │ /.well-known/ai-catalog.json             │      │   → registry_url = this chapter     │
 │   ├ <chapter>      → /.well-known/agent.json    └─────────────────────────────────────┘
 │   └ <member>       → /cards/<member>.json → url: /a2a/@<member>  (mailbox)
 └──────────────────────────────────────────┘
        │ federation (peer chapters, did-pinned)
        ▼
   other chapters, other members
```

1. **Join.** `POST /api/members` with `agent_id`, `name`, `origin`, `public_key`. Open to anyone; this is the TOFU bootstrap.
2. **Get admitted.** `open` mode: immediately. `council` mode: a `member_admission` proposal is filed; you are hidden from the directory, catalog and mailbox until a quorum of reviewers approves. `parc` mode: present a reputation credential at `POST /api/admission/parc`.
3. **Be found.** You are now an entry in `/.well-known/ai-catalog.json` with an A2A card. Anyone resolving the chapter on the Index finds you.
4. **Be reached.** Anyone can `POST /a2a/@<you>` (A2A JSON-RPC `message/send` or the NANDA adapter shape). You drain with a signed `GET /api/inbox`.
5. **Act.** Sign requests with `ed25519+nonce` (v0.3). Feedback, proposals and inbox reads all verify against your pinned key.

## The council

```
nanda-chapter council new-reviewer        # → did + private seed, per human reviewer
# put the DIDs in COUNCIL_REVIEWERS, COUNCIL_REQUIRED_M=2, ADMISSION_MODE=council
nanda-chapter council status
nanda-chapter council gesture --proposal prop-abc123 --decision approved --seed <mine> --cosign <peer-seed>
```

A gesture is an `sm-oversight` receipt the reviewer signs with their own key. The
chapter verifies the issuer signature, the reviewer's membership of the trusted
set, that the gesture reviews this proposal's receipt, then counts distinct
witness signatures toward `COUNCIL_REQUIRED_M`. On quorum the effect executes
(admission, promotion) and both receipts sit in the chapter's issuer log at
`/api/receipts/{id}` for anyone to re-verify.

## Getting on the NANDA Index

The Index holds one record per organisation and resolves it to a catalog; it does
not host agents. A chapter therefore needs **a domain it controls**: activation
is a DNS TXT record, which is the Index's proof of authority.

```
nanda-chapter index payload     # dry run: the exact org record and locator
nanda-chapter index register    # POST /api/v1/orgs → pending
nanda-chapter index challenge   # → publish _nanda-challenge.<domain> TXT nanda-verify=<token>
nanda-chapter index verify      # → active
nanda-chapter index resolve     # the only proof a stranger can find you
```

## Configuration

| Variable | Meaning |
|---|---|
| `CHAPTER_ID`, `CHAPTER_NAME`, `PUBLIC_URL`, `CHAPTER_DOMAIN` | Identity and where the chapter lives. The domain is the Index publisher. |
| `CHAPTER_HOME` | Seed, store and state live here (`~/.nanda-chapter`). The seed is the chapter's root secret. |
| `ADMISSION_MODE` | `open` · `council` · `parc` |
| `COUNCIL_REVIEWERS`, `COUNCIL_REQUIRED_M` | Reviewer DIDs and the quorum. |
| `PARC_TRUSTED_ISSUERS`, `PARC_MIN_SCORE` | Who may issue reputation credentials you accept, and the floor. |
| `CHAPTER_ORIGINS` | Admitted provenance labels (`sovereign,openclaw,managed`). |
| `INDEX_ACCOUNT_EMAIL`, `INDEX_ACCOUNT_PASSWORD`, `CONTACT_EMAIL` | NANDA Index account for `nanda-chapter index`. |
| `KNOWN_CHAPTER_ENDPOINTS` | Peer chapters named by the operator. |

## What this composes

| Primitive | Role here |
|---|---|
| [`sm-org-server`](https://github.com/Sharathvc23/sm-org-server) | The conformant floor: registration, rotation, signed requests, trust ledger, ARP issuer log, surfaces. |
| [`sm-bridge`](https://github.com/Sharathvc23/sm-bridge) | AI Catalog entries and A2A agent cards the Index resolves to. |
| [`sm-oversight`](https://github.com/Sharathvc23/sm-oversight) | Approve / deny / escalate gestures with M-of-N quorum. |
| [`sm-parc`](https://github.com/Sharathvc23/sm-parc) | Portable reputation checked at admission. |
| [`sm-dat`](https://github.com/Sharathvc23/sm-dat) | Bounded delegation from a human reviewer to their agent. |
| [`sm-arp`](https://github.com/Sharathvc23/sm-arp) | The receipt envelope everything above signs. |

The kit defines no protocol. The wire contract is the
[NANDA Chapter Protocol](https://github.com/Sharathvc23/Nanda_Chapter_Protocol)
spec and its conformance suite; when the kit and the spec disagree, the kit is wrong.

## Status

v0.1.0. Passes the umbrella server conformance suite (see CI). Not yet done, in
order: peer federation with did-pinning and badge-gated admission; `sm-dat`
grant verification on council gestures; minting the chapter's own signed
conformance badge; an MCP server over the member and council surfaces.

## Development

```
pip install -e ".[dev]"
python -m pytest tests/ -q
ruff check nanda_chapter tests
UMBRELLA=../Nanda_Chapter_Protocol CHAPTER_URL=http://localhost:8080 scripts/conformance.sh
```

MIT.
