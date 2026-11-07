"""``nanda-chapter`` — stand up, run, list and govern a chapter.

    nanda-chapter init --id tokyo --name "Tokyo Chapter" --url https://tokyo.example.org
    nanda-chapter run
    nanda-chapter identity
    nanda-chapter index payload | register | challenge | verify | resolve
    nanda-chapter council status | new-reviewer | propose | gesture
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .config import ChapterConfig


def _cfg() -> ChapterConfig:
    env_file = Path(os.environ.get("CHAPTER_HOME", "~/.nanda-chapter")).expanduser() / "chapter.env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())
    return ChapterConfig.from_env()


def _out(obj: object) -> None:
    print(json.dumps(obj, indent=2, default=str))


def cmd_init(a: argparse.Namespace) -> int:
    home = Path(a.home).expanduser()
    home.mkdir(parents=True, exist_ok=True)
    env = home / "chapter.env"
    if env.exists() and not a.force:
        print(f"{env} exists; pass --force to overwrite", file=sys.stderr)
        return 1
    domain = a.domain or a.url.split("://", 1)[-1].split("/", 1)[0]
    env.write_text(
        "\n".join(
            [
                f"CHAPTER_HOME={home}",
                f"CHAPTER_ID={a.id}",
                f"CHAPTER_NAME={a.name}",
                f"PUBLIC_URL={a.url.rstrip('/')}",
                f"CHAPTER_DOMAIN={domain}",
                f"CHAPTER_FOCUS={a.focus}",
                f"ADMISSION_MODE={a.admission}",
                "COUNCIL_REVIEWERS=",
                "COUNCIL_REQUIRED_M=1",
                "CONTACT_EMAIL=",
                "INDEX_ACCOUNT_EMAIL=",
                "INDEX_ACCOUNT_PASSWORD=",
                "KNOWN_CHAPTER_ENDPOINTS=",
                f"PORT={a.port}",
                "",
            ]
        )
    )
    os.environ["CHAPTER_HOME"] = str(home)
    cfg = _cfg()
    from sm_arp import Identity

    _out({"written": str(env), "chapter_id": cfg.chapter_id, "did": Identity.from_seed(cfg.seed_bytes).did, "next": "nanda-chapter run"})
    return 0


def cmd_run(a: argparse.Namespace) -> int:
    import uvicorn

    from .app import create_app

    cfg = _cfg()
    port = a.port or int(os.environ.get("PORT", "8080"))
    uvicorn.run(create_app(cfg), host=a.host, port=port, log_level="info")
    return 0


def cmd_identity(_: argparse.Namespace) -> int:
    from sm_arp import Identity

    cfg = _cfg()
    _out({"chapter_id": cfg.chapter_id, "did": Identity.from_seed(cfg.seed_bytes).did, "public_url": cfg.public_url, "domain": cfg.domain})
    return 0


def cmd_index(a: argparse.Namespace) -> int:
    from .index_client import IndexClient

    ic = IndexClient(_cfg())
    if a.action == "payload":
        _out(ic.register(dry_run=True))
        return 0
    problems = ic.preflight()
    if problems and a.action != "resolve":
        _out({"blocked": problems})
        return 2
    _out({"register": ic.register, "challenge": ic.domain_challenge, "verify": ic.verify_domain, "resolve": ic.resolve}[a.action]())
    return 0


def cmd_council(a: argparse.Namespace) -> int:
    import httpx

    from .reviewer import build_gesture, co_sign, new_reviewer_seed, reviewer_identity

    cfg = _cfg()
    base = a.chapter or cfg.public_url
    if a.action == "new-reviewer":
        seed = new_reviewer_seed()
        _out({"did": reviewer_identity(seed).did, "seed_b64": seed, "note": "keep the seed private; put the DID in COUNCIL_REVIEWERS"})
        return 0
    if a.action == "status":
        _out(httpx.get(f"{base}/api/council", timeout=15).json())
        return 0
    if a.action == "gesture":
        if not a.seed:
            print("--seed (reviewer seed, base64) required", file=sys.stderr)
            return 1
        proposal = httpx.get(f"{base}/api/council/proposals/{a.proposal}/public", timeout=15).json()
        reviewer = reviewer_identity(a.seed)
        gesture = build_gesture(reviewer, proposal, decision=a.decision, reviewers=a.reviewers or None, summary=a.summary)
        for extra in a.cosign or []:
            gesture = co_sign(gesture, reviewer_identity(extra))
        r = httpx.post(f"{base}/api/council/proposals/{a.proposal}/gestures", json=gesture, timeout=15)
        _out({"status_code": r.status_code, "body": r.json()})
        return 0 if r.status_code < 300 else 1
    print(f"unknown council action {a.action}", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="nanda-chapter", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    i = sub.add_parser("init", help="write chapter.env and create the chapter identity")
    i.add_argument("--id", required=True)
    i.add_argument("--name", required=True)
    i.add_argument("--url", required=True, help="public https URL of this chapter")
    i.add_argument("--domain", default="", help="DNS name for the Index locator (default: host of --url)")
    i.add_argument("--focus", default="")
    i.add_argument("--admission", default="council", choices=["open", "council", "parc"])
    i.add_argument("--port", type=int, default=8080)
    i.add_argument("--home", default=os.environ.get("CHAPTER_HOME", "~/.nanda-chapter"))
    i.add_argument("--force", action="store_true")
    i.set_defaults(fn=cmd_init)

    r = sub.add_parser("run", help="serve the chapter")
    r.add_argument("--host", default="0.0.0.0")
    r.add_argument("--port", type=int, default=0)
    r.set_defaults(fn=cmd_run)

    sub.add_parser("identity", help="print the chapter's did:key").set_defaults(fn=cmd_identity)

    x = sub.add_parser("index", help="NANDA Index v2 registration")
    x.add_argument("action", choices=["payload", "register", "challenge", "verify", "resolve"])
    x.set_defaults(fn=cmd_index)

    c = sub.add_parser("council", help="council operations")
    c.add_argument("action", choices=["status", "new-reviewer", "gesture"])
    c.add_argument("--chapter", default="", help="chapter URL (default PUBLIC_URL)")
    c.add_argument("--proposal", default="")
    c.add_argument("--decision", default="approved", choices=["approved", "denied", "escalated"])
    c.add_argument("--seed", default="", help="reviewer seed (base64)")
    c.add_argument("--cosign", action="append", help="additional reviewer seed(s) to co-witness")
    c.add_argument("--reviewers", action="append", help="reviewer DIDs named on the gesture")
    c.add_argument("--summary", default="")
    c.set_defaults(fn=cmd_council)

    a = p.parse_args(argv)
    return int(a.fn(a))


if __name__ == "__main__":
    sys.exit(main())
