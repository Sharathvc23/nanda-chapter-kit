"""Chapter configuration — one dataclass, read once from the environment.

Everything a deployment varies lives here. Nothing in the package reads
``os.environ`` anywhere else, so a test can build a ``ChapterConfig`` by hand.
"""

from __future__ import annotations

import base64
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_ORIGINS = ("sovereign", "openclaw", "managed")
ADMISSION_MODES = ("open", "council", "parc")


def _split(raw: str | None) -> tuple[str, ...]:
    return tuple(s.strip() for s in (raw or "").split(",") if s.strip())


@dataclass(frozen=True)
class ChapterConfig:
    chapter_id: str
    name: str
    public_url: str
    domain: str
    home: Path
    description: str = ""
    focus: str = ""
    origins: tuple[str, ...] = DEFAULT_ORIGINS
    nonrotatable_origins: tuple[str, ...] = ("managed",)
    # Council: the human reviewers (did:key of each reviewer's signing identity)
    # and how many of them must witness an approval. 0 reviewers = no council
    # (every proposal needs an operator to flip it by hand; nothing auto-executes).
    council_reviewers: tuple[str, ...] = ()
    council_required_m: int = 1
    # Admission: open (register == admitted), council (register, then a council
    # proposal gates listing + directory), parc (a PARC credential admits
    # without the council; without one, falls back to council).
    admission_mode: str = "open"
    parc_trusted_issuers: tuple[str, ...] = ()
    parc_min_score: float = 0.0
    # NANDA Index v2 (api.nandaindex.org). Operator-triggered, never at startup.
    index_url: str = "https://api.nandaindex.org"
    index_email: str = ""
    index_password: str = ""
    contact_email: str = ""
    # Peers this chapter federates with, named by the operator.
    known_peers: tuple[str, ...] = ()
    seed_b64: str = field(default="", repr=False)

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> ChapterConfig:
        e = dict(os.environ) if env is None else env
        home = Path(e.get("CHAPTER_HOME", "~/.nanda-chapter")).expanduser()
        home.mkdir(parents=True, exist_ok=True)
        chapter_id = e.get("CHAPTER_ID", "local-chapter")
        public_url = e.get("PUBLIC_URL", "http://localhost:8080").rstrip("/")
        domain = e.get("CHAPTER_DOMAIN") or public_url.split("://", 1)[-1].split("/", 1)[0]
        mode = e.get("ADMISSION_MODE", "open")
        if mode not in ADMISSION_MODES:
            raise ValueError(f"ADMISSION_MODE must be one of {ADMISSION_MODES}, got {mode!r}")
        seed = e.get("CHAPTER_SEED") or _load_or_create_seed(home / "seed.b64")
        return cls(
            chapter_id=chapter_id,
            name=e.get("CHAPTER_NAME", chapter_id),
            public_url=public_url,
            domain=domain,
            home=home,
            description=e.get("CHAPTER_DESCRIPTION", ""),
            focus=e.get("CHAPTER_FOCUS", ""),
            origins=_split(e.get("CHAPTER_ORIGINS")) or DEFAULT_ORIGINS,
            nonrotatable_origins=_split(e.get("CHAPTER_NONROTATABLE_ORIGINS")) or ("managed",),
            council_reviewers=_split(e.get("COUNCIL_REVIEWERS")),
            council_required_m=int(e.get("COUNCIL_REQUIRED_M", "1")),
            admission_mode=mode,
            parc_trusted_issuers=_split(e.get("PARC_TRUSTED_ISSUERS")),
            parc_min_score=float(e.get("PARC_MIN_SCORE", "0")),
            index_url=e.get("NANDA_INDEX_URL", "https://api.nandaindex.org").rstrip("/"),
            index_email=e.get("INDEX_ACCOUNT_EMAIL", ""),
            index_password=e.get("INDEX_ACCOUNT_PASSWORD", ""),
            contact_email=e.get("CONTACT_EMAIL", e.get("INDEX_ACCOUNT_EMAIL", "")),
            known_peers=_split(e.get("KNOWN_CHAPTER_ENDPOINTS")),
            seed_b64=seed,
        )

    @property
    def seed_bytes(self) -> bytes:
        return base64.b64decode(self.seed_b64)


def _load_or_create_seed(path: Path) -> str:
    """A stable Ed25519 seed for the chapter identity, created on first run.

    The seed is the chapter's root secret: it signs receipts, the conformance
    badge, and federation requests. It never leaves ``CHAPTER_HOME``.
    """
    if path.exists():
        return path.read_text().strip()
    seed = base64.b64encode(secrets.token_bytes(32)).decode()
    path.write_text(seed)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return seed
