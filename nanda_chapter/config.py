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


def _truthy(raw: str | None) -> bool:
    return (raw or "").strip().lower() in ("1", "true", "yes", "on")


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
    # Enumeration: the catalog is public, so listing is the member's choice.
    # Default off — a member opts in with a signed POST /api/me/listing.
    catalog_default_listed: bool = False
    # Abuse control (per client IP, per minute).
    rate_register_per_min: int = 10
    rate_mailbox_per_min: int = 30
    rate_writes_per_min: int = 60
    rate_reads_per_min: int = 60
    trust_proxy_headers: bool = False
    mailbox_allow_anonymous: bool = True
    # Council reviewers the operator has revoked (checked alongside state).
    council_revoked_reviewers: tuple[str, ...] = ()
    # Custody: True when the seed on disk is encrypted under CHAPTER_SEED_PASSPHRASE.
    seed_encrypted: bool = False
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
        passphrase = e.get("CHAPTER_SEED_PASSPHRASE", "")
        if e.get("CHAPTER_SEED"):
            seed, encrypted = e["CHAPTER_SEED"], True  # held by the operator's secret store, not on our disk
        else:
            seed, encrypted = _load_or_create_seed(home, passphrase)
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
            catalog_default_listed=_truthy(e.get("CATALOG_DEFAULT_LISTED", "false")),
            rate_register_per_min=int(e.get("RATE_REGISTER_PER_MIN", "10")),
            rate_mailbox_per_min=int(e.get("RATE_MAILBOX_PER_MIN", "30")),
            rate_writes_per_min=int(e.get("RATE_WRITES_PER_MIN", "60")),
            rate_reads_per_min=int(e.get("RATE_READS_PER_MIN", "60")),
            trust_proxy_headers=_truthy(e.get("TRUST_PROXY_HEADERS", "false")),
            mailbox_allow_anonymous=_truthy(e.get("MAILBOX_ALLOW_ANONYMOUS", "true")),
            council_revoked_reviewers=_split(e.get("COUNCIL_REVOKED_REVIEWERS")),
            seed_encrypted=encrypted,
            seed_b64=seed,
        )

    @property
    def seed_bytes(self) -> bytes:
        return base64.b64decode(self.seed_b64)


def _load_or_create_seed(home: Path, passphrase: str) -> tuple[str, bool]:
    """The chapter's root secret, created on first run.

    With ``CHAPTER_SEED_PASSPHRASE`` set, the seed lives in ``seed.enc``:
    AES-256-GCM under a key derived by PBKDF2-HMAC-SHA256 (600k rounds) from the
    passphrase, with a fresh salt and nonce. A plaintext ``seed.b64`` left over
    from an earlier run is migrated into ``seed.enc`` and deleted. Without a
    passphrase the seed is plaintext with mode 0600, and ``seed_encrypted`` is
    False so the operator sees it at startup.

    Returns ``(seed_b64, encrypted)``.
    """
    enc_path, plain_path = home / "seed.enc", home / "seed.b64"
    if passphrase:
        if enc_path.exists():
            return _decrypt_seed(enc_path.read_bytes(), passphrase), True
        seed = plain_path.read_text().strip() if plain_path.exists() else base64.b64encode(secrets.token_bytes(32)).decode()
        enc_path.write_bytes(_encrypt_seed(seed, passphrase))
        _chmod_600(enc_path)
        if plain_path.exists():
            plain_path.unlink()
        return seed, True
    if enc_path.exists():
        raise ValueError(f"{enc_path} exists but CHAPTER_SEED_PASSPHRASE is not set; refusing to run with an unreadable identity")
    if plain_path.exists():
        return plain_path.read_text().strip(), False
    seed = base64.b64encode(secrets.token_bytes(32)).decode()
    plain_path.write_text(seed)
    _chmod_600(plain_path)
    return seed, False


_KDF_ROUNDS = 600_000


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=_KDF_ROUNDS).derive(passphrase.encode())


def _encrypt_seed(seed_b64: str, passphrase: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    ct = AESGCM(_derive_key(passphrase, salt)).encrypt(nonce, seed_b64.encode(), b"nanda-chapter-seed-v1")
    return base64.b64encode(b"v1" + salt + nonce + ct)


def _decrypt_seed(blob: bytes, passphrase: str) -> str:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    raw = base64.b64decode(blob)
    if raw[:2] != b"v1":
        raise ValueError("unknown seed.enc format")
    salt, nonce, ct = raw[2:18], raw[18:30], raw[30:]
    try:
        return AESGCM(_derive_key(passphrase, salt)).decrypt(nonce, ct, b"nanda-chapter-seed-v1").decode()
    except Exception as exc:
        raise ValueError("CHAPTER_SEED_PASSPHRASE does not decrypt seed.enc") from exc


def _chmod_600(path: Path) -> None:
    try:
        path.chmod(0o600)
    except OSError:
        pass
