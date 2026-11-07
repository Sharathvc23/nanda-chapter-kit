"""Per-client sliding-window rate limits — abuse control for open endpoints.

Registration is open by design (TOFU), mailbox posts may be anonymous, and the
directory is enumerable by any signed member. Each is a cheap write or a cheap
scrape, so each has its own ceiling per client IP per minute. In-memory and
per-process: a chapter behind several replicas shares nothing here, which is
acceptable for a floor and honest about what it is.
"""

from __future__ import annotations

import threading
import time
from collections import deque

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

WINDOW_S = 60


class SlidingWindow:
    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        with self._lock:
            q = self._hits.setdefault(key, deque())
            cutoff = now - WINDOW_S
            while q and q[0] <= cutoff:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True

    def prune(self, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        with self._lock:
            for k in [k for k, q in self._hits.items() if not q or q[-1] <= now - WINDOW_S]:
                self._hits.pop(k, None)


def client_ip(scope: Scope, *, trust_proxy_headers: bool) -> str:
    if trust_proxy_headers:
        for name, value in scope.get("headers", []):
            if name == b"x-forwarded-for":
                return value.decode("latin-1").split(",")[0].strip() or "unknown"
    client = scope.get("client")
    return client[0] if client else "unknown"


class RateLimitMiddleware:
    """Pure ASGI: cheap, and runs before any body is read."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        register_per_min: int,
        mailbox_per_min: int,
        writes_per_min: int,
        reads_per_min: int,
        trust_proxy_headers: bool = False,
        window: SlidingWindow | None = None,
    ) -> None:
        self.app = app
        self.window = window or SlidingWindow()
        self.limits = {
            "register": register_per_min,
            "mailbox": mailbox_per_min,
            "writes": writes_per_min,
            "reads": reads_per_min,
        }
        self.trust_proxy_headers = trust_proxy_headers

    @staticmethod
    def bucket(method: str, path: str) -> str | None:
        p = path.rstrip("/") or "/"
        if method == "POST" and p == "/api/members":
            return "register"
        if method == "POST" and p.startswith("/a2a/@"):
            return "mailbox"
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            return "writes"
        if method == "GET" and (p == "/api/members" or p.startswith("/api/federation/") or p == "/api/inbox"):
            return "reads"
        return None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        bucket = self.bucket(scope["method"], scope["path"])
        if bucket is not None:
            ip = client_ip(scope, trust_proxy_headers=self.trust_proxy_headers)
            if not self.window.allow(f"{bucket}:{ip}", self.limits[bucket]):
                resp = JSONResponse(
                    {"error": "rate_limited", "bucket": bucket, "retry_after_seconds": WINDOW_S},
                    status_code=429,
                    headers={"Retry-After": str(WINDOW_S)},
                )
                await resp(scope, receive, send)
                return
        await self.app(scope, receive, send)


def request_ip(req: Request, *, trust_proxy_headers: bool) -> str:
    return client_ip(req.scope, trust_proxy_headers=trust_proxy_headers)
