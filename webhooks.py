"""Webhook passthrough: forward POSTs from the public internet (GitHub,
GitLab, etc.) to internal services behind the gateway.

Each configured webhook has:
- a secret URL path segment (matched via constant-time compare so the
  valid paths can't be enumerated by timing)
- a target URL on the internal side
- optionally an HMAC secret used to verify the signature header GitHub
  attaches to every delivery; when set, invalid signatures are rejected
  before the payload ever touches the target

Stats are kept in memory per webhook so admins can see when each was
last fired, what the upstream said, and whether recent deliveries failed.
Stats reset on process restart — persistence is not worth the complexity
for a "last delivered ~X minutes ago" display.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

# Headers forwarded from the original request to the target. Keep tight so
# we don't leak Authorization / cookies / proxy headers to internal services.
FORWARD_HEADERS = {
    "Content-Type",
    "User-Agent",
    "X-GitHub-Event",
    "X-GitHub-Delivery",
    "X-GitHub-Hook-ID",
    "X-GitHub-Hook-Installation-Target-ID",
    "X-GitHub-Hook-Installation-Target-Type",
    "X-Hub-Signature",
    "X-Hub-Signature-256",
    "X-Gitlab-Event",
    "X-Gitlab-Token",
}


@dataclass
class WebhookStats:
    total: int = 0
    successes: int = 0
    failures: int = 0
    last_forwarded_at: Optional[float] = None
    last_upstream_status: Optional[int] = None
    last_error: Optional[str] = None


@dataclass
class Webhook:
    name: str
    path: str
    target: str
    github_hmac_secret: Optional[str] = None
    timeout: int = 15
    # When True (default) the upstream's response body + status is returned
    # to the caller — useful because GitHub logs the response body on its
    # deliveries page for debugging. Set False to return a minimal 200
    # instead, which hides any upstream-revealing detail.
    return_response: bool = True
    # Admin runtime toggle. When False, incoming deliveries are silently
    # acknowledged with 200 and NOT forwarded. Persisted across restarts so
    # a restart doesn't re-enable something an admin deliberately disabled.
    enabled: bool = True
    stats: WebhookStats = field(default_factory=WebhookStats)


class WebhookRegistry:
    def __init__(self, configs: list[dict], state_path: Optional[Path] = None):
        self._webhooks: list[Webhook] = []
        seen_paths: set[str] = set()
        seen_names: set[str] = set()
        for c in configs or []:
            path = c["path"]
            name = c["name"]
            if path in seen_paths:
                raise ValueError(f"duplicate webhook path (name={name!r})")
            if name in seen_names:
                raise ValueError(f"duplicate webhook name={name!r}")
            seen_paths.add(path)
            seen_names.add(name)
            self._webhooks.append(Webhook(
                name=name,
                path=path,
                target=c["target"],
                github_hmac_secret=c.get("github_hmac_secret") or None,
                timeout=int(c.get("timeout", 15)),
                return_response=bool(c.get("return_response", True)),
            ))
        self._lock = threading.Lock()
        self._state_path = state_path
        self._load_state()

    # --- runtime enable/disable (persisted) -----------------------------

    def _load_state(self) -> None:
        if not self._state_path or not self._state_path.exists():
            return
        try:
            data = json.loads(self._state_path.read_text())
        except Exception as e:
            log.warning("could not load %s: %s", self._state_path, e)
            return
        if not isinstance(data, dict):
            return
        for wh in self._webhooks:
            entry = data.get(wh.name)
            if isinstance(entry, dict) and "enabled" in entry:
                wh.enabled = bool(entry["enabled"])

    def _save_state(self) -> None:
        if not self._state_path:
            return
        data = {wh.name: {"enabled": wh.enabled} for wh in self._webhooks}
        tmp = self._state_path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(data, indent=2))
            tmp.replace(self._state_path)
        except OSError as e:
            log.warning("could not save %s: %s", self._state_path, e)

    def set_enabled(self, name: str, enabled: bool) -> bool:
        with self._lock:
            for wh in self._webhooks:
                if wh.name == name:
                    wh.enabled = enabled
                    self._save_state()
                    return True
        return False

    def find(self, path: str) -> Optional[Webhook]:
        """Constant-time match of `path` against every configured webhook
        path. Compares against all entries unconditionally to avoid leaking
        which specific paths are valid via response timing."""
        match: Optional[Webhook] = None
        for wh in self._webhooks:
            # hmac.compare_digest is only constant-time for same-length
            # inputs, so guard the length check explicitly.
            if len(wh.path) == len(path) and hmac.compare_digest(wh.path, path):
                match = wh
        return match

    def all(self) -> list[Webhook]:
        return list(self._webhooks)

    def record_success(self, wh: Webhook, status: int) -> None:
        with self._lock:
            wh.stats.total += 1
            wh.stats.successes += 1
            wh.stats.last_forwarded_at = time.time()
            wh.stats.last_upstream_status = status
            wh.stats.last_error = None

    def record_failure(self, wh: Webhook, error: str, status: Optional[int] = None) -> None:
        with self._lock:
            wh.stats.total += 1
            wh.stats.failures += 1
            wh.stats.last_forwarded_at = time.time()
            wh.stats.last_upstream_status = status
            wh.stats.last_error = error


def verify_github_signature(header: Optional[str], body: bytes, secret: str) -> bool:
    """Verify GitHub's X-Hub-Signature-256 header. Returns False on any
    malformed input so callers can fail closed without special-casing."""
    if not header or not header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    # compare_digest resists timing attacks on the hex comparison.
    return hmac.compare_digest(header, expected)
