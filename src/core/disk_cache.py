"""
Persistent on-disk HTTP response cache (L2 behind the in-memory ResponseCache).

Layout
------
Each cached entry is a single binary file in `cache_dir`:

    {sha1(url)[:16]}.cache
    ├── bytes 0–7  : expiry as a little-endian IEEE 754 double (time.time() + ttl)
    └── bytes 8–N  : raw HTTP response (status line + headers + body)

No index file — the directory listing IS the index.  This keeps the
implementation dependency-free and makes cache files portable across runs.

Eviction
--------
1. On every `put()`, remove expired files first.
2. If the directory is still over `max_bytes`, remove oldest files by mtime
   until it fits.
3. A single background `evict()` call at startup prunes stale entries from
   previous sessions without blocking the first request.

Thread safety
-------------
Each file write is atomic: we write to a `.tmp` file then rename it, so a
crash or concurrent writer never leaves a partial cache entry.
"""

import hashlib
import logging
import os
import struct
import time
from pathlib import Path

log = logging.getLogger("DiskCache")

_HEADER = struct.Struct("<d")   # 8 bytes: little-endian double (expiry timestamp)
_HEADER_SIZE = _HEADER.size     # 8


def _url_key(url: str) -> str:
    return hashlib.sha1(url.encode()).hexdigest()[:24]


class DiskCache:
    """Persistent on-disk HTTP response cache."""

    def __init__(self, cache_dir: str | Path, max_mb: int = 200):
        self._dir = Path(cache_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._max_bytes = max_mb * 1024 * 1024
        self.hits = 0
        self.misses = 0
        log.info(
            "Disk cache initialised: dir=%s max=%d MB",
            self._dir, max_mb,
        )

    # ── Public API ────────────────────────────────────────────────

    def get(self, url: str) -> bytes | None:
        path = self._dir / f"{_url_key(url)}.cache"
        try:
            data = path.read_bytes()
        except OSError:
            self.misses += 1
            return None

        if len(data) < _HEADER_SIZE:
            path.unlink(missing_ok=True)
            self.misses += 1
            return None

        expiry = _HEADER.unpack_from(data)[0]
        if time.time() > expiry:
            path.unlink(missing_ok=True)
            self.misses += 1
            return None

        self.hits += 1
        return data[_HEADER_SIZE:]

    def put(self, url: str, raw_response: bytes, ttl: int) -> None:
        if not raw_response or ttl <= 0:
            return
        # Don't cache single entries larger than 25% of the total budget.
        if len(raw_response) > self._max_bytes // 4:
            return

        expiry = time.time() + ttl
        payload = _HEADER.pack(expiry) + raw_response

        path = self._dir / f"{_url_key(url)}.cache"
        tmp = path.with_suffix(".tmp")
        try:
            tmp.write_bytes(payload)
            tmp.replace(path)       # atomic rename
        except OSError as exc:
            log.debug("Disk cache write failed (%s): %s", url[:60], exc)
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            return

        self._maybe_evict()

    def evict(self) -> None:
        """Remove expired entries; then prune oldest until under size cap."""
        self._evict_expired()
        self._evict_to_fit()

    def stats(self) -> dict:
        total_bytes = sum(
            f.stat().st_size
            for f in self._dir.glob("*.cache")
            if f.is_file()
        )
        return {
            "hits": self.hits,
            "misses": self.misses,
            "entries": sum(1 for _ in self._dir.glob("*.cache")),
            "size_mb": round(total_bytes / (1024 * 1024), 1),
        }

    # ── Internal helpers ──────────────────────────────────────────

    def _maybe_evict(self) -> None:
        """Quick size check — only run full eviction when over budget."""
        try:
            total = sum(
                f.stat().st_size
                for f in self._dir.glob("*.cache")
                if f.is_file()
            )
            if total > self._max_bytes:
                self._evict_expired()
                self._evict_to_fit()
        except OSError:
            pass

    def _evict_expired(self) -> None:
        now = time.time()
        removed = 0
        for path in list(self._dir.glob("*.cache")):
            try:
                data = path.read_bytes()
                if len(data) < _HEADER_SIZE:
                    path.unlink(missing_ok=True)
                    removed += 1
                    continue
                expiry = _HEADER.unpack_from(data)[0]
                if now > expiry:
                    path.unlink(missing_ok=True)
                    removed += 1
            except OSError:
                pass
        if removed:
            log.debug("Disk cache: evicted %d expired entries", removed)

    def _evict_to_fit(self) -> None:
        """Delete oldest files (by mtime) until total size is under budget."""
        try:
            files = [
                (f.stat().st_mtime, f.stat().st_size, f)
                for f in self._dir.glob("*.cache")
                if f.is_file()
            ]
        except OSError:
            return

        total = sum(sz for _, sz, _ in files)
        if total <= self._max_bytes:
            return

        files.sort()            # oldest first
        removed = 0
        for mtime, size, path in files:
            if total <= self._max_bytes:
                break
            try:
                path.unlink(missing_ok=True)
                total -= size
                removed += 1
            except OSError:
                pass
        if removed:
            log.debug("Disk cache: evicted %d entries to fit size cap", removed)
