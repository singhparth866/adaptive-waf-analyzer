"""
Async HTTP dispatcher — thin wrapper around httpx.AsyncClient.
Provides a semaphore-gated, rate-limited GET with exponential-backoff retry.
Used as an async context manager; scanner.py delegates all HTTP through this.
"""
from __future__ import annotations

import asyncio
import time
from typing import Optional

import httpx

from core.config import Config
from utils.headers import base_headers, ua_cycle
from utils.logger  import get_logger

log = get_logger(__name__)


class Dispatcher:
    """
    Async context manager that owns an httpx.AsyncClient for the duration
    of a scan.  All requests go through ``get()`` which enforces:

    * Semaphore-based concurrency cap (``config.concurrency``)
    * Token-bucket rate limiting  (``config.rate_limit`` req/s, 0 = off)
    * Exponential-backoff retry   (``config.max_retries`` attempts)
    * Per-request User-Agent rotation
    """

    def __init__(self, config: Config) -> None:
        self._cfg     = config
        self._sem     = asyncio.Semaphore(config.concurrency)
        self._ua      = ua_cycle()
        self._client: Optional[httpx.AsyncClient] = None
        self._last_ts  = 0.0          # for rate-gate

    # ── Context manager ───────────────────────────────────────────────────────

    async def __aenter__(self) -> "Dispatcher":
        proxies = {"all://": self._cfg.proxy} if self._cfg.proxy else None
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self._cfg.timeout),
            follow_redirects=True,
            verify=self._cfg.verify_ssl,
            proxies=proxies,
            http2=True,
        )
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *args) -> None:
        if self._client:
            await self._client.__aexit__(*args)
            self._client = None

    # ── Public API ────────────────────────────────────────────────────────────

    async def get(
        self,
        url: str,
        extra_headers: Optional[dict[str, str]] = None,
    ) -> tuple[httpx.Response, float]:
        """
        Perform a GET request; return (response, elapsed_seconds).
        Raises the last exception after all retry attempts are exhausted.
        """
        assert self._client is not None, "Use Dispatcher inside `async with` block"

        last_exc: Exception = RuntimeError("no attempts made")

        for attempt in range(1, self._cfg.max_retries + 1):
            async with self._sem:
                await self._rate_gate()
                hdrs = base_headers(next(self._ua))
                hdrs.update(self._cfg.extra_headers)
                if extra_headers:
                    hdrs.update(extra_headers)
                try:
                    t0      = time.perf_counter()
                    resp    = await self._client.get(url, headers=hdrs)
                    elapsed = time.perf_counter() - t0
                    log.debug(
                        f"[cyan]{resp.status_code}[/cyan] {url[:80]} "
                        f"[dim]({elapsed*1000:.0f}ms)[/dim]"
                    )
                    return resp, elapsed
                except (httpx.TimeoutException, httpx.ConnectError) as exc:
                    last_exc = exc
                    wait = 0.5 * (2 ** (attempt - 1))   # 0.5s, 1s, 2s …
                    log.warning(
                        f"Attempt {attempt}/{self._cfg.max_retries} failed "
                        f"({exc!r}) — retrying in {wait:.1f}s"
                    )
                    if attempt < self._cfg.max_retries:
                        await asyncio.sleep(wait)

        raise last_exc

    # ── Private ───────────────────────────────────────────────────────────────

    async def _rate_gate(self) -> None:
        """Sleep until the next token is available (token-bucket, 1 token = 1 req)."""
        if self._cfg.rate_limit <= 0:
            return
        interval = 1.0 / self._cfg.rate_limit
        wait = (self._last_ts + interval) - time.perf_counter()
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_ts = time.perf_counter()
