# Copyright 2026 F6 JSC
# SPDX-License-Identifier: Apache-2.0

"""The HTTP client: requests to the ASM API with a Bearer token, throttling,
retries and the checks that keep an unexpected body out of the model's context."""

import asyncio
from typing import Any

import httpx

from asm_mcp.settings import (
    API_ROOT,
    MAX_ERROR_CHARS,
    MAX_RESULT_BYTES,
    RETRY_STATUSES,
    USER_AGENT,
    Settings,
)


class BudgetExceeded(Exception):
    """The caller's deadline would pass before the next request or retry could finish.
    Pages already received stay valid; the caller returns them with a resume cursor."""


class APIError(RuntimeError):
    """A non-2xx answer from ASM, with the status kept for callers that branch on it."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


class RequestTimeout(RuntimeError):
    """One request outlived ASM_TIMEOUT. Paging reacts by halving the page:
    heavy /assets/updated pages of domains are the usual cause."""


# Closes the hints of the statuses where the request never got a real answer,
# so that the model does not report "nothing found".
NOT_FETCHED = " — nothing was read, so report this data as unchecked, not as empty"

# Built from the server code (middlewares.try_handle_client_api, RateLimitDecorator,
# checker_api_limit, the request validators), so a failing call says what to fix
# instead of echoing a code.
STATUS_HINTS: dict[int, str] = {
    400: (
        "bad request — the body below names what the server rejected; fix that argument "
        "(asm_describe lists the accepted values and params)"
    ),
    401: "ASM_API_TOKEN is missing, wrong or revoked — issue a new API token in ASM",
    403: (
        "either this token has no access to the company (check company_id against "
        "asm_list_companies), a partner account called a client-only endpoint, or the API "
        "request quota of the account is used up (\"Your API request limit has been reached\")"
    ),
    404: "no such record or endpoint on this ASM installation",
    422: "ASM failed to build the answer (\"An error has occurred\"), retry later" + NOT_FETCHED,
    429: (
        "rate limited — one request per second per token (0.1 s for paid clients); lower the "
        "pace with ASM_MIN_INTERVAL"
    ),
    500: "server-side error on the ASM side, retry in a few minutes" + NOT_FETCHED,
    502: "ASM is unavailable behind its proxy, retry in a few minutes" + NOT_FETCHED,
    503: "ASM is temporarily unavailable, retry in a few minutes" + NOT_FETCHED,
    504: "ASM did not answer in time — lower page_size so it has less to process" + NOT_FETCHED,
}


class Throttle:
    """Keeps requests at most one per min_interval seconds.

    The ASM limit is per token across all endpoints, so there is one interval
    for the whole process. The lock is held across the wait to serialise callers;
    a deadline that the wait would overrun raises BudgetExceeded instead.
    """

    def __init__(self, min_interval: float) -> None:
        self._min_interval = min_interval
        self._lock = asyncio.Lock()
        self._last_start: float | None = None

    async def acquire(self, deadline: float | None = None) -> None:
        if self._min_interval <= 0:
            return
        async with self._lock:
            loop = asyncio.get_running_loop()
            wait = 0.0
            if self._last_start is not None:
                wait = max(0.0, self._min_interval - (loop.time() - self._last_start))
            if deadline is not None and loop.time() + wait >= deadline:
                raise BudgetExceeded()
            if wait:
                await asyncio.sleep(wait)
            self._last_start = loop.time()


class ASMClient:
    """The ASM API as this process sees it: one connection pool and one throttle
    for the server's whole lifetime, so calls reuse open connections and share
    the rate limit.

    trust_env=False keeps HTTP_PROXY and SSL_CERT_FILE out of the picture: the
    proxy is ASM_PROXY, the CA is ASM_CA_BUNDLE, both stated. follow_redirects
    stays off on purpose: a redirect would carry the token to wherever it points.
    A transport, when given, replaces the network entirely (tests), so the
    proxy and TLS settings do not apply to it.
    """

    def __init__(self, settings: Settings, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._settings = settings
        self._throttle = Throttle(settings.min_interval)
        network: dict[str, Any] = (
            {"verify": settings.verify, "proxy": settings.proxy}
            if transport is None
            else {"transport": transport}
        )
        self._http = httpx.AsyncClient(
            timeout=settings.timeout, follow_redirects=False, trust_env=False, **network
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
        deadline: float | None = None,
        max_bytes: int = MAX_RESULT_BYTES,
    ) -> Any:
        """One API call. `path` is relative to /api/v2 and built by the caller
        from constants and checked segments only (params.py)."""
        settings = self._settings
        if not settings.base_url or not settings.api_token:
            raise RuntimeError(
                "ASM_BASE_URL and ASM_API_TOKEN environment variables must be set "
                "(the address of your ASM installation and an API token)"
            )
        url = f"{settings.base_url}{API_ROOT}/{path.lstrip('/')}"
        headers = {
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
            "Authorization": f"Bearer {settings.api_token}",
        }
        query = {k: v for k, v in (params or {}).items() if v is not None}
        loop = asyncio.get_running_loop()
        timeout = settings.timeout

        try:
            for attempt in range(settings.retries + 1):
                await self._throttle.acquire(deadline)
                timeout = settings.timeout
                if deadline is not None:
                    remaining = deadline - loop.time()
                    if remaining <= 0.1:
                        raise BudgetExceeded()
                    # A request cut short by the budget is a budget stop, not a slow page.
                    timeout = min(timeout, remaining)
                response = await self._http.request(
                    method, url, params=query, json=body, headers=headers, timeout=timeout
                )
                if response.status_code not in RETRY_STATUSES or attempt == settings.retries:
                    break
                retry_after = (response.headers.get("Retry-After") or "").strip()
                delay = (
                    float(retry_after)
                    if retry_after.replace(".", "", 1).isdigit()
                    else max(settings.min_interval, 0.5) * (2**attempt)
                )
                if deadline is not None and loop.time() + delay >= deadline:
                    raise BudgetExceeded()
                await asyncio.sleep(delay)
        except httpx.TimeoutException as error:
            # Cut short by the caller's budget, with no time left: a budget stop, not a slow page.
            if timeout < settings.timeout and deadline is not None and deadline - loop.time() <= 0.5:
                raise BudgetExceeded() from error
            raise RequestTimeout(
                f"ASM did not answer {method} {path} within {settings.timeout:.0f} s "
                "(ASM_TIMEOUT) — lower page_size or narrow the filters" + NOT_FETCHED
            ) from error
        except httpx.HTTPError as error:
            # Transport failures can carry an empty message, so name the class and
            # the URL, and say how the proxy comes into play. Values of the ambient
            # variables are never echoed: they can carry a password.
            detail = str(error) or type(error).__name__
            if settings.proxy:
                hint = f" Requests go through ASM_PROXY ({settings.proxy_display})."
            elif settings.ambient_proxy:
                hint = " HTTP(S)_PROXY is ignored; set ASM_PROXY to route through a proxy."
            else:
                hint = ""
            raise RuntimeError(f"Network error contacting {url}: {detail}.{hint}") from error

        return _parse(response, path, max_bytes)


def _parse(response: httpx.Response, path: str, max_bytes: int) -> Any:
    """The JSON body of a successful answer, or an error that says what went wrong."""
    if response.is_redirect:
        location = response.headers.get("Location", "")
        raise RuntimeError(
            f"API error {response.status_code} (redirect to {location or 'unknown'}): not followed, "
            "because it would carry the token elsewhere — check ASM_BASE_URL (scheme, host, a "
            "trailing path) and whether a login proxy sits in front of the API"
        )

    if not response.is_success:
        parts = [f"API error {response.status_code} {response.reason_phrase}".rstrip()]
        if hint := STATUS_HINTS.get(response.status_code, ""):
            parts.append(hint)
        # Only echo a JSON error body, and only a bounded slice of it: an HTML
        # error page can carry tracebacks, settings and upstream names.
        if _is_json(response) and (text := response.text.strip()):
            parts.append(text[:MAX_ERROR_CHARS])
        raise APIError(response.status_code, " — ".join(parts))

    if len(response.content) > max_bytes:
        raise RuntimeError(
            f"response is {len(response.content)} bytes, over the {max_bytes} byte limit "
            "— narrow the request"
        )
    if not response.content:
        return {"status": response.status_code, "body": None}
    # Decided by the body, not the header. An HTML page or a binary file does
    # not parse, so neither reaches the model.
    try:
        return response.json()
    except ValueError as error:
        content_type = response.headers.get("content-type", "unknown")
        raise RuntimeError(
            f"expected JSON from {path}, got an unparsable body (content-type '{content_type}')"
        ) from error


def _is_json(response: httpx.Response) -> bool:
    return response.headers.get("content-type", "").split(";")[0].strip() == "application/json"
