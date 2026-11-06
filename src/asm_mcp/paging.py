# Copyright 2026 F6 JSC
# SPDX-License-Identifier: Apache-2.0

"""Walking /assets/updated and /issues/updated by their seqUpdate cursor, and
shaping the records that come back for the model."""

import asyncio
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from typing import Any

from asm_mcp.catalog import SEVERITIES
from asm_mcp.client import APIError, ASMClient, BudgetExceeded, RequestTimeout
from asm_mcp.settings import MAX_PAGE_BYTES

ASSETS = "assets"
ISSUES = "issues"
PATHS = {ASSETS: "assets/updated", ISSUES: "issues/updated"}
KEYS = {ASSETS: "id", ISSUES: "alertHash"}

MIN_PAGE = 50  # adaptive paging never goes below this
MIN_FILTERED_PAGE = 100  # with server-side filters a small count returns an empty page

_BY_ALERT_SEVERITY = {api: label for api, label in SEVERITIES.values()}
_LABELS = {label for _, label in SEVERITIES.values()}


def issue_severity(item: dict) -> str:
    """Normalised severity label ('Critical severity', ...) of an issue record."""
    body = item.get("alertBody") if isinstance(item.get("alertBody"), dict) else {}
    label = body.get("status")
    if label in _LABELS:
        return label
    api = item.get("alertSeverity") or ""
    return _BY_ALERT_SEVERITY.get(api, api or "-")


def _page_too_big(error: APIError) -> bool:
    return error.status == 400 and "failed to get paged" in str(error).lower()


def cursor_of(item: dict) -> str | None:
    value = item.get("seqUpdate")
    return str(value) if value not in (None, "") else None


def _unwrap(data: Any) -> dict:
    """/assets/updated is documented as an array of pages; accept a page or a list of them."""
    if isinstance(data, dict):
        return data
    if isinstance(data, list):
        merged: dict = {"items": []}
        for part in data:
            if isinstance(part, dict):
                merged["items"].extend(part.get("items") or [])
                merged["companyName"] = part.get("companyName") or merged.get("companyName")
                merged["seqUpdate"] = part.get("seqUpdate") or merged.get("seqUpdate")
        return merged
    return {"items": []}


async def iter_pages(
    client: ASMClient,
    kind: str,
    body: dict,
    page_size: int,
    *,
    deadline: float | None = None,
    has_filters: bool = False,
) -> AsyncIterator[tuple[list[dict], str | None, str | None]]:
    """Yields (items, cursor_after_page, company_name) page by page.

    * the cursor is the seqUpdate of the last item, so resuming never skips items;
    * a page that times out is asked again at half the size, down to MIN_PAGE;
    * the walk ends on an empty page or when the cursor stops moving.
    Raises BudgetExceeded when the deadline is reached; pages already yielded stay valid.
    """
    body = dict(body)
    cursor = body.get("seqUpdate")
    size = max(MIN_FILTERED_PAGE if has_filters else 1, int(page_size))
    while True:
        body["count"] = size
        if cursor:
            body["seqUpdate"] = str(cursor)
        try:
            data = await client.request(
                "POST", PATHS[kind], body=body, deadline=deadline, max_bytes=MAX_PAGE_BYTES
            )
        except (RequestTimeout, APIError) as error:
            # Both mean "this page is too big for the server right now": a timeout on
            # heavy domain pages, or 400 "Failed to get paged issues" that the live API
            # answers for some large pages (seen at count 750+ on one company, data-dependent).
            if isinstance(error, APIError) and not _page_too_big(error):
                raise
            if size <= MIN_PAGE:
                raise
            size = max(MIN_PAGE, size // 2)
            continue
        page = _unwrap(data)
        items = [it for it in (page.get("items") or []) if isinstance(it, dict)]
        next_cursor = (cursor_of(items[-1]) if items else None) or page.get("seqUpdate")
        next_cursor = str(next_cursor) if next_cursor not in (None, "") else None
        yield items, next_cursor or cursor, page.get("companyName")
        if not items or not next_cursor or next_cursor == str(cursor):
            return
        cursor = next_cursor


@dataclass
class Collected:
    company_name: str | None = None
    items: list[dict] = field(default_factory=list)
    pages: int = 0
    dropped: int = 0
    reason: str | None = None  # None = walked to the end
    cursor: str | None = None  # safe resume point


async def collect(
    client: ASMClient,
    kind: str,
    body: dict,
    *,
    max_items: int,
    page_size: int,
    deadline: float | None,
    keep: Callable[[dict], bool] | None = None,
    has_filters: bool = False,
) -> Collected:
    """Up to max_items records that pass `keep`, stopping early at the deadline."""
    key = KEYS[kind]
    out = Collected(cursor=body.get("seqUpdate"))
    seen: set = set()
    try:
        async for items, page_cursor, name in iter_pages(
            client, kind, body, page_size, deadline=deadline, has_filters=has_filters
        ):
            out.pages += 1
            out.company_name = name or out.company_name
            for item in items:
                ident = item.get(key)
                if ident is not None:
                    if ident in seen:
                        continue
                    seen.add(ident)
                if keep is not None and not keep(item):
                    out.dropped += 1
                    continue
                out.items.append(item)
                if len(out.items) >= max_items:
                    out.reason = "max_items"
                    out.cursor = cursor_of(item) or page_cursor
                    return out
            out.cursor = page_cursor
    except BudgetExceeded:
        out.reason = "time_budget"
    except RequestTimeout as error:
        if not out.items:
            raise
        out.reason = f"timeout: {error}"
    return out


def deadline_in(seconds: float) -> float:
    return asyncio.get_running_loop().time() + seconds


# --------------------------------------------------------------------------- shaping

_EMPTY = (None, "", "-", [], {})
_ISSUE_DROP = ("companyId", "companyName", "clientName", "companyWebsite", "seqUpdate")
# path: the discovery graph; log/leaks: raw lists; description: long boilerplate.
_ISSUE_BODY_DROP = ("path", "log", "leaks", "gibContext", "description")
# domainInfo: whois and DNS history, most of an asset record's weight.
_ASSET_DROP = ("domainInfo", "path", "companyId", "companyName", "clientId", "companyWebsite", "seqUpdate")


def compact_issue(item: dict) -> dict:
    out = {k: v for k, v in item.items() if k not in _ISSUE_DROP and v not in _EMPTY}
    body = out.get("alertBody")
    if isinstance(body, dict):
        body = {k: v for k, v in body.items() if k not in _ISSUE_BODY_DROP and v not in _EMPTY}
        if isinstance(body.get("cve"), dict):
            body["cve"] = {k: v for k, v in body["cve"].items() if k != "description" and v not in _EMPTY}
        if isinstance(body.get("score"), dict):
            body["score"] = body["score"].get("score")
        out["alertBody"] = body
    if isinstance(out.get("alertMitreInfo"), dict):
        out["alertMitreInfo"] = sorted(out["alertMitreInfo"])
    if out.get("alertAdditionInfo") == {"Value": {}}:
        out.pop("alertAdditionInfo")
    return out


def compact_asset(item: dict) -> dict:
    return {k: v for k, v in item.items() if k not in _ASSET_DROP and v not in _EMPTY}


def project(item: dict, fields: list[str]) -> dict:
    """Only `fields`, dotted paths allowed (alertBody.asset)."""
    out: dict = {}
    for name in fields:
        value: Any = item
        for part in name.split("."):
            value = value.get(part) if isinstance(value, dict) else None
        if value is not None:
            out[name] = value
    return out
