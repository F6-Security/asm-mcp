# Copyright 2026 F6 JSC
# SPDX-License-Identifier: Apache-2.0

"""Counts over every asset or issue of a company, without the records themselves.

A large company (10 000+ assets) takes minutes to page through at one request
per second, longer than an MCP client waits for a tool call. A summary therefore
runs inline until the tool budget is spent, then hands its running counts and
its cursor to a background task in this process and returns partial numbers
with a job id; a repeated call with the same arguments returns the progress and,
once done, the full result. Jobs live in memory only: no files, nothing kept
after the server stops.
"""

import asyncio
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from asm_mcp.client import ASMClient, BudgetExceeded
from asm_mcp.paging import ASSETS, ISSUES, KEYS, issue_severity, iter_pages

MAX_JOBS = 32  # finished jobs beyond this are forgotten, oldest first
MAX_RUNNING = 2  # each running job holds the shared rate limit
MAX_RECORDS = 500_000  # a job stops counting here and says so
# 500: larger issue pages are refused by the live API at times ("Failed to get paged
# issues"); iter_pages would halve them anyway, at the cost of a wasted request.
PAGE_SIZE = 500


def _top(counter: Counter, n: int = 20) -> dict:
    return dict(counter.most_common(n))


class Aggregator:
    """Running counts for one kind of record; holds ids, never the records."""

    def __init__(self, kind: str, keep=None) -> None:
        self.kind = kind
        self.keep = keep
        self.company_name: str | None = None
        self.seen: set = set()
        self.total = 0
        self.dropped = 0
        self.pages = 0
        self.c: dict[str, Counter] = defaultdict(Counter)
        self.by_type_level: dict[str, Counter] = defaultdict(Counter)

    def add_page(self, items: list[dict], company_name: str | None) -> None:
        self.pages += 1
        self.company_name = company_name or self.company_name
        key = KEYS[self.kind]
        for item in items:
            ident = item.get(key)
            if ident is not None:
                if ident in self.seen:
                    continue
                self.seen.add(ident)
            if self.keep is not None and not self.keep(item):
                self.dropped += 1
                continue
            self.total += 1
            (self._asset if self.kind == ASSETS else self._issue)(item)

    def _asset(self, item: dict) -> None:
        kind = item.get("type") or "-"
        level = item.get("hasIssues") or "clean"
        self.c["byType"][kind] += 1
        self.c["byStatus"][item.get("status") or "-"] += 1
        self.c["byIssueLevel"][level] += 1
        self.by_type_level[kind][level] += 1

    def _issue(self, item: dict) -> None:
        body = item.get("alertBody") if isinstance(item.get("alertBody"), dict) else {}
        cve = body.get("cve") if isinstance(body.get("cve"), dict) else {}
        extra = item.get("alertAdditionInfo") if isinstance(item.get("alertAdditionInfo"), dict) else {}
        self.c["bySeverity"][issue_severity(item)] += 1
        self.c["byStatus"][item.get("alertStatus") or "-"] += 1
        self.c["byAssetType"][body.get("valuetype") or "-"] += 1
        self.c["byCategory"][body.get("category") or "-"] += 1
        self.c["byTestName"][item.get("testName") or "-"] += 1
        self.c["topAssets"][body.get("asset") or body.get("value") or "-"] += 1
        if name := cve.get("cve") or extra.get("CVE"):
            self.c["topCVE"][str(name)] += 1

    def result(self) -> dict:
        out: dict[str, Any] = {"companyName": self.company_name, "total": self.total}
        if self.kind == ASSETS:
            out.update({
                "byType": dict(self.c["byType"]),
                "byStatus": dict(self.c["byStatus"]),
                "byIssueLevel": dict(self.c["byIssueLevel"]),
                "withIssues": sum(n for level, n in self.c["byIssueLevel"].items() if level != "clean"),
                "byTypeAndIssueLevel": {t: dict(c) for t, c in self.by_type_level.items()},
            })
        else:
            out.update({
                "droppedByFilter": self.dropped,
                "bySeverity": dict(self.c["bySeverity"]),
                "byStatus": dict(self.c["byStatus"]),
                "byAssetType": dict(self.c["byAssetType"]),
                "byCategory": _top(self.c["byCategory"]),
                "byTestName": _top(self.c["byTestName"], 30),
                "topAssets": _top(self.c["topAssets"]),
                "topCVE": _top(self.c["topCVE"]),
            })
        return out


async def walk(client: ASMClient, agg: Aggregator, body: dict, *, deadline: float | None,
               has_filters: bool) -> tuple[str | None, str | None]:
    """Feed pages into `agg`. Returns (cursor, reason): reason None means the end was reached."""
    cursor = body.get("seqUpdate")
    try:
        async for items, page_cursor, name in iter_pages(
            client, agg.kind, body, PAGE_SIZE, deadline=deadline, has_filters=has_filters
        ):
            agg.add_page(items, name)
            cursor = page_cursor
            if agg.total + agg.dropped >= MAX_RECORDS:
                return cursor, "max_records"
    except BudgetExceeded:
        return cursor, "time_budget"
    return cursor, None


@dataclass
class Job:
    id: str
    key: str
    agg: Aggregator
    state: str = "running"  # running / done / error
    reason: str | None = None
    error: str | None = None
    started: float = 0.0
    finished: float | None = None
    task: asyncio.Task | None = field(default=None, repr=False)

    def progress(self) -> dict:
        return {"records": self.agg.total, "pages": self.agg.pages, "droppedByFilter": self.agg.dropped}


class SummaryJobs:
    """Background summaries of this process, keyed by kind + company + filters."""

    def __init__(self, client: ASMClient) -> None:
        self.client = client
        self.jobs: dict[str, Job] = {}
        self._next = 0

    @staticmethod
    def key(kind: str, body: dict) -> str:
        return kind + "?" + json.dumps(
            {k: sorted(v) if isinstance(v, list) else v for k, v in body.items()}, sort_keys=True
        )

    def find(self, key: str, ttl: float) -> Job | None:
        """A running job for the key, or one that finished less than ttl seconds ago."""
        now = asyncio.get_running_loop().time()
        best = None
        for job in self.jobs.values():
            if job.key != key or job.state == "error":
                continue
            if job.state == "running":
                return job
            if job.finished is not None and now - job.finished <= ttl:
                if best is None or job.finished > best.finished:
                    best = job
        return best

    def last_error(self, key: str) -> Job | None:
        """The most recent failed job for the key, so a rerun can say why it reran."""
        failed = [j for j in self.jobs.values() if j.key == key and j.state == "error"]
        return max(failed, key=lambda j: j.finished or 0, default=None)

    def running(self) -> int:
        return sum(job.state == "running" for job in self.jobs.values())

    def start(self, key: str, agg: Aggregator, body: dict, cursor: str | None, has_filters: bool) -> Job:
        self._forget_old()
        self._next += 1
        loop = asyncio.get_running_loop()
        job = Job(id=f"s{self._next}", key=key, agg=agg, started=loop.time())
        body = dict(body)
        if cursor:
            body["seqUpdate"] = cursor
        job.task = asyncio.create_task(self._run(job, body, has_filters))
        self.jobs[job.id] = job
        return job

    async def _run(self, job: Job, body: dict, has_filters: bool) -> None:
        try:
            _, job.reason = await walk(self.client, job.agg, body, deadline=None, has_filters=has_filters)
            job.state = "done"
        except asyncio.CancelledError:
            job.state, job.error = "error", "cancelled"
            raise
        except Exception as error:  # noqa: BLE001 - surfaced through the tool
            job.state, job.error = "error", str(error) or type(error).__name__
        finally:
            job.finished = asyncio.get_running_loop().time()

    def _forget_old(self) -> None:
        finished = sorted((j for j in self.jobs.values() if j.state != "running"), key=lambda j: j.finished or 0)
        while len(self.jobs) >= MAX_JOBS and finished:
            self.jobs.pop(finished.pop(0).id, None)

    async def shutdown(self) -> None:
        tasks = [job.task for job in self.jobs.values() if job.task and not job.task.done()]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


__all__ = ["ASSETS", "ISSUES", "Aggregator", "Job", "SummaryJobs", "walk"]
