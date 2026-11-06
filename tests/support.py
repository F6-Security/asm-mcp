# Copyright 2026 F6 JSC
# SPDX-License-Identifier: Apache-2.0

"""Shared helpers for the test modules: the server state under a controlled
environment, a recording mock network, and a fake ASM API with the real one's quirks."""

import asyncio
import contextlib
import json
import os
import sys
from types import SimpleNamespace
from typing import Any

import httpx

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from asm_mcp import server  # noqa: E402 - needs the path above
from asm_mcp.settings import Settings  # noqa: E402

BASE_URL = "https://asm.example.com"
BASE_ENV = {"ASM_BASE_URL": BASE_URL, "ASM_API_TOKEN": "test-token", "ASM_MIN_INTERVAL": "0"}
COMPANY = "3f2b6c1e-0000-4a5b-8c9d-0123456789ab"


def settings(**env: str) -> Settings:
    return Settings.from_env({**BASE_ENV, **env})


class App:
    """The server's state with the network replaced by whichever handler is installed."""

    def __init__(self, **env: str):
        self.settings = settings(**env)
        self.handler = None
        self.state = server.app_state(self.settings, transport=httpx.MockTransport(self._handle))

    async def _handle(self, request: httpx.Request) -> httpx.Response:
        if self.handler is None:
            raise AssertionError(f"unexpected request: {request.method} {request.url}")
        result = self.handler(request)
        if asyncio.iscoroutine(result):
            result = await result
        return result

    @contextlib.contextmanager
    def install(self, handler):
        self.handler = handler
        try:
            yield handler
        finally:
            self.handler = None

    async def acall(self, name: str, **arguments: Any):
        params = server.types.CallToolRequestParams(name=name, arguments=arguments)
        return await server.on_call_tool(SimpleNamespace(lifespan_context=self.state), params)

    def call(self, name: str, **arguments: Any):
        return asyncio.run(self.acall(name, **arguments))


def parse(result) -> tuple[list[str], Any]:
    """(notes, payload) of a successful tool result."""
    text = result.content[0].text
    assert not result.is_error, text
    notes, _, body = text.rpartition("\n\n") if text.startswith("Note: ") else ("", "", text)
    return [line[len("Note: "):] for line in notes.splitlines()], json.loads(body)


class Recorder:
    """Records requests and plays back canned responses (the last one repeats)."""

    def __init__(self, *responses: httpx.Response, handler=None):
        self.responses = list(responses)
        self.handler = handler
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request):
        self.requests.append(request)
        if self.handler is not None:
            return self.handler(request)
        return self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]


def json_response(status: int, payload: Any, **headers: str) -> httpx.Response:
    return httpx.Response(
        status, content=json.dumps(payload).encode(), headers={"content-type": "application/json", **headers}
    )


# --------------------------------------------------------------------------- fake ASM

SEV = {"Crit": "Critical severity", "Error": "High severity", "Warning": "Medium severity", "Low": "Low severity"}


def make_assets(n: int = 1300) -> list[dict]:
    out = []
    for i in range(n):
        kind = ["domain", "ip", "software", "ip_range", "ssl"][i % 5]
        out.append({
            "id": f"a{i:05d}", "asset": f"h{i % 450}.ex.com" if kind != "ip" else f"10.0.{i // 250}.{i % 250}",
            "type": kind, "status": ["confirmed", "new", "false"][i % 3],
            "hasIssues": ["clean", "clean", "Critical severity", "Low severity"][i % 4],
            "seqUpdate": f"{1000000 + i}_a{i}", "companyName": "F6", "companyId": COMPANY,
            "domainInfo": {"whois": "x" * 40},
        })
    return out


def make_issues(n: int = 800) -> list[dict]:
    out = []
    for i in range(n):
        sev = ["Crit", "Error", "Warning", "Low"][i % 4]
        out.append({
            "alertHash": f"{i:032x}", "alertStatus": ["Detected", "Under review", "Solved", "Ignored"][i % 4],
            "alertSeverity": sev, "testName": f"T{i % 7}", "seqUpdate": f"{2000000 + i}_i{i}",
            "companyName": "F6", "companyId": COMPANY,
            "alertBody": {"asset": f"h{i % 450}.ex.com", "status": SEV[sev], "category": "Vulnerabilities",
                          "valuetype": "domain", "description": "long text", "path": [{"name": "x"}],
                          "cve": {"cve": f"CVE-2024-{i % 5}", "baseScore": 7.5, "description": "d"}
                          if i % 7 == 0 else {}},
        })
    return out


class FakeASM:
    """/assets/updated and /issues/updated with the quirks of the real API:

    * asset pages over `timeout_over` records time out (heavy domains);
    * the issue status filter leaks every 50th record of another status;
    * a status filter with count < 10 answers an empty page with seqUpdate null;
    * issue pages over `refuse_over` records get 400 "Failed to get paged issues";
    * asset pages come wrapped in a list, as the swagger documents;
    * `delay` seconds per request, to exercise the tool budget.
    """

    def __init__(self, assets=None, issues=None, *, delay: float = 0.0, timeout_over: int = 400,
                 refuse_over: int = 10_000):
        self.assets = make_assets() if assets is None else assets
        self.issues = make_issues() if issues is None else issues
        self.delay = delay
        self.timeout_over = timeout_over
        self.refuse_over = refuse_over
        self.requests: list[tuple[str, dict]] = []

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        if self.delay:
            await asyncio.sleep(self.delay)
        assert request.headers["authorization"] == "Bearer test-token"
        body = json.loads(request.content or b"{}")
        self.requests.append((request.url.path, body))
        cursor, count = body.get("seqUpdate"), body.get("count", 100)

        def key(cursor_value: str) -> int:
            return int(cursor_value.split("_")[0])

        if request.url.path.endswith("/assets/updated"):
            if count > self.timeout_over:
                raise httpx.ReadTimeout("slow", request=request)
            rows = [a for a in self.assets if (not cursor or key(a["seqUpdate"]) > key(cursor))
                    and (not body.get("type") or a["type"] in body["type"])
                    and (not body.get("status") or a["status"] in body["status"])]
            page = rows[:count]
            return json_response(200, [{"companyName": "F6", "items": page,
                                        "seqUpdate": page[-1]["seqUpdate"] if page else None}])
        if request.url.path.endswith("/issues/updated"):
            if count > self.refuse_over:
                return json_response(400, {"error": "Failed to get paged issues"})
            if body.get("status") and count < 10:
                return json_response(200, {"companyName": "F6", "items": [], "seqUpdate": None})
            want = {s.lower() for s in body.get("status", [])}
            rows = [x for x in self.issues if (not cursor or key(x["seqUpdate"]) > key(cursor))
                    and (not want or x["alertStatus"].lower() in want or int(x["alertHash"], 16) % 50 == 2)]
            page = rows[:count]
            return json_response(200, {"companyName": "F6", "items": page,
                                       "seqUpdate": page[-1]["seqUpdate"] if page else None})
        return json_response(200, {"path": request.url.path})
