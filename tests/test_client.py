# Copyright 2026 F6 JSC
# SPDX-License-Identifier: Apache-2.0

"""What leaves the process and what comes back, through a mock transport."""

import asyncio
import unittest
from unittest import mock

import httpx

from asm_mcp import client, server, settings
from support import BASE_URL, COMPANY, App, Recorder, json_response, parse

asm = App(ASM_RETRIES="1")


def request(app: App, recorder, method="GET", path="companies", **kwargs):
    with app.install(recorder):
        return asyncio.run(app.state.client.request(method, path, **kwargs))


class TestRequestShape(unittest.TestCase):
    def test_bearer_user_agent_and_api_root(self):
        recorder = Recorder(json_response(200, {"ok": True}))
        self.assertEqual(request(asm, recorder, params={"a": 1, "b": None}), {"ok": True})
        sent = recorder.requests[0]
        self.assertEqual(str(sent.url), f"{BASE_URL}/api/v2/companies?a=1")
        self.assertEqual(sent.headers["authorization"], "Bearer test-token")
        self.assertEqual(sent.headers["user-agent"], settings.USER_AGENT)

    def test_missing_settings_fail_before_any_request(self):
        for env in ({"ASM_API_TOKEN": ""}, {"ASM_BASE_URL": ""}):
            recorder = Recorder(json_response(200, {}))
            with self.subTest(env=env), self.assertRaisesRegex(RuntimeError, "ASM_BASE_URL and ASM_API_TOKEN"):
                request(App(**env), recorder)
            self.assertEqual(recorder.requests, [])


class TestResponses(unittest.TestCase):
    def test_redirect_is_not_followed(self):
        recorder = Recorder(httpx.Response(302, headers={"location": "https://evil.example/login"}))
        with self.assertRaisesRegex(RuntimeError, "not followed"):
            request(asm, recorder)
        self.assertEqual(len(recorder.requests), 1)

    def test_json_error_body_is_echoed_bounded_with_a_hint(self):
        recorder = Recorder(json_response(403, {"error": "x" * 2000}))
        with self.assertRaises(client.APIError) as caught:
            request(asm, recorder)
        message = str(caught.exception)
        self.assertEqual(caught.exception.status, 403)
        self.assertIn(client.STATUS_HINTS[403], message)
        self.assertLess(len(message), len(client.STATUS_HINTS[403]) + settings.MAX_ERROR_CHARS + 50)

    def test_html_error_body_is_not_echoed(self):
        html = httpx.Response(500, content=b"<html>Traceback</html>", headers={"content-type": "text/html"})
        recorder = Recorder(html)
        with self.assertRaises(client.APIError) as caught:
            request(asm, recorder)
        self.assertNotIn("Traceback", str(caught.exception))

    def test_oversized_and_non_json_responses_are_refused(self):
        with self.assertRaisesRegex(RuntimeError, "byte limit"):
            request(asm, Recorder(json_response(200, {"x": "y" * settings.MAX_RESULT_BYTES})))
        with self.assertRaisesRegex(RuntimeError, "unparsable body"):
            pdf = httpx.Response(200, content=b"%PDF-1.4", headers={"content-type": "application/pdf"})
            request(asm, Recorder(pdf))

    def test_retry_honours_retry_after_then_gives_up(self):
        recorder = Recorder(json_response(429, {"error": "Too many API calls per second"}, **{"retry-after": "0"}))
        with self.assertRaises(client.APIError) as caught:
            request(asm, recorder)
        self.assertEqual(caught.exception.status, 429)
        self.assertEqual(len(recorder.requests), asm.settings.retries + 1)

    def test_422_is_not_retried(self):
        recorder = Recorder(json_response(422, {"error": "An error has occurred. Please, try it again."}))
        with self.assertRaises(client.APIError):
            request(asm, recorder)
        self.assertEqual(len(recorder.requests), 1)

    def test_timeout_and_network_errors_say_what_happened(self):
        def slow(req):
            raise httpx.ReadTimeout("", request=req)

        with self.assertRaisesRegex(client.RequestTimeout, "ASM_TIMEOUT"):
            request(asm, Recorder(handler=slow))

        def boom(req):
            raise httpx.ConnectError("")

        with self.assertRaisesRegex(RuntimeError, f"Network error contacting {BASE_URL}/api/v2/companies"):
            request(asm, Recorder(handler=boom))

    def test_proxy_credentials_stay_out_of_errors(self):
        def boom(req):
            raise httpx.ConnectError("refused")

        with self.assertRaises(RuntimeError) as caught:
            request(App(ASM_PROXY="http://puser:psecret@proxy.local:3128"), Recorder(handler=boom))
        self.assertIn("ASM_PROXY (proxy.local:3128)", str(caught.exception))
        self.assertNotIn("psecret", str(caught.exception))


class TestThrottle(unittest.TestCase):
    def test_requests_are_spaced(self):
        async def scenario():
            throttle = client.Throttle(0.05)
            loop = asyncio.get_running_loop()
            start = loop.time()
            for _ in range(3):
                await throttle.acquire()
            return loop.time() - start

        self.assertGreaterEqual(asyncio.run(scenario()), 0.09)

    def test_a_wait_past_the_deadline_is_not_taken(self):
        async def scenario():
            throttle = client.Throttle(5)
            await throttle.acquire()
            await throttle.acquire(asyncio.get_running_loop().time() + 1)

        with self.assertRaises(client.BudgetExceeded):
            asyncio.run(scenario())


class TestToolsOnTheWire(unittest.TestCase):
    def test_evidence_path(self):
        recorder = Recorder(json_response(200, {"count": 1, "items": [{"header": "x"}]}))
        with asm.install(recorder):
            parse(asm.call("asm_get_issue_evidence", issue_id="A" * 32))
        self.assertEqual(recorder.requests[0].url.path, f"/api/v2/issues/evidence/{'a' * 32}")

    def test_request_get_and_post(self):
        recorder = Recorder(json_response(200, {"ok": 1}))
        with asm.install(recorder):
            parse(asm.call("asm_request", path=f"reports/{COMPANY}/last"))
            parse(asm.call("asm_request", method="POST", path="dashboard/scores",
                           params={"companyId": COMPANY, "dateFrom": "2026-10-01"}))
        get, post = recorder.requests
        self.assertEqual((get.method, get.url.path), ("GET", f"/api/v2/reports/{COMPANY}/last"))
        self.assertEqual((post.method, post.url.path), ("POST", "/api/v2/dashboard/scores"))
        self.assertIn(b'"companyId"', post.content)

    def test_error_text_is_bounded(self):
        with asm.install(Recorder(json_response(400, {"error": "x" * 5000}))):
            result = asm.call("asm_list_companies")
        self.assertTrue(result.is_error)
        self.assertLessEqual(len(result.content[0].text), settings.MAX_ERROR_TEXT_CHARS + len("Error: "))


class TestLifecycle(unittest.TestCase):
    def test_calls_share_one_http_client(self):
        with mock.patch.object(client.httpx, "AsyncClient", wraps=httpx.AsyncClient) as constructed:
            app = App()
            with app.install(Recorder(json_response(200, []))):
                for _ in range(3):
                    parse(app.call("asm_list_companies"))
        self.assertEqual(constructed.call_count, 1)

    def test_the_server_closes_its_client_when_it_stops(self):
        async def scenario():
            mcp_server = server.build_server(settings.Settings.from_env({}))
            async with mcp_server.lifespan(mcp_server) as state:
                http = state.client._http
                self.assertFalse(http.is_closed)
            return http

        self.assertTrue(asyncio.run(scenario()).is_closed)


if __name__ == "__main__":
    unittest.main()
