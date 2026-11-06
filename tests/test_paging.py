# Copyright 2026 F6 JSC
# SPDX-License-Identifier: Apache-2.0

"""asm_get_assets / asm_get_issues against a fake API with the real one's quirks."""

import asyncio
import unittest

from asm_mcp import server
from asm_mcp.settings import MAX_RESULT_BYTES
from support import COMPANY, App, FakeASM, parse


def walk_all(app: App, tool: str, **arguments) -> tuple[list[dict], list[dict]]:
    """Call until complete; returns (all items, every answer)."""
    answers, items = [], []
    cursor = None
    for _ in range(100):
        args = dict(arguments, company_id=COMPANY)
        if cursor:
            args["seq_update"] = cursor
        _, answer = parse(app.call(tool, **args))
        answers.append(answer)
        items += answer["items"]
        if answer["complete"]:
            return items, answers
        cursor = answer["seqUpdate"]
    raise AssertionError("never completed")


class TestAssets(unittest.TestCase):
    def setUp(self):
        self.app, self.fake = App(), FakeASM()

    def test_resuming_never_skips_or_repeats(self):
        with self.app.install(self.fake):
            items, answers = walk_all(self.app, "asm_get_assets", type=["domain", "ip"],
                                      status=["confirmed", "new"], max_items=97, page_size=60)
        expected = [a["id"] for a in self.fake.assets
                    if a["type"] in ("domain", "ip") and a["status"] in ("confirmed", "new")]
        self.assertEqual([i["id"] for i in items], expected)
        self.assertEqual(answers[0]["reason"], "max_items")

    def test_heavy_pages_are_halved_until_they_pass(self):
        with self.app.install(self.fake):
            _, answer = parse(self.app.call("asm_get_assets", company_id=COMPANY, max_items=5000, page_size=2000))
        self.assertTrue(answer["complete"])
        self.assertEqual(answer["returned"], len(self.fake.assets))
        sizes = [body["count"] for _, body in self.fake.requests]
        self.assertEqual(sizes[:3], [2000, 1000, 500])
        self.assertTrue(all(s <= 400 for s in sizes[3:]))

    def test_compact_drops_heavy_fields_and_fields_projects(self):
        with self.app.install(self.fake):
            _, compact = parse(self.app.call("asm_get_assets", company_id=COMPANY, max_items=3))
            _, projected = parse(self.app.call("asm_get_assets", company_id=COMPANY, max_items=3,
                                               fields=["asset", "status"]))
        self.assertNotIn("domainInfo", compact["items"][0])
        self.assertNotIn("companyName", compact["items"][0])
        self.assertEqual(list(projected["items"][0]), ["asset", "status"])

    def test_no_status_filter_says_excluded_are_included(self):
        with self.app.install(self.fake):
            notes, _ = parse(self.app.call("asm_get_assets", company_id=COMPANY, max_items=1))
        self.assertTrue(any("excluded assets" in n for n in notes))

    def test_result_is_cut_at_the_size_limit_with_an_exact_cursor(self):
        big = [dict(a, tags=[{"k": "v" * 2000}]) for a in FakeASM().assets[:900]]
        fake = FakeASM(assets=big, timeout_over=10_000)
        with self.app.install(fake):
            items, answers = walk_all(self.app, "asm_get_assets", max_items=900, page_size=900)
        self.assertEqual(answers[0]["reason"], "size_limit")
        self.assertLess(len(str(answers[0]["items"])), MAX_RESULT_BYTES)
        self.assertEqual([i["id"] for i in items], [a["id"] for a in big])

    def test_time_budget_returns_partial_data(self):
        app = App(ASM_TOOL_BUDGET="0.3")
        with app.install(FakeASM(delay=0.1)):
            notes, answer = parse(app.call("asm_get_assets", company_id=COMPANY, max_items=5000, page_size=50))
        self.assertFalse(answer["complete"])
        self.assertEqual(answer["reason"], "time_budget")
        self.assertTrue(answer["seqUpdate"])
        self.assertTrue(any("Partial result" in n for n in notes))


class TestIssues(unittest.TestCase):
    def setUp(self):
        self.app, self.fake = App(), FakeASM()

    def test_status_is_rechecked_locally(self):
        with self.app.install(self.fake):
            items, answers = walk_all(self.app, "asm_get_issues", status=["detected"], max_items=5000)
        self.assertTrue(all(i["alertStatus"] == "Detected" for i in items))
        self.assertEqual(len(items), sum(x["alertStatus"] == "Detected" for x in self.fake.issues))
        self.assertGreater(sum(a["droppedByFilter"] for a in answers), 0)

    def test_refused_large_pages_are_halved(self):
        fake = FakeASM(refuse_over=300)
        with self.app.install(fake):
            items, _ = walk_all(self.app, "asm_get_issues", max_items=5000, page_size=1000)
        self.assertEqual(len(items), len(fake.issues))
        self.assertEqual([body["count"] for _, body in fake.requests][:3], [1000, 500, 250])

    def test_other_400s_are_not_retried(self):
        from support import Recorder, json_response

        recorder = Recorder(json_response(400, {"error": "Input should be a valid integer"}))
        with self.app.install(recorder):
            result = self.app.call("asm_get_issues", company_id=COMPANY, page_size=1000)
        self.assertTrue(result.is_error)
        self.assertEqual(len(recorder.requests), 1)

    def test_filtered_pages_never_ask_for_fewer_than_100(self):
        with self.app.install(self.fake):
            _, answer = parse(self.app.call("asm_get_issues", company_id=COMPANY, status=["detected"],
                                            max_items=3, page_size=3))
        self.assertEqual(answer["returned"], 3)
        self.assertTrue(all(body["count"] >= 100 for _, body in self.fake.requests))

    def test_severity_and_cve_reach_the_body(self):
        with self.app.install(self.fake):
            _, answer = parse(self.app.call("asm_get_issues", company_id=COMPANY, severity=["crit"],
                                            cve=["CVE-2024-1"], port=[22.0], max_items=5))
        body = self.fake.requests[0][1]
        self.assertEqual(body["severity"], ["crit"])
        self.assertEqual(body["cve_params"], {"cve": ["CVE-2024-1"]})
        self.assertEqual(body["port"], [22])
        self.assertTrue(all(i["alertSeverity"] == "Crit" for i in answer["items"]))

    def test_compact_issue(self):
        with self.app.install(self.fake):
            _, answer = parse(self.app.call("asm_get_issues", company_id=COMPANY, max_items=1))
        body = answer["items"][0]["alertBody"]
        self.assertNotIn("description", body)
        self.assertNotIn("path", body)
        self.assertNotIn("description", body["cve"])

    def test_empty_company_is_complete(self):
        with self.app.install(FakeASM(assets=[], issues=[])):
            _, answer = parse(self.app.call("asm_get_issues", company_id=COMPANY))
        self.assertTrue(answer["complete"])
        self.assertEqual(answer["items"], [])


class TestShapes(unittest.TestCase):
    def test_issue_severity_falls_back_to_alert_severity(self):
        from asm_mcp.paging import issue_severity

        self.assertEqual(issue_severity({"alertSeverity": "Error", "alertBody": {}}), "High severity")
        self.assertEqual(issue_severity({"alertBody": {"status": "Low severity"}}), "Low severity")

    def test_asset_pages_as_object_or_list(self):
        from asm_mcp.paging import _unwrap

        self.assertEqual(_unwrap({"items": [1]})["items"], [1])
        self.assertEqual(_unwrap([{"items": [1], "seqUpdate": "5"}, {"items": [2]}])["items"], [1, 2])
        self.assertEqual(_unwrap(None)["items"], [])


class TestDeadlineHelper(unittest.TestCase):
    def test_deadline_is_on_the_loop_clock(self):
        async def scenario():
            return server.deadline_in(5) - asyncio.get_running_loop().time()

        self.assertAlmostEqual(asyncio.run(scenario()), 5, delta=0.1)


if __name__ == "__main__":
    unittest.main()
