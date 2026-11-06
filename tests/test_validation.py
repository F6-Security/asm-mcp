# Copyright 2026 F6 JSC
# SPDX-License-Identifier: Apache-2.0

"""Argument checks: nothing malformed reaches a URL or a request body."""

import unittest

from asm_mcp import params
from support import COMPANY, App, Recorder, json_response

asm = App()


def refused(test: unittest.TestCase, tool: str, needle: str, **arguments):
    recorder = Recorder(json_response(200, {}))
    with asm.install(recorder):
        result = asm.call(tool, **arguments)
    test.assertTrue(result.is_error, result.content[0].text)
    test.assertIn(needle, result.content[0].text)
    test.assertEqual(recorder.requests, [], "a refused call must not reach the network")


class TestIds(unittest.TestCase):
    def test_issue_id_must_be_an_alert_hash(self):
        for bad in ("../../../v2/companies", "x" * 32, "abc", "0" * 31 + "/", "0" * 33):
            with self.subTest(issue_id=bad):
                refused(self, "asm_get_issue_evidence", "32-hex-digit", issue_id=bad)

    def test_company_id_is_one_plain_segment(self):
        for bad in ("../companies", "a/b", "a%2Fb", "", " ", "a b"):
            with self.subTest(company_id=bad):
                refused(self, "asm_get_assets", "company_id", company_id=bad)

    def test_seq_update_shape(self):
        self.assertEqual(params.check_seq_update("1700000000000_0a1b2c3d"), "1700000000000_0a1b2c3d")
        self.assertEqual(params.check_seq_update(12.0), "12")
        self.assertIsNone(params.check_seq_update(""))
        for bad in ("abc", "-1", "1_x y", -1, True):
            with self.subTest(seq_update=bad), self.assertRaises(ValueError):
                params.check_seq_update(bad)


class TestFilters(unittest.TestCase):
    def test_choice_lists_are_case_insensitive_and_deduplicated(self):
        check = params.choice_list("status", ("detected", "under review"))
        self.assertEqual(check(["Detected", "detected", "UNDER REVIEW"]), ["detected", "under review"])

    def test_unknown_choice_is_named(self):
        refused(self, "asm_get_issues", "'urgent' is not one of", company_id=COMPANY, severity=["urgent"])

    def test_single_string_becomes_a_list(self):
        self.assertEqual(params.text_list("asset")("a.example"), ["a.example"])

    def test_control_characters_and_long_values_are_refused(self):
        refused(self, "asm_get_issues", "printable", company_id=COMPANY, asset=["a\nb"])
        refused(self, "asm_get_issues", "printable", company_id=COMPANY, asset=["a" * 300])

    def test_ports_and_limits(self):
        refused(self, "asm_get_issues", "port must be <= 65535", company_id=COMPANY, port=[70000])
        refused(self, "asm_get_issues", "max_items must be <= 5000", company_id=COMPANY, max_items=10_000)
        refused(self, "asm_get_assets", "page_size must be a whole number", company_id=COMPANY, page_size=10.5)

    def test_fields_are_names(self):
        refused(self, "asm_get_assets", "fields entries", company_id=COMPANY, fields=["__class__()"])

    def test_missing_required_argument(self):
        refused(self, "asm_get_assets", "company_id is required")


class TestRequestRoutes(unittest.TestCase):
    def test_allowed_routes_resolve(self):
        route, path, sent = params.resolve_route("get", f"/api/v2/reports/{COMPANY}/last/", {})
        self.assertEqual((route.template, path, sent), ("reports/{company_id}/last", f"reports/{COMPANY}/last", {}))
        route, path, _ = params.resolve_route("GET", "companies/logs", {"dateFrom": "2026-01-01"})
        self.assertEqual(route.template, "companies/logs")

    def test_write_endpoints_are_refused(self):
        for method, path in (
            ("POST", "issues/status/change"), ("POST", "assets/remove/domain"), ("POST", "companies/create"),
            ("POST", "issues/comments/add"), ("POST", "users/create"), ("GET", "get_token"),
            ("POST", "assets/updated"), ("GET", "internal/x"),
        ):
            with self.subTest(path=path):
                refused(self, "asm_request", "not a read-only endpoint", method=method, path=path)

    def test_placeholders_cannot_take_endpoint_names_or_traversal(self):
        refused(self, "asm_request", "endpoint name", path="companies/create")
        refused(self, "asm_request", "plain segments", path="companies/../users/create")
        refused(self, "asm_request", "plain segments", path="companies/%2e%2e")
        refused(self, "asm_request", "32-hex-digit", path="issues/evidence/abc")

    def test_leaks_get_a_default_status_list(self):
        _, _, sent = params.resolve_route(
            "POST", "issues/leaks", {"companyId": [COMPANY], "dateFrom": "2026-10-01", "dateTo": "2026-11-01"}
        )
        self.assertEqual(sent["status"], ["detected", "under review", "solved", "ignored", "false positive"])
        _, _, sent = params.resolve_route(
            "POST", "issues/leaks",
            {"companyId": [COMPANY], "dateFrom": "2026-10-01", "dateTo": "2026-11-01", "status": ["detected"]},
        )
        self.assertEqual(sent["status"], ["detected"])

    def test_only_documented_params_pass(self):
        refused(self, "asm_request", "does not take", path="users/logs", params={"userId": "x"})
        refused(self, "asm_request", "requires companyId", method="POST", path="dashboard/scores", params={})
        refused(self, "asm_request", "YYYY-MM-DD", path="users/logs", params={"dateFrom": "yesterday"})


if __name__ == "__main__":
    unittest.main()
