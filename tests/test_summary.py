# Copyright 2026 F6 JSC
# SPDX-License-Identifier: Apache-2.0

"""Summaries: inline when the company is small, finished in the background when not."""

import asyncio
import unittest

from asm_mcp import summary
from support import COMPANY, App, FakeASM, parse

OPEN = ("Detected", "Under review")


def expected_assets(fake: FakeASM, statuses=("confirmed", "new")):
    return [a for a in fake.assets if a["status"] in statuses]


class TestInline(unittest.TestCase):
    def test_assets_default_to_the_perimeter(self):
        app, fake = App(), FakeASM()
        with app.install(fake):
            _, result = parse(app.call("asm_assets_summary", company_id=COMPANY))
        own = expected_assets(fake)
        self.assertTrue(result["complete"])
        self.assertEqual(result["total"], len(own))
        self.assertEqual(set(result["byStatus"]), {"confirmed", "new"})
        self.assertEqual(result["withIssues"], sum(a["hasIssues"] != "clean" for a in own))
        self.assertNotIn("job_id", result)

    def test_issues_default_to_open_and_count_the_leak(self):
        app, fake = App(), FakeASM()
        with app.install(fake):
            _, result = parse(app.call("asm_issues_summary", company_id=COMPANY))
        self.assertEqual(result["total"], sum(x["alertStatus"] in OPEN for x in fake.issues))
        self.assertEqual(set(result["byStatus"]), set(OPEN))
        self.assertGreater(result["droppedByFilter"], 0)
        self.assertTrue(result["topCVE"])

    def test_issue_summary_survives_refused_pages(self):
        app, fake = App(), FakeASM(refuse_over=300)
        with app.install(fake):
            _, result = parse(app.call("asm_issues_summary", company_id=COMPANY))
        self.assertTrue(result["complete"])
        self.assertEqual(result["total"], sum(x["alertStatus"] in OPEN for x in fake.issues))

    def test_a_failed_job_is_reported_and_rerun(self):
        async def scenario():
            app = App()
            body = {"companyId": COMPANY, "status": ["confirmed", "new"]}
            key = app.state.jobs.key("assets", body)
            job = summary.Job(id="s9", key=key, agg=summary.Aggregator("assets"), state="error",
                              error="boom", finished=0.0)
            app.state.jobs.jobs[job.id] = job
            with app.install(FakeASM()):
                notes, result = parse(await app.acall("asm_assets_summary", company_id=COMPANY))
            self.assertTrue(any("s9" in n and "boom" in n for n in notes))
            self.assertTrue(result["complete"])
            self.assertNotIn("s9", app.state.jobs.jobs)

        asyncio.run(scenario())

    def test_explicit_status_list_widens_the_scope(self):
        app, fake = App(), FakeASM()
        with app.install(fake):
            _, result = parse(app.call("asm_assets_summary", company_id=COMPANY,
                                       status=["confirmed", "new", "false"]))
        self.assertEqual(result["total"], len(fake.assets))


class TestBackground(unittest.TestCase):
    def test_partial_then_progress_then_full_result(self):
        async def scenario():
            app, fake = App(ASM_TOOL_BUDGET="0.25"), FakeASM(delay=0.03)
            with app.install(fake):
                notes, first = parse(await app.acall("asm_assets_summary", company_id=COMPANY))
                self.assertFalse(first["complete"])
                self.assertEqual(first["reason"], "time_budget")
                self.assertTrue(first["job_id"])
                self.assertTrue(any("do not present" in n for n in notes))

                _, second = parse(await app.acall("asm_assets_summary", company_id=COMPANY))
                if not second["complete"]:
                    self.assertEqual(second["job_id"], first["job_id"])  # no second job

                for _ in range(200):
                    notes, last = parse(await app.acall("asm_assets_summary", company_id=COMPANY))
                    if last["complete"]:
                        break
                    await asyncio.sleep(0.05)
                self.assertTrue(last["complete"])
                self.assertEqual(last["total"], len(expected_assets(fake)))
                self.assertTrue(any("background job" in n for n in notes))
                self.assertEqual(len(app.state.jobs.jobs), 1)
                await app.state.jobs.shutdown()

        asyncio.run(scenario())

    def test_running_jobs_are_capped(self):
        async def scenario():
            app = App(ASM_TOOL_BUDGET="0.1")
            with app.install(FakeASM(delay=0.05)):
                ids = []
                for kind in ("domain", "ip", "ssl"):
                    notes, r = parse(await app.acall("asm_assets_summary", company_id=COMPANY, type=[kind]))
                    ids.append(r.get("job_id"))
                self.assertEqual(sum(1 for i in ids if i), summary.MAX_RUNNING)
                self.assertTrue(any("already running" in n for n in notes))
                await app.state.jobs.shutdown()

        asyncio.run(scenario())

    def test_old_finished_jobs_are_forgotten(self):
        async def scenario():
            app = App()
            jobs = app.state.jobs
            with app.install(FakeASM(assets=[], issues=[])):
                for i in range(summary.MAX_JOBS + 5):
                    agg = summary.Aggregator("assets")
                    job = jobs.start(f"k{i}", agg, {"companyId": COMPANY}, None, False)
                    await job.task
            self.assertLessEqual(len(jobs.jobs), summary.MAX_JOBS)

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
