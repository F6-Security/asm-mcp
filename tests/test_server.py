# Copyright 2026 F6 JSC
# SPDX-License-Identifier: Apache-2.0

"""The tool list, the local reference tool, and a real stdio handshake."""

import asyncio
import json
import os
import shutil
import subprocess
import threading
import unittest
from types import SimpleNamespace

from asm_mcp import __version__, catalog, server, settings
from support import App, parse

EXPECTED_TOOLS = [
    "asm_list_companies",
    "asm_get_assets",
    "asm_get_issues",
    "asm_get_issue_evidence",
    "asm_assets_summary",
    "asm_issues_summary",
    "asm_describe",
    "asm_request",
]

asm = App()


class TestToolList(unittest.TestCase):
    def test_lists_every_tool_once(self):
        result = asyncio.run(server.on_list_tools(SimpleNamespace(lifespan_context=asm.state), None))
        self.assertEqual([t.name for t in result.tools], EXPECTED_TOOLS)

    def test_every_tool_is_read_only(self):
        for tool in asm.state.tools:
            with self.subTest(tool=tool.name):
                self.assertTrue(tool.annotations.read_only_hint)
                self.assertFalse(tool.annotations.destructive_hint)

    def test_only_describe_is_local(self):
        self.assertEqual([t.name for t in asm.state.tools if not t.annotations.open_world_hint], ["asm_describe"])

    def test_schemas_have_no_nulls_or_titles(self):
        for tool in asm.state.tools:
            text = json.dumps(tool.input_schema)
            with self.subTest(tool=tool.name):
                self.assertNotIn('"null"', text)
                self.assertNotIn('"title"', text)

    def test_unknown_tool(self):
        result = asm.call("asm_delete_everything")
        self.assertTrue(result.is_error)


class TestVersion(unittest.TestCase):
    def test_user_agent_and_server_version_follow_the_package(self):
        self.assertEqual(settings.USER_AGENT, f"f6-asm-mcp/{__version__}")
        self.assertEqual(server.build_server(asm.settings).version, __version__)


class TestDescribe(unittest.TestCase):
    def test_sections(self):
        _, everything = parse(asm.call("asm_describe"))
        self.assertEqual(set(everything), {"assets", "issues", "requests", "limits"})
        _, routes = parse(asm.call("asm_describe", section="requests"))
        self.assertEqual(len(routes), len(catalog.ROUTES))
        self.assertEqual(everything["issues"]["severity"]["high"]["alertSeverity"], "Error")

    def test_routes_are_read_only(self):
        for route in catalog.ROUTES:
            with self.subTest(route=route.template):
                self.assertFalse({"create", "update", "add", "remove", "change"} & set(route.segments))


class TestStdio(unittest.TestCase):
    """The installed console script answers initialize and tools/list over stdio."""

    @unittest.skipUnless(shutil.which("asm-mcp"), "asm-mcp is not installed")
    def test_handshake(self):
        lines = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                        "clientInfo": {"name": "test", "version": "0"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        ]
        env = {**os.environ, "ASM_BASE_URL": "https://asm.invalid", "ASM_API_TOKEN": "placeholder"}
        # stdin stays open until both answers are in: on EOF the server stops at once.
        process = subprocess.Popen(  # noqa: S603 - fixed command
            [shutil.which("asm-mcp")], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, env=env,
        )
        timer = threading.Timer(30, process.kill)
        timer.start()
        answers: dict = {}
        try:
            for message in lines:
                process.stdin.write(json.dumps(message) + "\n")
                process.stdin.flush()
                if "id" in message:
                    while message["id"] not in answers:
                        line = process.stdout.readline()
                        if not line:
                            break
                        reply = json.loads(line)
                        if "id" in reply:
                            answers[reply["id"]] = reply
        finally:
            timer.cancel()
            process.stdin.close()
            process.wait(timeout=10)
            process.stdout.close()
        self.assertEqual(answers[1]["result"]["serverInfo"]["version"], __version__)
        self.assertEqual([t["name"] for t in answers[2]["result"]["tools"]], EXPECTED_TOOLS)

    @unittest.skipUnless(shutil.which("asm-mcp"), "asm-mcp is not installed")
    def test_bad_setting_stops_the_server(self):
        env = {**os.environ, "ASM_BASE_URL": "http://asm.invalid"}
        process = subprocess.run(  # noqa: S603 - fixed command
            [shutil.which("asm-mcp")], input="", capture_output=True, text=True, env=env, timeout=30,
        )
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("ASM_BASE_URL must use https://", process.stderr)


if __name__ == "__main__":
    unittest.main()
