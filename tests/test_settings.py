# Copyright 2026 F6 JSC
# SPDX-License-Identifier: Apache-2.0

"""Environment validation: a bad value stops the server at startup."""

import os
import tempfile
import unittest

from asm_mcp.settings import Settings, SettingsError
from support import BASE_ENV


def load(**env):
    return Settings.from_env({**BASE_ENV, **env})


class TestBaseUrl(unittest.TestCase):
    def test_api_root_suffix_is_accepted(self):
        self.assertEqual(load(ASM_BASE_URL="https://asm.example.com/api/v2/").base_url, "https://asm.example.com")

    def test_unset_is_allowed_and_empty(self):
        self.assertEqual(Settings.from_env({}).base_url, "")

    def test_refused_values(self):
        for value, message in (
            ("http://asm.example.com", "https://"),
            ("asm.example.com", "https://"),
            ("https://", "host"),
            ("https://user:pw@asm.example.com", "credentials"),
            ("https://asm.example.com/?x=1", "query"),
        ):
            with self.subTest(value=value), self.assertRaisesRegex(SettingsError, message):
                load(ASM_BASE_URL=value)


class TestSecrets(unittest.TestCase):
    def test_token_and_proxy_stay_out_of_repr(self):
        text = repr(load(ASM_API_TOKEN="s3cret-token", ASM_PROXY="http://u:pw@proxy.local:3128"))
        self.assertNotIn("s3cret", text)
        self.assertNotIn("pw@", text)

    def test_proxy_display_hides_credentials(self):
        self.assertEqual(load(ASM_PROXY="http://u:pw@proxy.local:3128").proxy_display, "proxy.local:3128")


class TestTls(unittest.TestCase):
    def test_there_is_no_switch_to_turn_verification_off(self):
        self.assertIs(load(ASM_VERIFY_SSL="false").verify, True)

    def test_missing_ca_bundle_is_refused(self):
        with self.assertRaisesRegex(SettingsError, "ASM_CA_BUNDLE is not a file"):
            load(ASM_CA_BUNDLE="/nonexistent.pem")

    def test_unloadable_ca_bundle_is_refused(self):
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as handle:
            handle.write("not a certificate")
        try:
            with self.assertRaisesRegex(SettingsError, "could not be loaded"):
                load(ASM_CA_BUNDLE=handle.name)
        finally:
            os.unlink(handle.name)


class TestNumbers(unittest.TestCase):
    def test_defaults(self):
        s = Settings.from_env({})
        self.assertEqual((s.timeout, s.min_interval, s.retries, s.tool_budget, s.summary_ttl), (60, 1.05, 3, 40, 600))

    def test_bad_numbers(self):
        for name, value in (("ASM_TIMEOUT", "fast"), ("ASM_TIMEOUT", "0"), ("ASM_RETRIES", "1.5"),
                            ("ASM_MIN_INTERVAL", "-1")):
            with self.subTest(name=name, value=value), self.assertRaises(SettingsError):
                load(**{name: value})

    def test_bad_proxy(self):
        with self.assertRaisesRegex(SettingsError, "ASM_PROXY"):
            load(ASM_PROXY="socks5://proxy:1080")


if __name__ == "__main__":
    unittest.main()
