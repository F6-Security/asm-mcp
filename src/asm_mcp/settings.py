# Copyright 2026 F6 JSC
# SPDX-License-Identifier: Apache-2.0

"""Settings from the environment, read once and validated when the server starts,
so a bad value fails it on startup rather than on the first tool call."""

import os
import ssl
from collections.abc import Mapping
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from asm_mcp import __version__

API_ROOT = "/api/v2"

# What one tool result may put into the model's context.
MAX_RESULT_BYTES = 1024 * 1024
# What one raw API page may weigh. Pages of /assets/updated and /issues/updated
# are processed here (heavy fields dropped, items counted) and never forwarded
# whole, so they get a larger bound than a result; anything else is held to
# MAX_RESULT_BYTES because it goes to the model as is.
MAX_PAGE_BYTES = 32 * 1024 * 1024
# How much of an error body is echoed back: enough for the field name a 400
# carries, not enough for a traceback or a settings dump.
MAX_ERROR_CHARS = 512
# The whole error text a tool returns: a hint from STATUS_HINTS plus that body slice.
MAX_ERROR_TEXT_CHARS = 1500

# The server answers count > 5000 with 400 (AlertModel / AssetModel: conint(le=5000));
# pages that large also time out on domains, so tools stay well below.
MAX_PAGE_SIZE = 2000

RETRY_STATUSES = {429, 500, 502, 503, 504}
AMBIENT_PROXY_VARS = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy")

# explicit so the UA doesn't silently change with the httpx version
USER_AGENT = f"f6-asm-mcp/{__version__}"


class SettingsError(RuntimeError):
    """An environment value the server refuses to start with."""


def _env_number(
    environ: Mapping[str, str], name: str, default: float, *, minimum: float, integer: bool = False
) -> float:
    """A numeric setting from the environment, with a readable failure."""
    raw = environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw) if integer else float(raw)
    except ValueError:
        kind = "an integer" if integer else "a number"
        raise SettingsError(f"{name} must be {kind}, got {raw!r}") from None
    if value < minimum:
        raise SettingsError(f"{name} must be at least {minimum}, got {raw!r}")
    return value


def _validated_base_url(environ: Mapping[str, str]) -> str:
    """Reject a base URL that would send the API token somewhere unintended.

    There is no default: every ASM installation has its own address. An unset
    value is not a startup error; the tools answer with what to set.
    """
    raw = environ.get("ASM_BASE_URL", "").strip().rstrip("/")
    if not raw:
        return ""
    parts = urlsplit(raw)
    if parts.scheme != "https":
        raise SettingsError(f"ASM_BASE_URL must use https:// (got {parts.scheme or 'no'} scheme)")
    if not parts.hostname:
        raise SettingsError("ASM_BASE_URL must contain a host")
    if parts.username or parts.password:
        raise SettingsError("ASM_BASE_URL must not carry credentials; use ASM_API_TOKEN")
    if parts.query or parts.fragment:
        raise SettingsError("ASM_BASE_URL must not contain a query string or fragment")
    # The swagger spells the root out as https://host/api/v2; accept that too.
    if raw.endswith(API_ROOT):
        raw = raw[: -len(API_ROOT)]
    return raw


def _verification(environ: Mapping[str, str]) -> ssl.SSLContext | bool:
    """Build the TLS verification setting.

    trust_env=False means SSL_CERT_FILE and SSL_CERT_DIR are ignored, so an
    on-prem installation behind an internal CA needs a way in that is not
    verify=False — which deliberately does not exist.
    """
    bundle = environ.get("ASM_CA_BUNDLE", "").strip()
    if not bundle:
        return True
    if not os.path.isfile(bundle):
        raise SettingsError(f"ASM_CA_BUNDLE is not a file: {bundle}")
    try:
        return ssl.create_default_context(cafile=bundle)
    except ssl.SSLError as error:
        raise SettingsError(f"ASM_CA_BUNDLE could not be loaded: {error}") from error


def _proxy(environ: Mapping[str, str]) -> str | None:
    """An explicit proxy. HTTP_PROXY and friends are ignored on purpose: the
    request carries the API token, so where it goes is stated, not inherited."""
    raw = environ.get("ASM_PROXY", "").strip()
    if not raw:
        return None
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise SettingsError(f"ASM_PROXY must be an http:// or https:// URL, got {raw!r}")
    return raw


@dataclass(frozen=True)
class Settings:
    """Everything the server takes from the environment, read once at startup."""

    base_url: str
    # Kept out of repr: a settings object in a traceback must not show the
    # token or a proxy password.
    api_token: str = field(repr=False)
    timeout: float
    verify: ssl.SSLContext | bool
    proxy: str | None = field(repr=False)
    # The server allows one API request per second per token (0.1 s for paid
    # clients) across all endpoints, and answers 429 otherwise.
    min_interval: float
    retries: int
    # How long one tool call may page before it returns what it has with a
    # resume cursor; must stay under the MCP client's own call timeout.
    tool_budget: float
    # How long a finished background summary is reused.
    summary_ttl: float
    # Whether HTTP(S)_PROXY is set, so a network error can say it was ignored.
    # Only the fact: the values can carry a password.
    ambient_proxy: bool

    @property
    def proxy_display(self) -> str | None:
        """What error messages may say about the proxy: host and port, never user:pass@."""
        return urlsplit(self.proxy).netloc.rpartition("@")[2] if self.proxy else None

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "Settings":
        """Read and validate the ASM_* variables; raises SettingsError on a bad value.

        Missing ASM_BASE_URL/ASM_API_TOKEN is not an error here: the server
        still starts, and every tool call answers with what to set.
        """
        env = os.environ if environ is None else environ
        return cls(
            base_url=_validated_base_url(env),
            api_token=(env.get("ASM_API_TOKEN") or "").strip(),
            timeout=_env_number(env, "ASM_TIMEOUT", 60, minimum=1),
            verify=_verification(env),
            proxy=_proxy(env),
            min_interval=_env_number(env, "ASM_MIN_INTERVAL", 1.05, minimum=0),
            retries=int(_env_number(env, "ASM_RETRIES", 3, minimum=0, integer=True)),
            tool_budget=_env_number(env, "ASM_TOOL_BUDGET", 40, minimum=0),
            summary_ttl=_env_number(env, "ASM_SUMMARY_TTL", 600, minimum=0),
            ambient_proxy=any(env.get(var) for var in AMBIENT_PROXY_VARS),
        )
