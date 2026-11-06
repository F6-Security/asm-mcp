# Copyright 2026 F6 JSC
# SPDX-License-Identifier: Apache-2.0

"""Checks on tool arguments before they shape a URL, a query string or a request body.

Every value that ends up in a path is one plain segment of a known shape: the
API sits behind a reverse proxy that normalises `..` and decodes `%2F`, so a
free-form id would let a call address a different endpoint with the same token.
"""

import re
from datetime import datetime
from typing import Any

from asm_mcp.catalog import LITERAL_SEGMENTS, ROUTES, Route

# Company, client and report ids are UUIDs in practice; the swagger example
# ("0000aaa00-bbbbb11111-22c") is looser, so the check is the shape, not UUID.
_ID = re.compile(r"[0-9A-Za-z][0-9A-Za-z_-]{0,63}")
# Issue ids (alertHash) are MD5 hex; the server refuses anything over 32 chars.
_ISSUE_ID = re.compile(r"[0-9A-Fa-f]{32}")
# seqUpdate as the API hands it out: "1700000000000_0a1b2c3d..." or plain digits.
_SEQ_UPDATE = re.compile(r"\d{1,20}(_[0-9A-Za-z]{1,64})?")
_FIELD = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}(\.[A-Za-z_][A-Za-z0-9_]{0,63}){0,3}")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

MAX_LIST_ITEMS = 200
MAX_TEXT_CHARS = 256
MAX_FIELDS = 40


def as_int(name: str, value: Any, *, minimum: int, maximum: int | None = None) -> int | None:
    """Coerce a JSON number to int; 10.0 passes, 10.5 and "10" do not."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be an integer, got {value!r}")
    if isinstance(value, float) and not value.is_integer():
        raise ValueError(f"{name} must be a whole number, got {value!r}")
    number = int(value)
    if number < minimum:
        raise ValueError(f"{name} must be >= {minimum}, got {number}")
    if maximum is not None and number > maximum:
        raise ValueError(f"{name} must be <= {maximum}, got {number}")
    return number


def check_id(value: Any, name: str) -> str:
    """A company / client / report id: one plain path segment."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} is required")
    text = value.strip()
    if not _ID.fullmatch(text):
        raise ValueError(
            f"{name} must be an id like 3f2b6c1e-0000-4a5b-8c9d-0123456789ab "
            f"(letters, digits, '-', '_'), got {value!r}"
        )
    return text


def check_issue_id(value: Any) -> str:
    if not isinstance(value, str) or not _ISSUE_ID.fullmatch(value.strip()):
        raise ValueError(f"issue_id must be the 32-hex-digit alertHash of an issue, got {value!r}")
    return value.strip().lower()


def check_seq_update(value: Any) -> str | None:
    """The resume cursor: omitted, empty, a non-negative integer or the string the API returned."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(as_int("seq_update", value, minimum=0))
    if isinstance(value, str) and _SEQ_UPDATE.fullmatch(value.strip()):
        return value.strip()
    raise ValueError(
        f"seq_update must be the seqUpdate value from a previous response "
        f"(e.g. 1700000000000_0a1b2c3d...), got {value!r}"
    )


def check_text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} entries must be non-empty strings, got {value!r}")
    text = value.strip()
    if len(text) > MAX_TEXT_CHARS or _CONTROL.search(text):
        raise ValueError(f"{name} entries must be at most {MAX_TEXT_CHARS} printable characters")
    return text


def text_list(name: str):
    """A filter list of strings; a single string is taken as a list of one."""

    def check(value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list):
            raise ValueError(f"{name} must be a list of strings")
        if len(value) > MAX_LIST_ITEMS:
            raise ValueError(f"{name} takes at most {MAX_LIST_ITEMS} entries, got {len(value)}")
        return list(dict.fromkeys(check_text(item, name) for item in value))

    return check


def choice_list(name: str, allowed: tuple[str, ...]):
    """A filter list of documented values, matched case-insensitively."""
    lookup = {a.lower(): a for a in allowed}

    def check(value: Any) -> list[str]:
        out = []
        for item in text_list(name)(value):
            if item.lower() not in lookup:
                raise ValueError(f"{name}: {item!r} is not one of {', '.join(allowed)}")
            out.append(lookup[item.lower()])
        return list(dict.fromkeys(out))

    return check


def check_ports(value: Any) -> list[int]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > MAX_LIST_ITEMS:
        raise ValueError(f"port must be a list of at most {MAX_LIST_ITEMS} port numbers")
    return list(dict.fromkeys(as_int("port", item, minimum=1, maximum=65535) for item in value))


def check_fields(value: Any) -> list[str]:
    """Projection paths such as alertBody.asset."""
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > MAX_FIELDS:
        raise ValueError(f"fields must be a list of at most {MAX_FIELDS} field names")
    out = []
    for item in value:
        if not isinstance(item, str) or not _FIELD.fullmatch(item.strip()):
            raise ValueError(f"fields entries are field names or dotted paths like alertBody.asset, got {item!r}")
        out.append(item.strip())
    return list(dict.fromkeys(out))


def check_date(value: Any, name: str) -> str | None:
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    if isinstance(value, str):
        try:
            datetime.strptime(value.strip(), "%Y-%m-%d")
            return value.strip()
        except ValueError:
            pass
    raise ValueError(f"{name} must be YYYY-MM-DD, got {value!r}")


# --------------------------------------------------------------------------- asm_request


def _scalar(key: str, value: Any) -> Any:
    if isinstance(value, bool) or isinstance(value, (str, int, float)):
        if isinstance(value, str) and (len(value) > MAX_TEXT_CHARS or _CONTROL.search(value)):
            raise ValueError(f"params.{key} must be at most {MAX_TEXT_CHARS} printable characters")
        return value
    if isinstance(value, list) and len(value) <= MAX_LIST_ITEMS and all(
        isinstance(v, (str, int, float)) and not isinstance(v, bool) for v in value
    ):
        return [_scalar(key, v) for v in value]
    raise ValueError(f"params.{key} must be a string, a number or a list of those, got {value!r}")


def _placeholder(name: str, value: str) -> str:
    if value in LITERAL_SEGMENTS:
        raise ValueError(f"{name} must be an id, got the endpoint name {value!r}")
    return check_issue_id(value) if name == "issue_id" else check_id(value, name)


def resolve_route(method: Any, path: Any, params: Any) -> tuple[Route, str, dict[str, Any]]:
    """Match an asm_request call against the read-only route list.

    Returns the route, the path to send (placeholders checked) and the params.
    Anything not on the list — every endpoint that creates, updates, removes or
    changes a status — is refused before a request is made.
    """
    method = (method or "GET").upper() if isinstance(method, str) else method
    if method not in ("GET", "POST"):
        raise ValueError("method must be GET or POST")
    if not isinstance(path, str) or not path.strip():
        raise ValueError("path is required")
    text = path.strip().strip("/")
    if text.startswith("api/v2/"):
        text = text[len("api/v2/"):]
    if "?" in text or "#" in text:
        raise ValueError("put query parameters in params, not in path")
    segments = text.split("/")
    if any(not s or s in (".", "..") or "%" in s or "\\" in s or _CONTROL.search(s) for s in segments):
        raise ValueError(f"path must be plain segments separated by '/', without percent-encoding, got {path!r}")

    chosen: tuple[Route, list[str]] | None = None
    # Literal-only templates first, so "companies/logs" never reads as a company id.
    for route in sorted(ROUTES, key=lambda r: r.template.count("{")):
        if route.method != method or len(route.segments) != len(segments):
            continue
        if all(t.startswith("{") or t == s for t, s in zip(route.segments, segments, strict=True)):
            chosen = (route, segments)
            break
    if chosen is None:
        allowed = "; ".join(f"{r.method} {r.template}" for r in ROUTES)
        raise ValueError(
            f"{method} {text} is not a read-only endpoint this tool may call. Allowed: {allowed}. "
            "Assets and issues have their own tools."
        )
    route, segments = chosen
    resolved = [
        _placeholder(t[1:-1], s) if t.startswith("{") else s for t, s in zip(route.segments, segments, strict=True)
    ]

    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise ValueError("params must be an object")
    unknown = sorted(set(params) - set(route.params))
    if unknown:
        accepted = ", ".join(route.params) or "none"
        raise ValueError(f"{route.method} {route.template} does not take {', '.join(unknown)}; accepted: {accepted}")
    clean = {k: _scalar(k, v) for k, v in params.items() if v is not None}
    for key in ("dateFrom", "dateTo"):
        if key in clean:
            clean[key] = check_date(clean[key], f"params.{key}")
    for key, value in route.defaults:
        clean.setdefault(key, value)
    missing = [k for k in route.required if k not in clean]
    if missing:
        raise ValueError(f"{route.method} {route.template} requires {', '.join(missing)}")
    return route, "/".join(resolved), clean
