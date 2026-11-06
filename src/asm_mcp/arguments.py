# Copyright 2026 F6 JSC
# SPDX-License-Identifier: Apache-2.0

"""Tool arguments as typed models: one model per tool both checks what the
caller sent and produces the tool's inputSchema, so the two cannot drift.

The checks themselves are the ones in params.py; the models only say which
check applies to which argument. Their messages name the argument and the
value, because the model reads them and has to fix the call.
"""

from collections.abc import Callable
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field, PlainValidator, ValidationError, WithJsonSchema
from pydantic.json_schema import GenerateJsonSchema, JsonSchemaValue

from asm_mcp.catalog import (
    ASSET_STATUSES,
    ASSET_TYPES,
    ISSUE_STATUSES,
    OPEN_ISSUE_STATUSES,
    PERIMETER_STATUSES,
    SEVERITIES,
    TEST_NAME_EXAMPLES,
)
from asm_mcp.params import (
    MAX_LIST_ITEMS,
    as_int,
    check_fields,
    check_id,
    check_issue_id,
    check_ports,
    check_seq_update,
    choice_list,
    text_list,
)
from asm_mcp.settings import MAX_PAGE_SIZE


def checked(kind: Any, check: Callable[[Any], Any], schema: JsonSchemaValue) -> Any:
    """An argument of type `kind` validated by one of the params.py checks and
    shown to the client as `schema`. The check alone decides what passes."""
    return Annotated[kind, PlainValidator(check), WithJsonSchema(schema)]


def _int(name: str, minimum: int, maximum: int) -> Any:
    return checked(int | None, lambda v: as_int(name, v, minimum=minimum, maximum=maximum), NUMBER)


def _choices(name: str, allowed: dict[str, Any]) -> Any:
    schema = {"type": "array", "items": {"type": "string", "enum": list(allowed)}}
    return checked(list[str], choice_list(name, tuple(allowed)), schema)


def _texts(name: str) -> Any:
    return checked(list[str], text_list(name), STRINGS)


def _issue_ids(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or len(value) > MAX_LIST_ITEMS:
        raise ValueError(f"issue_hash must be a list of at most {MAX_LIST_ITEMS} issue ids")
    return list(dict.fromkeys(check_issue_id(v) for v in value))


STRING = {"type": "string"}
NUMBER = {"type": "number"}
STRINGS = {"type": "array", "items": STRING}

CompanyId = checked(str, lambda v: check_id(v, "company_id"), STRING)
SeqUpdate = checked(str | None, check_seq_update, STRING)
Fields = checked(list[str], check_fields, STRINGS)

COMPANY_DESCRIPTION = "Company id from asm_list_companies (field id), e.g. 3f2b6c1e-0000-4a5b-8c9d-0123456789ab."
SEQ_DESCRIPTION = (
    "Resume cursor: the seqUpdate of a previous answer of this tool with the same filters. "
    "Omit to start from the oldest record. Saved after a full walk, it returns only what "
    "changed since."
)
PAGE_DESCRIPTION = (
    f"Records per API request, at most {MAX_PAGE_SIZE}. A page that times out is retried at "
    "half the size automatically."
)
COMPACT_DESCRIPTION = (
    "Default true: drop heavy and repeated fields (whois/DNS of domains, discovery graph, "
    "descriptions, company fields). false returns records as the API sent them."
)
SEVERITY_DESCRIPTION = (
    "crit / high / medium / low. In records they read as alertSeverity Crit / Error / Warning / "
    "Low and alertBody.status 'Critical severity' / 'High severity' / ..."
)


class Arguments(BaseModel):
    """Base of every tool's arguments. Unknown keys are ignored."""


class ListCompaniesArguments(Arguments):
    pass


class GetAssetsArguments(Arguments):
    company_id: CompanyId = Field(description=COMPANY_DESCRIPTION)
    seq_update: SeqUpdate = Field(None, description=SEQ_DESCRIPTION)
    max_items: _int("max_items", 1, 5000) = Field(
        None, description="Integer, 1-5000, default 500: stop after this many assets."
    )
    page_size: _int("page_size", 1, MAX_PAGE_SIZE) = Field(None, description=PAGE_DESCRIPTION)
    type: _choices("type", ASSET_TYPES) = Field(
        default_factory=list,
        description="Asset types; empty = all. Infrastructure = domain, ip, ip_range, ssl.",
    )
    status: _choices("status", ASSET_STATUSES) = Field(
        default_factory=list,
        description=(
            "Empty = all, including excluded assets ('false'). The company perimeter is "
            "['confirmed', 'new']."
        ),
    )
    asset: _texts("asset") = Field(default_factory=list, description="Exact asset values (domain, IP).")
    software: _texts("software") = Field(default_factory=list, description="Software names, e.g. nginx.")
    version: _texts("version") = Field(default_factory=list, description="Software versions.")
    compact: bool = Field(True, description=COMPACT_DESCRIPTION)
    fields: Fields = Field(
        default_factory=list,
        description="Return only these fields, e.g. ['asset', 'type', 'status', 'hasIssues', 'ports'].",
    )


class GetIssuesArguments(Arguments):
    company_id: CompanyId = Field(description=COMPANY_DESCRIPTION)
    seq_update: SeqUpdate = Field(None, description=SEQ_DESCRIPTION)
    max_items: _int("max_items", 1, 5000) = Field(
        None, description="Integer, 1-5000, default 200: stop after this many issues."
    )
    page_size: _int("page_size", 1, MAX_PAGE_SIZE) = Field(None, description=PAGE_DESCRIPTION)
    severity: _choices("severity", SEVERITIES) = Field(default_factory=list, description=SEVERITY_DESCRIPTION)
    status: _choices("status", ISSUE_STATUSES) = Field(
        default_factory=list,
        description=f"Empty = every status. Open issues = {list(OPEN_ISSUE_STATUSES)}.",
    )
    category: _texts("category") = Field(
        default_factory=list, description="e.g. Vulnerabilities, Network Security, DNS & Domains."
    )
    test_name: _texts("test_name") = Field(
        default_factory=list,
        description="Exact test names, e.g. " + ", ".join(repr(t) for t in TEST_NAME_EXAMPLES[:3]) + ".",
    )
    asset: _texts("asset") = Field(default_factory=list, description="Issues of these assets (domain, IP).")
    port: checked(list[int], check_ports, {"type": "array", "items": NUMBER}) = Field(
        default_factory=list, description="Ports, e.g. [22, 3389]."
    )
    issue_hash: checked(list[str], _issue_ids, STRINGS) = Field(
        default_factory=list, description="Specific issues by id (alertHash)."
    )
    cve: _texts("cve") = Field(default_factory=list, description="CVE ids, e.g. CVE-2024-6387.")
    sort_by_first_seen: bool | None = Field(None, description="Order by first detection instead of last update.")
    compact: bool = Field(True, description=COMPACT_DESCRIPTION)
    fields: Fields = Field(
        default_factory=list,
        description=(
            "Return only these fields, dotted paths allowed, e.g. ['alertHash', 'alertSeverity', "
            "'alertStatus', 'testName', 'alertBody.asset', 'alertBody.reason']."
        ),
    )


class IssueEvidenceArguments(Arguments):
    issue_id: checked(str, check_issue_id, STRING) = Field(description="Issue id (alertHash, 32 hex digits).")


class AssetsSummaryArguments(Arguments):
    company_id: CompanyId = Field(description=COMPANY_DESCRIPTION)
    type: _choices("type", ASSET_TYPES) = Field(default_factory=list, description="Empty = all types.")
    status: checked(list[str] | None, lambda v: None if v is None else choice_list("status", tuple(ASSET_STATUSES))(v),
                    {"type": "array", "items": {"type": "string", "enum": list(ASSET_STATUSES)}}) = Field(
        None,
        description=f"Default: the perimeter {list(PERIMETER_STATUSES)}. Pass all three to include excluded.",
    )


class IssuesSummaryArguments(Arguments):
    company_id: CompanyId = Field(description=COMPANY_DESCRIPTION)
    status: checked(list[str] | None, lambda v: None if v is None else choice_list("status", tuple(ISSUE_STATUSES))(v),
                    {"type": "array", "items": {"type": "string", "enum": list(ISSUE_STATUSES)}}) = Field(
        None, description=f"Default: open issues {list(OPEN_ISSUE_STATUSES)}. Pass every status for history."
    )
    severity: _choices("severity", SEVERITIES) = Field(default_factory=list, description=SEVERITY_DESCRIPTION)
    asset: _texts("asset") = Field(default_factory=list, description="Only issues of these assets.")


class DescribeArguments(Arguments):
    section: Literal["assets", "issues", "requests", "limits"] | None = Field(
        None, description="Optional: only this part of the reference."
    )


class RequestArguments(Arguments):
    method: Literal["GET", "POST"] = Field(
        "GET", description="GET for most routes; POST for dashboard/scores and issues/leaks."
    )
    path: str = Field(description="Path under /api/v2 without a leading slash, e.g. \"reports/<company_id>/last\".")
    params: dict[str, Any] = Field(
        default_factory=dict,
        description="Query parameters (GET) or JSON body (POST), only the keys the route accepts.",
    )


class _ToolSchema(GenerateJsonSchema):
    """inputSchema without anyOf-with-null, defaults or titles."""

    def nullable_schema(self, schema: Any) -> JsonSchemaValue:
        return self.generate_inner(schema["schema"])

    def default_schema(self, schema: Any) -> JsonSchemaValue:
        return self.generate_inner(schema["schema"])

    def field_title_should_be_set(self, schema: Any) -> bool:
        return False


def input_schema(model: type[Arguments]) -> dict[str, Any]:
    schema = model.model_json_schema(schema_generator=_ToolSchema)
    schema.pop("title", None)
    return schema


def describe_errors(error: ValidationError) -> str:
    """One line per bad argument, worded for the model that has to fix the call."""
    messages = []
    for item in error.errors(include_url=False):
        name = ".".join(str(part) for part in item["loc"])
        if item["type"] == "missing":
            messages.append(f"{name} is required")
        elif item["type"] == "value_error":
            messages.append(str(item["ctx"]["error"]))
        else:
            messages.append(f"{name}: {item['msg']}")
    return "; ".join(messages)
