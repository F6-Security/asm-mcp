# Copyright 2026 F6 JSC
# SPDX-License-Identifier: Apache-2.0

"""Reference data about the ASM client API, taken from its swagger (Client API
3.0.0) and the server code, and the read-only routes asm_request may reach.

Everything here is answered locally by asm_describe, with no API call."""

from dataclasses import dataclass

# --------------------------------------------------------------------------- values

ASSET_TYPES: dict[str, str] = {
    "domain": "domain or subdomain found for the company",
    "ip": "single IP address with ports, ASN, netname, location",
    "ip_range": "IP range (netblock) with ASN and netname",
    "ssl": "TLS certificate: common name, issuer, validity",
    "software": "software/version detected on a host and port (the source of most CVE issues)",
    "login_form": "login form found on a company site",
    "typosq": "typosquatting domain imitating the company (a third party's asset, not the company's)",
}
INFRA_ASSET_TYPES = ("domain", "ip", "ip_range", "ssl")

# 'false' is a string here: the swagger lists it as a JSON boolean by mistake,
# the server (ASSET_STATUS) compares strings.
ASSET_STATUSES: dict[str, str] = {
    "confirmed": "in the perimeter, confirmed by the client or by rules",
    "new": "found and attributed to the company, not yet reviewed",
    "false": "excluded from the perimeter (false positive or not the company's)",
}
PERIMETER_STATUSES = ("confirmed", "new")

ISSUE_STATUSES: dict[str, str] = {
    "detected": "open, found by the last scan",
    "under review": "open, being handled",
    "solved": "no longer observed",
    "manually solved": "closed by a user",
    "ignored": "accepted risk",
    "false positive": "marked as not a real problem",
}
OPEN_ISSUE_STATUSES = ("detected", "under review")

# filter value -> alertSeverity in a record -> alertBody.status in a record
SEVERITIES: dict[str, tuple[str, str]] = {
    "crit": ("Crit", "Critical severity"),
    "high": ("Error", "High severity"),
    "medium": ("Warning", "Medium severity"),
    "low": ("Low", "Low severity"),
}

ISSUE_CATEGORIES = (
    "Vulnerabilities", "Network Security", "DNS & Domains", "SSL/TLS Security", "Email Security",
)
TEST_NAME_EXAMPLES = (
    "CVE vulnurability",  # sic: the server spells it this way, filters must too
    "Insecure Network Headers",
    "Remote management open port: 22",
    "Certificate expires soon",
    "Invalid certificate",
    "Domain Expired",
    "Open login form",
    "DNS DNSSEC",
    "SPF Record Published",
    "DMARC Policy Enabled",
)

ASSET_FIELDS: dict[str, tuple[str, ...]] = {
    "common": ("id", "asset", "type", "status", "hasIssues", "score", "discoverBy", "detectionDate",
               "lastSeen", "lastScan", "tags", "seqUpdate"),
    "domain": ("registrar", "regDate", "expDate", "owner", "email", "redirecting", "ssl_cert", "domainInfo"),
    "ip": ("asn", "netname", "location", "ports", "range_number"),
    "ip_range": ("ip_range_asn", "ip_range_netname", "ip_range_location", "ip_range_ports"),
    "ssl": ("common", "issuer", "valid_from", "valid_till", "hash"),
    "software": ("software", "version", "software_type", "software_port", "vulnerabilities"),
    "login_form": ("login_form_domain", "login_form_software", "login_form_report_id"),
    "typosq": ("typosq_root_domain", "typosq_owner", "typosq_redirect", "typosq_domain_status",
               "typosq_dotmagnet_id"),
}
ISSUE_FIELDS = (
    "alertHash", "alertSeverity", "alertStatus", "testName", "alertFirstSeen", "alertLastSeen",
    "alertLifetime", "commandToCheck", "alertMitreInfo", "alertAdditionInfo", "seqUpdate",
    "alertBody.asset", "alertBody.valuetype", "alertBody.category", "alertBody.status",
    "alertBody.reason", "alertBody.description", "alertBody.cve", "alertBody.software_info",
    "alertBody.port", "alertBody.protocol", "alertBody.url", "alertBody.score", "alertBody.path",
)

QUIRKS = (
    "The status filter of /issues/updated lets through records with other statuses; tools "
    "re-check status and severity locally and report how many they dropped (droppedByFilter).",
    "With a status filter and a small count the API answers an empty page with seqUpdate null; "
    "tools never ask for fewer than 100 records when a filter is set and trim locally.",
    "Large /assets/updated pages of domains time out (whois/DNS in every record), and large "
    "/issues/updated pages are sometimes refused with 400 \"Failed to get paged issues\"; such a "
    "page is retried at half the size, down to 50.",
    "The resume cursor is the seqUpdate of the last record returned, so continuing with it never "
    "skips records; records are ordered oldest-first and an updated record is renumbered.",
    "Without a status filter /assets/updated returns excluded assets (status 'false') too; the "
    "company perimeter is status confirmed + new.",
    "testName of CVE findings is spelled 'CVE vulnurability'.",
    "POST issues/leaks fails without an explicit status list; asm_request sends every valid status "
    "when status is left out.",
    "GET reports/{company_id}/last can exceed the 1 MB result limit for a large company; "
    "GET reports/{company_id} lists report ids, reports/{report_id}/report returns one report.",
)

RATE_LIMIT = (
    "one request per second per token across all endpoints (0.1 s for paid clients), 429 otherwise; "
    "accounts may also have a request quota (403 \"Your API request limit has been reached\")"
)


# --------------------------------------------------------------------------- asm_request routes


@dataclass(frozen=True)
class Route:
    """A read-only endpoint asm_request may call.

    template: path under /api/v2, placeholders in braces; params: the only
    keys accepted, sent as the query string (GET) or the JSON body (POST).
    """

    method: str
    template: str
    description: str
    params: tuple[str, ...] = ()
    required: tuple[str, ...] = ()
    # Values sent when the caller leaves a param out, for params the server
    # needs although the swagger marks them optional.
    defaults: tuple[tuple[str, object], ...] = ()

    @property
    def segments(self) -> tuple[str, ...]:
        return tuple(self.template.split("/"))


ROUTES: tuple[Route, ...] = (
    Route("GET", "companies", "companies available to the token (also asm_list_companies)"),
    Route("GET", "companies/logs", "change log of companies", ("companyId", "dateFrom", "dateTo")),
    Route("GET", "companies/{company_id}", "company card: client, license type, scan country, branches"),
    Route("GET", "assets/{company_id}",
          "perimeter settings: confirmed and excluded domains and IPs set by hand"),
    Route("GET", "reports/{company_id}", "list of the company's reports"),
    Route("GET", "reports/{company_id}/last", "the latest report of the company"),
    Route("GET", "reports/{report_id}/report", "one full report by its id"),
    Route("GET", "issues/evidence/{issue_id}", "evidence of one issue (also asm_get_issue_evidence)"),
    Route("GET", "users/logs", "actions of this account's users", ("dateFrom", "dateTo")),
    Route("GET", "clients", "clients visible to the token"),
    Route("GET", "clients/{client_id}", "one client"),
    Route("GET", "partners", "partners visible to the token"),
    Route("POST", "dashboard/scores", "security score history and counters of a company",
          ("companyId", "dateFrom", "dateTo"), ("companyId",)),
    Route("POST", "issues/leaks", "leaked credentials of the company's domains; companyId is a list",
          ("companyId", "dateFrom", "dateTo", "status"), ("companyId", "dateFrom", "dateTo"),
          # Without status the server fails its own validation ("Status[1] must be one of ...").
          (("status", ["detected", "under review", "solved", "ignored", "false positive"]),)),
)

# Literal segments of every route in the API, including the ones that change data:
# a placeholder may never take one of them, so a template cannot be bent into
# another endpoint ("companies/{company_id}" must not reach "companies/create").
LITERAL_SEGMENTS = frozenset({
    "companies", "assets", "reports", "issues", "users", "clients", "partners", "dashboard",
    "logs", "last", "report", "evidence", "scores", "leaks", "updated", "create", "update",
    "add", "remove", "status", "change", "comments", "domain", "ip", "get_token", "web", "hi",
})
