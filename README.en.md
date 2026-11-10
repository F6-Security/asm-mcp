# F6 ASM MCP Server

[Русский](https://github.com/F6-Security/asm-mcp/blob/HEAD/README.md)

[![PyPI](https://img.shields.io/pypi/v/asm-mcp)](https://pypi.org/project/asm-mcp/)
[![Python](https://img.shields.io/pypi/pyversions/asm-mcp)](https://pypi.org/project/asm-mcp/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/F6-Security/asm-mcp/blob/HEAD/LICENSE)
[![CI](https://github.com/F6-Security/asm-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/F6-Security/asm-mcp/actions/workflows/ci.yml)

An MCP server for the F6 ASM (Attack Surface Management) client API. It gives
an AI assistant access to a company's external perimeter: its assets (domains,
IPs, ranges, certificates, software) and the issues found on them. You can get
the records themselves with filters, or summary counts.

## Tools

| Tool | Purpose |
| --- | --- |
| `asm_list_companies` | Companies the token may read; also checks the address, the token and access |
| `asm_get_assets` | Assets of a company with filters, paged by `seqUpdate` |
| `asm_get_issues` | Issues of a company with filters, paged by `seqUpdate` |
| `asm_get_issue_evidence` | Evidence of one issue |
| `asm_assets_summary` | Counts over every asset: type, status, issue level |
| `asm_issues_summary` | Counts over issues: severity, status, category, test, top hosts and CVEs |
| `asm_describe` | Reference: types, statuses, severities, fields, limits, API quirks. Works without an API call |
| `asm_request` | Other endpoints, from a fixed read-only list only: reports, logs, company card, scores, leaks |

Every tool only reads data. `asm_request` refuses any endpoint that creates,
updates, removes or changes a status before a request is sent.

## Quick start

You need [uv](https://docs.astral.sh/uv/) (or Python 3.10+ and pip), the address of
your ASM installation and an API token. `uvx asm-mcp` downloads the package from
PyPI and runs it in an isolated environment; nothing has to be installed first.

```json
{
  "mcpServers": {
    "asm": {
      "command": "uvx",
      "args": ["asm-mcp"],
      "env": {
        "ASM_BASE_URL": "https://asm.example.com",
        "ASM_API_TOKEN": "<token>"
      }
    }
  }
}
```

This block works for Claude Desktop and Cursor. VS Code uses the file
`.vscode/mcp.json`: the key is `servers` and you add `"type": "stdio"`;
everything else is the same.

For Claude Code:

```sh
claude mcp add asm \
  -e ASM_BASE_URL=https://asm.example.com -e ASM_API_TOKEN=<token> \
  -- uvx asm-mcp
```

Instead of `uvx` you can run `pip install asm-mcp` and point the client at the
`asm-mcp` command.

To install from source into a separate environment:

```sh
cd asm-mcp
python3 -m venv venv
./venv/bin/pip install --require-hashes -r requirements.lock
./venv/bin/pip install --no-deps -e .
```

Then point the client at `"command": "/path/to/asm-mcp/venv/bin/asm-mcp"` with
no `args`. On Windows the path is `venv\Scripts\asm-mcp.exe`.

You can also run it in a container:

```sh
docker build -t asm-mcp .
docker run -i --rm -e ASM_BASE_URL -e ASM_API_TOKEN asm-mcp
```

Make `asm_list_companies` your first call. It shows that the address, the token
and company access are all in order.

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `ASM_BASE_URL` | — | Address of the ASM installation, `https://` only. The `/api/v2` suffix is optional |
| `ASM_API_TOKEN` | — | API token, sent as `Authorization: Bearer` |
| `ASM_CA_BUNDLE` | — | PEM CA bundle for an internal certificate. It replaces the system CAs, so it must contain every CA you need |
| `ASM_PROXY` | — | Proxy as `http://host:port`. `HTTP_PROXY` and `HTTPS_PROXY` are not read |
| `ASM_TIMEOUT` | `60` | Timeout of one request, seconds |
| `ASM_RETRIES` | `3` | Number of retries on 429/500/502/503/504, honouring `Retry-After` |
| `ASM_MIN_INTERVAL` | `1.05` | Pause between requests, seconds. The server allows 1 request/s per token, 0.1 s for paid clients |
| `ASM_TOOL_BUDGET` | `40` | How many seconds one tool call may take. Must be less than the MCP client's timeout |
| `ASM_SUMMARY_TTL` | `600` | How many seconds a finished background summary is reused |

You cannot turn TLS verification off; there is deliberately no such setting.
For an internal CA, use `ASM_CA_BUNDLE`.

## Examples

```
asm_list_companies
asm_issues_summary  company_id="…"
asm_get_issues      company_id="…" severity=["crit"] status=["detected"] fields=["alertBody.asset","testName","alertBody.reason"]
asm_get_assets      company_id="…" type=["domain","ip"] status=["confirmed","new"]
asm_get_assets      company_id="…" seq_update="1700000000000_0a1b…"
asm_request         path="reports/<company_id>/last"
asm_request         method="POST" path="dashboard/scores" params={"companyId":"…","dateFrom":"2026-10-01"}
```

The company perimeter is the assets with status `confirmed` or `new`. Status
`false` means the asset is excluded. Open issues are those with status
`detected` or `under review`.

### Paging

`asm_get_assets` and `asm_get_issues` read from the oldest records to the newest
and turn the pages themselves. One call stops in one of three cases: it has
collected `max_items` records, `ASM_TOOL_BUDGET` has run out, or the answer has
reached 1 MB. The answer then has `complete: false`, the cause in `reason` and
a cursor in `seqUpdate`. The cursor is the `seqUpdate` of the last record
returned, so continuing from it skips no records. If you save `seqUpdate` after
a full walk, the next call with it returns only the changes.

### Summaries of large companies

A company with 10 000+ assets cannot be walked in one call at 1 request/s. A
summary counts while `ASM_TOOL_BUDGET` lasts, then passes its counts and cursor
to a background task in the server process. The answer comes back with
`complete: false` and a `job_id`. Calling again with the same arguments returns
the progress, and the full result once the task is done. Tasks are kept in
memory only and no files are written. At most two tasks run at the same time.

### Working around API quirks

- The `status` filter of `/issues/updated` lets through records with other
  statuses. Status and severity are re-checked on the client, and the number
  of dropped records is returned in `droppedByFilter`.
- When a filter is set and `count` is small, the API answers with an empty
  page. So with filters `count` is never below 100, and the extra records are
  trimmed on the client.
- Heavy pages of domains do not load in time. Such a page is requested again
  at half the size, but not below 50.
- Severity mapping: `crit/high/medium/low` = `alertSeverity` `Crit/Error/Warning/Low`
  = `alertBody.status` `Critical/High/Medium/Low severity`.
- The CVE test is named `CVE vulnurability` (exactly so, with the typo).

## Security

Everything the tools return reaches the language model's context: the
company perimeter, its vulnerabilities, and through `issues/leaks` leaked
credentials as well. Choose the model provider with that in mind. Give the
server a token with access only to the companies it needs.

The token is sent only to the address in `ASM_BASE_URL` and only over
`https://`. Redirects are not followed. An answer over 1 MB is not passed to
the model.

The threat model is described in [SECURITY.md](https://github.com/F6-Security/asm-mcp/blob/HEAD/SECURITY.md).

## Contributing

See [CONTRIBUTING.md](https://github.com/F6-Security/asm-mcp/blob/HEAD/CONTRIBUTING.md).

## License

[Apache License 2.0](https://github.com/F6-Security/asm-mcp/blob/HEAD/LICENSE)
