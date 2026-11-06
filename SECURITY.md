# Security Policy

## Reporting a vulnerability

Please report security issues privately, not in a public issue.

- Preferred: use GitHub's [private vulnerability reporting](https://docs.github.com/code-security/security-advisories/guiding-contributors-to-report-security-vulnerabilities/privately-reporting-a-security-vulnerability)
  on this repository (Security → Report a vulnerability).
- Alternatively, email `asm@f6.ru`.

Please include the version, the environment variables in use (**never the value
of `ASM_API_TOKEN`**), and the steps to reproduce. We will acknowledge receipt and
keep you updated on the fix.

## Supported versions

The latest released version is supported. Fixes are not backported.

## Scope

This repository covers only the MCP server: the client-side process that talks
to the ASM client API. Vulnerabilities in the ASM platform itself are out of
scope here.

## Threat model

These are properties of the design, not defects. Understand them before you
deploy the server.

**Everything the tools return reaches the model provider.** Tool results go into
the model's context. That includes the company's external perimeter, its open
vulnerabilities with CVEs and ports, through `issues/leaks` leaked credentials,
through `clients` and `clients/{client_id}` the e-mail addresses and names of
the account's users, and through `users/logs` the IP addresses they log in from. Give the server a token that covers only the companies the task
needs, and choose the model provider with that in mind.

**Record content can be shaped by an attacker.** Whois owner fields, page titles,
service banners, certificate subjects and typosquatting domains are written by
whoever controls them. That text lands in the model's context next to the real
results, so it can carry instructions aimed at the model. The server has no tool
that writes to ASM: it never changes a status, never adds or removes an asset,
never adds a comment. `asm_request` only allows a fixed list of read-only routes.
Its placeholders accept ids only, never endpoint names, `..` or percent-encoding.
So instructions like these cannot act through this server. What the assistant
does with other tools is the client's responsibility.

**The API token goes wherever `ASM_BASE_URL` points.** The URL is checked at
startup: `https://` only, with no credentials, query string or fragment. That
stops the token from travelling in the clear or to a malformed address. It is
still sent to whatever host the value names, so treat the variable as part of
the credential. Redirects are not followed, for the same reason.

**Proxies and certificates are set explicitly, never inherited.** `HTTP_PROXY`,
`HTTPS_PROXY` and `SSL_CERT_FILE` from the environment are ignored. Set a proxy
with `ASM_PROXY` and a private CA with `ASM_CA_BUNDLE`. TLS verification cannot
be turned off.

**Responses are bounded.** These never reach the model:

- a tool result over 1 MiB;
- a body that is not JSON;
- an error body that is not JSON;
- more than 512 characters of a JSON error body.

Raw pages of the two paged endpoints are allowed up to 32 MiB, because they are
cut down locally before anything is returned.

**Path segments are checked.** Every id that goes into a URL must match its
shape first:

- a UUID-like company, client or report id;
- a 32-hex-digit issue id;
- a numeric or numeric_hex `seqUpdate`.

## What this server does not do

It makes no network calls except to `ASM_BASE_URL` (through `ASM_PROXY` when it
is set). It reads only the environment variables documented in the README. It
sends no telemetry and writes no files. Background summaries live in the
server's memory and disappear when it stops.
