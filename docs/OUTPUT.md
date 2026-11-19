# Output reference

One directory per target. Nothing is overwritten without `--overwrite` or
`--timestamped`.

```
FullRecon-Results/<target>/
```

## 01-Subdomains

| File | Format | Contents |
|---|---|---|
| `all_subdomains.txt` | one per line | Every hostname from every source, in discovery order. |
| `unique_subdomains.txt` | sorted | Same set, de-duplicated and sorted. |
| `resolved_subdomains.txt` | sorted | Hosts that resolve via A/AAAA/CNAME. |
| `unresolved_subdomains.txt` | sorted | Hosts with no record; takeover candidates when a CNAME exists. |
| `by_source.txt` | `host` TAB `source` | Provenance for each name. |
| `wildcard_dns.txt` | one line | Present only when wildcard DNS was detected. |
| `sources_summary.json` | JSON | Per-source counts, errors, wildcard detail. |

## 02-DNS

| File | Format | Contents |
|---|---|---|
| `dns_records.txt` | `host` TAB `TYPE` TAB `value` | All records, grouped by host with `# host` headers. |
| `dns_records.json` | `{host: {TYPE: [values]}}` | Same data, machine readable. |
| `cname_records.txt` | `host -> target` | Every CNAME. |
| `dangling_cnames.txt` | `host -> target [reason]` | CNAMEs pointing at claimable third-party services. |
| `interesting_dns.txt` | lines | SPF, DMARC, DKIM, MX, NS, CAA and SOA values. |

## 03-Live-Hosts

| File | Format | Contents |
|---|---|---|
| `live_hosts.txt` | hostnames | Hosts that answered on HTTP or HTTPS. |
| `http_hosts.txt` / `https_hosts.txt` | URLs | Split by scheme. |
| `host_details.txt` | aligned columns | host, status, URL, server, title, redirect. |
| `live_urls.txt` | URLs | Final URLs after redirects: the crawl seeds. |
| `live_hosts.json` | JSON | Full response metadata. |

## 04-Ports

| File | Format | Contents |
|---|---|---|
| `open_ports.txt` | `host:port` | Open TCP ports. |
| `services.txt` | `host:port service (version)` | Service names and versions when nmap is present. |
| `web_ports.txt` | `host:port` | Ports that look like HTTP(S). |
| `unusual_ports.txt` | `host:port service` | Sensitive ports that answered. |
| `ports.json` / `ports_by_host.json` | JSON | Full data with `web` and `unusual` flags. |

Results are attributed to the hostname that was scanned, not to the IP it
resolved to.

## 05-Technologies

| File | Format | Contents |
|---|---|---|
| `technologies.txt` | grouped sections | `[Web server]`, `[CMS]`, and so on, with versions. |
| `by_host.txt` | `host` TAB `category` TAB `tech` TAB `evidence` | Why each technology was detected. |
| `technologies.json` | JSON | Aggregated view plus per-host detail. |

Every detection carries the evidence string that triggered it (a header value, a
cookie name, a body marker), so a false positive is easy to spot and dismiss.

## 06-URLs

| File | Format | Contents |
|---|---|---|
| `all_urls.txt` | one per line | Everything found, in discovery order. |
| `unique_urls.txt` | sorted | De-duplicated. |
| `interesting_urls.txt` | sorted | Keyword, extension or parameter matches. |
| `urls_with_parameters.txt` | `url` TAB `param1,param2` | URLs carrying query parameters. |
| `urls_without_query.txt` | URLs | Path-only form, useful for content discovery. |
| `js_files_from_crawl.txt` | URLs | JavaScript referenced by pages. |
| `summary.json` | JSON | Counts, per-source attribution, host list. |

## 07-API

| File | Contents |
|---|---|
| `api_endpoints.txt` | REST routes and parameterised paths. |
| `graphql.txt` | GraphQL endpoints that responded with a GraphQL signature. |
| `swagger.txt` | OpenAPI/Swagger documents that validated. |
| `api_parameters.txt` | Parameter names harvested from URLs and JavaScript. |
| `api_methods.txt` | HTTP methods observed in client code. |
| `api_summary.json` | All of the above in one object. |

## 08-JavaScript

| File | Contents |
|---|---|
| `javascript_files.txt` | Analysed JS files. |
| `extracted_endpoints.txt` | Endpoints found inside bundles. |
| `potential_exposures.txt` | confidence, type, REDACTED value, source. |
| `sensitive_comments.txt` | Comments containing security-relevant keywords. |
| `config_references.txt` | `window.*`, `process.env.*`, `config.*` references. |
| `javascript_analysis.json` | Full detail including per-file sizes and MIME types. |

Secret values are **always** redacted, for example `AKIAI...MPLE [len=20]`.
FullRecon never stores a usable credential and never sends one anywhere.

## 09-Content-Discovery

| File | Format | Contents |
|---|---|---|
| `discovered_paths.txt` | `url status length content-type` | Every path that differed from the soft-404 baseline. |
| `interesting_files.txt` | `url status length title` | Sensitive extensions, 401/403 responses, sensitive keywords. |
| `forbidden_paths.txt` | `url (status)` | 401/403 only: access-controlled but present. |
| `content_discovery.json` | JSON | Full records plus the baseline fingerprints used. |

## 10-Reports

| File | Contents |
|---|---|
| `summary.txt` | Human-readable overview: statistics, findings, module status, errors. |
| `report.json` | Complete machine-readable export of the scan. |
| `report.html` | Standalone styled report, no external assets. |
| `findings.txt` / `findings.json` | Prioritised intelligence output. |
| `manifest.json` | Every generated file with size and line count. |

## logs/ and raw/

- `logs/fullrecon.log`: full execution log at DEBUG level, ANSI codes stripped.
- `raw/`: unprocessed source responses (live probe payloads, source counts) so
  you can audit how a result was produced.