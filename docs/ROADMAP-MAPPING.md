# Recon roadmap → FullRecon mapping

The user supplied a recon roadmap (a curated list of techniques and commands) and
asked for it to be built into the tool. This document records, item by item, what
was implemented, what was already covered before the request, and what was
deliberately not implemented.

Status legend: **native** = implemented in Python with no external binary;
**adapter** = drives the real binary when installed, falls back to native;
**covered** = already existed before the roadmap request; **skipped** = not
implemented, with the reason.

## Certificate Transparency

| Roadmap item | Status | Where |
|---|---|---|
| `curl crt.sh?output=json \| jq .[].name_value` | covered | `modules/subdomains.py::Sources.crtsh` — parses `name_value` and `common_name`, strips wildcards, excludes expired/duplicate entries |

## Subdomain enumeration

| Roadmap item | Status | Where |
|---|---|---|
| `subfinder -d … -all -recursive` | adapter | `core/tools.py::subfinder`, driven by `modules/subdomains.py::_external_sources` |
| `subfinder … -silent` | adapter | same adapter (`-silent` always applied) |
| `assetfinder --subs-only` | adapter | `core/tools.py::assetfinder` |
| subdomainfinder.c99.nl (manual website) | skipped | no API; automated scraping of a third-party website is unreliable and impolite |
| `ffuf -u https://FUZZ.<domain> -w …` | adapter | `modules/subdomains.py::_ffuf_subdomains` (opt-in via `--ffuf`) |
| `cat … \| sort -u > merge.txt` | covered | built-in de-duplication; `by_source.txt` attributes every name |
| `dnsx -l merge.txt` | covered | native resolver in `modules/subdomains.py::_validate`; `core/tools.py::dnsx` available |
| `httpx -l resolved.txt -follow-redirects` | adapter | `core/tools.py::httpx` + `modules/live_hosts.py::_httpx_probe` (opt-in via `--httpx`) |

## Fingerprinting

| Roadmap item | Status | Where |
|---|---|---|
| `httpx -tech-detect` | adapter | httpx adapter returns a `tech` array, merged into live-host records |
| `whatweb -i live.txt --log-json` | adapter | `core/tools.py::whatweb` + `modules/technologies.py::_merge_whatweb` |
| `for h in $(cat live.txt); do curl -sI … grep -Ei 'server\|x-powered-by\|…'` | native | `modules/headers.py` — scores 7 security headers, records disclosures |
| `wafw00f -i live.txt` | adapter + native | `modules/waf.py` (17 signature families + behavioural probes) and `core/tools.py::wafw00f` merged in |
| `wpscan --url … --enumerate vp,vt,u` | adapter + native | `modules/wordpress.py` implements the same enumeration natively; `core/tools.py::wpscan` adds CVE data when installed |
| `nmap -sV -iL resolved.txt` | covered + adapter | `core/portscan.py` (nmap when present) and `core/tools.py::nmap_services` |

## Crawling

| Roadmap item | Status | Where |
|---|---|---|
| `katana -u … -d 5 -jc -kf all` | adapter | `modules/urls.py::katana_crawl` (depth from `katana_depth`) |
| `katana … -hl` (headless) | skipped | requires a browser engine; the regex crawler plus `-jc` covers the JS-endpoint goal |
| Burp "Copy URLs in this host" | skipped by design | manual GUI workflow; paste results with `--in-scope` or a scope file |

## ASN and WHOIS-adjacent infrastructure

| Roadmap item | Status | Where |
|---|---|---|
| `whois target.com` | native | `modules/whois.py` — RDAP instead of the WHOIS protocol, no binary needed |
| `amass intel -org "Org"` | adapter | `core/tools.py::amass_intel_org`, triggered by `--org` |
| `amass intel -asn AS12345` | adapter | `core/tools.py::amass_intel_asn` |
| Google search for acquisitions | skipped | manual OSINT; not automatable reliably |
| GitHub search for acquisitions | skipped | same |
| `waybackurls target.com` | adapter | `modules/urls.py::historical_tools` + `core/tools.py::waybackurls` |
| `gau target.com` | adapter | `modules/urls.py::historical_tools` + `core/tools.py::gau` |

## JavaScript and bundle analysis

All thirteen greps from the roadmap are implemented as compiled patterns in
`modules/javascript.py`, not shelled-out `grep`:

| # | Roadmap grep | Method |
|---|---|---|
| 1 | `/api/[^"' ]+` | `ENDPOINT_PATTERNS[2]` |
| 2 | `https?://[^"' ]+` | `ENDPOINT_PATTERNS[3]` |
| 3 | `api\|endpoint\|route` | `ENDPOINT_PATTERNS[0..1]` + `PARAM_NAME_RE` |
| 4 | `admin\|administrator\|management` | `JS_SENSITIVE_HINTS` applied to comments |
| 5 | `login\|signin\|auth…` | `JS_SENSITIVE_HINTS` |
| 6 | `user\|account\|profile\|settings` | `JS_SENSITIVE_HINTS` |
| 7 | `id=\|userId\|redirect\|returnUrl` | `_find_params` |
| 8 | `/api/v[0-9]+` | `_find_api_versions` |
| 9 | `ws://\|wss://\|websocket` | `_find_websockets` |
| 10 | `…(php\|json\|xml\|config\|graphql)` | `_find_sensitive_files` |
| 11 | `graphql\|mutation\|query` | `ENDPOINT_PATTERNS[2]` + `modules/api.py` |
| 12 | `\.map` | `_find_source_maps` |
| 13 | `fetch(\|axios\|XMLHttpRequest` | `_count_client_calls` |

Bundles are collected automatically (crawler, katana, `<script src>`) rather than
downloaded by hand, and secret patterns are matched with redacted output.

## API surface mapping

| Roadmap item | Status | Where |
|---|---|---|
| Burp Proxy → HTTP history | skipped by design | requires a hand-driven proxy session; FullRecon observes the same surfaces without one |
| APIs from JavaScript | covered | `modules/javascript.py` → `modules/api.py` |
| Documentation paths (`ffuf -w api-docs.txt`) | covered | `modules/api.py::SWAGGER_PATHS` + native probing |
| API version checks | covered | `modules/api.py` harvests `/v1`, `/v2` from URLs and JS |
| GraphQL discovery | covered | `modules/api.py::GRAPHQL_PATHS`; introspection is **not** attempted |
| HTTP methods | covered | `modules/api.py::METHOD_HINT_RE` |
| Parameter collection | covered | `modules/api.py` + `javascript._find_params` |
| Merge Burp + JS + Swagger + historical + GraphQL | covered | `modules/api.py` merges all in-scope sources before writing `api_endpoints.txt` |
| Prioritise functionality (admin, payments, uploads…) | covered | `modules/intelligence.py` keyword scoring and severity rules |
| Keep files organised | covered | the numbered output tree |

## Deliberate omissions

1. **Burp Suite integration** — a GUI workflow with no CLI automation surface. Its
   output (URL lists) can be fed in through scope files.
2. **subdomainfinder.c99.nl** — a website, not an API; scraping it would be fragile
   and would load a third party without a documented rate policy.
3. **Google/GitHub acquisition OSINT** — manual searching; automating it would
   produce unreliable noise and possibly violate the search provider's terms.
4. **GraphQL introspection** — the roadmap itself says "don't assume introspection
   is enabled". FullRecon detects endpoints and stops there.
5. **`katana -hl` headless mode** — needs Chromium; `-jc` achieves the same goal
   without the install burden.
6. **WPScan credential attacks** — FullRecon never attempts authentication.

## Verification

Every "native" and "adapter" row above has an automated test, except where the
external binary is not installed on the development machine (nmap, whatweb,
wafw00f, wpscan, amass). Those adapters are covered by stub-binary parsing tests
in `tests/test_tool_adapters.py`.
