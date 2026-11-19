# FullRecon

**Automated reconnaissance framework for bug bounty hunters and authorized penetration testers.**

FullRecon maps a target's external attack surface in one command: it enumerates
subdomains from public datasets, resolves DNS, finds live web hosts, scans ports,
fingerprints technologies, crawls for URLs, analyses JavaScript, discovers APIs,
brute-forces content, and turns all of it into prioritised findings plus JSON and
HTML reports.

```bash
fullrecon -d example.com
```

```
 ███████╗██╗   ██╗██╗     ██╗         ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██╔════╝██║   ██║██║     ██║         ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 █████╗  ██║   ██║██║     ██║         ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██╔══╝  ██║   ██║██║     ██║         ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ██║     ╚██████╔╝███████╗███████╗    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═╝      ╚═════╝ ╚══════╝╚══════╝    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝

 target : example.com
 output : FullRecon-Results/example.com
 mode   : active | threads 15 | rate 20/s | timeout 10s
 modules: subdomains, dns, ports, live, technologies, urls, javascript, api, content, intel

────────────────────────────────────────────────────────────────
 [1/10] Subdomain Enumeration
────────────────────────────────────────────────────────────────
18:05:11 INF [subdomains]   certspotter          2 hostnames
18:05:11 INF [subdomains]   subdomain_center   449 hostnames
18:05:13 INF [subdomains]   urlscan              2 hostnames
18:06:04 INF [subdomains] Subdomains: 452 unique, 2 resolve, 450 unresolved

────────────────────────────────────────────────────────────────
 [4/10] Live Host Discovery
────────────────────────────────────────────────────────────────
18:07:09 INF [live] Live hosts: 2 host(s), 4 endpoint(s) responding
...
════════════════════════════════════════════════════════════════
 SCAN COMPLETE
════════════════════════════════════════════════════════════════
  Duration            5m 50s
  Subdomains          452
  Resolved hosts      2
  Live hosts          2
  Open ports          4
  Technologies        1
  URLs                4
  API endpoints       0
  JS files / secrets  0 / 0
  Content paths       0

  findings: HIGH 0 | MEDIUM 2 | LOW 2 | INFO 0
```

---

## Features

| Stage | What FullRecon does |
|---|---|
| **Subdomain enumeration** | 9 passive sources in parallel: crt.sh, Cert Spotter, HackerTarget, subdomain.center, urlscan.io, RapidDNS, AlienVault OTX, Wayback CDX, Common Crawl. Optional wordlist brute force. Per-source attribution. Wildcard-DNS detection. |
| **DNS enumeration** | A, AAAA, CNAME, MX, NS, TXT, SOA, CAA records. Dangling-CNAME detection against 30+ takeover fingerprints. SPF/DMARC/DKIM surfacing. |
| **Live host discovery** | HTTP/HTTPS probing of resolved hosts, status codes, titles, redirect chains, server headers, response times. |
| **Port scanning** | nmap with `-sV` service/version detection when available, built-in threaded TCP connect scanner as fallback. Sensitive-port flagging. |
| **Technology detection** | 60+ signatures across servers, languages, frameworks, CMS, CDNs, analytics and cloud providers — each match carries its evidence string and version where disclosed. |
| **URL & endpoint discovery** | Depth-controlled crawler, robots.txt / sitemap.xml / security.txt parsing, Wayback and Common Crawl history, query-parameter extraction, keyword scoring. |
| **JavaScript analysis** | Endpoint extraction from fetch/axios/config patterns, 23 secret patterns (AWS, GCP, Stripe, GitHub, Slack, JWT, private keys…), sensitive-comment mining, config-reference discovery. **Values are redacted and never used.** |
| **API discovery** | GraphQL endpoint probing, Swagger/OpenAPI spec detection and validation, REST route harvesting, parameter and HTTP-method extraction. |
| **Content discovery** | Configurable wordlist, extension expansion, soft-404 baseline fingerprinting per host, 401/403 and sensitive-extension flagging. |
| **Intelligence** | Rule-based severity scoring that correlates everything above into prioritized findings with evidence. |

Cross-cutting: strict scope enforcement, per-host rate limiting, configurable
concurrency, timestamped runs, structured output tree, JSON + HTML + text
reports, full execution log, and graceful degradation when any source is down.

---

## Installation

### Kali / Ubuntu / Debian (recommended)

```bash
git clone https://github.com/Abobakr-1/FullRecon.git
cd FullRecon
chmod +x install.sh
./install.sh
```

Then from any directory:

```bash
fullrecon -d example.com
```

The installer:

- verifies Python ≥ 3.8 and pip, installing them via `apt` if missing,
- installs FullRecon with `pipx` (preferred), `pip --user`, or a venv
  (`./install.sh --venv`),
- adds the console script and tells you if `~/.local/bin` is missing from `PATH`,
- verifies the install by running `fullrecon --version` and `--list-modules`,
- reports which optional external tools (`nmap`, `subfinder`, `jq`, `curl`) are absent.

`sudo ./install.sh` performs a system-wide install.

Tested on **Python 3.9, 3.13 and 3.14** on Linux and Windows. The test suite runs
on every push via GitHub Actions against 3.9, 3.11 and 3.13.

Linux users who prefer an isolated install without touching the system Python:

```bash
git clone https://github.com/Abobakr-1/FullRecon.git
cd FullRecon
./install.sh --venv
source .venv/bin/activate      # or add .venv/bin to PATH
fullrecon -d example.com
```

### pip

```bash
pip install git+https://github.com/Abobakr-1/FullRecon.git
```

### From a clone, for development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

### Optional external tools

FullRecon runs with **only `dnspython`**, but these improve results:

```bash
sudo apt-get install -y nmap curl jq
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

| Tool | Effect if present | Effect if absent |
|---|---|---|
| `nmap` | faster scans + service/version detection | built-in TCP connect scanner, service names from a port table |
| `dnspython` | resolver-controlled, fast DNS | falls back to `socket.getaddrinfo`, A/AAAA only |
| `curl` / `jq` | handy for manual follow-up | no effect on the tool |

---

## Usage

### Core commands

```bash
fullrecon -d example.com                    # standard pipeline
fullrecon -d example.com --full             # every module
fullrecon -d example.com --passive          # no traffic to the target
fullrecon -d example.com --active           # skip passive enumeration
fullrecon -d example.com --subdomains       # one stage
fullrecon -d example.com --ports
fullrecon -d example.com --api
fullrecon -d example.com --js
fullrecon -d example.com -o /path/to/results
fullrecon -d example.com --threads 20
fullrecon --help
```

### All options

```
target
  -d, --domain DOMAIN        target domain (required for scans)
  -o, --output DIR           results directory (default: FullRecon-Results)
      --timestamped          write into <target>/<YYYYmmdd-HHMMSS>/
      --overwrite            replace an existing result directory

scan modes
      --full                 run every module
      --passive              passive sources + DNS only (no target traffic)
      --active               active reconnaissance only

single-module shortcuts
      --subdomains  --dns  --ports  --live  --urls  --api  --js
      --content     --tech

performance
  -t, --threads N            worker threads (default 15)
      --rate-limit RPS       max requests/second per host (default 20)
      --timeout SEC          per-request timeout (default 10)
      --retries N            retries per failed request (default 1)
      --proxy URL            HTTP(S) proxy

scanning options
      --ports-list LIST      e.g. 80,443,8000-8100
      --top-ports N          scan the N most common ports
      --no-nmap              always use the built-in TCP scanner
      --no-resolve           skip DNS validation of subdomains
      --no-crawl             disable crawling
      --no-archives          disable Wayback / Common Crawl
      --no-content           disable content discovery
      --crawl-depth N        crawl depth (default 2)
      --max-pages N          page budget (default 200)
      --wordlist FILE        content-discovery wordlist
      --subdomain-wordlist FILE   brute-force wordlist
      --bruteforce           enable subdomain brute force
      --sources LIST         pick passive sources
      --verify-tls           require valid TLS certificates

scope control
      --scope-file FILE      in-scope hosts/CIDRs, one per line, ! to exclude
      --in-scope LIST        extra in-scope domains/CIDRs
      --out-of-scope LIST    domains/CIDRs to never touch
      --allowed-ports LIST   restrict every module to these ports

general
  -c, --config FILE          JSON config file
  -v, --verbose              verbose output
  -q, --quiet                warnings and errors only
      --no-color             disable colour
      --yes                  assume yes for prompts
      --authorized           confirm authorization (required non-interactively)
      --list-modules         list modules and exit
```

### Scope control

Scope is enforced in the HTTP client, the port scanner and every module — an
out-of-scope host is never contacted, even if a scan result references it.

```bash
# one target plus a partner domain, excluding a staging host
fullrecon -d example.com \
  --in-scope partner.net,10.0.0.0/24 \
  --out-of-scope staging.example.com

# or keep it in a file
cat > scope.txt <<'EOF'
# comments and blank lines are ignored
example.com
assets.partner.net
192.0.2.0/24
!legacy.example.com       # leading ! excludes
EOF

fullrecon -d example.com --scope-file scope.txt
```

### Configuration file

Copy the example and edit it:

```bash
mkdir -p ~/.config/fullrecon
cp config/fullrecon.example.json ~/.config/fullrecon/config.json
fullrecon -d example.com            # picks it up automatically
fullrecon -d example.com -c other.json
```

CLI flags always win over the config file, which wins over built-in defaults.

---

## Output

Every target gets its own directory, created automatically:

```
FullRecon-Results/
└── example.com/
    ├── 01-Subdomains/
    │   ├── all_subdomains.txt          every hostname discovered
    │   ├── unique_subdomains.txt       sorted, de-duplicated
    │   ├── resolved_subdomains.txt     DNS-validated
    │   ├── unresolved_subdomains.txt   stale / takeover candidates
    │   ├── by_source.txt               hostname <tab> source
    │   ├── wildcard_dns.txt            present only if wildcard detected
    │   └── sources_summary.json
    ├── 02-DNS/
    │   ├── dns_records.txt             host <tab> type <tab> value
    │   ├── dns_records.json
    │   ├── cname_records.txt
    │   ├── dangling_cnames.txt         takeover candidates with reason
    │   └── interesting_dns.txt         SPF, DMARC, MX, NS, CAA, SOA
    ├── 03-Live-Hosts/
    │   ├── live_hosts.txt
    │   ├── http_hosts.txt / https_hosts.txt
    │   ├── host_details.txt            status, title, server, redirect
    │   ├── live_urls.txt
    │   └── live_hosts.json
    ├── 04-Ports/
    │   ├── open_ports.txt
    │   ├── services.txt                port + service + version
    │   ├── web_ports.txt
    │   ├── unusual_ports.txt           sensitive ports reachable
    │   ├── ports.json / ports_by_host.json
    ├── 05-Technologies/
    │   ├── technologies.txt            grouped by category
    │   ├── by_host.txt                 host <tab> category <tab> tech <tab> evidence
    │   └── technologies.json
    ├── 06-URLs/
    │   ├── all_urls.txt
    │   ├── unique_urls.txt
    │   ├── interesting_urls.txt
    │   ├── urls_with_parameters.txt
    │   ├── urls_without_query.txt
    │   ├── js_files_from_crawl.txt
    │   └── summary.json
    ├── 07-API/
    │   ├── api_endpoints.txt
    │   ├── graphql.txt
    │   ├── swagger.txt
    │   ├── api_parameters.txt
    │   ├── api_methods.txt
    │   └── api_summary.json
    ├── 08-JavaScript/
    │   ├── javascript_files.txt
    │   ├── extracted_endpoints.txt
    │   ├── potential_exposures.txt     secret type + REDACTED value + source
    │   ├── sensitive_comments.txt
    │   ├── config_references.txt
    │   └── javascript_analysis.json
    ├── 09-Content-Discovery/
    │   ├── discovered_paths.txt
    │   ├── interesting_files.txt
    │   ├── forbidden_paths.txt         401/403 responses
    │   └── content_discovery.json
    ├── 10-Reports/
    │   ├── summary.txt                 human-readable overview
    │   ├── report.json                 machine-readable full export
    │   ├── report.html                 standalone HTML report
    │   ├── findings.txt / findings.json
    │   └── manifest.json               every file with size and line count
    ├── logs/
    │   └── fullrecon.log               full execution log
    ├── raw/
    │   └── …                           unprocessed source responses
    └── README.txt                      what this directory contains
```

- Previous results are **never overwritten silently** — run with `--overwrite`
  or `--timestamped`, or confirm interactively.
- Raw and processed data are stored separately (`raw/` vs numbered folders).
- Every list is de-duplicated; output uses a consistent `<tab>`-separated layout
  that is easy to pipe into `awk`/`cut`.

---

## How the pipeline chains

```
target validation
   └─→ subdomains ──→ dns ──→ resolved hosts
                        ├─→ ports ──→ web ports ──→ live hosts
                        └─→ live hosts ──→ technologies
                                     └─→ urls (crawl + archives)
                                            ├─→ javascript
                                            ├─→ api
                                            └─→ content discovery
                                                     └─→ intelligence → reports
```

Each module reads the parsed results of earlier stages (`ReconState`) rather
than re-querying; for example the port scanner feeds discovered web ports back
into live-host discovery, and the JavaScript module consumes the URL list instead
of crawling again.

---

## How findings are scored

Findings are produced by explicit rules, not guesses:

| Severity | Examples |
|---|---|
| **High** | dangling CNAME at a claimable service; sensitive port reachable (3306/5432/6379/9200/27017/3389); exposed `.env`/backup/SQL/`actuator/env`; high-confidence secret pattern in JS; API docs exposing full surface |
| **Medium** | admin/staging/internal subdomains; plain-HTTP endpoints; permissive SPF (`+all`); non-web services exposed; interesting parameterised URLs |
| **Low** | unresolved subdomains; version disclosure; sensitive JS comments; dual HTTP/HTTPS |
| **Info** | wildcard DNS, endpoint inventories, 5xx errors, CMS present |

Findings are reconnaissance leads. **Nothing is an exploit.** Manual
verification is required before reporting anything.

---

## Safety and legal use

FullRecon is built for **authorized** testing only.

- **Explicit scope** — in-scope/out-of-scope domains and CIDRs are enforced
  before any connection is made. Out-of-scope hosts are excluded even when
  discovered indirectly.
- **Non-interactive runs require `--authorized`** (or
  `FULLRECON_ACCEPT_AUTHORIZATION=1`); interactive runs ask once.
- **Rate limited by default** — 20 requests/second per host, 15 threads,
  one retry. Lower it further with `--rate-limit 5`.
- **No exploitation.** No SQL injection, authentication bypass, credential
  stuffing, or destructive requests.
- **No credential use.** Secrets found in JavaScript are redacted in every
  output file and are never validated or submitted.
- **TLS relaxed only for reading** — certificate validation is off by default so
  misconfigured hosts are still inventoried; `--verify-tls` enforces it.
- **Passive mode** (`--passive`) sends no traffic to the target at all; it only
  reads third-party public datasets and public DNS.

You are responsible for having permission and for following the program's rules.
See [LICENSE](LICENSE) for the full notice.

---

## Limitations

- **Passive sources are third-party and unreliable.** crt.sh and AlienVault OTX
  rate-limit aggressively; Wayback is occasionally offline. Every failure is
  logged in `summary.txt` and `logs/fullrecon.log`, and the run continues.
- **Wildcard DNS inflates brute-force results.** FullRecon detects wildcards and
  records them, but cannot tell a real wildcard host from noise without a
  baseline comparison; treat brute-force output with suspicion when a wildcard is
  reported.
- **Subdomain coverage is bounded by public data.** No active zone transfer,
  no DNSSEC walking.
- **Technology detection is signature based.** It reports what is observable in
  headers, cookies and HTML; it does not confirm a version is vulnerable.
- **JavaScript secret detection is heuristic.** Placeholders are filtered, but
  expect false positives; always verify before reporting.
- **Content discovery uses a small default wordlist** to stay polite. Point
  `--wordlist` at a larger list (SecLists, raft) for deeper coverage.
- **No screenshotting, no headless browser, no subdomain-takeover verification**
  (fingerprints only flag candidates).
- **Not a substitute for manual testing.** It shortens the boring part of recon.

---

## Development

```bash
pytest -q                  # 126 tests, no network required
pytest -q -k scope         # just scope tests
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the review bar,
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for design details,
[docs/OUTPUT.md](docs/OUTPUT.md) for the full output reference and
[docs/TESTING.md](docs/TESTING.md) for real scan results. Tests never touch the network: modules are exercised with a fake
HTTP client and HTML fixtures.

### Project layout

```
fullrecon/
  cli.py                     argparse CLI, authorization gate, entrypoint
  config.py                  defaults + JSON config loading
  core/
    context.py               ReconState (shared results) + ModuleContext
    orchestrator.py          pipeline definition and sequencing
    scope.py                 in/out-of-scope decisions (wildcards, CIDRs)
    scanner.py               rate-limited HTTP client with scope checks
    portscan.py              nmap + threaded TCP connect scanning
    output_manager.py        result tree creation and overwrite policy
    report_generator.py      summary.txt / report.json / report.html
    deduplication.py         thread-safe de-duplication primitives
  modules/
    subdomains.py dns.py live_hosts.py portscan.py technologies.py
    urls.py javascript.py api.py content_discovery.py intelligence.py
  utils/                     colours, logging, progress, validators, helpers
  data/content_wordlist.txt  default content-discovery wordlist
tests/                       pytest suite
wordlists/                   extra wordlists
```

---

## License

MIT — see [LICENSE](LICENSE). Includes an additional authorized-use notice.

## Disclaimer

FullRecon is provided for educational and authorized security testing purposes.
The author is not responsible for misuse or for any damage caused by this
software. Scanning systems without explicit permission may be illegal. Always
obtain written authorization before testing.

---

**Author:** [Abobakr Mohamed](https://github.com/Abobakr-1) ·
**Repository:** [github.com/Abobakr-1/FullRecon](https://github.com/Abobakr-1/FullRecon) ·
**License:** MIT