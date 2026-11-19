# Testing report

All results below come from running the test suite and real scans during
development. Nothing here is estimated.

## Unit and integration tests

```
$ pytest -q
.............................................................  [100%]
129 passed in 1.14s
```

| File | Tests | Covers |
|---|---|---|
| `tests/test_validators.py` | 27 | Target normalisation/validation, domain/IP/URL predicates, eTLD+1 comparison, host:port splitting |
| `tests/test_scope.py` | 13 | In/out-of-scope precedence, subdomain matching, CIDR support, port restrictions, scope files, passive-source allowlist |
| `tests/test_helpers.py` | 28 | File I/O, de-duplication, URL normalisation, HTML/title/script/form/comment extraction, gzip + chunked HTTP decoding, rate limiter |
| `tests/test_modules.py` | 16 | Subdomain source parsers (crt.sh, Cert Spotter, HackerTarget, subdomain.center), source-failure isolation, takeover fingerprints, DNS output files, technology detection, JavaScript secrets/endpoints/comments |
| `tests/test_modules_extra.py` | 16 | URL crawling and de-duplication, API spec/GraphQL detection, soft-404 content filtering, nmap parsing, port merge, live-host de-duplication, intelligence scoring and severity ordering |
| `tests/test_cli.py` | 29 | Argument parsing, config assembly, output-manager overwrite policy, orchestrator end-to-end with stubs, module crash isolation, passive mode, authorization gate |

The suite makes **no network requests**: modules are exercised with a fake HTTP
client and HTML fixtures.

## Real scan 1 — `example.com` (public benign example domain)

Command:

```bash
fullrecon -d example.com --authorized --yes --ports-list 80,443
```

| Metric | Result |
|---|---|
| Duration | 5m 50s |
| Subdomains | 452 unique (449 from subdomain.center, 2 Cert Spotter, 2 urlscan, 2 RapidDNS, 1 HackerTarget) |
| Resolving | 2 (`example.com`, `www.example.com`) |
| DNS records | 8 |
| Live endpoints | 4 (HTTP + HTTPS on both hosts) |
| Open ports | 2 (80, 443) |
| Technologies | Cloudflare |
| URLs | 4 |
| Findings | 0 high, 2 medium, 2 low |

Verified: directory tree, all 10 report artefacts, output de-duplication, log
file, findings scoring, clean exit code.

**Bugs found and fixed during this run:**

1. TLS handshake failed on every HTTPS site because SNI was omitted when
   certificate verification was disabled.
2. `DnsModule._write` called a module-level function as a method and crashed the
   DNS stage.
3. Port scanning returned duplicates when nmap reported both the hostname and the
   IP section.
4. Live-host discovery probed all 450 non-resolving names, wasting one timeout
   each; it now only probes DNS-validated hosts.
5. DNS enumeration ran full record lookups against unresolved names.

## Real scan 2 — `scanme.nmap.org` (host Nmap explicitly authorizes for testing)

Command:

```bash
fullrecon -d scanme.nmap.org --authorized --yes --top-ports 20 --threads 30 --rate-limit 40
```

| Metric | Result |
|---|---|
| Duration | 2m 40s |
| Subdomains | 3 unique, 1 resolving |
| Ports | 22 (ssh), 80 (http) — correctly attributed to the hostname |
| Live endpoints | 2 after de-duplication fix |
| Technologies | Apache 2.4.7, Google Analytics |
| URLs | 42 (32 from Wayback, 10 from crawl/robots) |
| JavaScript | 3 files analysed |
| Content paths | 4 (includes `.svn` on 401/403 detection) |
| Findings | 0 high, 4 medium, 3 low |

Verified: nmap fallback path, archive harvesting, soft-404 filtering against a
live server, severity calibration (SSH reported as *administrative*, not
*high-risk*), report generation.

**Bugs found and fixed during this run:**

6. Every port was rated HIGH, including SSH on 22; severity now distinguishes
   unauthenticated database/cache APIs (high) from administrative services
   (medium).
7. Port results were keyed by resolved IP instead of the scanned hostname.
8. `http://host/` and `http://host:80/` appeared as two separate live endpoints.
9. Content discovery could run 1200 probes per host with no time estimate; it is
   now budgeted per base URL and prints an ETA.

## Linux installation test — Ubuntu 26.04 (WSL2)

```
$ ./install.sh --venv
[*] installer mode: venv
[*] checking Python...
[+] python: Python 3.14.4 (/usr/bin/python3)
[*] checking pip...
[+] pip: pip 25.1.1
[*] creating virtual environment at ./.venv
[*] installing FullRecon into ./.venv
[+] installed into /tmp/frtest/.venv
[+] command: /tmp/frtest/.venv/bin/fullrecon
[!] /tmp/frtest/.venv/bin is not on your PATH.
[*] verifying installation...
[+] verified: FullRecon 1.0.0 (https://github.com/Abobakr-1/FullRecon)
[+] all modules load correctly
[*] checking optional external tools
[+] curl found
[!] optional tools not installed: nmap subfinder jq
```

Then, from an unrelated directory:

```
$ cd /tmp && /tmp/frtest/.venv/bin/fullrecon -d example.com --authorized --yes --subdomains
Resolved hosts      2
findings: HIGH 0 | MEDIUM 0 | LOW 0 | INFO 0
results  /tmp/scan-out/example.com
```

Confirmed: the console script runs from any directory, reports are written, and
the tool exits 0.

**Installer bugs found and fixed:**

10. The installer aborted when system pip was missing, even in `--venv` mode.
    It now tries `ensurepip`, then `apt-get`, and only fails with actionable
    instructions.
11. A missing `python3-venv` package produced a bare `die`; the installer now
    attempts to install `python3-<ver>-venv` and retries, falling back to a clear
    message with two alternatives.

## Cross-platform and version checks

| Check | Python 3.9.25 | Python 3.13.2 | Python 3.14.10 |
|---|---|---|---|
| `pip install -e ".[dev]"` | pass | pass | pass |
| `pytest -q` | 129 passed | 129 passed | 129 passed |
| `fullrecon --version` | pass | pass | pass |
| `fullrecon --list-modules` | pass | pass | pass |
| Real scan + report files | pass | pass | pass |
| OS | Windows 11 | Windows 11 | Windows 11 / Ubuntu 26.04 (WSL) |

Python 3.9 is the floor stated in `pyproject.toml`; it was verified with a real
3.9.25 interpreter (via `uv`), not inferred. Source is parsed with
`ast.parse(..., feature_version=(3, 8))` to confirm the syntax floor, and every
module using PEP 604 unions carries `from __future__ import annotations`.

## Clean-clone install test (the commands users will actually type)

```bash
git clone https://github.com/Abobakr-1/FullRecon.git
cd FullRecon
chmod +x install.sh
./install.sh --venv
```

Run in Ubuntu 26.04 against the public repository:

```
[+] python: Python 3.14.4 (/usr/bin/python3)
[+] pip: pip 25.1.1
[*] installing FullRecon into ./.venv
[+] installed into /tmp/clonetest/.venv
[+] verified: FullRecon 1.0.0 (https://github.com/Abobakr-1/FullRecon)
[+] all modules load correctly
```

Then, from `/tmp` (a different directory than the clone):

```
$ fullrecon -d example.com --authorized --yes --subdomains
 Duration            54.5s
 Subdomains          453
 Resolved hosts      2
 results  /tmp/gh-test-out/example.com
 exit=0
```

Reports were present: `summary.txt`, `report.json`, `report.html`, `manifest.json`.
`git clone` also preserved the executable bit on `install.sh` (`-rwxr-xr-x`).

## Known limitations observed in testing

- crt.sh returned HTTP 502 twice and AlienVault OTX rate-limited anonymous
  requests. Both were handled gracefully: zero results, an error recorded in
  `sources_summary.json`, and the scan continued.
- Wayback's CDX API is slow (20-40s). It is now capped at 30s and treated as
  optional.
- Wildcard DNS detection did not trigger on the test domains, so the wildcard
  path is covered by unit tests rather than a live scan.