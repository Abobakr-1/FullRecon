"""Professional command-line interface for FullRecon."""

from __future__ import annotations

import argparse
import os
import sys
import textwrap
from pathlib import Path
from typing import List, Optional, Sequence

from . import BANNER, __author__, __url__, __version__
from .config import Config, default_config_path, merge
from .core.orchestrator import ALL_MODULES, MODULE_GROUPS, Orchestrator
from .core.output_manager import OutputExists
from .utils.colors import Colors
from .utils.logger import enable_verbose, get_logger, silence_external
from .utils.validators import ValidationError, normalise_target, validate_target


EXAMPLES = """
examples:
  fullrecon -d example.com                      standard recon pipeline
  fullrecon -d example.com --full               every module, incl. content discovery
  fullrecon -d example.com --passive            passive sources + DNS only
  fullrecon -d example.com --active             skip passive enumeration
  fullrecon -d example.com --subdomains         subdomain enumeration only
  fullrecon -d example.com --ports --threads 40 targeted port scan
  fullrecon -d example.com --api --js           API + JavaScript analysis
  fullrecon -d example.com -o /tmp/results      custom output directory
  fullrecon -d example.com --scope-file scope.txt
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fullrecon",
        description="FullRecon - automated reconnaissance framework for authorized testing.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
    )
    parser.add_argument("-h", "--help", action="help", help="show this help message and exit")
    parser.add_argument("-V", "--version", action="version",
                        version=f"FullRecon {__version__} ({__url__})")

    target = parser.add_argument_group("target")
    target.add_argument("-d", "--domain", metavar="DOMAIN",
                        help="target domain, e.g. example.com (required for scans)")
    target.add_argument("-o", "--output", metavar="DIR", default=None,
                        help="results directory (default: FullRecon-Results)")
    target.add_argument("--timestamped", action="store_true",
                        help="write results into a timestamped subfolder")
    target.add_argument("--overwrite", action="store_true",
                        help="replace an existing result directory without asking")

    mode = parser.add_argument_group("scan modes")
    mode.add_argument("--full", action="store_true",
                      help="run every module including content discovery")
    mode.add_argument("--passive", action="store_true",
                      help="passive reconnaissance only (no traffic to the target)")
    mode.add_argument("--active", action="store_true",
                      help="active reconnaissance only (skip passive enumeration)")

    single = parser.add_argument_group("single-module shortcuts")
    single.add_argument("--subdomains", action="store_true", help="subdomain enumeration only")
    single.add_argument("--dns", action="store_true", help="DNS enumeration only")
    single.add_argument("--ports", action="store_true", help="port scanning only")
    single.add_argument("--live", action="store_true", help="live host discovery only")
    single.add_argument("--urls", action="store_true", help="URL discovery only")
    single.add_argument("--api", action="store_true", help="API discovery only")
    single.add_argument("--js", action="store_true", help="JavaScript analysis only")
    single.add_argument("--content", action="store_true", help="content discovery only")
    single.add_argument("--tech", action="store_true", help="technology detection only")
    single.add_argument("--whois-only", dest="whois_only", action="store_true",
                        help="WHOIS/RDAP lookup only")
    single.add_argument("--asn-only", dest="asn_only", action="store_true",
                        help="ASN / network mapping only")
    single.add_argument("--headers-only", dest="headers_only", action="store_true",
                        help="security header audit only")
    single.add_argument("--waf-only", dest="waf_only", action="store_true",
                        help="WAF/CDN detection only")
    single.add_argument("--wp", dest="wordpress_only", action="store_true",
                        help="WordPress enumeration only")

    perf = parser.add_argument_group("performance")
    perf.add_argument("-t", "--threads", type=int, metavar="N", default=None,
                      help="worker threads (default: 15)")
    perf.add_argument("--rate-limit", type=float, metavar="RPS", default=None,
                      help="max requests per second per host (default: 20)")
    perf.add_argument("--timeout", type=float, metavar="SEC", default=None,
                      help="per-request timeout in seconds (default: 10)")
    perf.add_argument("--retries", type=int, metavar="N", default=None,
                      help="retries per failed request (default: 1)")
    perf.add_argument("--proxy", metavar="URL", default=None,
                      help="HTTP(S) proxy, e.g. http://127.0.0.1:8080")

    scan = parser.add_argument_group("scanning options")
    scan.add_argument("--ports-list", metavar="LIST", default=None,
                      help="comma separated ports or ranges, e.g. 80,443,8000-8100")
    scan.add_argument("--top-ports", type=int, metavar="N", default=None,
                      help="scan the N most common ports")
    scan.add_argument("--no-nmap", action="store_true",
                      help="never use nmap, always use the built-in TCP scanner")
    scan.add_argument("--no-resolve", action="store_true",
                      help="skip DNS validation of discovered subdomains")
    scan.add_argument("--no-crawl", action="store_true", help="disable web crawling")
    scan.add_argument("--no-archives", action="store_true",
                      help="disable Wayback/Common Crawl lookups")
    scan.add_argument("--no-content", action="store_true",
                      help="disable content discovery in the full pipeline")
    scan.add_argument("--crawl-depth", type=int, metavar="N", default=None,
                      help="crawl depth (default: 2)")
    scan.add_argument("--max-pages", type=int, metavar="N", default=None,
                      help="maximum pages to crawl per scan (default: 200)")
    scan.add_argument("--wordlist", metavar="FILE", default=None,
                      help="wordlist for content discovery")
    scan.add_argument("--subdomain-wordlist", metavar="FILE", default=None,
                      help="wordlist for subdomain brute force (needs --bruteforce)")
    scan.add_argument("--bruteforce", action="store_true",
                      help="also brute-force subdomains using --subdomain-wordlist")
    scan.add_argument("--sources", metavar="LIST", default=None,
                      help="comma separated passive sources "
                           "(crtsh,certspotter,hackertarget,subdomain_center,urlscan,"
                           "rapiddns,otx,wayback,commoncrawl,anubis)")
    scan.add_argument("--verify-tls", action="store_true",
                      help="require valid TLS certificates (off by default for recon)")

    ext = parser.add_argument_group("external tools")
    ext.add_argument("--no-external-tools", action="store_true",
                     help="never call external binaries, use only built-in logic")
    ext.add_argument("--external-timeout", type=float, metavar="SEC", default=None,
                     help="timeout for each external tool call (default: 240)")
    ext.add_argument("--ffuf", action="store_true",
                     help="use ffuf for subdomain fuzzing and content discovery")
    ext.add_argument("--httpx", dest="httpx", action="store_true",
                     help="pre-probe live hosts with httpx when installed")
    ext.add_argument("--whatweb", dest="whatweb", action="store_true",
                     help="add whatweb technology detection when installed")
    ext.add_argument("--no-waf-probes", action="store_true",
                     help="fingerprint WAFs by signature only, send no probe requests")
    ext.add_argument("--check-tools", action="store_true",
                     help="report which external recon tools are installed, then exit")
    ext.add_argument("--org", metavar="NAME", default=None,
                     help="organisation name for amass intel -org lookup")

    scope = parser.add_argument_group("scope control")
    scope.add_argument("--scope-file", metavar="FILE", default=None,
                       help="file with in-scope hosts/domains/CIDRs (one per line, ! to exclude)")
    scope.add_argument("--in-scope", metavar="LIST", default=None,
                       help="comma separated extra in-scope domains/CIDRs")
    scope.add_argument("--out-of-scope", metavar="LIST", default=None,
                       help="comma separated domains/CIDRs to never touch")
    scope.add_argument("--allowed-ports", metavar="LIST", default=None,
                       help="restrict every module to these ports (comma separated)")

    general = parser.add_argument_group("general")
    general.add_argument("-c", "--config", metavar="FILE", default=None,
                         help="JSON config file (see config/fullrecon.example.json)")
    general.add_argument("-v", "--verbose", action="store_true", help="verbose output")
    general.add_argument("-q", "--quiet", action="store_true", help="minimal output")
    general.add_argument("--no-color", action="store_true", help="disable coloured output")
    general.add_argument("--yes", action="store_true",
                         help="assume yes for overwrite prompts (non-interactive runs)")
    general.add_argument("--authorized", action="store_true",
                         help="confirm you are authorised to test this target "
                              "(required in non-interactive environments)")
    general.add_argument("--list-modules", action="store_true",
                         help="list available modules and exit")
    return parser


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _split(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [part.strip() for part in value.replace(";", ",").split(",") if part.strip()]


def parse_ports(value: Optional[str]) -> List[int]:
    """Parse ``80,443,8000-8100`` (also accepts spaces)."""
    if not value:
        return []
    ports: List[int] = []
    for token in value.replace(" ", ",").split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            start, _, end = token.partition("-")
            try:
                low, high = int(start), int(end)
            except ValueError:
                raise ValidationError(f"invalid port range: {token!r}")
            if low > high:
                low, high = high, low
            ports.extend(range(max(1, low), min(high, 65535) + 1))
        else:
            try:
                port = int(token)
            except ValueError:
                raise ValidationError(f"invalid port: {token!r}")
            if 0 < port < 65536:
                ports.append(port)
    return sorted(set(ports))


def top_ports(count: int) -> List[int]:
    from .config import DEFAULT_PORTS

    return list(DEFAULT_PORTS[: max(1, count)])


def selected_modules(args: argparse.Namespace) -> Optional[List[str]]:
    single = {
        "subdomains": args.subdomains,
        "dns": args.dns,
        "ports": args.ports,
        "live": args.live,
        "urls": args.urls,
        "api": args.api,
        "javascript": args.js,
        "content": args.content,
        "technologies": args.tech,
        "whois": args.whois_only,
        "asn": args.asn_only,
        "headers": args.headers_only,
        "waf": args.waf_only,
        "wordpress": args.wordpress_only,
    }
    picked = [name for name, flag in single.items() if flag]
    if picked:
        # A single-module run still needs DNS/subdomain inputs where relevant.
        requires_hosts = {
            "live", "urls", "api", "javascript", "content", "technologies",
            "ports", "headers", "waf", "wordpress",
        }
        if any(p in requires_hosts for p in picked) and "subdomains" not in picked:
            picked = ["subdomains", "dns"] + picked
        return picked
    if args.full:
        return list(MODULE_GROUPS["full"])
    if args.passive:
        return list(MODULE_GROUPS["passive"])
    if args.active:
        return list(MODULE_GROUPS["active"])
    return None


def build_config(args: argparse.Namespace) -> Config:
    cfg = Config()

    config_path = args.config or default_config_path()
    if config_path:
        if not Path(config_path).is_file():
            raise ValidationError(f"config file not found: {config_path}")
        file_cfg = Config.load_file(config_path)
        cfg = merge(cfg, file_cfg)

    domain = args.domain
    if not domain:
        raise ValidationError("a target is required: use -d/--domain")
    cfg.domain = validate_target(domain)

    if args.output:
        cfg.out_dir = args.output
    if args.timestamped:
        cfg.timestamped = True
    if args.overwrite:
        cfg.overwrite = True
    if args.threads is not None:
        if args.threads < 1:
            raise ValidationError("--threads must be >= 1")
        cfg.threads = args.threads
    if args.rate_limit is not None:
        if args.rate_limit < 0:
            raise ValidationError("--rate-limit cannot be negative")
        cfg.rate_limit = args.rate_limit
    if args.timeout is not None:
        cfg.timeout = max(1.0, args.timeout)
    if args.retries is not None:
        cfg.retries = max(0, args.retries)
    if args.proxy:
        cfg.proxy = args.proxy
    if args.verify_tls:
        cfg.verify_tls = True
    if args.passive:
        cfg.passive_only = True
    if args.active:
        cfg.active_only = True

    ports = parse_ports(args.ports_list)
    if ports:
        cfg.ports = ports
    elif args.top_ports:
        cfg.ports = top_ports(args.top_ports)

    if args.no_nmap:
        cfg.use_nmap = False
    if args.no_resolve:
        cfg.resolve_subdomains = False
    if args.no_crawl:
        cfg.crawl_depth = 0
    if args.no_archives:
        cfg.wayback_urls = False
        cfg.commoncrawl_urls = False
    if args.no_content:
        cfg.content_discovery = False
    if args.no_external_tools:
        cfg.use_external_tools = False
    if args.external_timeout is not None:
        cfg.external_tool_timeout = max(10.0, args.external_timeout)
    if args.ffuf:
        cfg.ffuf_enabled = True
    if args.httpx:
        cfg.httpx_enabled = True
    if args.whatweb:
        cfg.whatweb_enabled = True
    if args.no_waf_probes:
        cfg.waf_probes = False
    if args.org:
        org_scope = dict(cfg.scope or {})
        org_scope["organization"] = args.org
        cfg.scope = org_scope
    if args.crawl_depth is not None:
        cfg.crawl_depth = max(0, args.crawl_depth)
    if args.max_pages is not None:
        cfg.crawl_max_pages = max(1, args.max_pages)
    if args.wordlist:
        cfg.content_wordlist = args.wordlist
        cfg.content_discovery = True
    if args.subdomain_wordlist:
        cfg.subdomain_wordlist = args.subdomain_wordlist
    if args.bruteforce:
        cfg.subdomain_bruteforce = True
    sources = _split(args.sources)
    if sources:
        cfg.subdomain_sources = sources

    scope_data = dict(cfg.scope or {})
    scope_data.setdefault("in_scope", [])
    scope_data.setdefault("out_of_scope", [])
    if args.in_scope:
        scope_data["in_scope"] = list(scope_data["in_scope"]) + _split(args.in_scope)
    if args.out_of_scope:
        scope_data["out_of_scope"] = list(scope_data["out_of_scope"]) + _split(args.out_of_scope)
    if args.scope_file:
        if not Path(args.scope_file).is_file():
            raise ValidationError(f"scope file not found: {args.scope_file}")
        scope_data["file"] = args.scope_file
    allowed = parse_ports(args.allowed_ports)
    if allowed:
        scope_data["allowed_ports"] = allowed
    cfg.scope = scope_data

    cfg.resolved()
    return cfg


# ---------------------------------------------------------------------------
# entrypoint
# ---------------------------------------------------------------------------


def _print_tools() -> None:
    """Report which external recon tools are installed."""
    from .core import tools as toolmod

    report = toolmod.summary()
    installed = report["installed"]
    missing = report["missing"]
    registry = report["registry"]

    print()
    print(Colors.bold("External recon tools"))
    print()
    if installed:
        print(Colors.ok("  installed:"))
        for name in sorted(installed):
            print(f"    {Colors.green('+')} {name:<14} {Colors.grey(registry.get(name, ''))}")
    if missing:
        print()
        print(Colors.warn("  not installed (optional):"))
        for name in sorted(missing):
            print(f"    {Colors.grey('-')} {name:<14} {Colors.grey(registry.get(name, ''))}")
    print()
    print(Colors.grey("  FullRecon works without any of these; each unlocks extra coverage."))
    print(Colors.grey("  Install: go install github.com/projectdiscovery/<tool>/v2/cmd/<tool>@latest"))
    print()


def _print_modules() -> None:
    from .core.orchestrator import PIPELINE

    print(Colors.bold("\nAvailable modules\n"))
    for key, cls, passive_safe, _ in PIPELINE:
        mode = "passive-safe" if passive_safe else "active"
        print(f"  {key:<14} {cls.label:<28} {Colors.grey(mode)}")
    print("\nGroups:")
    for name, modules in MODULE_GROUPS.items():
        print(f"  {name:<14} {', '.join(modules)}")
    print()


def _prompt_overwrite(path: Path) -> bool:
    if not sys.stdin.isatty():
        return False
    try:
        answer = input(
            Colors.warn(f"\nResults already exist in {path}. Overwrite? [y/N] ")
        ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in ("y", "yes")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.no_color or os.environ.get("NO_COLOR"):
        Colors.configure(False)
    if args.quiet:
        import logging

        logging.getLogger("fullrecon").setLevel(logging.WARNING)

    silence_external()
    log = get_logger("fullrecon")

    if args.list_modules:
        _print_modules()
        return 0

    if args.check_tools:
        _print_tools()
        return 0

    if not args.domain:
        print(Colors.err("error: a target is required (-d/--domain)"), file=sys.stderr)
        print(Colors.grey("run 'fullrecon --help' for usage"), file=sys.stderr)
        return 2

    try:
        cfg = build_config(args)
    except ValidationError as exc:
        print(Colors.err(f"error: {exc}"), file=sys.stderr)
        return 2

    modules = selected_modules(args)

    # Authorization gate: interactive users confirm once; automation must pass
    # --authorized explicitly.  This is a deliberate speed bump, not a lie detector.
    if not args.authorized:
        if sys.stdin.isatty() and not args.yes:
            try:
                answer = input(
                    Colors.warn(
                        f"\nYou are about to scan {cfg.domain}. Only continue if you have "
                        "explicit permission.\nProceed? [y/N] "
                    )
                ).strip().lower()
            except (EOFError, KeyboardInterrupt):
                answer = ""
            if answer not in ("y", "yes"):
                print(Colors.err("aborted: authorization not confirmed"), file=sys.stderr)
                return 3
        elif not args.yes:
            # Non-interactive without --authorized/--yes: require the flag.
            if not os.environ.get("FULLRECON_ACCEPT_AUTHORIZATION") == "1":
                print(
                    Colors.err(
                        "error: non-interactive run requires --authorized "
                        "(or FULLRECON_ACCEPT_AUTHORIZATION=1)"
                    ),
                    file=sys.stderr,
                )
                return 3

    if args.verbose:
        enable_verbose(True)

    orchestrator = Orchestrator(cfg, log)
    try:
        orchestrator.prepare(
            confirm=(lambda path: True) if (args.overwrite or args.yes) else _prompt_overwrite
        )
    except OutputExists as exc:
        print(Colors.err(f"error: {exc}"), file=sys.stderr)
        return 4
    except OSError as exc:
        print(Colors.err(f"error: cannot create results directory: {exc}"), file=sys.stderr)
        return 4

    try:
        state = orchestrator.run(modules)
    except KeyboardInterrupt:
        print(Colors.warn("\ninterrupted - partial results were kept"), file=sys.stderr)
        try:
            orchestrator.state.finished_at = ""
            orchestrator._generate_reports()
        except Exception:  # noqa: BLE001
            pass
        return 130
    except Exception as exc:  # noqa: BLE001
        print(Colors.err(f"fatal: {type(exc).__name__}: {exc}"), file=sys.stderr)
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1

    failed = [k for k, v in state.module_status.items()
              if not v.get("ok") and not v.get("skipped")]
    if failed:
        print(
            Colors.warn(f"warning: {len(failed)} module(s) failed: {', '.join(failed)}"),
            file=sys.stderr,
        )
    return 0


def entrypoint() -> None:  # console_scripts hook
    raise SystemExit(main())


if __name__ == "__main__":  # pragma: no cover
    entrypoint()