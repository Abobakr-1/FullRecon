"""A. Subdomain enumeration from public sources + DNS validation.

Sources are queried in parallel; every failure is isolated so one dead API
never blocks the pipeline.  All results are normalised to the target domain.
"""

from __future__ import annotations

import json
import random
import re
import string
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import quote

from ..core import tools
from ..core.context import ModuleContext
from ..utils.helpers import dedupe, read_lines
from ..utils.validators import in_domain, is_ip, is_valid_hostname, normalise_target

try:  # pragma: no cover
    import dns.resolver  # type: ignore
    _HAS_DNS = True
except Exception:  # pragma: no cover
    dns = None  # type: ignore
    _HAS_DNS = False

HOSTNAME_RE = re.compile(r"^[a-z0-9_]([a-z0-9_.-]*[a-z0-9_])?$")


# ---------------------------------------------------------------------------
# Source implementations: each returns a list of raw hostname strings
# ---------------------------------------------------------------------------


class Sources:
    """Static HTTP-based passive sources."""

    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.http = ctx.http

    # -- helpers -------------------------------------------------------
    def _get(self, url: str, timeout: Optional[float] = None, headers: Optional[Dict[str, str]] = None):
        # Passive sources are third-party public datasets, not the scan target.
        return self.http.get(
            url,
            timeout=timeout or max(self.ctx.cfg.timeout, 25),
            headers=headers,
            external=True,
        )

    def _json(self, url: str, headers: Optional[Dict[str, str]] = None):
        resp = self._get(url, headers=headers)
        if not resp.ok or not resp.body.strip():
            return None
        try:
            return json.loads(resp.body)
        except (json.JSONDecodeError, ValueError):
            return None

    # -- sources -------------------------------------------------------
    def crtsh(self, domain: str) -> List[str]:
        """Certificate Transparency via crt.sh (JSON)."""
        names: List[str] = []
        url = (
            "https://crt.sh/?q=%25."
            + quote(domain)
            + "&output=json&exclude=expired&deduplicate=Y"
        )
        data = self._json(url)
        if not data:
            return names
        if isinstance(data, dict):  # error payload
            return names
        for entry in data:
            for field in ("name_value", "common_name"):
                value = entry.get(field) or ""
                for name in str(value).split("\n"):
                    name = name.strip().lower().lstrip("*.").rstrip(".")
                    if name:
                        names.append(name)
        return names

    def certspotter(self, domain: str) -> List[str]:
        names: List[str] = []
        url = (
            "https://api.certspotter.com/v1/issuances?domain="
            + quote(domain)
            + "&include_subdomains=true&expand=dns_names"
        )
        data = self._json(url)
        if not isinstance(data, list):
            return names
        for entry in data:
            if not isinstance(entry, dict):
                continue
            for name in entry.get("dns_names", []) or []:
                name = str(name).strip().lower().lstrip("*.").rstrip(".")
                if name:
                    names.append(name)
        return names

    def hackertarget(self, domain: str) -> List[str]:
        resp = self._get(f"https://api.hackertarget.com/hostsearch/?q={quote(domain)}")
        names = []
        if not resp.ok:
            return names
        for line in resp.body.splitlines():
            if "," in line:
                host = line.split(",")[0].strip().lower()
                if host:
                    names.append(host)
        return names

    def subdomain_center(self, domain: str) -> List[str]:
        data = self._json(f"https://api.subdomain.center/?domain={quote(domain)}")
        if not isinstance(data, list):
            return []
        return [str(n).strip().lower().lstrip("*.").rstrip(".") for n in data]

    def urlscan(self, domain: str) -> List[str]:
        names: List[str] = []
        data = self._json(
            f"https://urlscan.io/api/v1/search/?q=domain:{quote(domain)}&size=100"
        )
        if not isinstance(data, dict):
            return names
        for result in data.get("results", []) or []:
            page = result.get("page") or {}
            for key in ("domain", "apexDomain"):
                host = str(page.get(key) or "").strip().lower()
                if host:
                    names.append(host)
            task = result.get("task") or {}
            host = str(task.get("domain") or "").strip().lower()
            if host:
                names.append(host)
        return names

    def otx(self, domain: str) -> List[str]:
        names: List[str] = []
        data = self._json(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{quote(domain)}/passive_dns"
        )
        if not isinstance(data, dict):
            return names
        for record in data.get("passive_dns", []) or []:
            host = str(record.get("hostname") or "").strip().lower()
            if host:
                names.append(host)
        return names

    def rapiddns(self, domain: str) -> List[str]:
        resp = self._get(f"https://rapiddns.io/subdomain/{quote(domain)}?full=1")
        if not resp.ok:
            return []
        names = []
        for match in re.finditer(r"<td>([A-Za-z0-9_.*-]+\." + re.escape(domain) + r")</td>", resp.body, re.IGNORECASE):
            names.append(match.group(1).strip().lower().lstrip("*."))
        return names

    def anubis(self, domain: str) -> List[str]:
        data = self._json(f"https://jldc.me/anubis/subdomains/{quote(domain)}")
        if not isinstance(data, list):
            return []
        return [str(n).strip().lower().lstrip("*.") for n in data]

    def wayback(self, domain: str) -> List[str]:
        """Hostnames observed in Wayback Machine CDX records."""
        url = (
            f"https://web.archive.org/cdx/search/cdx?url=*.{quote(domain)}"
            "&output=json&collapse=urlkey&fl=original&limit=1500"
        )
        data = self._json(url, headers=None)
        if not isinstance(data, list):
            return []
        names: List[str] = []
        from urllib.parse import urlsplit

        for row in data[1:]:
            if not row:
                continue
            try:
                host = (urlsplit(row[0]).hostname or "").lower()
            except ValueError:
                continue
            if host:
                names.append(host)
        return names

    def commoncrawl(self, domain: str) -> List[str]:
        """Hostnames from the latest Common Crawl index (multi-line JSON)."""
        index = self._latest_commoncrawl_index()
        if not index:
            return []
        url = (
            f"http://index.commoncrawl.org/{index}-index?url=*.{quote(domain)}/*"
            "&output=json&limit=3000&fl=url"
        )
        resp = self._get(url, timeout=45)
        if not resp.ok or not resp.body.strip():
            return []
        from urllib.parse import urlsplit

        names = []
        for line in resp.body.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            try:
                host = (urlsplit(record.get("url", "")).hostname or "").lower()
            except ValueError:
                continue
            if host:
                names.append(host)
        return names

    def _latest_commoncrawl_index(self) -> Optional[str]:
        cached = getattr(Sources, "_cc_index", None)
        if cached:
            return cached
        data = self._json("https://index.commoncrawl.org/collinfo.json", headers={"Accept": "application/json"})
        if not isinstance(data, list) or not data:
            return None
        index_id = ""
        for entry in data:
            if isinstance(entry, dict) and entry.get("id"):
                index_id = str(entry["id"])
                break
        Sources._cc_index = index_id or None  # type: ignore[attr-defined]
        return Sources._cc_index  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------


class SubdomainModule:
    name = "subdomains"
    label = "Subdomain Enumeration"

    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.state = ctx.state
        self.sources = Sources(ctx)
        self.source_map: Dict[str, Callable[[str], List[str]]] = {
            "crtsh": self.sources.crtsh,
            "certspotter": self.sources.certspotter,
            "hackertarget": self.sources.hackertarget,
            "subdomain_center": self.sources.subdomain_center,
            "urlscan": self.sources.urlscan,
            "otx": self.sources.otx,
            "rapiddns": self.sources.rapiddns,
            "anubis": self.sources.anubis,
            "wayback": self.sources.wayback,
            "commoncrawl": self.sources.commoncrawl,
        }

    # ------------------------------------------------------------------
    def run(self) -> Dict[str, object]:
        ctx = self.ctx
        cfg = ctx.cfg
        domain = cfg.domain

        selected = [s for s in cfg.subdomain_sources if s in self.source_map]
        unknown = [s for s in cfg.subdomain_sources if s not in self.source_map]
        for name in unknown:
            ctx.warn(f"unknown subdomain source '{name}' ignored")

        ctx.emit(f"Querying {len(selected)} passive source(s) in parallel")
        per_source: Dict[str, List[str]] = {}
        errors: Dict[str, str] = {}

        with ThreadPoolExecutor(max_workers=max(1, min(len(selected), 10))) as pool:
            futures = {pool.submit(self._guarded, name, domain): name for name in selected}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    raw_names, error = future.result()
                except Exception as exc:  # noqa: BLE001
                    raw_names, error = [], str(exc)
                if error:
                    errors[name] = error
                    ctx.debug("source %s failed: %s", name, error)
                cleaned = self._normalise(raw_names, domain)
                per_source[name] = cleaned
                if cleaned:
                    ctx.emit(f"  {name:<16} {len(cleaned):>5} hostnames")
                else:
                    ctx.emit(f"  {name:<16} {'-':>5} (no data)")

        # External binaries: subfinder and assetfinder add sources FullRecon's
        # built-in list does not cover. Each failure is isolated and reported.
        if cfg.use_external_tools:
            per_source.update(self._external_sources(domain))

        # Optional brute force from a wordlist.
        if cfg.subdomain_bruteforce and cfg.subdomain_wordlist:
            brute = self._bruteforce(domain, cfg.subdomain_wordlist)
            if brute:
                per_source["bruteforce"] = brute
                ctx.emit(f"  {'bruteforce':<16} {len(brute):>5} hostnames")

        all_hosts = dedupe(
            [h for names in per_source.values() for h in names] + [domain],
            lowercase=True,
        )
        all_hosts = [h for h in all_hosts if ctx.in_scope(h)]
        if len(all_hosts) > cfg.max_subdomains:
            ctx.warn(
                f"limiting subdomains to {cfg.max_subdomains} "
                f"(found {len(all_hosts)})"
            )
            all_hosts = all_hosts[: cfg.max_subdomains]

        self.state.subdomains = per_source
        if errors:
            for name, error in errors.items():
                self.state.errors.append(f"subdomains/{name}: {error}")

        resolved, unresolved, wildcard = self._validate(all_hosts, domain)
        self.state.resolved_subdomains = resolved
        self.state.unresolved_subdomains = unresolved
        self.state.wildcard = wildcard

        self._write(per_source, all_hosts, resolved, unresolved, wildcard, errors)
        ctx.emit(
            f"Subdomains: {len(all_hosts)} unique, {len(resolved)} resolve, "
            f"{len(unresolved)} unresolved"
        )
        if wildcard.get("enabled"):
            ctx.warn(f"wildcard DNS detected: {wildcard.get('detail')}")

        return {
            "unique": len(all_hosts),
            "resolved": len(resolved),
            "unresolved": len(unresolved),
            "sources": {k: len(v) for k, v in per_source.items() if v},
            "wildcard": wildcard.get("enabled", False),
        }

    # ------------------------------------------------------------------
    def _external_sources(self, domain: str) -> Dict[str, List[str]]:
        """Run configured external enumerators; return source -> hostnames."""
        found: Dict[str, List[str]] = {}
        timeout = min(self.ctx.cfg.external_tool_timeout, 240.0)

        if self.ctx.cfg.subfinder_enabled and tools.tool_available("subfinder"):
            result = tools.subfinder(domain, all_sources=True, timeout=timeout)
            if result.ok:
                names = self._normalise(result.items, domain)
                found["subfinder"] = names
                self.ctx.emit(f"  {'subfinder':<16} {len(names):>5} hostnames")
            else:
                self.ctx.debug("subfinder failed: %s", result.error)
                self.state.errors.append(f"subdomains/subfinder: {result.error}")

        if self.ctx.cfg.assetfinder_enabled and tools.tool_available("assetfinder"):
            result = tools.assetfinder(domain, timeout=min(timeout, 120))
            if result.ok:
                names = self._normalise(result.items, domain)
                found["assetfinder"] = names
                self.ctx.emit(f"  {'assetfinder':<16} {len(names):>5} hostnames")
            else:
                self.ctx.debug("assetfinder failed: %s", result.error)
        return found

    def _guarded(self, name: str, domain: str) -> Tuple[List[str], str]:
        try:
            return self.source_map[name](domain), ""
        except Exception as exc:  # noqa: BLE001
            return [], f"{type(exc).__name__}: {exc}"

    def _normalise(self, names: Iterable[str], domain: str) -> List[str]:
        cleaned: List[str] = []
        for name in names:
            if not name:
                continue
            value = str(name).strip().lower().strip(".")
            value = value.lstrip("*.").replace(" ", "")
            if "@" in value:
                value = value.split("@")[-1]
            if not value or "." not in value:
                continue
            if not in_domain(value, domain):
                continue
            if value not in cleaned and is_valid_hostname(value):
                cleaned.append(value)
        return cleaned

    # ------------------------------------------------------------------
    def _resolver(self):
        if not _HAS_DNS:
            return None
        resolver = dns.resolver.Resolver(configure=True)
        resolver.lifetime = 3
        resolver.timeout = 1.5
        return resolver

    def _lookup(self, host: str, resolver) -> bool:
        if resolver is not None:
            try:
                answers = resolver.resolve(host, "A", raise_on_no_answer=False)
                return answers.rrset is not None
            except Exception:
                try:
                    answers = resolver.resolve(host, "CNAME", raise_on_no_answer=False)
                    return answers.rrset is not None
                except Exception:
                    return False
        import socket

        try:
            socket.getaddrinfo(host, None)
            return True
        except (socket.gaierror, UnicodeError):
            return False

    def _wildcard_probe(self, domain: str, resolver) -> Optional[str]:
        """Return the wildcard address if random names resolve."""
        for _ in range(3):
            token = "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
            probe = f"{token}.{domain}"
            if self._lookup(probe, resolver):
                if resolver is not None:
                    try:
                        answers = resolver.resolve(probe, "A")
                        return str(next(iter(answers)))
                    except Exception:
                        return "detected"
                return "detected"
        return None

    def _validate(self, hosts: List[str], domain: str):
        cfg = self.ctx.cfg
        wildcard_addr = None
        resolver = self._resolver()
        if cfg.resolve_subdomains and hosts:
            wildcard_addr = self._wildcard_probe(domain, resolver)

        resolved: List[str] = []
        unresolved: List[str] = []
        if not cfg.resolve_subdomains:
            self.ctx.warn("subdomain DNS validation disabled (--no-resolve)")
            return list(hosts), [], {"enabled": bool(wildcard_addr)}

        def check(host: str) -> Tuple[str, bool]:
            return host, self._lookup(host, resolver)

        workers = max(1, min(cfg.dns_threads, 40))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for host, ok in pool.map(check, hosts):
                (resolved if ok else unresolved).append(host)

        wildcard = {"enabled": bool(wildcard_addr), "address": wildcard_addr}
        if wildcard_addr:
            wildcard["detail"] = f"*.{domain} resolves to {wildcard_addr}"
        return resolved, unresolved, wildcard

    def _bruteforce(self, domain: str, wordlist: str) -> List[str]:
        words = [w for w in read_lines(wordlist) if w and not w.startswith("#")]
        if not words:
            self.ctx.warn(f"bruteforce wordlist is empty or unreadable: {wordlist}")
            return []
        self.ctx.emit(f"Brute-forcing {len(words)} labels from {wordlist}")
        candidates = [f"{w.strip('.').lower()}.{domain}" for w in words]
        resolver = self._resolver()
        found: List[str] = []
        workers = max(1, min(self.ctx.cfg.dns_threads, 40))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for host, ok in pool.map(lambda h: (h, self._lookup(h, resolver)), candidates):
                if ok:
                    found.append(host)
        return dedupe(found)

    # ------------------------------------------------------------------
    def _write(self, per_source, all_hosts, resolved, unresolved, wildcard, errors) -> None:
        out = self.ctx.out
        out.write("subdomains", "all_subdomains.txt", all_hosts)
        out.write("subdomains", "unique_subdomains.txt", dedupe(sorted(all_hosts)))
        out.write("subdomains", "resolved_subdomains.txt", sorted(resolved))
        out.write("subdomains", "unresolved_subdomains.txt", sorted(unresolved))

        per_source_lines = []
        for source in sorted(per_source):
            for host in per_source[source]:
                per_source_lines.append(f"{host}\t{source}")
        out.write("subdomains", "by_source.txt", per_source_lines)

        if wildcard.get("enabled"):
            out.write("subdomains", "wildcard_dns.txt", [wildcard.get("detail", "detected")])
        out.write_json("subdomains", "sources_summary.json", {
            "counts": {k: len(v) for k, v in per_source.items()},
            "errors": errors,
            "wildcard": wildcard,
            "total_unique": len(all_hosts),
        })
        out.write_raw("subdomain_sources.json", [
            json.dumps({"source": k, "count": len(v)}) for k, v in sorted(per_source.items())
        ])


__all__ = ["SubdomainModule", "Sources"]