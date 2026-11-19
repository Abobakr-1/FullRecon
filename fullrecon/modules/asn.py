"""ASN and network-block intelligence.

Maps the target's addresses to announcing ASNs and prefixes, which is how you
find infrastructure that lives outside the domain tree (shared hosting, cloud
ranges, sibling brands).  Data comes from RIPE Stat's public API, with
``amass intel`` used when the binary is installed.
"""

from __future__ import annotations

import ipaddress
import json
from typing import Any, Dict, List, Optional, Set

from ..core.context import ModuleContext
from ..core import tools
from ..utils.helpers import dedupe
from ..utils.validators import is_ip, is_private_ip

RIPE_PREFIX = "https://stat.ripe.net/data/prefix-overview/data.json"
RIPE_ASN = "https://stat.ripe.net/data/as-overview/data.json"
RIPE_ANNOUNCED = "https://stat.ripe.net/data/announced-prefixes/data.json"


class AsnModule:
    name = "asn"
    label = "ASN / Network Mapping"

    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.state = ctx.state
        self.addresses: Dict[str, List[str]] = {}   # host -> IPs
        self.asns: Dict[int, Dict[str, Any]] = {}
        self.prefixes: List[str] = []
        self.unannounced: List[str] = []

    # ------------------------------------------------------------------
    def _collect_addresses(self) -> Dict[str, List[str]]:
        """Gather host -> IPs from DNS results, then resolve anything missing."""
        mapping: Dict[str, List[str]] = {}
        for host, records in (self.state.dns or {}).items():
            ips = list(records.get("A", []) or []) + list(records.get("AAAA", []) or [])
            ips = [ip for ip in ips if is_ip(ip) and not is_private_ip(ip)]
            if ips:
                mapping[host] = dedupe(ips)

        # The apex may not have been resolved yet.
        if self.ctx.cfg.domain not in mapping:
            from ..core.portscan import PortScanner

            scanner = PortScanner(self.ctx.cfg, self.ctx.scope, self.ctx.log)
            resolved = [ip for ip in scanner.resolve(self.ctx.cfg.domain) if is_ip(ip)]
            if resolved:
                mapping[self.ctx.cfg.domain] = dedupe(resolved)
        return mapping

    # ------------------------------------------------------------------
    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """ASN + prefix for one address via RIPE Stat."""
        result: Dict[str, Any] = {"ip": ip, "asn": None, "holder": "", "prefix": "", "error": ""}
        resp = self.ctx.http.get(f"{RIPE_PREFIX}?resource={ip}", timeout=20, external=True)
        if not resp.ok or not resp.body.strip():
            result["error"] = resp.error or f"HTTP {resp.status}"
            return result
        try:
            data = json.loads(resp.body).get("data", {})
        except json.JSONDecodeError:
            result["error"] = "invalid JSON from RIPE Stat"
            return result

        asns = data.get("asns") or []
        if asns:
            entry = asns[0]
            result["asn"] = entry.get("asn")
            result["holder"] = entry.get("holder", "")
        related = data.get("related_prefixes") or []
        for prefix in related:
            if prefix.get("resource"):
                result["prefix"] = prefix["resource"]
                break
        if not result["prefix"]:
            result["prefix"] = (data.get("block") or {}).get("resource", "")
        return result

    def announced_prefixes(self, asn: int) -> List[str]:
        """All prefixes announced by *asn* (bounded to keep requests sane)."""
        url = f"{RIPE_ANNOUNCED}?resource=AS{asn}"
        resp = self.ctx.http.get(url, timeout=30, external=True)
        if not resp.ok or not resp.body.strip():
            return []
        try:
            payload = json.loads(resp.body).get("data", {})
        except json.JSONDecodeError:
            return []
        return dedupe([
            str(entry.get("prefix", ""))
            for entry in payload.get("prefixes", []) or []
            if entry.get("prefix")
        ])

    # ------------------------------------------------------------------
    def run(self) -> Dict[str, object]:
        ctx = self.ctx
        cfg = ctx.cfg

        addresses = self._collect_addresses()
        self.addresses = addresses
        if not addresses:
            ctx.warn("no public IP addresses available for ASN mapping")
            self._write([], [])
            return {"asns": 0, "prefixes": 0}

        unique_ips = dedupe([ip for ips in addresses.values() for ip in ips])
        ctx.emit(f"Mapping {len(unique_ips)} address(es) to announcing ASNs")

        lookups: List[Dict[str, Any]] = []
        for ip in unique_ips[:40]:
            info = self.lookup_ip(ip)
            lookups.append(info)
            if info["asn"] is not None:
                entry = self.asns.setdefault(
                    int(info["asn"]),
                    {"asn": int(info["asn"]), "holder": info["holder"], "prefixes": [], "ips": []},
                )
                if info["holder"] and not entry["holder"]:
                    entry["holder"] = info["holder"]
                if ip not in entry["ips"]:
                    entry["ips"].append(ip)
                if info["prefix"] and info["prefix"] not in entry["prefixes"]:
                    entry["prefixes"].append(info["prefix"])
            elif info["error"]:
                ctx.debug("ASN lookup failed for %s: %s", ip, info["error"])
            else:
                # The address sits in an unannounced block (e.g. documentation
                # ranges). Record it so the report does not imply full coverage.
                self.unannounced.append(ip)
                ctx.debug("no announcing ASN for %s", ip)

        # Expand the primary ASN(s) so the operator sees the whole netblock.
        extra_prefixes: List[str] = []
        for asn in list(self.asns)[:3]:
            more = self.announced_prefixes(asn)
            if more:
                extra_prefixes.extend(more)
                ctx.emit(f"  AS{asn}: {len(more)} announced prefix(es)")

        # Optional: amass intel gives org -> domains / ASN -> CIDRs.
        amass_org = ""
        amass_domains: List[str] = []
        if cfg.scope.get("organization") and tools.tool_available("amass"):
            result = tools.amass_intel_org(str(cfg.scope["organization"]), timeout=600)
            if result.ok:
                amass_domains = result.items
                ctx.emit(f"  amass intel -org: {len(amass_domains)} related domain(s)")
        elif tools.tool_available("amass"):
            ctx.debug("amass installed but no --org supplied; skipping org intel")

        # amass intel -asn expands each discovered ASN into its CIDR blocks,
        # which RIPE's announced-prefixes call does not always list in full.
        amass_prefixes: List[str] = []
        if tools.tool_available("amass"):
            for asn in list(self.asns)[:3]:
                result = tools.amass_intel_asn(str(asn), timeout=600)
                if result.ok and result.items:
                    amass_prefixes.extend(result.items)
                    ctx.debug("amass intel -asn AS%s: %d entries", asn, len(result.items))
        if amass_prefixes:
            extra_prefixes.extend(amass_prefixes)
            ctx.emit(f"  amass intel -asn: {len(dedupe(amass_prefixes))} CIDR(s)")

        self.prefixes = dedupe(extra_prefixes)
        ctx.emit(
            f"ASN: {len(self.asns)} ASN(s), "
            f"{len(self.prefixes)} announced prefix(es)"
        )
        self.state.asns = {str(k): v for k, v in self.asns.items()}
        self.state.summary["asn"] = {"asns": self.state.asns, "prefixes": self.prefixes}
        self._write(lookups, amass_domains, amass_prefixes)
        return {
            "asns": len(self.asns),
            "prefixes": len(self.prefixes),
            "amass_domains": len(amass_domains),
        }

    # ------------------------------------------------------------------
    def _write(self, lookups: List[Dict[str, Any]], amass_domains: List[str],
               amass_prefixes: Optional[List[str]] = None) -> None:
        out = self.ctx.out

        map_lines = []
        for host, ips in sorted(self.addresses.items()):
            map_lines.append(f"{host}\t{','.join(ips)}")
        out.write("asn", "host_addresses.txt", map_lines)

        asn_lines = []
        for asn in sorted(self.asns):
            entry = self.asns[asn]
            asn_lines.append(f"AS{asn}\t{entry['holder']}")
            for prefix in entry["prefixes"]:
                asn_lines.append(f"  prefix\t{prefix}")
            for ip in entry["ips"]:
                asn_lines.append(f"  address\t{ip}")
        out.write("asn", "asn_info.txt", asn_lines)

        out.write("asn", "announced_prefixes.txt", self.prefixes)
        if self.unannounced:
            # Documented as a coverage gap, not a silent omission.
            out.write("asn", "unannounced_addresses.txt", sorted(self.unannounced))
        detail = [
            f"{entry['ip']}\tAS{entry['asn'] if entry['asn'] is not None else '?'}\t"
            f"{entry.get('holder', '')}\t{entry.get('prefix', '')}"
            for entry in lookups
        ]
        out.write("asn", "ip_asn_map.txt", detail)
        if amass_domains:
            out.write("asn", "amass_related_domains.txt", amass_domains)
        if amass_prefixes:
            out.write("asn", "amass_cidrs.txt", dedupe(amass_prefixes))

        out.write_json("asn", "asn.json", {
            "hosts": self.addresses,
            "asns": {str(k): v for k, v in self.asns.items()},
            "prefixes": self.prefixes,
            "lookups": lookups,
            "amass_related_domains": amass_domains,
        })
