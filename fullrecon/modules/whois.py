"""WHOIS / RDAP module: registration data and infrastructure ownership.

Uses RDAP (the structured, JSON successor to WHOIS) so no system binary is
required.  The IANA bootstrap file maps a TLD to its authoritative RDAP server,
with a small built-in fallback table for when that lookup fails.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from ..core.context import ModuleContext
from ..utils.helpers import dedupe, truncate

# Minimal bootstrap fallback: TLD -> RDAP base URL.
FALLBACK_RDAP = {
    "com": "https://rdap.verisign.com/com/v1",
    "net": "https://rdap.verisign.com/net/v1",
    "org": "https://rdap.publicinterestregistry.org/rdap",
    "io": "https://rdap.identitydigital.services/rdap",
    "co": "https://rdap.nic.co/rdap",
    "dev": "https://www.registry.google/rdap",
    "app": "https://www.registry.google/rdap",
    "info": "https://rdap.identitydigital.services/rdap",
    "me": "https://rdap.nic.me/rdap",
    "xyz": "https://rdap.centralnic.com/xyz",
    "uk": "https://rdap.nominet.uk/uk",
    "de": "https://rdap.denic.de",
    "fr": "https://rdap.nic.fr",
    "nl": "https://rdap.sidn.nl",
    "eu": "https://rdap.eu",
    "ca": "https://rdap.ca.fury.ca/rdap",
    "au": "https://rdap.auda.org.au",
    "jp": "https://rdap.jprs.jp",
}

REDACTED = {"redacted for privacy", "not disclosed", "redacted", "withheld"}


def _rdap_key(domain: str) -> str:
    """Normalise an RDAP label (IDNs are punycode-encoded)."""
    try:
        return domain.encode("idna").decode("ascii").lower()
    except (UnicodeError, AttributeError):
        return (domain or "").lower()


class WhoisModule:
    name = "whois"
    label = "WHOIS / RDAP"

    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.state = ctx.state
        self._bootstrap: Optional[Dict[str, str]] = None

    # ------------------------------------------------------------------
    def _load_bootstrap(self) -> Dict[str, str]:
        """IANA RDAP bootstrap: TLD -> base URL. Cached per process."""
        if self._bootstrap is not None:
            return self._bootstrap
        mapping: Dict[str, str] = dict(FALLBACK_RDAP)
        resp = self.ctx.http.get(
            "https://data.iana.org/rdap/dns.json", timeout=25, external=True
        )
        if resp.ok and resp.body.strip():
            try:
                data = json.loads(resp.body)
            except json.JSONDecodeError:
                data = None
            if isinstance(data, dict):
                for service in data.get("services", []):
                    if not isinstance(service, list) or len(service) < 2:
                        continue
                    tlds, urls = service[0], service[1]
                    if not urls:
                        continue
                    base = str(urls[0]).rstrip("/")
                    for tld in tlds:
                        mapping[str(tld).lower()] = base
        self._bootstrap = mapping
        return mapping

    def _rdap_url(self, domain: str) -> Optional[str]:
        key = _rdap_key(domain)
        if "." not in key:
            return None
        tld = key.rsplit(".", 1)[-1]
        base = self._load_bootstrap().get(tld)
        if not base:
            return None
        return f"{base}/domain/{quote(key)}"

    # ------------------------------------------------------------------
    def lookup(self, domain: str) -> Dict[str, Any]:
        """Fetch and flatten RDAP data for one domain."""
        record: Dict[str, Any] = {"domain": domain, "source": "", "error": ""}
        url = self._rdap_url(domain)
        if not url:
            record["error"] = f"no RDAP server known for .{domain.rsplit('.', 1)[-1]}"
            return record

        resp = self.ctx.http.get(url, timeout=max(self.ctx.cfg.timeout, 15), external=True)
        record["source"] = url
        if not resp.ok:
            record["error"] = resp.error or f"HTTP {resp.status}"
            return record
        try:
            data = json.loads(resp.body)
        except json.JSONDecodeError:
            record["error"] = "response was not valid JSON"
            return record
        if not isinstance(data, dict):
            record["error"] = "unexpected RDAP payload"
            return record

        record["handle"] = data.get("handle", "")
        record["ldhName"] = data.get("ldhName", domain)
        record["status"] = list(data.get("status", []) or [])

        for event in data.get("events", []) or []:
            action = str(event.get("eventAction", "")).lower()
            date = str(event.get("eventDate", ""))
            if action and date:
                record.setdefault("events", {})[action] = date

        nameservers = []
        for ns in data.get("nameservers", []) or []:
            name = ns.get("ldhName") or ns.get("unicodeName") or ""
            if name:
                nameservers.append(name.lower().rstrip("."))
        record["nameservers"] = dedupe(nameservers)

        secure_dns = data.get("secureDNS") or {}
        record["dnssec_signed"] = bool(secure_dns.get("delegationSigned"))

        # Entities: registrar, registrant, abuse contact, tech contact.
        entities = self._walk_entities(data.get("entities", []) or [])
        record["entities"] = entities
        registrar = next((e for e in entities if "registrar" in e["roles"]), None)
        if registrar:
            record["registrar"] = registrar.get("name", "")
            record["registrar_id"] = registrar.get("handle", "")
            record["abuse_email"] = registrar.get("abuse_email", "")

        registrant = next((e for e in entities if "registrant" in e["roles"]), None)
        if registrant:
            record["registrant_org"] = registrant.get("org", "")
            record["registrant_country"] = registrant.get("country", "")

        return record

    def _walk_entities(self, entities: List[dict], depth: int = 0) -> List[Dict[str, Any]]:
        """Flatten nested RDAP entities into a simple list."""
        out: List[Dict[str, Any]] = []
        if depth > 3:
            return out
        for entity in entities:
            if not isinstance(entity, dict):
                continue
            roles = [str(r).lower() for r in (entity.get("roles") or [])]
            vcard = self._vcard(entity.get("vcardArray"))
            entry = {
                "roles": roles,
                "handle": entity.get("handle", ""),
                "name": vcard.get("fn", "") or vcard.get("org", ""),
                "org": vcard.get("org", ""),
                "country": vcard.get("adr_country", ""),
                "email": vcard.get("email", ""),
                "abuse_email": "",
            }
            # Abuse contacts live on a nested entity with role "abuse".
            for sub in entity.get("entities", []) or []:
                if isinstance(sub, dict) and "abuse" in [str(r).lower() for r in (sub.get("roles") or [])]:
                    sub_vcard = self._vcard(sub.get("vcardArray"))
                    if sub_vcard.get("email"):
                        entry["abuse_email"] = sub_vcard["email"]
            out.append(entry)
            out.extend(self._walk_entities(entity.get("entities", []) or [], depth + 1))
        return out

    @staticmethod
    def _vcard(vcard_array: Any) -> Dict[str, str]:
        """Extract a few useful fields from an RDAP jCard structure."""
        values: Dict[str, str] = {}
        if not isinstance(vcard_array, list) or len(vcard_array) < 2:
            return values
        for item in vcard_array[1] or []:
            if not isinstance(item, list) or len(item) < 4:
                continue
            name = str(item[0]).lower()
            value = item[3]
            if isinstance(value, list):
                value = " ".join(str(v) for v in value if v)
            text = truncate(str(value), 120)
            if not text or text.lower() in REDACTED:
                continue
            if name == "fn" and "fn" not in values:
                values["fn"] = text
            elif name == "org" and "org" not in values:
                values["org"] = text
            elif name == "email" and "email" not in values:
                values["email"] = text
            elif name == "adr":
                match = re.search(r"\b([A-Z]{2})\b", text)
                if match and "adr_country" not in values:
                    values["adr_country"] = match.group(1)
        return values

    # ------------------------------------------------------------------
    def run(self) -> Dict[str, object]:
        ctx = self.ctx
        domain = ctx.cfg.domain
        ctx.emit(f"Querying RDAP registration data for {domain}")

        record = self.lookup(domain)
        if record.get("error"):
            ctx.warn(f"RDAP lookup failed: {record['error']}")
            self.state.errors.append(f"whois: {record['error']}")
        else:
            ctx.emit(
                f"  registrar: {record.get('registrar') or 'unknown'} | "
                f"created: {record.get('events', {}).get('registration', 'unknown')[:10]} | "
                f"expires: {record.get('events', {}).get('expiration', 'unknown')[:10]}"
            )
            if record.get("registrant_org"):
                ctx.emit(f"  registrant org: {record['registrant_org']}")

        self.state.summary["whois"] = record
        self.state.whois = record
        self._write(record)
        return {
            "registrar": record.get("registrar", ""),
            "nameservers": len(record.get("nameservers", [])),
            "error": bool(record.get("error")),
        }

    # ------------------------------------------------------------------
    def _write(self, record: Dict[str, Any]) -> None:
        out = self.ctx.out
        lines: List[str] = []
        add = lines.append

        add(f"# WHOIS / RDAP summary for {record.get('domain')}")
        add(f"# source: {record.get('source', '') or 'n/a'}")
        add("")
        if record.get("error"):
            add(f"ERROR: {record['error']}")
            out.write("whois", "whois.txt", lines)
            out.write_json("whois", "whois.json", record)
            return

        rows = [
            ("Handle", record.get("handle", "")),
            ("Registrar", record.get("registrar", "")),
            ("Registrar ID", record.get("registrar_id", "")),
            ("Abuse contact", record.get("abuse_email", "")),
            ("Registrant org", record.get("registrant_org", "")),
            ("Registrant country", record.get("registrant_country", "")),
            ("DNSSEC signed", "yes" if record.get("dnssec_signed") else "no"),
        ]
        for label, value in rows:
            if value:
                add(f"{label:<20}: {value}")

        events = record.get("events", {}) or {}
        if events:
            add("")
            add("## Key dates")
            for action in ("registration", "expiration", "last changed", "last update of RDAP database"):
                if action in events:
                    add(f"{action:<32}: {events[action][:10]}")

        if record.get("nameservers"):
            add("")
            add("## Nameservers")
            for ns in record["nameservers"]:
                add(ns)

        if record.get("status"):
            add("")
            add("## Domain status")
            for status in record["status"]:
                add(status)

        entities = record.get("entities") or []
        if entities:
            add("")
            add("## Contacts")
            for entity in entities:
                roles = ",".join(entity.get("roles") or []) or "unknown"
                detail = entity.get("name") or entity.get("org") or entity.get("handle") or ""
                add(f"{roles:<24} {detail}")

        out.write("whois", "whois.txt", lines)
        out.write_json("whois", "whois.json", record)

        # Nameservers are useful input for later stages.
        if record.get("nameservers"):
            out.write("whois", "nameservers.txt", record["nameservers"])
        if entities:
            contacts = [
                f"{','.join(e.get('roles') or [])}\t{e.get('name', '')}\t{e.get('email', '')}"
                for e in entities
                if e.get("name") or e.get("email")
            ]
            out.write("whois", "contacts.txt", contacts)