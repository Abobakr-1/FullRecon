"""Report generation: plain-text summary, JSON export and a standalone HTML report."""

from __future__ import annotations

import html
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .. import __version__
from ..core.context import ReconState
from ..utils.helpers import dedupe, truncate
from ..utils.progress import human_duration


SEVERITY_COLORS = {
    "high": "#d64545",
    "medium": "#d98b2b",
    "low": "#3f7fbf",
    "info": "#6b7280",
}


class ReportGenerator:
    """Builds summary.txt, report.json, report.html and the results manifest."""

    def __init__(self, state: ReconState, out_manager, cfg, logger=None) -> None:
        self.state = state
        self.out = out_manager
        self.cfg = cfg
        self.log = logger

    # ------------------------------------------------------------------
    def generate(self) -> Dict[str, Path]:
        paths = {}
        paths["summary"] = self._write_summary()
        paths["json"] = self._write_json()
        paths["html"] = self._write_html()
        paths["manifest"] = self.out.write_manifest()
        return paths

    # ------------------------------------------------------------------
    def _write_summary(self) -> Path:
        state = self.state
        counts = state.counts()
        lines: List[str] = []
        add = lines.append

        add("=" * 78)
        add(f" FullRecon summary - {state.target}")
        add("=" * 78)
        add("")
        add(f" Tool version   : {__version__}")
        add(f" Started (UTC)  : {state.started_at}")
        add(f" Finished (UTC) : {state.finished_at}")
        add(f" Duration       : {human_duration(state.duration)}")
        add(f" Results dir    : {self.out.target_dir}")
        add("")
        add("-" * 78)
        add(" Statistics")
        add("-" * 78)
        for key, label in (
            ("subdomains", "Subdomains found"),
            ("resolved", "Subdomains resolving"),
            ("dns_records", "DNS records"),
            ("live_hosts", "Live hosts"),
            ("open_ports", "Open ports"),
            ("technologies", "Technologies"),
            ("urls", "URLs"),
            ("api_endpoints", "API endpoints"),
            ("js_files", "JavaScript files"),
            ("js_secrets", "Potential JS secrets"),
            ("content_paths", "Content paths"),
            ("asns", "Announcing ASNs"),
            ("waf_hosts", "Hosts behind WAF/CDN"),
            ("wordpress_sites", "WordPress sites"),
            ("findings", "Intelligence findings"),
        ):
            add(f" {label:<24}: {counts.get(key, 0)}")
        add("")

        severity = {level: sum(1 for f in state.findings if f["severity"] == level)
                    for level in ("high", "medium", "low", "info")}
        add("-" * 78)
        add(" Findings by severity")
        add("-" * 78)
        add(f" HIGH: {severity['high']}   MEDIUM: {severity['medium']}   "
            f"LOW: {severity['low']}   INFO: {severity['info']}")
        add("")

        if state.findings:
            add("-" * 78)
            add(" Top findings")
            add("-" * 78)
            for finding in state.findings[:15]:
                add(f" [{finding['severity'].upper():<6}] {finding['title']}")
                add(f"          {truncate(finding['detail'], 150)}")
                for item in finding["evidence"][:3]:
                    add(f"          - {truncate(str(item), 140)}")
            add("")

        add("-" * 78)
        add(" Module status")
        add("-" * 78)
        for name, info in state.module_status.items():
            status = "ok" if info.get("ok") else ("skipped" if info.get("skipped") else "failed")
            add(f" {name:<18} {status:<8} {human_duration(info.get('duration', 0)):>8}  "
                f"{info.get('detail', '')}")
        add("")

        if state.errors:
            add("-" * 78)
            add(" Non-fatal errors and limitations")
            add("-" * 78)
            for error in state.errors[:60]:
                add(f" - {truncate(error, 150)}")
            if len(state.errors) > 60:
                add(f" ... {len(state.errors) - 60} more (see logs/fullrecon.log)")
            add("")

        add("-" * 78)
        add(" Reminder")
        add("-" * 78)
        add(" These results are reconnaissance data, not confirmed vulnerabilities.")
        add(" Verify every finding manually and report only through the program's")
        add(" official channel. Never test credentials discovered in JavaScript.")
        add("")

        return self.out.write_text("reports", "summary.txt", "\n".join(lines))

    # ------------------------------------------------------------------
    def _write_json(self) -> Path:
        payload = {
            "tool": {
                "name": "FullRecon",
                "version": __version__,
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            "scan": {
                "target": self.state.target,
                "started_at": self.state.started_at,
                "finished_at": self.state.finished_at,
                "duration_seconds": round(self.state.duration, 2),
                "options": {
                    "threads": self.cfg.threads,
                    "rate_limit": self.cfg.rate_limit,
                    "timeout": self.cfg.timeout,
                    "passive_only": self.cfg.passive_only,
                },
            },
            "results": self.state.to_dict(),
            "files": self.out.summary()["files"],
        }
        return self.out.write_json("reports", "report.json", payload)

    # ------------------------------------------------------------------
    def _write_html(self) -> Path:
        return self.out.write_text("reports", "report.html", self._render_html())

    def _render_html(self) -> str:
        state = self.state
        counts = state.counts()
        severity = {level: sum(1 for f in state.findings if f["severity"] == level)
                    for level in ("high", "medium", "low", "info")}
        esc = html.escape

        cards = "".join(
            f'<div class="card"><div class="num">{value}</div>'
            f'<div class="lbl">{esc(label)}</div></div>'
            for label, value in (
                ("Subdomains", counts["subdomains"]),
                ("Resolved", counts["resolved"]),
                ("DNS records", counts["dns_records"]),
                ("Live hosts", counts["live_hosts"]),
                ("Open ports", counts["open_ports"]),
                ("Technologies", counts["technologies"]),
                ("URLs", counts["urls"]),
                ("API endpoints", counts["api_endpoints"]),
                ("JS files", counts["js_files"]),
                ("Content paths", counts["content_paths"]),
            )
        )

        finding_html = []
        for finding in state.findings:
            color = SEVERITY_COLORS.get(finding["severity"], "#6b7280")
            evidence = "".join(
                f"<li><code>{esc(str(item))}</code></li>" for item in finding["evidence"][:12]
            )
            ref = ""
            if finding.get("reference"):
                ref = (f'<p class="ref"><a href="{esc(finding["reference"])}" target="_blank" '
                       f'rel="noopener">reference</a></p>')
            finding_html.append(
                f'<details class="finding" open>'
                f'<summary><span class="badge" style="background:{color}">'
                f'{esc(finding["severity"].upper())}</span>'
                f'<strong>{esc(finding["title"])}</strong>'
                f'<span class="cat">{esc(finding["category"])}</span></summary>'
                f'<p>{esc(finding["detail"])}</p>'
                f'{ref}<ul>{evidence}</ul></details>'
            )

        modules_html = "".join(
            f'<tr><td>{esc(name)}</td>'
            f'<td class="{"ok" if info.get("ok") else "bad"}">'
            f'{"ok" if info.get("ok") else ("skipped" if info.get("skipped") else "failed")}</td>'
            f'<td>{human_duration(info.get("duration", 0))}</td>'
            f'<td>{esc(str(info.get("detail", "")))}</td></tr>'
            for name, info in state.module_status.items()
        )

        errors_html = ""
        if state.errors:
            items = "".join(f"<li>{esc(e)}</li>" for e in state.errors[:80])
            errors_html = f'<h2>Errors &amp; limitations</h2><ul class="errors">{items}</ul>'

        table_sections = [
            ("Live hosts", [f"{r['url']} [{r['status']}] {r.get('title', '')}" for r in state.live]),
            ("Open ports", [f"{p['host']}:{p['port']} {p.get('service', '')} {p.get('version', '')}".strip()
                            for p in state.ports]),
            ("Interesting URLs", state.interesting_urls),
            ("API endpoints", state.api_endpoints),
            ("GraphQL", state.graphql_endpoints),
            ("Swagger/OpenAPI", state.swagger_endpoints),
            ("Sensitive paths", [str(f.get("url")) for f in state.interesting_files]),
            ("WAF / CDN", [
                f"{w['url']} - {', '.join(w.get('signatures') or ['behavioural blocking'])}"
                for w in state.waf_results if w.get("waf_detected")
            ]),
            ("Security header scores", [
                f"{h['url']} - {h.get('score')}/{h.get('max_score')}"
                for h in state.header_audits
            ]),
            ("WordPress plugins", sorted({
                slug for s in state.wordpress_sites for slug in (s.get("plugins") or [])
            })),
        ]
        sections_html = []
        for title, items in table_sections:
            items = dedupe([str(i) for i in items if i])[:400]
            if not items:
                continue
            rows = "".join(f"<li><code>{esc(truncate(i, 220))}</code></li>" for i in items)
            sections_html.append(
                f"<details><summary><strong>{esc(title)}</strong> ({len(items)})</summary>"
                f'<ul class="list">{rows}</ul></details>'
            )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(self.cfg.report_title)} - {esc(state.target)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
         margin: 0; padding: 0 0 60px; background: #0f1115; color: #e6e8ee; }}
  header {{ padding: 32px 28px 20px; background: linear-gradient(135deg,#111827,#1f2937);
            border-bottom: 1px solid #2a2f3a; }}
  h1 {{ margin: 0 0 6px; font-size: 24px; letter-spacing: .3px; }}
  .meta {{ color: #9aa4b2; font-size: 13px; }}
  main {{ max-width: 1180px; margin: 0 auto; padding: 24px 20px; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fill,minmax(140px,1fr));
            gap: 12px; margin-bottom: 28px; }}
  .card {{ background: #171b23; border: 1px solid #262b36; border-radius: 10px;
           padding: 14px; text-align: center; }}
  .card .num {{ font-size: 24px; font-weight: 700; color: #7dd3fc; }}
  .card .lbl {{ font-size: 11px; text-transform: uppercase; letter-spacing: .6px;
                color: #939eb2; margin-top: 4px; }}
  h2 {{ font-size: 15px; text-transform: uppercase; letter-spacing: .8px;
        color: #9aa4b2; margin: 28px 0 12px; }}
  .sev {{ display: flex; gap: 10px; margin-bottom: 18px; flex-wrap: wrap; }}
  .sev span {{ padding: 6px 12px; border-radius: 999px; font-size: 12px;
               font-weight: 600; color: #fff; }}
  details {{ background: #171b23; border: 1px solid #262b36; border-radius: 10px;
             padding: 12px 14px; margin-bottom: 10px; }}
  summary {{ cursor: pointer; display: flex; align-items: center; gap: 10px;
             font-size: 14px; }}
  .badge {{ color: #fff; font-size: 10px; font-weight: 700; padding: 3px 8px;
            border-radius: 4px; letter-spacing: .5px; }}
  .cat {{ margin-left: auto; color: #7b8598; font-size: 11px; text-transform: uppercase; }}
  .finding p {{ color: #b6bfcd; font-size: 13px; line-height: 1.55; }}
  .finding ul {{ margin: 6px 0 0 18px; padding: 0; font-size: 12px; color: #93a0b4; }}
  .finding li {{ margin: 3px 0; }}
  code {{ font-family: ui-monospace, "Cascadia Code", Consolas, monospace;
          font-size: 12px; color: #a5d6ff; word-break: break-all; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid #242a35; }}
  th {{ color: #8e99ab; text-transform: uppercase; font-size: 11px; letter-spacing: .6px; }}
  td.ok {{ color: #4ade80; }} td.bad {{ color: #f87171; }}
  ul.list {{ margin: 8px 0 0 16px; padding: 0; font-size: 12px; }}
  ul.list li {{ margin: 3px 0; }}
  ul.errors li {{ font-size: 12px; color: #f0a3a3; }}
  footer {{ max-width: 1180px; margin: 40px auto 0; padding: 0 20px;
            color: #6b7484; font-size: 12px; line-height: 1.6; }}
  a {{ color: #7dd3fc; }}
</style>
</head>
<body>
<header>
  <h1>{esc(self.cfg.report_title)} &mdash; {esc(state.target)}</h1>
  <div class="meta">
    FullRecon {esc(__version__)} &middot; started {esc(state.started_at)} &middot;
    finished {esc(state.finished_at)} &middot; duration {esc(human_duration(state.duration))}
  </div>
</header>
<main>
  <div class="cards">{cards}</div>

  <h2>Findings by severity</h2>
  <div class="sev">
    <span style="background:#d64545">HIGH {severity['high']}</span>
    <span style="background:#d98b2b">MEDIUM {severity['medium']}</span>
    <span style="background:#3f7fbf">LOW {severity['low']}</span>
    <span style="background:#6b7280">INFO {severity['info']}</span>
  </div>

  <h2>Findings</h2>
  {''.join(finding_html) or '<p>No findings recorded.</p>'}

  <h2>Raw results</h2>
  {''.join(sections_html) or '<p>No additional detail.</p>'}

  <h2>Module status</h2>
  <table>
    <tr><th>Module</th><th>Status</th><th>Duration</th><th>Detail</th></tr>
    {modules_html}
  </table>

  {errors_html}

  <footer>
    <p><strong>Reconnaissance data only.</strong> These results indicate areas to
    review; they are not confirmed vulnerabilities. Verify manually and report
    through the program's official channel.</p>
    <p>Scope: {esc(self.cfg.domain)} &mdash; generated by FullRecon {esc(__version__)}.
    Only scan assets you are authorised to test.</p>
  </footer>
</main>
</body>
</html>
"""