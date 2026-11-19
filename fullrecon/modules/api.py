"""F. API discovery: REST routes, GraphQL, Swagger/OpenAPI, parameters."""

from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit

from ..core.context import ModuleContext
from ..utils.helpers import dedupe, read_text, truncate, url_host
from ..utils.validators import in_domain

GRAPHQL_PATHS = ["/graphql", "/graphiql", "/api/graphql", "/v1/graphql", "/gql", "/api/gql", "/query", "/v2/graphql"]
SWAGGER_PATHS = [
    "/swagger.json", "/swagger.yaml", "/swagger/v1/swagger.json", "/openapi.json",
    "/openapi.yaml", "/api/openapi.json", "/api/swagger.json", "/v1/swagger.json",
    "/v2/swagger.json", "/v3/api-docs", "/swagger-ui.html", "/swagger-ui/",
    "/docs", "/redoc", "/api/docs", "/api-docs", "/spec", "/api/swagger",
]
API_PATH_RE = re.compile(r"""/[A-Za-z0-9_\-./{}$:]{0,120}/?(?:api|v\d+|rest|graphql)[A-Za-z0-9_\-./{}$:]*""", re.IGNORECASE)
REST_SEGMENT_RE = re.compile(r"""^/(?:api|rest|v\d+)(?:/[A-Za-z0-9_\-{}$:.]{1,60}){0,8}/?$""")
METHOD_HINT_RE = re.compile(r"""(?:method|type)\s*:\s*['"](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['"]""", re.IGNORECASE)


class ApiModule:
    name = "api"
    label = "API Discovery"

    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.state = ctx.state
        self.endpoints: Set[str] = set()
        self.graphql: Set[str] = set()
        self.swagger: Set[str] = set()
        self.parameters: Set[str] = set()
        self.methods: Dict[str, Set[str]] = {}

    # ------------------------------------------------------------------
    def run(self) -> Dict[str, object]:
        cfg = self.ctx.cfg
        bases = self._bases()
        if not bases:
            self.ctx.warn("no in-scope base URLs for API discovery")
            return {"api_endpoints": 0}

        self.ctx.emit(f"Probing {len(bases)} base URL(s) for API surfaces")

        # 1. Known documentation/handshake paths on each live host.
        with ThreadPoolExecutor(max_workers=max(1, min(cfg.threads, 20))) as pool:
            futures = {
                pool.submit(self._probe_host, base): base for base in bases
            }
            for future in as_completed(futures):
                base = futures[future]
                try:
                    future.result()
                except Exception as exc:  # noqa: BLE001
                    self.ctx.record_error(self.name, f"{base}: {exc}")

        # 2. Endpoints harvested from URLs and JavaScript.
        for url in list(self.state.urls) + list(self.state.js_endpoints):
            self._harvest(url)
        self._harvest_from_js_files()

        self.state.api_endpoints = sorted(self.endpoints)
        self.state.graphql_endpoints = sorted(self.graphql)
        self.state.swagger_endpoints = sorted(self.swagger)
        self.state.api_parameters = sorted(self.parameters)
        self._write()

        self.ctx.emit(
            f"API: {len(self.endpoints)} endpoint(s), {len(self.graphql)} GraphQL, "
            f"{len(self.swagger)} doc surface(s), {len(self.parameters)} parameter(s)"
        )
        return {
            "api_endpoints": len(self.endpoints),
            "graphql": len(self.graphql),
            "swagger": len(self.swagger),
            "parameters": len(self.parameters),
        }

    # ------------------------------------------------------------------
    def _bases(self) -> List[str]:
        bases: List[str] = []
        for url in self.state.live_urls():
            parts = urlsplit(url)
            if parts.scheme and parts.netloc:
                base = f"{parts.scheme}://{parts.netloc}"
                if base not in bases and self.ctx.in_scope(parts.hostname or ""):
                    bases.append(base)
        if not bases:
            bases = [f"https://{self.ctx.cfg.domain}"]
        return bases[:40]

    def _probe_host(self, base: str) -> None:
        cfg = self.ctx.cfg
        # Documentation probes are speculative: use a short timeout so a
        # filtered host cannot stall the pipeline for minutes.
        probe_timeout = min(cfg.timeout, 6.0)
        for path in SWAGGER_PATHS:
            url = base + path
            resp = self.ctx.http.get(url, timeout=probe_timeout)
            if not resp.ok:
                continue
            ctype = resp.header("content-type", "").lower()
            body = resp.body or ""
            if resp.status in (200, 401, 403) and (
                "swagger" in body[:4000].lower()
                or "openapi" in body[:4000].lower()
                or "redoc" in body[:2000].lower()
                or path.endswith((".json", ".yaml"))
                and _looks_like_spec(body)
            ):
                if resp.status == 200:
                    self.swagger.add(url)
                    self.endpoints.add(url)
                break

        for path in GRAPHQL_PATHS:
            url = base + path
            resp = self.ctx.http.get(url, timeout=probe_timeout)
            if not resp.ok:
                continue
            body = (resp.body or "").lower()
            if resp.status in (400, 401, 403, 405, 200) and any(
                marker in body for marker in ("graphql", "graphiql", "must provide query", "query")
            ):
                self.graphql.add(url)
                self.endpoints.add(url)
                break

    def _harvest(self, url: str) -> None:
        from ..utils.helpers import query_params

        if not self.ctx.in_scope(url_host(url)):
            return
        for param in query_params(url):
            self.parameters.add(param)
        parts = urlsplit(url)
        path = parts.path or "/"
        if not path or path == "/":
            return
        candidate = path
        if candidate.endswith("/"):
            candidate = candidate.rstrip("/")
        api_like = bool(re.search(r"/(?:api|rest|v\d+|graphql|oauth|internal|admin)(?:/|$)", candidate, re.I))
        templated = bool(re.search(r"/(?:\d+|[0-9a-f]{8}-[0-9a-f-]{20,})(?:/|$)", candidate, re.I))
        if api_like or templated:
            host_part = f"{parts.scheme}://{parts.netloc}"
            self.endpoints.add(host_part + candidate)

    def _harvest_from_js_files(self) -> None:
        for endpoint in self.state.js_endpoints:
            self._harvest(endpoint)
        for url in self.state.js_files:
            if not self.ctx.in_scope(url_host(url)):
                continue
            resp = self.ctx.http.get(url, timeout=self.ctx.cfg.timeout, max_bytes=self.ctx.cfg.js_max_size)
            if not resp.ok or not resp.body:
                continue
            base = "{0.scheme}://{0.netloc}".format(urlsplit(url))
            for match in API_PATH_RE.finditer(resp.body):
                path = match.group(0)
                if len(path) < 4:
                    continue
                self.endpoints.add(base + path)
            for method in METHOD_HINT_RE.finditer(resp.body):
                self.methods.setdefault("_observed", set()).add(method.group(1).upper())
            for match in re.finditer(r"""['"]([A-Za-z_][A-Za-z0-9_\-]{1,40})['"]\s*:""", resp.body):
                name = match.group(1)
                if len(name) > 2 and not name.isdigit():
                    self.parameters.add(name)

    # ------------------------------------------------------------------
    def _write(self) -> None:
        out = self.ctx.out
        out.write("api", "api_endpoints.txt", sorted(self.endpoints))
        out.write("api", "graphql.txt", sorted(self.graphql))
        out.write("api", "swagger.txt", sorted(self.swagger))

        param_lines = []
        for param in sorted(self.parameters):
            param_lines.append(param)
        out.write("api", "api_parameters.txt", param_lines)

        method_lines = []
        for group, values in self.methods.items():
            for value in sorted(values):
                method_lines.append(value)
        out.write("api", "api_methods.txt", dedupe(method_lines))

        # Documentation surfaces discovered but not parsed further.
        out.write("api", "api_documentation.txt", sorted(self.swagger | self.graphql))

        out.write_json("api", "api_summary.json", {
            "endpoints": sorted(self.endpoints),
            "graphql": sorted(self.graphql),
            "swagger": sorted(self.swagger),
            "parameters": sorted(self.parameters),
            "methods": {k: sorted(v) for k, v in self.methods.items()},
        })


def _looks_like_spec(body: str) -> bool:
    head = (body or "")[:2000].strip()
    if not head:
        return False
    if head.startswith("{"):
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return '"openapi"' in head.lower() or '"swagger"' in head.lower()
        if isinstance(data, dict):
            return any(key in data for key in ("swagger", "openapi", "paths"))
    return "swagger:" in head.lower() or "openapi:" in head.lower()