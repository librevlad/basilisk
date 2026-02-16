"""OpenAPI / Swagger spec parser — auto-import API structure for pentesting.

Discovers and parses OpenAPI 2.0 (Swagger) and 3.x specs, extracting
endpoints, parameters, authentication schemes, and data types.
Results are stored in pipeline for consumption by pentesting plugins.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Discovery paths to probe for API documentation, ordered by likelihood.
# Covers common frameworks: Spring Boot, ASP.NET, Django REST, FastAPI,
# Express/Swagger-UI, NestJS, Laravel, Rails, and cloud API gateways.
# ---------------------------------------------------------------------------
SPEC_PATHS = [
    # Standard OpenAPI / Swagger locations
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/api-docs.json",
    # Versioned Swagger
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/swagger/v3/swagger.json",
    # Under /api prefix
    "/api/swagger.json",
    "/api/openapi.json",
    "/api/v1/openapi.json",
    "/api/v2/openapi.json",
    "/api/v1/swagger.json",
    "/api/api-docs",
    "/api/doc",
    "/api/docs",
    # Under /rest prefix
    "/rest/api-docs",
    "/rest/swagger.json",
    # Versioned api-docs (Spring Boot)
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    # Well-known
    "/.well-known/openapi",
    "/.well-known/openapi.json",
    "/.well-known/openapi.yaml",
    # Swagger UI / documentation pages
    "/swagger-ui.html",
    "/swagger-ui/",
    "/swagger-resources",
    "/swagger-resources/configuration/ui",
    # YAML variants
    "/openapi.yaml",
    "/openapi.yml",
    "/swagger.yaml",
    "/api/openapi.yaml",
    # FastAPI / Redoc
    "/docs",
    "/docs/openapi.json",
    "/redoc",
    # ASP.NET
    "/swagger/doc.json",
    "/swagger/docs/v1",
    "/swagger/docs/v2",
    # NestJS
    "/api/docs-json",
    # Less common
    "/documentation",
    "/api/documentation",
    "/api/schema",
    "/api/spec",
    "/apispec.json",
    "/apispec_1.json",
]

# Swagger UI HTML signatures (used to detect Swagger UI pages and extract
# the underlying spec URL from the HTML).
_SWAGGER_UI_PATTERNS = [
    re.compile(r"""url\s*:\s*['"]([^'"]+\.json)['"]"""),
    re.compile(r"""spec[Uu]rl\s*[:=]\s*['"]([^'"]+)['"]"""),
    re.compile(r"""swagger[Uu]i\.init\s*\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""configUrl\s*[:=]\s*['"]([^'"]+)['"]"""),
]

# Dangerous endpoint patterns (paths that may reveal sensitive operations)
_DANGEROUS_PATTERNS: list[tuple[str, str, str]] = [
    ("/admin", "Administrative endpoint", "high"),
    ("/internal", "Internal endpoint exposed publicly", "high"),
    ("/debug", "Debug endpoint in production", "high"),
    ("/actuator", "Spring Boot Actuator endpoint", "high"),
    ("/metrics", "Metrics endpoint (may leak infrastructure info)", "medium"),
    ("/health", "Health check endpoint", "low"),
    ("/env", "Environment variables endpoint", "critical"),
    ("/config", "Configuration endpoint", "high"),
    ("/settings", "Settings endpoint", "medium"),
    ("/users", "User management endpoint", "medium"),
    ("/accounts", "Account management endpoint", "medium"),
    ("/tokens", "Token management endpoint", "high"),
    ("/keys", "Key management endpoint", "high"),
    ("/secrets", "Secrets endpoint", "critical"),
    ("/password", "Password-related endpoint", "high"),
    ("/reset", "Password reset endpoint", "medium"),
    ("/upload", "File upload endpoint", "medium"),
    ("/download", "File download endpoint", "medium"),
    ("/file", "File operation endpoint", "medium"),
    ("/exec", "Command execution endpoint", "critical"),
    ("/eval", "Code evaluation endpoint", "critical"),
    ("/backup", "Backup endpoint", "high"),
    ("/export", "Data export endpoint", "medium"),
    ("/import", "Data import endpoint", "medium"),
    ("/migrate", "Migration endpoint", "high"),
    ("/console", "Console endpoint", "critical"),
    ("/shell", "Shell access endpoint", "critical"),
    ("/system", "System management endpoint", "high"),
    ("/sudo", "Privilege escalation endpoint", "critical"),
    ("/register", "Registration endpoint (check for abuse)", "low"),
    ("/signup", "Signup endpoint (check for abuse)", "low"),
    ("/webhook", "Webhook endpoint (check for SSRF)", "medium"),
]


class OpenApiParserPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="openapi_parser",
        display_name="OpenAPI/Swagger Parser",
        category=PluginCategory.ANALYSIS,
        description=(
            "Discovers and parses OpenAPI/Swagger specs, extracts endpoints, "
            "authentication, parameters, and flags dangerous routes"
        ),
        depends_on=["api_detect"],
        produces=["openapi_spec", "api_endpoints_detailed"],
        timeout=45.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        findings: list[Finding] = []
        spec_data: dict[str, Any] = {}
        endpoints: list[dict[str, Any]] = []

        from basilisk.utils.http_check import resolve_base_url
        base_url = await resolve_base_url(target.host, ctx)
        if not base_url:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info("Host not reachable")],
                data={"openapi_spec": {}, "endpoints": []},
            )

        # Phase 1: Probe for spec files
        spec_json, spec_url = await self._discover_spec(
            base_url, ctx, findings,
        )

        if not spec_json:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=findings or [Finding.info(
                    "No OpenAPI/Swagger spec found",
                    tags=["analysis", "api", "openapi"],
                )],
                data={"openapi_spec": {}, "endpoints": []},
            )

        # Phase 2: Parse spec metadata
        version = self._get_spec_version(spec_json)
        title = self._get_spec_title(spec_json)
        description = self._get_spec_description(spec_json)

        findings.append(Finding.medium(
            f"OpenAPI spec discovered: {spec_url}",
            description=(
                f"Version: {version}, Title: {title}"
                + (f", Description: {description[:120]}" if description else "")
            ),
            evidence=spec_url,
            remediation=(
                "Restrict API documentation access to authorized users only. "
                "Consider disabling spec endpoints in production."
            ),
            tags=["analysis", "api", "openapi", "info-disclosure"],
        ))

        # Phase 3: Extract structured data
        endpoints = self._extract_endpoints(spec_json)
        auth_schemes = self._extract_auth_schemes(spec_json)
        servers = self._extract_servers(spec_json, base_url)
        deprecated_endpoints = self._find_deprecated(endpoints)
        response_schemas = self._extract_response_schemas(spec_json)

        if endpoints:
            # Summary by method
            method_counts: dict[str, int] = {}
            for ep in endpoints:
                m = ep["method"].upper()
                method_counts[m] = method_counts.get(m, 0) + 1
            method_summary = ", ".join(
                f"{m}: {c}" for m, c in sorted(method_counts.items())
            )

            findings.append(Finding.info(
                f"Parsed {len(endpoints)} API endpoints "
                f"({method_summary})",
                evidence=", ".join(
                    f"{e['method'].upper()} {e['path']}"
                    for e in endpoints[:15]
                ),
                tags=["analysis", "api", "openapi"],
            ))

        if auth_schemes:
            findings.append(Finding.info(
                f"API auth schemes: {', '.join(auth_schemes)}",
                tags=["analysis", "api", "openapi"],
            ))

        if servers and len(servers) > 1:
            findings.append(Finding.info(
                f"API servers: {', '.join(servers)}",
                description="Multiple servers defined — may include staging",
                tags=["analysis", "api", "openapi"],
            ))

        # Phase 4: Security analysis

        # Check for dangerous endpoints
        self._check_dangerous_endpoints(endpoints, findings)

        # Check for endpoints without auth
        self._check_unprotected_endpoints(endpoints, spec_json, findings)

        # Check for deprecated endpoints still available
        if deprecated_endpoints:
            findings.append(Finding.low(
                f"{len(deprecated_endpoints)} deprecated endpoints in spec",
                description=(
                    "Deprecated endpoints may have known vulnerabilities "
                    "or lack maintenance"
                ),
                evidence=", ".join(
                    f"{e['method'].upper()} {e['path']}"
                    for e in deprecated_endpoints[:10]
                ),
                remediation="Remove deprecated endpoints from production",
                tags=["analysis", "api", "openapi", "deprecated"],
            ))

        # Check for info disclosure in descriptions/examples
        self._check_info_disclosure(spec_json, findings)

        # Check for file upload endpoints
        self._check_file_uploads(endpoints, findings)

        # Check auth scheme weaknesses
        self._check_auth_weaknesses(spec_json, findings)

        # Store discovered endpoints for pentesting plugins
        discovered_paths = ctx.state.setdefault("discovered_api_paths", {})
        host_paths = discovered_paths.setdefault(target.host, [])
        for ep in endpoints:
            if ep["path"] not in host_paths:
                host_paths.append(ep["path"])

        # Store detailed endpoint info for param_discover and injection plugins
        ctx.state.setdefault(
            "api_endpoints_detailed", {},
        )[target.host] = endpoints

        spec_data = {
            "version": version,
            "title": title,
            "description": description,
            "servers": servers,
            "auth_schemes": auth_schemes,
            "endpoint_count": len(endpoints),
            "deprecated_count": len(deprecated_endpoints),
            "response_schemas_count": len(response_schemas),
        }

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={
                "openapi_spec": spec_data,
                "endpoints": endpoints,
                "response_schemas": response_schemas,
            },
        )

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    async def _discover_spec(
        self,
        base_url: str,
        ctx: Any,
        findings: list[Finding],
    ) -> tuple[dict | None, str]:
        """Probe for OpenAPI/Swagger spec.

        Returns (parsed_spec, spec_url) or (None, "").
        """
        for path in SPEC_PATHS:
            if ctx.should_stop:
                break
            url = f"{base_url}{path}"
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(url, timeout=8.0)
                    if resp.status != 200:
                        continue
                    content_type = resp.headers.get("Content-Type", "")
                    body = await resp.text(
                        encoding="utf-8", errors="replace",
                    )

                    # Try JSON
                    if "json" in content_type or body.lstrip().startswith("{"):
                        try:
                            parsed = json.loads(body)
                            if self._is_openapi_spec(parsed):
                                return parsed, url
                        except json.JSONDecodeError:
                            pass

                    # Try YAML
                    if (
                        ("yaml" in content_type or "yml" in path)
                        and ("openapi:" in body or "swagger:" in body)
                    ):
                        try:
                            import yaml
                            parsed = yaml.safe_load(body)
                            if self._is_openapi_spec(parsed):
                                return parsed, url
                        except ImportError:
                            findings.append(Finding.info(
                                f"YAML OpenAPI spec at {path} "
                                "(install PyYAML to parse)",
                                tags=["analysis", "api", "openapi"],
                            ))
                        except Exception as e:
                            logger.debug("openapi_parser: YAML parse failed at %s: %s", path, e)
                        continue

                    # Check for Swagger UI HTML page — extract spec URL
                    if "text/html" in content_type:
                        spec_ref = self._extract_spec_url_from_html(
                            body, base_url, url,
                        )
                        if spec_ref:
                            result = await self._fetch_spec_from_url(
                                spec_ref, ctx,
                            )
                            if result:
                                return result, spec_ref

            except Exception as e:
                logger.debug("openapi_parser: spec probe %s failed: %s", path, e)
                continue

        return None, ""

    def _extract_spec_url_from_html(
        self, html: str, base_url: str, page_url: str,
    ) -> str | None:
        """Try to extract the spec JSON URL from a Swagger UI HTML page."""
        # Check if this looks like a Swagger UI page
        html_lower = html.lower()
        if not any(
            sig in html_lower
            for sig in ("swagger-ui", "swaggerui", "openapi", "api-docs")
        ):
            return None

        for pattern in _SWAGGER_UI_PATTERNS:
            m = pattern.search(html)
            if m:
                ref = m.group(1).strip()
                if ref.startswith("http"):
                    return ref
                if ref.startswith("//"):
                    return f"https:{ref}"
                if ref.startswith("/"):
                    from urllib.parse import urlparse
                    parsed = urlparse(base_url)
                    return f"{parsed.scheme}://{parsed.netloc}{ref}"
                # Relative to current page
                base = page_url.rsplit("/", 1)[0]
                return f"{base}/{ref}"

        return None

    async def _fetch_spec_from_url(
        self, url: str, ctx: Any,
    ) -> dict | None:
        """Fetch and parse a spec from a specific URL."""
        try:
            async with ctx.rate:
                resp = await ctx.http.get(url, timeout=8.0)
                if resp.status != 200:
                    return None
                body = await resp.text(encoding="utf-8", errors="replace")
                parsed = json.loads(body)
                if self._is_openapi_spec(parsed):
                    return parsed
        except Exception as e:
            logger.debug("openapi_parser: spec fetch from %s failed: %s", url, e)
        return None

    # ------------------------------------------------------------------
    # Spec parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_openapi_spec(data: Any) -> bool:
        """Check if parsed JSON/YAML is an OpenAPI/Swagger spec."""
        if not isinstance(data, dict):
            return False
        return (
            "openapi" in data
            or "swagger" in data
            or ("info" in data and "paths" in data)
        )

    @staticmethod
    def _get_spec_version(spec: dict) -> str:
        if "openapi" in spec:
            return f"OpenAPI {spec['openapi']}"
        if "swagger" in spec:
            return f"Swagger {spec['swagger']}"
        return "unknown"

    @staticmethod
    def _get_spec_title(spec: dict) -> str:
        info = spec.get("info", {})
        return info.get("title", "Untitled API")

    @staticmethod
    def _get_spec_description(spec: dict) -> str:
        info = spec.get("info", {})
        return info.get("description", "")

    @staticmethod
    def _extract_servers(spec: dict, fallback: str) -> list[str]:
        """Extract server base URLs from spec."""
        servers: list[str] = []
        # OpenAPI 3.x
        for s in spec.get("servers", []):
            url = s.get("url", "")
            if url:
                servers.append(url)
        # Swagger 2.0
        if "host" in spec:
            scheme = "https"
            schemes = spec.get("schemes", [])
            if schemes:
                scheme = schemes[0]
            base_path = spec.get("basePath", "")
            servers.append(f"{scheme}://{spec['host']}{base_path}")
        if not servers:
            servers.append(fallback)
        return servers

    @staticmethod
    def _extract_auth_schemes(spec: dict) -> list[str]:
        """Extract authentication scheme names and types."""
        schemes: list[str] = []
        # OpenAPI 3.x
        components = spec.get("components", {})
        security_schemes = components.get("securitySchemes", {})
        for name, scheme in security_schemes.items():
            scheme_type = scheme.get("type", "unknown")
            scheme_in = scheme.get("in", "")
            bearer_format = scheme.get("bearerFormat", "")
            label = f"{name}({scheme_type}"
            if scheme_in:
                label += f",in={scheme_in}"
            if bearer_format:
                label += f",format={bearer_format}"
            label += ")"
            schemes.append(label)
        # Swagger 2.0
        for name, scheme in spec.get("securityDefinitions", {}).items():
            scheme_type = scheme.get("type", "unknown")
            scheme_in = scheme.get("in", "")
            label = f"{name}({scheme_type}"
            if scheme_in:
                label += f",in={scheme_in}"
            label += ")"
            schemes.append(label)
        return schemes

    @classmethod
    def _extract_endpoints(cls, spec: dict) -> list[dict[str, Any]]:
        """Extract all endpoints with their parameters and metadata."""
        endpoints: list[dict[str, Any]] = []
        paths = spec.get("paths", {})

        # Determine global security requirements
        global_security = spec.get("security", [])

        http_methods = {
            "get", "post", "put", "delete", "patch",
            "options", "head", "trace",
        }

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, details in methods.items():
                if method.lower() not in http_methods:
                    continue
                if not isinstance(details, dict):
                    continue

                params = cls._extract_params(
                    details, methods.get("parameters", []),
                )
                # Check if endpoint has security requirement
                security = details.get("security", global_security)
                requires_auth = bool(security)

                # Detect if this is a deprecated endpoint
                deprecated = details.get("deprecated", False)

                # Extract response codes
                responses = details.get("responses", {})
                response_codes = sorted(str(c) for c in responses)

                endpoint = {
                    "path": path,
                    "method": method.lower(),
                    "summary": details.get("summary", ""),
                    "description": details.get("description", ""),
                    "operation_id": details.get("operationId", ""),
                    "parameters": params,
                    "requires_auth": requires_auth,
                    "deprecated": deprecated,
                    "consumes": details.get(
                        "consumes", spec.get("consumes", []),
                    ),
                    "produces": details.get(
                        "produces", spec.get("produces", []),
                    ),
                    "tags": details.get("tags", []),
                    "request_body": cls._extract_request_body(details),
                    "response_codes": response_codes,
                }
                endpoints.append(endpoint)

        return endpoints

    @staticmethod
    def _extract_params(
        operation: dict,
        path_params: list[dict] | None = None,
    ) -> list[dict[str, Any]]:
        """Extract parameters from an operation."""
        params: list[dict[str, Any]] = []
        seen: set[str] = set()

        all_params = list(path_params or []) + operation.get("parameters", [])

        for p in all_params:
            if not isinstance(p, dict):
                continue
            name = p.get("name", "")
            if not name or name in seen:
                continue
            seen.add(name)

            # Resolve schema (handles both OAS 2.0 and 3.0)
            schema = p.get("schema", {})
            param_type = p.get("type", schema.get("type", "string"))
            param_format = p.get("format", schema.get("format", ""))
            enum_values = p.get("enum", schema.get("enum"))
            example = p.get("example", schema.get("example"))
            default = p.get("default", schema.get("default"))

            param: dict[str, Any] = {
                "name": name,
                "in": p.get("in", "query"),
                "required": p.get("required", False),
                "type": param_type,
                "description": p.get("description", ""),
            }
            if param_format:
                param["format"] = param_format
            if enum_values:
                param["enum"] = enum_values
            if example is not None:
                param["example"] = example
            if default is not None:
                param["default"] = default

            params.append(param)

        return params

    @staticmethod
    def _extract_request_body(
        operation: dict,
    ) -> dict[str, Any] | None:
        """Extract request body schema (OpenAPI 3.x)."""
        request_body = operation.get("requestBody", {})
        if not request_body:
            return None

        content = request_body.get("content", {})
        bodies: list[dict[str, Any]] = []
        for content_type, schema_info in content.items():
            schema = schema_info.get("schema", {})
            if schema:
                bodies.append({
                    "content_type": content_type,
                    "required": request_body.get("required", False),
                    "schema": schema,
                })

        if len(bodies) == 1:
            return bodies[0]
        if bodies:
            return {
                "content_types": [b["content_type"] for b in bodies],
                "required": request_body.get("required", False),
                "schemas": bodies,
            }
        return None

    @staticmethod
    def _extract_response_schemas(spec: dict) -> dict[str, Any]:
        """Extract top-level response and component schemas.

        Returns a dict mapping schema names to their definition.
        This is useful for pentesting plugins that need to craft
        valid payloads.
        """
        schemas: dict[str, Any] = {}

        # OpenAPI 3.x
        components = spec.get("components", {})
        for name, schema in components.get("schemas", {}).items():
            schemas[name] = {
                "type": schema.get("type", "object"),
                "properties": list(
                    schema.get("properties", {}).keys()
                ),
                "required": schema.get("required", []),
            }

        # Swagger 2.0
        for name, schema in spec.get("definitions", {}).items():
            schemas[name] = {
                "type": schema.get("type", "object"),
                "properties": list(
                    schema.get("properties", {}).keys()
                ),
                "required": schema.get("required", []),
            }

        return schemas

    @staticmethod
    def _find_deprecated(
        endpoints: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Filter deprecated endpoints."""
        return [e for e in endpoints if e.get("deprecated")]

    # ------------------------------------------------------------------
    # Security checks
    # ------------------------------------------------------------------

    @staticmethod
    def _check_dangerous_endpoints(
        endpoints: list[dict[str, Any]],
        findings: list[Finding],
    ) -> None:
        """Flag endpoints matching dangerous patterns."""
        flagged: set[str] = set()

        for ep in endpoints:
            path_lower = ep["path"].lower()
            for pattern, desc, severity in _DANGEROUS_PATTERNS:
                if pattern in path_lower:
                    # Avoid duplicate findings for the same endpoint
                    key = f"{ep['method']}:{ep['path']}"
                    if key in flagged:
                        break
                    flagged.add(key)

                    factory = getattr(Finding, severity)
                    findings.append(factory(
                        f"Sensitive API endpoint: "
                        f"{ep['method'].upper()} {ep['path']}",
                        description=(
                            f"{desc}. "
                            f"{ep.get('summary') or ep.get('description', '')}"
                        ).rstrip(". "),
                        remediation=(
                            "Ensure endpoint requires proper authorization. "
                            "Consider removing from public API spec."
                        ),
                        tags=["analysis", "api", "openapi", "sensitive"],
                    ))
                    break  # One finding per endpoint

    @staticmethod
    def _check_unprotected_endpoints(
        endpoints: list[dict[str, Any]],
        spec: dict,
        findings: list[Finding],
    ) -> None:
        """Check for state-changing endpoints without auth."""
        state_changing_methods = {"post", "put", "delete", "patch"}

        unprotected = [
            e for e in endpoints
            if (
                not e.get("requires_auth")
                and e["method"] in state_changing_methods
            )
        ]

        if not unprotected:
            return

        # Distinguish severity: if the spec has NO security at all
        # vs. some endpoints missing it
        has_any_security = bool(spec.get("security"))
        has_scheme_defs = bool(
            spec.get("securityDefinitions", {})
            or spec.get("components", {}).get("securitySchemes", {})
        )

        if not has_any_security and not has_scheme_defs:
            # No security defined at all
            findings.append(Finding.high(
                f"No authentication defined in API spec "
                f"({len(unprotected)} state-changing endpoints)",
                evidence=", ".join(
                    f"{e['method'].upper()} {e['path']}"
                    for e in unprotected[:10]
                ),
                remediation=(
                    "Define securitySchemes and apply security "
                    "requirements to all state-changing endpoints"
                ),
                tags=["analysis", "api", "openapi", "auth"],
            ))
        else:
            findings.append(Finding.high(
                f"{len(unprotected)} state-changing endpoints "
                "without auth requirement",
                evidence=", ".join(
                    f"{e['method'].upper()} {e['path']}"
                    for e in unprotected[:10]
                ),
                remediation=(
                    "Ensure all state-changing endpoints require "
                    "authentication"
                ),
                tags=["analysis", "api", "openapi", "auth"],
            ))

    @staticmethod
    def _check_info_disclosure(
        spec: dict, findings: list[Finding],
    ) -> None:
        """Check for information disclosure in spec descriptions/examples."""
        # Patterns indicating sensitive data in descriptions or examples
        sensitive_patterns = [
            (re.compile(r"password\s*[:=]\s*\S+", re.I), "password"),
            (re.compile(r"token\s*[:=]\s*\S+", re.I), "token"),
            (re.compile(r"secret\s*[:=]\s*\S+", re.I), "secret"),
            (re.compile(r"api[_-]?key\s*[:=]\s*\S+", re.I), "API key"),
            (
                re.compile(
                    r"(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+",
                ),
                "internal IP",
            ),
            (
                re.compile(
                    r"(?:jdbc|mongodb|postgres|mysql)://\S+", re.I,
                ),
                "connection string",
            ),
        ]

        # Walk the entire spec as a string for quick scanning
        spec_str = json.dumps(spec)

        disclosure_found: list[str] = []
        for pattern, label in sensitive_patterns:
            matches = pattern.findall(spec_str)
            if matches:
                # Limit evidence to avoid huge findings
                sample = matches[0]
                if len(sample) > 80:
                    sample = sample[:77] + "..."
                disclosure_found.append(f"{label}: {sample}")

        if disclosure_found:
            findings.append(Finding.medium(
                f"Info disclosure in API spec: "
                f"{len(disclosure_found)} types found",
                description=(
                    "The OpenAPI spec contains potentially sensitive "
                    "information in descriptions, examples, or defaults"
                ),
                evidence="; ".join(disclosure_found[:5]),
                remediation=(
                    "Remove sensitive data from API spec descriptions "
                    "and examples. Use placeholder values instead."
                ),
                tags=["analysis", "api", "openapi", "info-disclosure"],
            ))

        # Check for overly detailed server info
        info = spec.get("info", {})
        contact = info.get("contact", {})
        if contact.get("email"):
            findings.append(Finding.low(
                "Developer contact email in API spec",
                description=(
                    f"Contact email exposed: {contact['email']}"
                ),
                remediation="Remove developer contact from public API spec",
                tags=["analysis", "api", "openapi", "info-disclosure"],
            ))

    @staticmethod
    def _check_file_uploads(
        endpoints: list[dict[str, Any]],
        findings: list[Finding],
    ) -> None:
        """Detect file upload endpoints (potential for RCE/abuse)."""
        upload_endpoints: list[dict] = []

        for ep in endpoints:
            rb = ep.get("request_body")
            if not rb:
                continue

            # Check content types
            content_types = []
            if "content_type" in rb:
                content_types = [rb["content_type"]]
            elif "content_types" in rb:
                content_types = rb["content_types"]

            is_upload = any(
                "multipart" in ct or "octet-stream" in ct
                for ct in content_types
            )

            # Also check parameters for file type
            for p in ep.get("parameters", []):
                if p.get("type") == "file" or p.get("format") == "binary":
                    is_upload = True
                    break

            if is_upload:
                upload_endpoints.append(ep)

        if upload_endpoints:
            findings.append(Finding.medium(
                f"{len(upload_endpoints)} file upload endpoints found",
                description=(
                    "File upload endpoints can be exploited for remote "
                    "code execution if not properly validated"
                ),
                evidence=", ".join(
                    f"{e['method'].upper()} {e['path']}"
                    for e in upload_endpoints[:10]
                ),
                remediation=(
                    "Validate file types, enforce size limits, scan for "
                    "malware, and store uploads outside web root"
                ),
                tags=["analysis", "api", "openapi", "upload"],
            ))

    @staticmethod
    def _check_auth_weaknesses(
        spec: dict, findings: list[Finding],
    ) -> None:
        """Analyze authentication schemes for weaknesses."""
        # OpenAPI 3.x
        schemes = (
            spec.get("components", {}).get("securitySchemes", {})
        )
        # Swagger 2.0 fallback
        if not schemes:
            schemes = spec.get("securityDefinitions", {})

        for name, scheme in schemes.items():
            scheme_type = scheme.get("type", "").lower()

            # API key in query string
            if (
                scheme_type == "apikey"
                and scheme.get("in", "").lower() == "query"
            ):
                findings.append(Finding.medium(
                    f"API key in query string: {name}",
                    description=(
                        "API keys in query strings appear in server logs, "
                        "browser history, and referrer headers"
                    ),
                    remediation=(
                        "Send API keys in the Authorization header or "
                        "a custom header instead of query parameters"
                    ),
                    tags=["analysis", "api", "openapi", "auth"],
                ))

            # Basic auth without HTTPS note
            if scheme_type == "http" and scheme.get("scheme") == "basic":
                findings.append(Finding.low(
                    f"HTTP Basic authentication used: {name}",
                    description=(
                        "Basic authentication sends credentials as "
                        "base64-encoded text (not encrypted). Ensure "
                        "HTTPS is enforced."
                    ),
                    remediation=(
                        "Use token-based authentication (OAuth2, JWT) "
                        "instead of Basic auth"
                    ),
                    tags=["analysis", "api", "openapi", "auth"],
                ))

            # OAuth2 with implicit flow
            if scheme_type == "oauth2":
                flows = scheme.get("flows", scheme.get("flow", ""))
                uses_implicit = (
                    (isinstance(flows, dict) and "implicit" in flows)
                    or (isinstance(flows, str) and flows == "implicit")
                )
                if uses_implicit:
                    findings.append(Finding.medium(
                        f"OAuth2 implicit flow used: {name}",
                        description=(
                            "The implicit grant type is deprecated in "
                            "OAuth 2.1 due to token exposure risks"
                        ),
                        remediation=(
                            "Use Authorization Code flow with PKCE "
                            "instead of implicit flow"
                        ),
                        tags=["analysis", "api", "openapi", "auth"],
                    ))
