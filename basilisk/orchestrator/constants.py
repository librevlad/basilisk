"""Shared constants for the orchestrator package."""

from __future__ import annotations

# Canonical set of HTTP port numbers — single source of truth.
# Used by planner, selector, and attack_paths to identify HTTP services.
HTTP_PORTS: frozenset[int] = frozenset({
    80, 443, 3000, 4280, 5000, 8000, 8080, 8180, 8280, 8443, 8888, 9090, 9200,
})

# Gap satisfaction flag keys — written into entity.data by the loop,
# read by the planner to suppress re-firing of gap rules.
GAP_SERVICES_CHECKED = "services_checked"
GAP_TECH_CHECKED = "tech_checked"
GAP_ENDPOINTS_CHECKED = "endpoints_checked"
GAP_FORMS_CHECKED = "forms_checked"
GAP_VERSION_CHECKED = "version_checked"
GAP_CONTAINER_RUNTIME_CHECKED = "container_runtime_checked"
GAP_CONTAINERS_ENUMERATED = "containers_enumerated"
GAP_CONFIG_AUDITED = "config_audited"
GAP_VULNERABILITIES_CHECKED = "vulnerabilities_checked"
GAP_VERIFIED = "verified"
GAP_SERVICE_TESTED = "service_tested"
