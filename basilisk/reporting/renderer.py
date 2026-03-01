"""HTML + JSON report renderer — self-contained cyberpunk dashboard."""

from __future__ import annotations

import html
import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from basilisk.reporting.collector import ReportCollector

_VERSION = "4.0.0"

_KILL_CHAIN_PHASES = [
    ("Recon", [
        "dns_enum", "subdomain_enum", "whois_lookup", "port_scan",
        "ssl_check", "certificate_transparency", "dns_zone_transfer",
        "cloud_enum",
    ]),
    ("Mapping", [
        "web_crawler", "sitemap_parser", "tech_fingerprint",
        "cms_detection", "waf_detection", "api_discovery",
        "form_analyzer", "directory_bruteforce", "vhost_discovery",
        "container_discovery", "container_enumeration",
    ]),
    ("Exploit", [
        "sqli_basic", "xss_scanner", "command_injection", "lfi_rfi",
        "ssrf_scanner", "xxe_scanner", "ssti_scanner",
        "nosqli_scanner", "ldap_injection", "csrf_scanner",
        "cors_check", "open_redirect", "parameter_pollution",
        "http_method_test", "crlf_injection",
        "deserialization_scanner", "graphql_scanner",
        "prototype_pollution", "web_cache_poisoning",
    ]),
    ("Privesc", [
        "container_escape_probe", "privilege_escalation",
        "lateral_movement", "credential_bruteforce",
        "session_analysis", "jwt_analyzer",
    ]),
    ("Verify", [
        "finding_confirmer", "finding_revalidator",
        "container_verification",
    ]),
]


def assemble_data(collector: ReportCollector) -> dict[str, Any]:
    """Convert collector state to a JSON-serializable dict."""
    now = datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    return {
        "version": _VERSION,
        "status": collector.status,
        "mode": collector.mode,
        "target": collector.target,
        "timestamp": now,
        "duration_seconds": round(collector.elapsed, 1),
        "termination_reason": collector.termination_reason,
        "summary": {
            "steps": collector.step,
            "max_steps": collector.max_steps,
            "total_entities": collector.total_entities,
            "total_relations": collector.total_relations,
            "total_findings": len(collector.findings),
            "total_gaps": collector.gap_count,
            "entity_counts": dict(collector.entity_counts),
            "severity_counts": collector.severity_counts,
            "risk_score": round(collector.risk_score, 1),
        },
        "findings": [
            {
                "title": f.title,
                "severity": f.severity.upper(),
                "host": f.host,
                "evidence": f.evidence,
                "description": f.description,
                "tags": f.tags,
                "confidence": f.confidence,
                "verified": f.verified,
                "step": f.step,
            }
            for f in collector.findings
        ],
        "decisions": [
            {
                "step": d.step,
                "plugin": d.plugin,
                "target": d.target,
                "score": round(d.score, 3),
                "reasoning": d.reasoning,
                "productive": d.productive,
                "duration": round(d.duration, 2),
                "new_entities": d.new_entities,
            }
            for d in collector.decisions
        ],
        "plugins": [
            {
                "name": p.name,
                "target": p.target,
                "duration": round(p.duration, 2),
                "findings_count": p.findings_count,
                "step": p.step,
            }
            for p in collector.plugins
        ],
        "step_history": [
            {
                "step": s.step,
                "entities": s.entities,
                "relations": s.relations,
                "gaps": s.gaps,
                "entities_gained": s.entities_gained,
            }
            for s in collector.step_history
        ],
        "reasoning": {
            "hypotheses_confirmed": collector.hypotheses_confirmed,
            "hypotheses_rejected": collector.hypotheses_rejected,
            "hypotheses_active": collector.hypotheses_active,
            "beliefs_strengthened": collector.beliefs_strengthened,
            "beliefs_weakened": collector.beliefs_weakened,
            "events": [
                {
                    "type": e.event_type,
                    "data": e.data,
                    "step": e.step,
                }
                for e in collector.reasoning_events
            ],
        },
        "training": collector.training,
    }


def render_json(data: dict[str, Any]) -> str:
    """Render report data as formatted JSON string."""
    return json.dumps(data, indent=2, ensure_ascii=False, default=str)


def render_html(
    data: dict[str, Any], *, auto_refresh: bool = True,
) -> str:
    """Render a self-contained HTML report from data dict."""
    data_json = json.dumps(data, ensure_ascii=False, default=str)
    safe_json = html.escape(data_json, quote=False)

    refresh_tag = (
        '  <meta http-equiv="refresh" content="3">\n'
        if auto_refresh
        else ""
    )
    target = html.escape(data.get("target", ""))

    parts = [
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
        "<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" "
        "content=\"width=device-width, initial-scale=1\">\n",
        refresh_tag,
        "<title>Basilisk Report — ",
        target,
        "</title>\n",
        _CSS,
        "\n</head>\n<body>\n",
        "<script>const DATA = ",
        safe_json,
        ";</script>\n",
        _sidebar_html(data),
        "\n<div class=\"main\">\n",
        _command_center_html(data),
        "\n",
        _kill_chain_html(data),
        "\n",
        _kg_growth_html(data),
        "\n",
        _findings_html(data),
        "\n",
        _decisions_html(data),
        "\n",
        _attack_surface_html(data),
        "\n",
        _plugin_perf_html(data),
        "\n",
        _reasoning_html(data),
        "\n",
        _training_html(data),
        "\n",
        _footer_html(data),
        "\n</div>\n",
        _JS,
        "\n</body>\n</html>",
    ]
    return "".join(parts)


# ---------------------------------------------------------------------------
# CSS (regular string — no f-string needed)
# ---------------------------------------------------------------------------

_CSS = (  # noqa: E501
    "<style>\n"
    "@import url('https://fonts.googleapis.com/css2?"
    "family=JetBrains+Mono:wght@300;400;500;600;700;800"
    "&display=swap');\n"
    ":root {\n"
    "  --bg: #06080d; --bg2: #0b0f18;"
    " --bg3: #0f1420; --bg4: #131926;\n"
    "  --fg: #c8d0df; --fg-dim: #5a6580;"
    " --fg-muted: #384058;\n"
    "  --border: #1a2236; --border-glow: #1e2d4a;\n"
    "  --neon-green: #00ff6a; --neon-cyan: #00e5ff;"
    " --neon-blue: #4d7cff;\n"
    "  --neon-purple: #b44dff; --neon-pink: #ff2d7b;"
    " --neon-orange: #ff8a00;\n"
    "  --neon-yellow: #ffe100; --neon-red: #ff1744;\n"
    "  --critical: #ff1744;"
    " --critical-bg: rgba(255,23,68,0.08);\n"
    "  --high: #ff6b35;"
    " --high-bg: rgba(255,107,53,0.08);\n"
    "  --medium: #ffb800;"
    " --medium-bg: rgba(255,184,0,0.08);\n"
    "  --low: #00ff6a;"
    " --low-bg: rgba(0,255,106,0.08);\n"
    "  --info: #4d7cff;"
    " --info-bg: rgba(77,124,255,0.08);\n"
    "  --sidebar-w: 240px;\n"
    "  --radius-sm: 4px; --radius: 8px;"
    " --radius-lg: 12px;\n"
    "  --shadow-sm: 0 1px 2px rgba(0,0,0,0.25);\n"
    "  --shadow-md: 0 4px 12px rgba(0,0,0,0.35);\n"
    "  --shadow-lg: 0 8px 24px rgba(0,0,0,0.45);\n"
    "  --shadow-glow-green: 0 0 20px rgba(0,255,106,0.06);\n"
    "  --text-xs: 0.6rem; --text-sm: 0.7rem;"
    " --text-base: 0.78rem;\n"
    "  --text-md: 0.85rem; --text-lg: 0.95rem;"
    " --text-xl: 1.2rem; --text-2xl: 1.6rem;\n"
    "  --sp-1: 0.25rem; --sp-2: 0.5rem;"
    " --sp-3: 0.75rem; --sp-4: 1rem;\n"
    "  --sp-5: 1.25rem; --sp-6: 1.5rem;"
    " --sp-8: 2rem; --sp-10: 2.5rem;\n"
    "  --surface-1: var(--bg2); --surface-2: var(--bg3);"
    " --surface-3: var(--bg4);\n"
    "}\n"
    "* { margin: 0; padding: 0; box-sizing: border-box; }\n"
    "html { scroll-behavior: smooth; }\n"
    "body {\n"
    "  font-family: 'JetBrains Mono', 'Fira Code',"
    " 'Cascadia Code', monospace;\n"
    "  background: var(--bg); color: var(--fg);"
    " line-height: 1.65; font-size: 13px;\n"
    "}\n"
    "body::after {\n"
    "  content: ''; position: fixed; inset: 0;"
    " pointer-events: none; z-index: 9999;\n"
    "  background: repeating-linear-gradient(0deg,"
    " transparent, transparent 2px,\n"
    "    rgba(0,255,106,0.004) 2px,"
    " rgba(0,255,106,0.004) 4px);\n"
    "  mix-blend-mode: overlay;\n"
    "}\n"
    "body::before {\n"
    "  content: ''; position: fixed; inset: 0;"
    " pointer-events: none; z-index: -1;\n"
    "  background-image:"
    " linear-gradient(rgba(0,229,255,0.01) 1px,"
    " transparent 1px),\n"
    "    linear-gradient(90deg,"
    " rgba(0,229,255,0.01) 1px, transparent 1px);\n"
    "  background-size: 60px 60px;\n"
    "}\n"
    "::-webkit-scrollbar { width: 6px; height: 6px; }\n"
    "::-webkit-scrollbar-track { background: var(--bg); }\n"
    "::-webkit-scrollbar-thumb {"
    " background: var(--border-glow);"
    " border-radius: 3px; }\n"
    "::-webkit-scrollbar-thumb:hover {"
    " background: var(--neon-green); }\n"
    "\n"
    "@keyframes pulse-glow {\n"
    "  0%, 100% {"
    " box-shadow: 0 0 4px rgba(0,255,106,0.3); }\n"
    "  50% {"
    " box-shadow: 0 0 12px rgba(0,255,106,0.6); }\n"
    "}\n"
    "@keyframes scan-line {\n"
    "  from { top: -4px; } to { top: 100%; }\n"
    "}\n"
    "\n"
    ".sidebar {\n"
    "  position: fixed; top: 0; left: 0;"
    " width: var(--sidebar-w); height: 100vh;\n"
    "  background: var(--surface-1);"
    " border-right: 1px solid var(--border);\n"
    "  padding: 0; overflow-y: auto; z-index: 100;"
    " box-shadow: var(--shadow-lg);\n"
    "}\n"
    ".sidebar-brand {\n"
    "  padding: 1.2rem 1rem 1rem;\n"
    "  background: linear-gradient(180deg,"
    " rgba(0,255,106,0.03) 0%, transparent 100%);\n"
    "}\n"
    ".sidebar-brand pre {\n"
    "  color: var(--neon-green);"
    " font-size: var(--text-xs); line-height: 1.15;\n"
    "  text-shadow: 0 0 10px rgba(0,255,106,0.3);"
    " margin-bottom: 0.4rem;\n"
    "}\n"
    ".sidebar-brand .brand-sub {\n"
    "  font-size: var(--text-xs); color: var(--fg-dim);\n"
    "  letter-spacing: 0.15em;"
    " text-transform: uppercase;\n"
    "}\n"
    ".sidebar nav { padding: 0.5rem 0; }\n"
    ".sidebar nav a {\n"
    "  display: flex; justify-content: space-between;"
    " align-items: center;\n"
    "  padding: 0.45rem 1rem; color: var(--fg-dim);"
    " text-decoration: none;\n"
    "  font-size: var(--text-sm); font-weight: 500;\n"
    "  border-left: 2px solid transparent;\n"
    "  transition: color 0.15s, background 0.15s,"
    " border-color 0.15s;\n"
    "}\n"
    ".sidebar nav a:hover {"
    " color: var(--fg);"
    " background: rgba(0,255,106,0.03); }\n"
    ".sidebar nav a.active {\n"
    "  color: var(--neon-green);"
    " border-left-color: var(--neon-green);\n"
    "  background: rgba(0,255,106,0.06);\n"
    "}\n"
    ".sidebar nav a .cnt {\n"
    "  background: var(--bg4); padding: 1px 6px;"
    " border-radius: var(--radius-sm);\n"
    "  font-size: var(--text-xs); color: var(--fg-dim);\n"
    "}\n"
    ".sidebar .sep {\n"
    "  height: 1px; margin: 0.5rem 1rem;\n"
    "  background: linear-gradient(90deg,"
    " transparent, var(--border), transparent);\n"
    "}\n"
    ".risk-indicator {\n"
    "  margin: 0.8rem 1rem; padding: 0.6rem;\n"
    "  background: var(--surface-2);"
    " border-radius: var(--radius);\n"
    "  text-align: center;\n"
    "}\n"
    ".risk-score {\n"
    "  font-size: var(--text-2xl); font-weight: 800;\n"
    "  background: linear-gradient(135deg,"
    " var(--neon-green), var(--neon-cyan));\n"
    "  -webkit-background-clip: text;"
    " -webkit-text-fill-color: transparent;\n"
    "  background-clip: text;\n"
    "}\n"
    ".risk-score.high-risk {\n"
    "  background: linear-gradient(135deg,"
    " var(--high), var(--critical));\n"
    "  -webkit-background-clip: text;"
    " background-clip: text;\n"
    "}\n"
    ".risk-label {"
    " font-size: var(--text-xs); color: var(--fg-dim);"
    " text-transform: uppercase; }\n"
    "\n"
    ".status-badge {\n"
    "  display: inline-block; padding: 2px 8px;"
    " border-radius: var(--radius-sm);\n"
    "  font-size: var(--text-xs); font-weight: 600;"
    " text-transform: uppercase;\n"
    "}\n"
    ".status-running {\n"
    "  color: var(--neon-green);"
    " border: 1px solid var(--neon-green);\n"
    "  animation: pulse-glow 2s ease-in-out infinite;\n"
    "}\n"
    ".status-completed {"
    " color: var(--neon-cyan);"
    " border: 1px solid var(--neon-cyan); }\n"
    "\n"
    ".main {"
    " margin-left: var(--sidebar-w);"
    " padding: var(--sp-6); }\n"
    "\n"
    ".section {\n"
    "  margin-bottom: var(--sp-6);\n"
    "  background: var(--surface-1);"
    " border-radius: var(--radius-lg);\n"
    "  border: 1px solid var(--border);"
    " padding: var(--sp-5);\n"
    "  box-shadow: var(--shadow-md);\n"
    "}\n"
    ".section-title {\n"
    "  font-size: var(--text-lg); font-weight: 700;"
    " color: var(--neon-green);\n"
    "  margin-bottom: var(--sp-4);"
    " padding-bottom: var(--sp-2);\n"
    "  border-bottom: 1px solid var(--border);\n"
    "  text-transform: uppercase;"
    " letter-spacing: 0.08em;\n"
    "}\n"
    "\n"
    ".cmd-logo pre {\n"
    "  color: var(--neon-green);"
    " font-size: var(--text-xs); line-height: 1.1;\n"
    "  text-shadow: 0 0 8px rgba(0,255,106,0.3);"
    " margin-bottom: var(--sp-3);\n"
    "}\n"
    ".cmd-meta {"
    " display: flex; gap: var(--sp-4);"
    " align-items: center; flex-wrap: wrap; }\n"
    ".cmd-meta span {"
    " font-size: var(--text-sm);"
    " color: var(--fg-dim); }\n"
    ".cmd-meta .target {"
    " color: var(--neon-cyan); font-weight: 600; }\n"
    "\n"
    ".progress-container {\n"
    "  margin: var(--sp-3) 0; background: var(--bg4);"
    " border-radius: var(--radius-sm);\n"
    "  height: 6px; overflow: hidden;\n"
    "}\n"
    ".progress-bar {\n"
    "  height: 100%; background: linear-gradient(90deg,"
    " var(--neon-green), var(--neon-cyan));\n"
    "  border-radius: var(--radius-sm);"
    " transition: width 0.5s;\n"
    "}\n"
    "\n"
    ".metrics-grid {\n"
    "  display: grid;"
    " grid-template-columns:"
    " repeat(auto-fit, minmax(140px, 1fr));\n"
    "  gap: var(--sp-3); margin-top: var(--sp-4);\n"
    "}\n"
    ".metric-card {\n"
    "  background: var(--surface-2);"
    " border-radius: var(--radius);\n"
    "  padding: var(--sp-3); text-align: center;\n"
    "}\n"
    ".metric-value {\n"
    "  font-size: var(--text-xl); font-weight: 800;"
    " color: var(--neon-green);\n"
    "}\n"
    ".metric-label {\n"
    "  font-size: var(--text-xs); color: var(--fg-dim);"
    " text-transform: uppercase;\n"
    "  margin-top: var(--sp-1);\n"
    "}\n"
    "\n"
    ".severity-bar {\n"
    "  display: flex; height: 8px;"
    " border-radius: var(--radius-sm);\n"
    "  overflow: hidden; margin-top: var(--sp-3);"
    " gap: 1px;\n"
    "}\n"
    ".severity-bar .seg { transition: width 0.5s; }\n"
    "\n"
    ".kill-chain {\n"
    "  display: flex; gap: var(--sp-2);"
    " align-items: stretch; flex-wrap: wrap;\n"
    "}\n"
    ".kc-phase {\n"
    "  flex: 1; min-width: 120px;"
    " background: var(--surface-2);\n"
    "  border-radius: var(--radius);"
    " padding: var(--sp-3); text-align: center;\n"
    "  border: 1px solid var(--border);"
    " position: relative;\n"
    "}\n"
    ".kc-phase.active {"
    " border-color: var(--neon-green);"
    " box-shadow: var(--shadow-glow-green); }\n"
    ".kc-name {\n"
    "  font-size: var(--text-sm); font-weight: 700;"
    " text-transform: uppercase;\n"
    "  color: var(--neon-cyan);"
    " margin-bottom: var(--sp-1);\n"
    "}\n"
    ".kc-count {"
    " font-size: var(--text-2xl); font-weight: 800;"
    " color: var(--fg); }\n"
    ".kc-label {"
    " font-size: var(--text-xs);"
    " color: var(--fg-dim); }\n"
    ".kc-arrow {\n"
    "  position: absolute; right: -12px; top: 50%;"
    " transform: translateY(-50%);\n"
    "  color: var(--fg-muted);"
    " font-size: var(--text-base); z-index: 1;\n"
    "}\n"
    "\n"
    ".growth-chart {"
    " display: flex; align-items: flex-end;"
    " gap: 2px; height: 100px; }\n"
    ".growth-bar {\n"
    "  flex: 1; background: linear-gradient(0deg,"
    " var(--neon-green), var(--neon-cyan));\n"
    "  border-radius: 2px 2px 0 0;"
    " min-width: 4px; max-width: 20px;\n"
    "  transition: height 0.3s;"
    " position: relative; opacity: 0.8;\n"
    "}\n"
    ".growth-bar:hover { opacity: 1; }\n"
    ".growth-bar .tooltip {\n"
    "  display: none; position: absolute;"
    " bottom: 100%; left: 50%;"
    " transform: translateX(-50%);\n"
    "  background: var(--bg4); padding: 2px 6px;"
    " border-radius: var(--radius-sm);\n"
    "  font-size: var(--text-xs);"
    " white-space: nowrap; color: var(--fg);\n"
    "}\n"
    ".growth-bar:hover .tooltip { display: block; }\n"
    "\n"
    ".filter-bar {\n"
    "  display: flex; gap: var(--sp-2);"
    " align-items: center; flex-wrap: wrap;\n"
    "  margin-bottom: var(--sp-3);\n"
    "}\n"
    ".filter-chip {\n"
    "  padding: 3px 10px;"
    " border-radius: var(--radius-sm);"
    " font-size: var(--text-xs);\n"
    "  font-weight: 600; cursor: pointer;"
    " border: 1px solid var(--border);\n"
    "  background: var(--surface-2);"
    " color: var(--fg-dim);"
    " text-transform: uppercase;\n"
    "  transition: all 0.15s;\n"
    "}\n"
    ".filter-chip.active { color: var(--bg); }\n"
    ".filter-chip[data-sev=\"CRITICAL\"].active {\n"
    "  background: var(--critical);"
    " border-color: var(--critical); }\n"
    ".filter-chip[data-sev=\"HIGH\"].active {\n"
    "  background: var(--high);"
    " border-color: var(--high); }\n"
    ".filter-chip[data-sev=\"MEDIUM\"].active {\n"
    "  background: var(--medium);"
    " border-color: var(--medium); }\n"
    ".filter-chip[data-sev=\"LOW\"].active {\n"
    "  background: var(--low);"
    " border-color: var(--low); }\n"
    ".filter-chip[data-sev=\"INFO\"].active {\n"
    "  background: var(--info);"
    " border-color: var(--info); }\n"
    "\n"
    ".search-box {\n"
    "  padding: 4px 10px;"
    " background: var(--surface-2);"
    " border: 1px solid var(--border);\n"
    "  border-radius: var(--radius-sm);"
    " color: var(--fg); font-size: var(--text-sm);\n"
    "  font-family: inherit; outline: none;"
    " flex: 1; max-width: 240px;\n"
    "}\n"
    ".search-box:focus {"
    " border-color: var(--neon-green); }\n"
    "\n"
    ".finding-card {\n"
    "  background: var(--surface-2);"
    " border-radius: var(--radius);\n"
    "  border: 1px solid var(--border);"
    " margin-bottom: var(--sp-2);\n"
    "  overflow: hidden;\n"
    "}\n"
    ".finding-card summary {\n"
    "  padding: var(--sp-3); cursor: pointer;"
    " display: flex;\n"
    "  align-items: center; gap: var(--sp-2);"
    " list-style: none;\n"
    "  font-size: var(--text-base);\n"
    "}\n"
    ".finding-card summary::-webkit-details-marker {"
    " display: none; }\n"
    ".finding-card[open] {"
    " border-color: var(--border-glow); }\n"
    ".finding-body {"
    " padding: 0 var(--sp-3) var(--sp-3); }\n"
    "\n"
    ".sev-badge {\n"
    "  padding: 2px 8px;"
    " border-radius: var(--radius-sm);"
    " font-size: var(--text-xs);\n"
    "  font-weight: 700; text-transform: uppercase;\n"
    "}\n"
    ".sev-CRITICAL {\n"
    "  background: var(--critical-bg);"
    " color: var(--critical);\n"
    "  border: 1px solid var(--critical); }\n"
    ".sev-HIGH {\n"
    "  background: var(--high-bg);"
    " color: var(--high);\n"
    "  border: 1px solid var(--high); }\n"
    ".sev-MEDIUM {\n"
    "  background: var(--medium-bg);"
    " color: var(--medium);\n"
    "  border: 1px solid var(--medium); }\n"
    ".sev-LOW {\n"
    "  background: var(--low-bg);"
    " color: var(--low);\n"
    "  border: 1px solid var(--low); }\n"
    ".sev-INFO {\n"
    "  background: var(--info-bg);"
    " color: var(--info);\n"
    "  border: 1px solid var(--info); }\n"
    "\n"
    ".evidence-block {\n"
    "  background: var(--bg); padding: var(--sp-3);"
    " border-radius: var(--radius-sm);\n"
    "  font-size: var(--text-sm);"
    " white-space: pre-wrap; word-break: break-all;\n"
    "  border: 1px solid var(--border);"
    " margin-top: var(--sp-2);\n"
    "  max-height: 200px; overflow-y: auto;"
    " color: var(--neon-green);\n"
    "}\n"
    ".conf-badge {\n"
    "  padding: 1px 6px;"
    " border-radius: var(--radius-sm);"
    " font-size: var(--text-xs);\n"
    "  background: var(--surface-3);"
    " color: var(--fg-dim);\n"
    "}\n"
    ".tag-chip {\n"
    "  display: inline-block; padding: 1px 6px;"
    " border-radius: var(--radius-sm);\n"
    "  font-size: var(--text-xs);"
    " background: var(--surface-3);"
    " color: var(--fg-dim);\n"
    "  margin-right: var(--sp-1);\n"
    "}\n"
    ".verified-badge {\n"
    "  color: var(--neon-green);"
    " font-size: var(--text-xs); font-weight: 600;\n"
    "}\n"
    "\n"
    ".timeline {"
    " position: relative; padding-left: 24px; }\n"
    ".timeline::before {\n"
    "  content: ''; position: absolute;"
    " left: 8px; top: 0; bottom: 0;\n"
    "  width: 2px; background: var(--border);\n"
    "}\n"
    ".timeline-item {\n"
    "  position: relative;"
    " margin-bottom: var(--sp-3);\n"
    "  padding: var(--sp-3);"
    " background: var(--surface-2);\n"
    "  border-radius: var(--radius);"
    " border: 1px solid var(--border);\n"
    "}\n"
    ".timeline-item::before {\n"
    "  content: ''; position: absolute;"
    " left: -20px; top: 14px;\n"
    "  width: 8px; height: 8px; border-radius: 50%;\n"
    "  background: var(--neon-cyan);"
    " border: 2px solid var(--bg);\n"
    "}\n"
    ".timeline-item.productive::before {"
    " background: var(--neon-green); }\n"
    ".timeline-item.unproductive::before {"
    " background: var(--fg-muted); }\n"
    ".tl-header {\n"
    "  display: flex; gap: var(--sp-2);"
    " align-items: center; flex-wrap: wrap;\n"
    "  font-size: var(--text-sm);\n"
    "}\n"
    ".tl-plugin {"
    " color: var(--neon-cyan); font-weight: 600; }\n"
    ".tl-score { color: var(--fg-dim); }\n"
    ".tl-reasoning {\n"
    "  font-size: var(--text-xs); color: var(--fg-dim);"
    " margin-top: var(--sp-1);\n"
    "  line-height: 1.4;\n"
    "}\n"
    "\n"
    ".surface-grid {\n"
    "  display: grid; grid-template-columns:"
    " repeat(auto-fill, minmax(300px, 1fr));\n"
    "  gap: var(--sp-3);\n"
    "}\n"
    ".host-card {\n"
    "  background: var(--surface-2);"
    " border-radius: var(--radius);\n"
    "  border: 1px solid var(--border);"
    " padding: var(--sp-3);\n"
    "}\n"
    ".host-name {"
    " font-weight: 700; color: var(--neon-cyan);"
    " margin-bottom: var(--sp-2); }\n"
    ".host-card table {"
    " width: 100%; border-collapse: collapse;"
    " font-size: var(--text-sm); }\n"
    ".host-card th {\n"
    "  text-align: left;"
    " padding: var(--sp-1) var(--sp-2);"
    " color: var(--fg-dim);\n"
    "  border-bottom: 1px solid var(--border);"
    " font-weight: 500;\n"
    "  text-transform: uppercase;"
    " font-size: var(--text-xs);\n"
    "}\n"
    ".host-card td {"
    " padding: var(--sp-1) var(--sp-2); }\n"
    "\n"
    ".perf-table {"
    " width: 100%; border-collapse: collapse;"
    " font-size: var(--text-sm); }\n"
    ".perf-table th {\n"
    "  text-align: left; padding: var(--sp-2);"
    " color: var(--fg-dim);\n"
    "  border-bottom: 1px solid var(--border);"
    " font-weight: 600;\n"
    "  text-transform: uppercase;"
    " font-size: var(--text-xs); cursor: pointer;\n"
    "}\n"
    ".perf-table th:hover {"
    " color: var(--neon-green); }\n"
    ".perf-table td {"
    " padding: var(--sp-2);"
    " border-bottom: 1px solid var(--border); }\n"
    ".perf-table tr:hover td {"
    " background: rgba(0,255,106,0.02); }\n"
    "\n"
    ".reasoning-grid {\n"
    "  display: grid; grid-template-columns:"
    " repeat(auto-fit, minmax(140px, 1fr));\n"
    "  gap: var(--sp-3);"
    " margin-bottom: var(--sp-4);\n"
    "}\n"
    ".reasoning-stat {\n"
    "  background: var(--surface-2);"
    " border-radius: var(--radius);\n"
    "  padding: var(--sp-3); text-align: center;\n"
    "}\n"
    ".reasoning-value {"
    " font-size: var(--text-xl); font-weight: 800; }\n"
    ".reasoning-label {"
    " font-size: var(--text-xs); color: var(--fg-dim);"
    " text-transform: uppercase; }\n"
    "\n"
    ".training-table {"
    " width: 100%; border-collapse: collapse;"
    " font-size: var(--text-sm); }\n"
    ".training-table th {\n"
    "  text-align: left; padding: var(--sp-2);"
    " color: var(--fg-dim);\n"
    "  border-bottom: 1px solid var(--border);"
    " font-size: var(--text-xs);\n"
    "  text-transform: uppercase;\n"
    "}\n"
    ".training-table td {"
    " padding: var(--sp-2);"
    " border-bottom: 1px solid var(--border); }\n"
    ".pass-badge {\n"
    "  padding: 2px 10px;"
    " border-radius: var(--radius-sm);"
    " font-weight: 700;\n"
    "  font-size: var(--text-sm);\n"
    "}\n"
    ".pass-badge.passed {"
    " background: var(--low-bg); color: var(--low); }\n"
    ".pass-badge.failed {"
    " background: var(--critical-bg);"
    " color: var(--critical); }\n"
    "\n"
    ".footer {\n"
    "  text-align: center; padding: var(--sp-4);"
    " color: var(--fg-muted);\n"
    "  font-size: var(--text-xs);"
    " border-top: 1px solid var(--border);\n"
    "  margin-top: var(--sp-6);\n"
    "}\n"
    "\n"
    "@media (max-width: 800px) {\n"
    "  .sidebar { display: none; }\n"
    "  .main { margin-left: 0; }\n"
    "  .kill-chain { flex-direction: column; }\n"
    "  .surface-grid {"
    " grid-template-columns: 1fr; }\n"
    "  .metrics-grid {"
    " grid-template-columns: repeat(2, 1fr); }\n"
    "}\n"
    "\n"
    "@media print {\n"
    "  .sidebar { display: none; }\n"
    "  .main { margin-left: 0; }\n"
    "  body::before, body::after { display: none; }\n"
    "  body { background: #fff; color: #1a1e2e; }\n"
    "  .section {"
    " border: 1px solid #ddd;"
    " box-shadow: none; background: #fff; }\n"
    "}\n"
    "</style>"
)


# ---------------------------------------------------------------------------
# HTML section builders (use str.format / concatenation to avoid
# Python 3.13 f-string parser issues with format specs in HTML)
# ---------------------------------------------------------------------------

_ASCII_LOGO = (
    "\n ____            _ _ _     _\n"
    "| __ )  __ _ ___(_) (_)___| | __\n"
    "|  _ \\ / _` / __| | | / __| |/ /\n"
    "| |_) | (_| \\__ \\ | | \\__ \\   <\n"
    "|____/ \\__,_|___/_|_|_|___/_|\\_\\"
)


def _e(s: str) -> str:
    """Shorthand for html.escape."""
    return html.escape(str(s))


def _fmt(val: float, spec: str = ".1f") -> str:
    """Pre-format a float value (avoids f-string format spec issues)."""
    return format(val, spec)


def _sidebar_html(data: dict) -> str:
    summary = data.get("summary", {})
    risk = summary.get("risk_score", 0)
    status = data.get("status", "running")
    findings_count = summary.get("total_findings", 0)
    decisions_count = len(data.get("decisions", []))
    plugins_count = len(data.get("plugins", []))

    risk_class = "high-risk" if risk >= 5.0 else ""
    risk_str = _fmt(risk, ".1f")
    status_class = "status-" + status
    version = _e(data.get("version", _VERSION))

    training = data.get("training")
    training_link = ""
    if training is not None:
        training_link = (
            '<a href="#training">Training '
            '<span class="cnt">1</span></a>'
        )

    return (
        '<aside class="sidebar">\n'
        '  <div class="sidebar-brand">\n'
        "    <pre>" + _e(_ASCII_LOGO) + "</pre>\n"
        '    <div class="brand-sub">v'
        + version + "</div>\n"
        "  </div>\n"
        '  <div class="risk-indicator">\n'
        '    <div class="risk-score '
        + risk_class + '">' + risk_str + "</div>\n"
        '    <div class="risk-label">Risk Score</div>\n'
        '    <div style="margin-top:4px">'
        '<span class="status-badge '
        + status_class + '">'
        + _e(status) + "</span></div>\n"
        "  </div>\n"
        "  <nav>\n"
        '    <a href="#command-center">Command Center</a>\n'
        '    <a href="#kill-chain">Kill Chain</a>\n'
        '    <a href="#kg-growth">KG Growth</a>\n'
        '    <div class="sep"></div>\n'
        '    <a href="#findings">Findings '
        '<span class="cnt">'
        + str(findings_count) + "</span></a>\n"
        '    <a href="#decisions">Decisions '
        '<span class="cnt">'
        + str(decisions_count) + "</span></a>\n"
        '    <a href="#attack-surface">Attack Surface</a>\n'
        '    <a href="#plugins">Plugins '
        '<span class="cnt">'
        + str(plugins_count) + "</span></a>\n"
        '    <a href="#reasoning">Reasoning</a>\n'
        "    " + training_link + "\n"
        "  </nav>\n"
        "</aside>"
    )


def _command_center_html(data: dict) -> str:
    summary = data.get("summary", {})
    steps = summary.get("steps", 0)
    max_steps = summary.get("max_steps", 100)
    progress_pct = (steps / max_steps * 100) if max_steps > 0 else 0
    total_ent = summary.get("total_entities", 0)
    total_rel = summary.get("total_relations", 0)
    total_findings = summary.get("total_findings", 0)
    total_gaps = summary.get("total_gaps", 0)
    duration = data.get("duration_seconds", 0)

    mins, secs = divmod(int(duration), 60)
    elapsed_str = str(mins) + "m " + str(secs) + "s"
    progress_str = _fmt(progress_pct, ".1f")

    sev_counts = summary.get("severity_counts", {})
    total_sev = max(sum(sev_counts.values()), 1)
    sev_bar_parts: list[str] = []
    sev_colors = [
        ("CRITICAL", "var(--critical)"),
        ("HIGH", "var(--high)"),
        ("MEDIUM", "var(--medium)"),
        ("LOW", "var(--low)"),
        ("INFO", "var(--info)"),
    ]
    for sev, color in sev_colors:
        cnt = sev_counts.get(sev, 0)
        if cnt > 0:
            pct = _fmt(cnt / total_sev * 100, ".1f")
            sev_bar_parts.append(
                '<div class="seg" style="width:'
                + pct + "%;background:" + color + '"></div>'
            )
    sev_bar = "".join(sev_bar_parts)

    target_escaped = _e(data.get("target", ""))
    mode_escaped = _e(data.get("mode", "auto"))
    ts_escaped = _e(data.get("timestamp", ""))

    return (
        '<div class="section" id="command-center">\n'
        '  <div class="cmd-logo"><pre>'
        + _e(_ASCII_LOGO) + "</pre></div>\n"
        '  <div class="cmd-meta">\n'
        '    <span>Target: <span class="target">'
        + target_escaped + "</span></span>\n"
        "    <span>Mode: " + mode_escaped + "</span>\n"
        "    <span>Elapsed: " + elapsed_str + "</span>\n"
        "    <span>" + ts_escaped + "</span>\n"
        "  </div>\n"
        '  <div class="progress-container">\n'
        '    <div class="progress-bar" style="width:'
        + progress_str + '%"></div>\n'
        "  </div>\n"
        '  <div style="font-size:var(--text-xs);'
        'color:var(--fg-dim);margin-top:2px">\n'
        "    Step " + str(steps) + "/" + str(max_steps)
        + "\n  </div>\n"
        '  <div class="metrics-grid">\n'
        '    <div class="metric-card">'
        '<div class="metric-value">'
        + str(steps) + '</div>'
        '<div class="metric-label">Steps</div></div>\n'
        '    <div class="metric-card">'
        '<div class="metric-value">'
        + str(total_ent) + '</div>'
        '<div class="metric-label">Entities</div></div>\n'
        '    <div class="metric-card">'
        '<div class="metric-value">'
        + str(total_rel) + '</div>'
        '<div class="metric-label">Relations</div></div>\n'
        '    <div class="metric-card">'
        '<div class="metric-value">'
        + str(total_findings) + '</div>'
        '<div class="metric-label">Findings</div></div>\n'
        '    <div class="metric-card">'
        '<div class="metric-value">'
        + str(total_gaps) + '</div>'
        '<div class="metric-label">Gaps</div></div>\n'
        "  </div>\n"
        '  <div class="severity-bar">' + sev_bar + "</div>\n"
        "</div>"
    )


def _kill_chain_html(data: dict) -> str:
    plugins = data.get("plugins", [])
    plugin_names = {p["name"] for p in plugins}

    phases_parts: list[str] = []
    for i, (name, members) in enumerate(_KILL_CHAIN_PHASES):
        count = sum(1 for m in members if m in plugin_names)
        active = " active" if count > 0 else ""
        arrow = (
            '<span class="kc-arrow">&#x25B6;</span>'
            if i < len(_KILL_CHAIN_PHASES) - 1
            else ""
        )
        phases_parts.append(
            '<div class="kc-phase' + active + '">\n'
            '      <div class="kc-name">'
            + _e(name) + "</div>\n"
            '      <div class="kc-count">'
            + str(count) + "</div>\n"
            '      <div class="kc-label">plugins</div>\n'
            "      " + arrow + "\n"
            "    </div>"
        )
    phases_html = "".join(phases_parts)

    return (
        '<div class="section" id="kill-chain">\n'
        '  <div class="section-title">Kill Chain</div>\n'
        '  <div class="kill-chain">'
        + phases_html + "</div>\n"
        "</div>"
    )


def _kg_growth_html(data: dict) -> str:
    history = data.get("step_history", [])
    if not history:
        return (
            '<div class="section" id="kg-growth">'
            '<div class="section-title">KG Growth</div>'
            '<div style="color:var(--fg-dim)">'
            "No data yet</div></div>"
        )

    max_gained = max(
        (s.get("entities_gained", 0) for s in history), default=1,
    )
    max_gained = max(max_gained, 1)

    bars_parts: list[str] = []
    for s in history:
        gained = s.get("entities_gained", 0)
        h = max(gained / max_gained * 100, 2)
        step = s.get("step", 0)
        h_str = _fmt(h, ".0f")
        bars_parts.append(
            '<div class="growth-bar" style="height:'
            + h_str + '%">'
            '<span class="tooltip">Step '
            + str(step) + ": +" + str(gained)
            + " entities</span></div>"
        )
    bars_html = "".join(bars_parts)

    return (
        '<div class="section" id="kg-growth">\n'
        '  <div class="section-title">'
        "Knowledge Graph Growth</div>\n"
        '  <div class="growth-chart">'
        + bars_html + "</div>\n"
        "</div>"
    )


def _findings_html(data: dict) -> str:
    findings = data.get("findings", [])
    sev_counts = data.get("summary", {}).get("severity_counts", {})

    chip_parts: list[str] = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        cnt = sev_counts.get(sev, 0)
        chip_parts.append(
            '<span class="filter-chip active" data-sev="'
            + sev + '" onclick="toggleFilter(this)">'
            + sev + " (" + str(cnt) + ")</span>"
        )
    chips = "".join(chip_parts)

    card_parts: list[str] = []
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        title = _e(f.get("title", ""))
        host = _e(f.get("host", ""))
        evidence = _e(f.get("evidence", ""))
        desc = _e(f.get("description", ""))
        conf = f.get("confidence", 0)
        verified = f.get("verified", False)
        step = f.get("step", 0)
        tags = f.get("tags", [])

        conf_str = _fmt(conf * 100, ".0f") + "%"
        verified_html = (
            '<span class="verified-badge">VERIFIED</span>'
            if verified
            else ""
        )
        tags_html = "".join(
            '<span class="tag-chip">' + _e(t) + "</span>"
            for t in tags
        )
        evidence_html = (
            '<div class="evidence-block">'
            + evidence + "</div>"
            if evidence
            else ""
        )
        desc_html = (
            '<div style="margin-bottom:var(--sp-2)">'
            + desc + "</div>"
            if desc
            else ""
        )
        tags_block = (
            '<div style="margin-top:var(--sp-2)">'
            + tags_html + "</div>"
            if tags_html
            else ""
        )

        card_parts.append(
            '<details class="finding-card" data-sev="'
            + sev + '">\n'
            "  <summary>\n"
            '    <span class="sev-badge sev-'
            + sev + '">' + sev + "</span>\n"
            '    <span style="flex:1">'
            + title + "</span>\n"
            '    <span class="conf-badge">'
            + conf_str + "</span>\n"
            "    " + verified_html + "\n"
            "  </summary>\n"
            '  <div class="finding-body">\n'
            '    <div style="color:var(--fg-dim);'
            "font-size:var(--text-sm);"
            'margin-bottom:var(--sp-2)">\n'
            "      Host: " + host
            + " &middot; Step " + str(step) + "\n"
            "    </div>\n"
            "    " + desc_html + "\n"
            "    " + evidence_html + "\n"
            "    " + tags_block + "\n"
            "  </div>\n"
            "</details>"
        )

    if not findings:
        cards = (
            '<div style="color:var(--fg-dim);'
            'padding:var(--sp-3)">No findings yet</div>'
        )
    else:
        cards = "".join(card_parts)

    return (
        '<div class="section" id="findings">\n'
        '  <div class="section-title">'
        "Findings (War Board)</div>\n"
        '  <div class="filter-bar">\n'
        "    " + chips + "\n"
        '    <input type="text" class="search-box"'
        ' placeholder="Search findings..."'
        ' oninput="applyFilters()">\n'
        '    <span style="font-size:var(--text-xs);'
        "color:var(--fg-dim);cursor:pointer\""
        ' onclick="toggleAll(true)">Expand All</span>\n'
        '    <span style="font-size:var(--text-xs);'
        "color:var(--fg-dim);cursor:pointer\""
        ' onclick="toggleAll(false)">'
        "Collapse All</span>\n"
        "  </div>\n"
        '  <div id="findings-list">' + cards + "</div>\n"
        "</div>"
    )


def _decisions_html(data: dict) -> str:
    decisions = data.get("decisions", [])
    item_parts: list[str] = []
    for d in decisions:
        prod = d.get("productive", False)
        prod_class = "productive" if prod else "unproductive"
        prod_label = (
            '<span class="verified-badge">productive</span>'
            if prod
            else ""
        )
        plugin = _e(d.get("plugin", ""))
        target = _e(d.get("target", ""))
        score = _fmt(d.get("score", 0), ".3f")
        step = d.get("step", 0)
        reasoning = _e(d.get("reasoning", ""))

        item_parts.append(
            '<div class="timeline-item '
            + prod_class + '">\n'
            '  <div class="tl-header">\n'
            '    <span style="color:var(--fg-dim)">#'
            + str(step) + "</span>\n"
            '    <span class="tl-plugin">'
            + plugin + "</span>\n"
            '    <span style="color:var(--fg-dim)">'
            "&rarr; " + target + "</span>\n"
            '    <span class="tl-score">score: '
            + score + "</span>\n"
            "    " + prod_label + "\n"
            "  </div>\n"
            '  <div class="tl-reasoning">'
            + reasoning + "</div>\n"
            "</div>"
        )

    if not decisions:
        items = (
            '<div style="color:var(--fg-dim);'
            'padding:var(--sp-3)">No decisions yet</div>'
        )
    else:
        items = "".join(item_parts)

    return (
        '<div class="section" id="decisions">\n'
        '  <div class="section-title">'
        "Decision Timeline</div>\n"
        '  <div class="timeline">' + items + "</div>\n"
        "</div>"
    )


def _attack_surface_html(data: dict) -> str:
    ec = data.get("summary", {}).get("entity_counts", {})
    hosts = ec.get("host", 0)
    services = ec.get("service", 0)
    endpoints = ec.get("endpoint", 0)
    techs = ec.get("technology", 0)
    containers = ec.get("container", 0)

    return (
        '<div class="section" id="attack-surface">\n'
        '  <div class="section-title">'
        "Attack Surface</div>\n"
        '  <div class="surface-grid">\n'
        '    <div class="host-card">\n'
        '      <div class="host-name">Overview</div>\n'
        "      <table>\n"
        "        <tr><th>Type</th><th>Count</th></tr>\n"
        "        <tr><td>Hosts</td><td>"
        + str(hosts) + "</td></tr>\n"
        "        <tr><td>Services</td><td>"
        + str(services) + "</td></tr>\n"
        "        <tr><td>Endpoints</td><td>"
        + str(endpoints) + "</td></tr>\n"
        "        <tr><td>Technologies</td><td>"
        + str(techs) + "</td></tr>\n"
        "        <tr><td>Containers</td><td>"
        + str(containers) + "</td></tr>\n"
        "      </table>\n"
        "    </div>\n"
        "  </div>\n"
        "</div>"
    )


def _plugin_perf_html(data: dict) -> str:
    plugins = data.get("plugins", [])
    row_parts: list[str] = []
    for p in plugins:
        name = _e(p.get("name", ""))
        target = _e(p.get("target", ""))
        dur = _fmt(p.get("duration", 0), ".2f")
        fc = p.get("findings_count", 0)
        step = p.get("step", 0)
        fc_style = (
            " style=\"color:var(--neon-green);font-weight:600\""
            if fc > 0
            else ""
        )
        row_parts.append(
            "<tr>\n"
            "  <td>" + name + "</td>"
            "<td>" + target + "</td>"
            "<td>" + dur + "s</td>\n"
            "  <td" + fc_style + ">"
            + str(fc) + "</td>"
            "<td>" + str(step) + "</td>\n"
            "</tr>"
        )

    if not plugins:
        rows = (
            '<tr><td colspan="5" style="color:var(--fg-dim)">'
            "No plugins executed yet</td></tr>"
        )
    else:
        rows = "".join(row_parts)

    return (
        '<div class="section" id="plugins">\n'
        '  <div class="section-title">'
        "Plugin Performance</div>\n"
        '  <table class="perf-table sortable">\n'
        "    <thead><tr>"
        "<th>Plugin</th><th>Target</th>"
        "<th>Duration</th><th>Findings</th>"
        "<th>Step</th>"
        "</tr></thead>\n"
        "    <tbody>" + rows + "</tbody>\n"
        "  </table>\n"
        "</div>"
    )


def _reasoning_html(data: dict) -> str:
    r = data.get("reasoning", {})
    confirmed = r.get("hypotheses_confirmed", 0)
    rejected = r.get("hypotheses_rejected", 0)
    active = r.get("hypotheses_active", 0)
    strengthened = r.get("beliefs_strengthened", 0)
    weakened = r.get("beliefs_weakened", 0)

    has_data = any([confirmed, rejected, active, strengthened, weakened])
    if not has_data:
        return (
            '<div class="section" id="reasoning">\n'
            '  <div class="section-title">Reasoning</div>\n'
            '  <div style="color:var(--fg-dim)">'
            "No reasoning events recorded</div>\n"
            "</div>"
        )

    def _stat(val: int, color: str, label: str) -> str:
        return (
            '    <div class="reasoning-stat">\n'
            '      <div class="reasoning-value"'
            ' style="color:var(--' + color + ')">'
            + str(val) + "</div>\n"
            '      <div class="reasoning-label">'
            + label + "</div>\n"
            "    </div>\n"
        )

    return (
        '<div class="section" id="reasoning">\n'
        '  <div class="section-title">Reasoning</div>\n'
        '  <div class="reasoning-grid">\n'
        + _stat(confirmed, "neon-green", "Confirmed")
        + _stat(rejected, "neon-red", "Rejected")
        + _stat(active, "neon-cyan", "Active")
        + _stat(strengthened, "neon-green", "Strengthened")
        + _stat(weakened, "neon-orange", "Weakened")
        + "  </div>\n"
        "</div>"
    )


def _training_html(data: dict) -> str:
    training = data.get("training")
    if training is None:
        return ""

    profile = _e(training.get("profile_name", ""))
    coverage = training.get("coverage", 0)
    verification = training.get("verification_rate", 0)
    passed = training.get("passed", False)
    expected = training.get("expected_findings", [])

    badge_class = "passed" if passed else "failed"
    badge_text = "PASSED" if passed else "FAILED"
    pct_str = _fmt(coverage * 100, ".0f")
    verif_str = _fmt(verification * 100, ".0f")

    row_parts: list[str] = []
    for ef in expected:
        title = _e(ef.get("title", ""))
        sev = _e(ef.get("severity", ""))
        disc = ef.get("discovered", False)
        verif = ef.get("verified", False)
        step = ef.get("discovery_step")
        disc_html = (
            '<span style="color:var(--neon-green)">YES</span>'
            if disc
            else '<span style="color:var(--critical)">NO</span>'
        )
        verif_html = (
            '<span style="color:var(--neon-green)">YES</span>'
            if verif
            else (
                '<span style="color:var(--medium)">NO</span>'
                if disc
                else "-"
            )
        )
        step_html = str(step) if step is not None else "-"
        row_parts.append(
            "<tr><td>" + title + "</td>"
            "<td>" + sev + "</td>"
            "<td>" + disc_html + "</td>"
            "<td>" + verif_html + "</td>"
            "<td>" + step_html + "</td></tr>"
        )
    rows = "".join(row_parts)

    return (
        '<div class="section" id="training">\n'
        '  <div class="section-title">'
        "Training Validation</div>\n"
        '  <div style="display:flex;gap:var(--sp-4);'
        'align-items:center;margin-bottom:var(--sp-4)">\n'
        '    <span class="pass-badge '
        + badge_class + '">'
        + badge_text + "</span>\n"
        "    <span>Profile: " + profile + "</span>\n"
        "    <span>Coverage: " + pct_str + "%</span>\n"
        "    <span>Verification: "
        + verif_str + "%</span>\n"
        "  </div>\n"
        '  <div class="progress-container"'
        ' style="margin-bottom:var(--sp-3)">\n'
        '    <div class="progress-bar"'
        ' style="width:' + pct_str + '%"></div>\n'
        "  </div>\n"
        '  <table class="training-table">\n'
        "    <thead><tr>"
        "<th>Expected Finding</th>"
        "<th>Severity</th>"
        "<th>Discovered</th>"
        "<th>Verified</th>"
        "<th>Step</th>"
        "</tr></thead>\n"
        "    <tbody>" + rows + "</tbody>\n"
        "  </table>\n"
        "</div>"
    )


def _footer_html(data: dict) -> str:
    ts = _e(data.get("timestamp", ""))
    v = _e(data.get("version", _VERSION))
    return (
        '<div class="footer">\n'
        "  Basilisk v" + v
        + " &middot; " + ts
        + " &middot; Confidential\n"
        "</div>"
    )


# ---------------------------------------------------------------------------
# JavaScript (regular string — no f-string)
# ---------------------------------------------------------------------------

_JS = (
    "<script>\n"
    "function toggleFilter(btn) {\n"
    "  btn.classList.toggle('active');\n"
    "  applyFilters();\n"
    "}\n"
    "\n"
    "function applyFilters() {\n"
    "  var active = [];\n"
    "  document.querySelectorAll('.filter-chip.active')"
    ".forEach(function(c) {\n"
    "    active.push(c.dataset.sev);\n"
    "  });\n"
    "  var q = '';\n"
    "  var box = document.querySelector('.search-box');\n"
    "  if (box) q = box.value.toLowerCase();\n"
    "  document.querySelectorAll('.finding-card')"
    ".forEach(function(card) {\n"
    "    var sev = card.dataset.sev;\n"
    "    var text = card.textContent.toLowerCase();\n"
    "    var sevMatch = active.length === 0"
    " || active.indexOf(sev) !== -1;\n"
    "    var textMatch = !q || text.indexOf(q) !== -1;\n"
    "    card.style.display ="
    " (sevMatch && textMatch) ? '' : 'none';\n"
    "  });\n"
    "}\n"
    "\n"
    "function toggleAll(open) {\n"
    "  document.querySelectorAll('.finding-card')"
    ".forEach(function(d) {\n"
    "    d.open = open;\n"
    "  });\n"
    "}\n"
    "\n"
    "var obs = new IntersectionObserver(function(entries)"
    " {\n"
    "  entries.forEach(function(entry) {\n"
    "    if (entry.isIntersecting) {\n"
    "      var id = entry.target.id;\n"
    "      document.querySelectorAll('.sidebar nav a')"
    ".forEach(function(a) {\n"
    "        a.classList.toggle('active',"
    " a.getAttribute('href') === '#' + id);\n"
    "      });\n"
    "    }\n"
    "  });\n"
    "}, { rootMargin: '-20% 0px -60% 0px' });\n"
    "document.querySelectorAll('.section[id]')"
    ".forEach(function(s) { obs.observe(s); });\n"
    "\n"
    "document.querySelectorAll('table.sortable')"
    ".forEach(function(table) {\n"
    "  var headers = table.querySelectorAll('th');\n"
    "  headers.forEach(function(th, idx) {\n"
    "    th.style.cursor = 'pointer';\n"
    "    th.addEventListener('click', function() {\n"
    "      var tbody = table.querySelector('tbody');\n"
    "      var rows ="
    " Array.from(tbody.querySelectorAll('tr'));\n"
    "      var asc ="
    " !th.classList.contains('sort-asc');\n"
    "      headers.forEach(function(h) {"
    " h.classList.remove('sort-asc', 'sort-desc'); });\n"
    "      th.classList.add("
    "asc ? 'sort-asc' : 'sort-desc');\n"
    "      rows.sort(function(a, b) {\n"
    "        var av = a.cells[idx].textContent.trim();\n"
    "        var bv = b.cells[idx].textContent.trim();\n"
    "        var an = parseFloat(av),"
    " bn = parseFloat(bv);\n"
    "        if (!isNaN(an) && !isNaN(bn))"
    " return asc ? an - bn : bn - an;\n"
    "        return asc ?"
    " av.localeCompare(bv) : bv.localeCompare(av);\n"
    "      });\n"
    "      rows.forEach(function(r) {"
    " tbody.appendChild(r); });\n"
    "    });\n"
    "  });\n"
    "});\n"
    "\n"
    "document.querySelectorAll('.evidence-block')"
    ".forEach(function(block) {\n"
    "  var h = block.innerHTML;\n"
    "  block.innerHTML ="
    " h.replace(/(https?:\\/\\/[^\\s<&]+)/g,\n"
    "    '<a href=\"$1\" target=\"_blank\"'"
    " + ' rel=\"noopener\"'"
    " + ' style=\"color:var(--neon-cyan)\">$1</a>');\n"
    "});\n"
    "</script>"
)
