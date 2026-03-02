"""HTML + JSON report renderer — self-contained cyberpunk dashboard.

Renderers are PURE PRESENTATION. All business logic (risk score, severity counts,
kill chain, etc.) is computed by ReportBuilder. Renderers accept a data dict derived
from a canonical ReportModel and assemble HTML/JSON — nothing more.
"""

from __future__ import annotations

import html
import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from basilisk.reporting.builder import KILL_CHAIN_PHASES

if TYPE_CHECKING:
    from basilisk.reporting.collector import ReportCollector
    from basilisk.reporting.model import ReportModel

_VERSION = "4.0.0"

# Re-export for backward compat (now canonical source is builder)
_KILL_CHAIN_PHASES = KILL_CHAIN_PHASES


def assemble_data(collector: ReportCollector) -> dict[str, Any]:
    """Convert collector state to a JSON-serializable dict via ReportBuilder.

    Delegates all computation to the builder, then converts to the
    renderer-compatible dict format.
    """
    from basilisk.reporting.builder import ReportBuilder

    model = ReportBuilder.from_collector(collector)
    return model_to_data(model)


def model_to_data(model: ReportModel) -> dict[str, Any]:
    """Convert a frozen ReportModel to the renderer-compatible dict format.

    This is the bridge between the canonical data model and the HTML template.
    """
    now = datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    stats = model.statistics

    training_data = None
    if model.training is not None:
        t = model.training
        # false_positives carries full expected_findings when built from legacy dict
        expected_findings = t.false_positives if t.false_positives else [
            {
                "title": m.get("title", ""),
                "severity": m.get("severity", ""),
                "discovered": False,
                "verified": False,
                "discovery_step": None,
            }
            for m in t.missed
        ]
        training_data = {
            "profile_name": t.profile_name,
            "coverage": t.coverage_percent / 100.0 if t.coverage_percent else 0.0,
            "verification_rate": t.verification_rate / 100.0 if t.verification_rate else 0.0,
            "passed": t.passed,
            "expected_findings": expected_findings,
        }

    return {
        "version": _VERSION,
        "status": model.status,
        "mode": model.mode,
        "target": model.target,
        "timestamp": now,
        "duration_seconds": stats.duration_seconds,
        "termination_reason": model.termination_reason,
        "summary": {
            "steps": stats.steps_completed,
            "max_steps": stats.max_steps,
            "total_entities": stats.total_entities,
            "total_relations": stats.total_relations,
            "total_findings": stats.findings_total,
            "total_gaps": stats.total_gaps,
            "entity_counts": dict(stats.entity_counts),
            "severity_counts": dict(stats.severity_counts),
            "risk_score": stats.risk_score,
        },
        "findings": list(model.findings_raw),
        "vulnerabilities": [
            {
                "vulnerability_id": v.vulnerability_id,
                "vuln_type": v.vuln_type,
                "severity": v.severity,
                "affected_surfaces": v.affected_surfaces,
                "scenarios": v.scenarios,
                "confidence_aggregate": v.confidence_aggregate,
                "proofs": v.proofs,
                "reproduction_steps": v.reproduction_steps,
            }
            for v in model.vulnerabilities
        ],
        "execution_timeline": [
            {
                "timestamp": str(ev.timestamp),
                "scenario": ev.scenario,
                "action": ev.action,
                "result": ev.result,
            }
            for ev in model.execution_timeline
        ],
        "decisions": list(model.decisions),
        "plugins": list(model.plugins_raw),
        "step_history": list(model.step_history),
        "reasoning": dict(model.reasoning),
        "topology": dict(model.topology),
        "training": training_data,
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
        _vulnerabilities_html(data),
        "\n",
        _decisions_html(data),
        "\n",
        _attack_surface_html(data),
        "\n",
        _network_map_html(data),
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
    "  --fg: #c8d0df; --fg-dim: #6d7a94;"
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
    "  --text-xs: 0.65rem; --text-sm: 0.7rem;"
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
    "@media (prefers-reduced-motion: reduce) {\n"
    "  *, *::before, *::after {\n"
    "    animation-duration: 0.01ms !important;\n"
    "    animation-iteration-count: 1 !important;\n"
    "    transition-duration: 0.01ms !important;\n"
    "  }\n"
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
    "button.filter-chip { font-family: inherit; }\n"
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
    ".remediation-block {\n"
    "  background: rgba(0,229,255,0.06); padding: var(--sp-3);"
    " border-radius: var(--radius-sm);\n"
    "  font-size: var(--text-sm);"
    " border: 1px solid rgba(0,229,255,0.2);\n"
    "  margin-top: var(--sp-2); color: var(--neon-cyan);\n"
    "}\n"
    ".fp-risk {\n"
    "  padding: 1px 6px; border-radius: var(--radius-sm);"
    " font-size: var(--text-xs);\n"
    "}\n"
    ".fp-risk.fp-medium { background: var(--medium-bg);"
    " color: var(--medium); }\n"
    ".fp-risk.fp-high { background: var(--high-bg);"
    " color: var(--high); }\n"
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
    "  transition: border-color 0.2s,"
    " box-shadow 0.2s, transform 0.2s;\n"
    "}\n"
    ".host-card:hover {\n"
    "  border-color: var(--border-glow);"
    " box-shadow: 0 0 12px rgba(0,255,106,0.08);\n"
    "  transform: translateY(-1px);\n"
    "}\n"
    ".host-card summary.host-summary {\n"
    "  cursor: pointer; list-style: none;\n"
    "  display: flex; align-items: center; gap: var(--sp-2);\n"
    "}\n"
    ".host-card summary.host-summary::-webkit-details-marker {\n"
    "  display: none;\n"
    "}\n"
    ".host-card summary.host-summary::before {\n"
    "  content: '\\25B6'; font-size: var(--text-xs);\n"
    "  color: var(--fg-dim); transition: transform 0.2s;\n"
    "}\n"
    ".host-card[open] summary.host-summary::before {\n"
    "  transform: rotate(90deg);\n"
    "}\n"
    ".host-card-body {\n"
    "  padding-top: var(--sp-2);\n"
    "}\n"
    ".nm-grid .host-card {"
    " animation: fade-in-up 0.4s ease-out both; }\n"
    ".nm-grid .host-card:nth-child(2)"
    " { animation-delay: 0.05s; }\n"
    ".nm-grid .host-card:nth-child(3)"
    " { animation-delay: 0.1s; }\n"
    ".nm-grid .host-card:nth-child(4)"
    " { animation-delay: 0.15s; }\n"
    ".nm-grid .host-card:nth-child(5)"
    " { animation-delay: 0.2s; }\n"
    ".nm-grid .host-card:nth-child(6)"
    " { animation-delay: 0.25s; }\n"
    ".nm-grid .host-card:nth-child(n+7)"
    " { animation-delay: 0.3s; }\n"
    ".host-card.subdomain {\n"
    "  margin-left: var(--sp-4);"
    " border-left: 3px solid var(--neon-cyan);\n"
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
    ".nm-grid {\n"
    "  display: grid; grid-template-columns:"
    " repeat(auto-fill, minmax(340px, 1fr));\n"
    "  gap: var(--sp-3);\n"
    "}\n"
    ".nm-services-table {\n"
    "  width: 100%; border-collapse: collapse;"
    " font-size: var(--text-sm); margin-top: var(--sp-2);\n"
    "}\n"
    ".nm-services-table th {\n"
    "  text-align: left; padding: var(--sp-1) var(--sp-2);"
    " color: var(--fg-dim);\n"
    "  border-bottom: 1px solid var(--border);"
    " font-weight: 500;\n"
    "  text-transform: uppercase;"
    " font-size: var(--text-xs);\n"
    "}\n"
    ".nm-services-table td {"
    " padding: var(--sp-1) var(--sp-2); }\n"
    ".nm-port {\n"
    "  color: var(--neon-green); font-weight: 700;\n"
    "}\n"
    ".nm-endpoints {\n"
    "  margin-top: var(--sp-2);"
    " font-size: var(--text-sm); color: var(--fg-dim);\n"
    "}\n"
    ".nm-endpoints div {"
    " padding: 1px 0; }\n"
    ".nm-endpoints-toggle {\n"
    "  margin-top: var(--sp-1);\n"
    "}\n"
    ".nm-endpoints-toggle summary {\n"
    "  cursor: pointer; color: var(--neon-cyan);\n"
    "  font-size: var(--text-xs); font-weight: 600;\n"
    "}\n"
    ".nm-endpoints-list {\n"
    "  padding: var(--sp-1) var(--sp-2);\n"
    "  font-size: var(--text-sm); color: var(--fg-dim);\n"
    "}\n"
    ".nm-tech-chip {\n"
    "  display: inline-block; padding: 1px 8px;"
    " margin: 2px 2px;\n"
    "  background: rgba(180,77,255,0.12);"
    " border: 1px solid rgba(180,77,255,0.25);\n"
    "  border-radius: 10px; font-size: var(--text-xs);"
    " color: var(--neon-purple);\n"
    "}\n"
    ".nm-subdomain-badge {\n"
    "  display: inline-block; padding: 1px 6px;"
    " margin-left: var(--sp-2);\n"
    "  background: rgba(0,229,255,0.12);"
    " border: 1px solid rgba(0,229,255,0.25);\n"
    "  border-radius: 8px; font-size: var(--text-xs);"
    " color: var(--neon-cyan);\n"
    "}\n"
    ".nm-more {\n"
    "  color: var(--fg-dim); font-size: var(--text-xs);"
    " margin-top: var(--sp-1);\n"
    "}\n"
    "\n"
    ".nm-stats {\n"
    "  display: flex; gap: var(--sp-3);"
    " margin-bottom: var(--sp-4); flex-wrap: wrap;\n"
    "}\n"
    ".nm-stat-card {\n"
    "  background: var(--surface-2); flex: 1;"
    " min-width: 100px;\n"
    "  border-radius: var(--radius);"
    " border: 1px solid var(--border);\n"
    "  padding: var(--sp-3); text-align: center;\n"
    "}\n"
    ".nm-stat-value {\n"
    "  font-size: var(--text-lg); font-weight: 800;\n"
    "}\n"
    ".nm-stat-label {\n"
    "  font-size: var(--text-xs); color: var(--fg-dim);"
    " text-transform: uppercase;\n"
    "}\n"
    "\n"
    ".nm-port.well-known {"
    " color: var(--neon-green); }\n"
    ".nm-port.high-port {"
    " color: var(--neon-cyan); opacity: 0.8; }\n"
    ".nm-svc-badge {\n"
    "  display: inline-block; padding: 0 6px;"
    " margin-left: var(--sp-1);\n"
    "  border-radius: 8px; font-size: var(--text-xs);"
    " font-weight: 600;\n"
    "}\n"
    ".nm-svc-http { background: rgba(0,255,106,0.12);"
    " color: var(--neon-green); }\n"
    ".nm-svc-https { background: rgba(0,229,255,0.12);"
    " color: var(--neon-cyan); }\n"
    ".nm-svc-ssh { background: rgba(255,184,0,0.12);"
    " color: var(--neon-yellow); }\n"
    ".nm-svc-ftp { background: rgba(255,107,53,0.12);"
    " color: var(--high); }\n"
    ".nm-svc-mysql { background: rgba(77,124,255,0.12);"
    " color: var(--neon-blue); }\n"
    ".nm-svc-postgres { background: rgba(180,77,255,0.12);"
    " color: var(--neon-purple); }\n"
    ".nm-svc-redis { background: rgba(255,23,68,0.12);"
    " color: var(--neon-red); }\n"
    ".nm-svc-smtp { background: rgba(255,138,0,0.12);"
    " color: var(--neon-orange); }\n"
    "\n"
    ".nm-findings-badge {\n"
    "  display: inline-block; padding: 1px 8px;"
    " margin-left: var(--sp-2);\n"
    "  background: rgba(255,23,68,0.15);"
    " border: 1px solid rgba(255,23,68,0.3);\n"
    "  border-radius: 10px; font-size: var(--text-xs);"
    " color: var(--neon-red); font-weight: 600;\n"
    "}\n"
    ".host-card.sev-accent-CRITICAL {\n"
    "  border-top: 3px solid var(--critical);\n"
    "}\n"
    ".host-card.sev-accent-HIGH {\n"
    "  border-top: 3px solid var(--high);\n"
    "}\n"
    ".host-card.sev-accent-MEDIUM {\n"
    "  border-top: 3px solid var(--medium);\n"
    "}\n"
    ".host-card.sev-accent-LOW {\n"
    "  border-top: 3px solid var(--low);\n"
    "}\n"
    ".host-card.sev-accent-INFO {\n"
    "  border-top: 3px solid var(--info);\n"
    "}\n"
    ".host-copy {\n"
    "  background: var(--surface-3); border: 1px solid var(--border);\n"
    "  color: var(--fg-dim); cursor: pointer;\n"
    "  border-radius: var(--radius-sm); font-size: var(--text-xs);\n"
    "  font-family: inherit; padding: 1px 6px;\n"
    "  transition: color 0.15s;\n"
    "}\n"
    ".host-copy:hover { color: var(--neon-green); }\n"
    ".nm-search-status {\n"
    "  font-size: var(--text-xs); color: var(--fg-dim);\n"
    "  margin-bottom: var(--sp-3);\n"
    "}\n"
    ".nm-no-matches {\n"
    "  display: none; padding: var(--sp-4);\n"
    "  text-align: center; color: var(--fg-dim);\n"
    "}\n"
    ".nm-port-bar {\n"
    "  display: flex; height: 4px; border-radius: var(--radius-sm);\n"
    "  overflow: hidden; margin-top: var(--sp-2); gap: 1px;\n"
    "}\n"
    ".nm-port-seg {"
    " height: 100%; border-radius: 2px;"
    " transition: width 0.3s; }\n"
    ".nm-port-seg.well-known-seg {"
    " background: var(--neon-green); }\n"
    ".nm-port-seg.high-port-seg {"
    " background: var(--neon-cyan); opacity: 0.7; }\n"
    ".nm-toggle-btn {\n"
    "  background: var(--surface-3); border: 1px solid var(--border);\n"
    "  color: var(--fg-dim); cursor: pointer;\n"
    "  border-radius: var(--radius-sm); font-size: var(--text-xs);\n"
    "  font-family: inherit; padding: 2px 8px;\n"
    "  float: right; transition: color 0.15s;\n"
    "}\n"
    ".nm-toggle-btn:hover { color: var(--neon-green); }\n"
    ".nm-search {\n"
    "  width: 100%; padding: var(--sp-2) var(--sp-3);\n"
    "  background: var(--surface-2);"
    " border: 1px solid var(--border);\n"
    "  border-radius: var(--radius);"
    " color: var(--fg); font-family: inherit;\n"
    "  font-size: var(--text-sm);"
    " margin-bottom: var(--sp-3);\n"
    "  outline: none;\n"
    "}\n"
    ".nm-search:focus {\n"
    "  border-color: var(--neon-green);"
    " box-shadow: 0 0 8px rgba(0,255,106,0.1);\n"
    "}\n"
    ".nm-filter-bar {\n"
    "  display: flex; gap: var(--sp-2); flex-wrap: wrap;\n"
    "  margin-bottom: var(--sp-3);\n"
    "}\n"
    ".nm-findings-preview {\n"
    "  margin-top: var(--sp-2);"
    " border-top: 1px solid var(--border);\n"
    "  padding-top: var(--sp-2);\n"
    "}\n"
    ".nm-finding-item {\n"
    "  display: flex; align-items: center;"
    " gap: var(--sp-2);\n"
    "  font-size: var(--text-sm); color: var(--fg-dim);\n"
    "}\n"
    ".nm-sev-dot {\n"
    "  width: 6px; height: 6px; border-radius: 50%;\n"
    "  flex-shrink: 0;\n"
    "}\n"
    ".nm-sev-dot.dot-CRITICAL { background: var(--critical); }\n"
    ".nm-sev-dot.dot-HIGH { background: var(--high); }\n"
    ".nm-sev-dot.dot-MEDIUM { background: var(--medium); }\n"
    ".nm-sev-dot.dot-LOW { background: var(--low); }\n"
    ".nm-sev-dot.dot-INFO { background: var(--info); }\n"
    ".nm-sort-bar {\n"
    "  display: inline-flex; gap: 2px; margin-left: var(--sp-2);\n"
    "}\n"
    ".nm-sort-btn {\n"
    "  background: var(--surface-3); border: 1px solid var(--border);\n"
    "  color: var(--fg-dim); cursor: pointer;\n"
    "  font-size: var(--text-xs); border-radius: var(--radius-sm);\n"
    "  font-family: inherit; padding: 1px 6px;\n"
    "}\n"
    ".nm-sort-btn.active {"
    " color: var(--neon-green);"
    " border-color: var(--neon-green); }\n"
    ".nm-risk-badge {\n"
    "  display: inline-block; padding: 1px 8px;"
    " margin-left: var(--sp-2);\n"
    "  border-radius: 10px; font-size: var(--text-xs);"
    " font-weight: 700;\n"
    "  border: 1px solid currentColor;\n"
    "}\n"
    ".nm-risk-badge.risk-green {"
    " color: var(--neon-green);"
    " background: rgba(0,255,106,0.15); }\n"
    ".nm-risk-badge.risk-yellow {"
    " color: var(--neon-yellow);"
    " background: rgba(255,225,0,0.15); }\n"
    ".nm-risk-badge.risk-orange {"
    " color: var(--neon-orange);"
    " background: rgba(255,138,0,0.15); }\n"
    ".nm-risk-badge.risk-red {"
    " color: var(--neon-red);"
    " background: rgba(255,23,68,0.15); }\n"
    ".nm-svc-count-badge {\n"
    "  display: inline-block; padding: 1px 8px;"
    " margin-left: var(--sp-2);\n"
    "  background: rgba(0,229,255,0.15);"
    " border: 1px solid rgba(0,229,255,0.3);\n"
    "  border-radius: 10px; font-size: var(--text-xs);"
    " color: var(--neon-cyan); font-weight: 600;\n"
    "}\n"
    ".nm-compact-table {\n"
    "  display: none; width: 100%; border-collapse: collapse;\n"
    "  font-size: var(--text-sm);\n"
    "}\n"
    ".nm-compact-table th {\n"
    "  text-align: left; padding: var(--sp-1) var(--sp-2);\n"
    "  color: var(--fg-dim); text-transform: uppercase;\n"
    "  font-size: var(--text-xs); font-weight: 500;\n"
    "  border-bottom: 1px solid var(--border); cursor: pointer;\n"
    "}\n"
    ".nm-compact-table td {\n"
    "  padding: var(--sp-1) var(--sp-2);\n"
    "  border-bottom: 1px solid var(--border);\n"
    "}\n"
    ".nm-compact-table tr:hover td {"
    " background: var(--surface-3); }\n"
    ".nm-view-btn {\n"
    "  background: var(--surface-3); border: 1px solid var(--border);\n"
    "  color: var(--fg-dim); cursor: pointer;\n"
    "  border-radius: var(--radius-sm); font-size: var(--text-xs);\n"
    "  font-family: inherit; padding: 2px 8px;\n"
    "  float: right; transition: color 0.15s;\n"
    "}\n"
    ".nm-view-btn:hover { color: var(--neon-green); }\n"
    ".nm-focused {\n"
    "  border-color: var(--neon-green) !important;\n"
    "  box-shadow: 0 0 12px rgba(0,255,106,0.15);\n"
    "}\n"
    ".nm-kb-hint {\n"
    "  font-size: var(--text-xs); color: var(--fg-dim);\n"
    "  text-align: center; margin-top: var(--sp-3);\n"
    "}\n"
    ".nm-kb-hint kbd {\n"
    "  background: var(--surface-3); border: 1px solid var(--border);\n"
    "  border-radius: 3px; padding: 0 4px;\n"
    "}\n"
    ".nm-filter-indicator {\n"
    "  font-size: var(--text-xs); color: var(--fg-dim);\n"
    "  margin-bottom: var(--sp-3); display: none;\n"
    "}\n"
    ".nm-filter-indicator a {\n"
    "  color: var(--neon-cyan); cursor: pointer;\n"
    "  text-decoration: underline; margin-left: var(--sp-2);\n"
    "}\n"
    ".nm-proto-bar {\n"
    "  display: flex; height: 8px; border-radius: var(--radius);\n"
    "  overflow: hidden; gap: 1px;\n"
    "}\n"
    ".nm-proto-seg {"
    " height: 100%; border-radius: 2px;"
    " transition: width 0.3s; }\n"
    ".nm-proto-legend {\n"
    "  display: flex; gap: var(--sp-3); flex-wrap: wrap;\n"
    "  font-size: var(--text-xs); color: var(--fg-dim);\n"
    "  margin-top: var(--sp-2);\n"
    "}\n"
    ".nm-proto-legend-item {"
    " display: flex; align-items: center;"
    " gap: var(--sp-1); }\n"
    ".nm-proto-swatch {\n"
    "  width: 8px; height: 8px; border-radius: 2px;\n"
    "}\n"
    "\n"
    ".surface-stats-grid {\n"
    "  display: grid; grid-template-columns:"
    " repeat(auto-fill, minmax(220px, 1fr));\n"
    "  gap: var(--sp-3);\n"
    "}\n"
    ".surface-stat {\n"
    "  background: var(--surface-2);"
    " border-radius: var(--radius);\n"
    "  border: 1px solid var(--border);"
    " padding: var(--sp-3);\n"
    "}\n"
    ".surface-stat-header {\n"
    "  display: flex; justify-content: space-between;"
    " align-items: center;\n"
    "  margin-bottom: var(--sp-2);"
    " font-size: var(--text-sm);\n"
    "}\n"
    ".surface-bar {\n"
    "  height: 4px; background: var(--bg);"
    " border-radius: 2px;\n"
    "  overflow: hidden;\n"
    "}\n"
    ".surface-bar-fill {\n"
    "  height: 100%; border-radius: 2px;"
    " transition: width 0.3s ease;\n"
    "  min-width: 2px; opacity: 0.7;\n"
    "}\n"
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
    "th.sort-asc::after {"
    " content: ' \\25B2'; font-size: var(--text-xs);"
    " color: var(--neon-green); }\n"
    "th.sort-desc::after {"
    " content: ' \\25BC'; font-size: var(--text-xs);"
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
    "/* Hover states */\n"
    ".finding-card { transition: border-color 0.2s, box-shadow 0.2s; }\n"
    ".finding-card:hover {\n"
    "  border-color: var(--border-glow);\n"
    "  box-shadow: 0 0 12px rgba(0,255,106,0.08);\n"
    "}\n"
    ".timeline-item { transition: border-color 0.2s, background 0.2s; }\n"
    ".timeline-item:hover {\n"
    "  border-color: var(--border-glow);\n"
    "  background: var(--surface-3);\n"
    "}\n"
    ".surface-stat { transition: box-shadow 0.2s; }\n"
    ".surface-stat:hover {\n"
    "  box-shadow: 0 0 12px rgba(0,255,106,0.1);\n"
    "}\n"
    ".kc-phase { transition: transform 0.15s, box-shadow 0.15s; }\n"
    ".kc-phase:hover {\n"
    "  transform: translateY(-1px);\n"
    "  box-shadow: var(--shadow-md);\n"
    "}\n"
    ".metric-card { transition: background 0.15s; }\n"
    ".metric-card:hover { background: var(--surface-3); }\n"
    ".perf-table tbody tr { transition: background 0.15s; }\n"
    "\n"
    "/* Evidence expand/collapse */\n"
    ".evidence-block { position: relative; transition: max-height 0.3s; }\n"
    ".evidence-block.expanded { max-height: none !important; }\n"
    ".evidence-toggle {\n"
    "  display: none; position: absolute; bottom: 0; left: 0; right: 0;\n"
    "  background: linear-gradient(transparent, var(--bg) 60%);\n"
    "  border: none; color: var(--neon-cyan); cursor: pointer;\n"
    "  padding: 16px 0 4px; font-family: inherit;\n"
    "  font-size: var(--text-xs); text-align: center;\n"
    "}\n"
    ".evidence-block.overflows .evidence-toggle { display: block; }\n"
    ".evidence-block.expanded .evidence-toggle {\n"
    "  position: static; background: none; padding: 4px 0;\n"
    "}\n"
    "\n"
    "/* Copy button for evidence */\n"
    ".evidence-copy {\n"
    "  position: absolute; top: 4px; right: 4px;\n"
    "  background: var(--surface-3); border: 1px solid var(--border);\n"
    "  color: var(--fg-dim); cursor: pointer; padding: 2px 8px;\n"
    "  border-radius: var(--radius-sm); font-family: inherit;\n"
    "  font-size: var(--text-xs); transition: color 0.15s;\n"
    "}\n"
    ".evidence-copy:hover { color: var(--neon-green); }\n"
    "\n"
    "/* Entrance animations */\n"
    "@keyframes fade-in-up {\n"
    "  from { opacity: 0; transform: translateY(12px); }\n"
    "  to { opacity: 1; transform: translateY(0); }\n"
    "}\n"
    ".section {\n"
    "  animation: fade-in-up 0.4s ease-out both;\n"
    "}\n"
    ".section:nth-child(2) { animation-delay: 0.05s; }\n"
    ".section:nth-child(3) { animation-delay: 0.1s; }\n"
    ".section:nth-child(4) { animation-delay: 0.15s; }\n"
    ".section:nth-child(5) { animation-delay: 0.2s; }\n"
    ".section:nth-child(6) { animation-delay: 0.25s; }\n"
    ".section:nth-child(7) { animation-delay: 0.3s; }\n"
    ".section:nth-child(8) { animation-delay: 0.35s; }\n"
    ".section:nth-child(9) { animation-delay: 0.4s; }\n"
    ".section:nth-child(10) { animation-delay: 0.45s; }\n"
    "\n"
    "/* Reasoning events */\n"
    ".reasoning-events-toggle { margin-top: var(--sp-3); }\n"
    ".reasoning-events-toggle summary {\n"
    "  cursor: pointer; color: var(--neon-cyan);\n"
    "  font-size: var(--text-sm); font-weight: 600;\n"
    "}\n"
    ".reasoning-events {\n"
    "  padding: var(--sp-3) 0; display: flex;\n"
    "  flex-direction: column; gap: var(--sp-2);\n"
    "}\n"
    ".reasoning-event {\n"
    "  padding: var(--sp-2) var(--sp-3);\n"
    "  background: var(--surface-2); border-radius: var(--radius-sm);\n"
    "  font-size: var(--text-sm);\n"
    "}\n"
    ".re-type {\n"
    "  font-weight: 600; margin-right: var(--sp-2);\n"
    "}\n"
    ".re-step { color: var(--fg-dim); font-size: var(--text-xs); }\n"
    ".re-detail {\n"
    "  color: var(--fg-dim); font-size: var(--text-xs);\n"
    "  margin-top: var(--sp-1);\n"
    "}\n"
    "\n"
    "/* Decision timeline extras */\n"
    ".tl-duration { color: var(--fg-dim); font-size: var(--text-xs); }\n"
    ".tl-entities {\n"
    "  color: var(--neon-green); font-size: var(--text-xs);\n"
    "  font-weight: 600;\n"
    "}\n"
    "\n"
    "/* Entity breakdown in sidebar */\n"
    ".entity-breakdown {\n"
    "  padding: var(--sp-2) 1rem; font-size: var(--text-xs);\n"
    "}\n"
    ".entity-row {\n"
    "  display: flex; justify-content: space-between;\n"
    "  padding: 1px 0; color: var(--fg-dim);\n"
    "}\n"
    ".entity-type { text-transform: capitalize; }\n"
    ".entity-count { color: var(--fg); font-weight: 600; }\n"
    "\n"
    "@media (max-width: 800px) {\n"
    "  .sidebar { display: none; }\n"
    "  .main { margin-left: 0; }\n"
    "  .kill-chain { flex-direction: column; }\n"
    "  .surface-grid {"
    " grid-template-columns: 1fr; }\n"
    "  .metrics-grid {"
    " grid-template-columns: repeat(2, 1fr); }\n"
    "  .surface-stats-grid {"
    " grid-template-columns: repeat(2, 1fr); }\n"
    "  .perf-table { display: block; overflow-x: auto; }\n"
    "  .filter-bar { flex-direction: column;"
    " align-items: stretch; }\n"
    "  .reasoning-grid {"
    " grid-template-columns: repeat(2, 1fr); }\n"
    "  .nm-grid { grid-template-columns: 1fr; }\n"
    "  .nm-stats { flex-direction: column; }\n"
    "  .host-card.subdomain {"
    " margin-left: var(--sp-2); }\n"
    "}\n"
    "\n"
    "@media print {\n"
    "  .sidebar { display: none; }\n"
    "  .main { margin-left: 0; }\n"
    "  body::before, body::after { display: none; }\n"
    "  body { background: #fff; color: #1a1e2e; }\n"
    "  .section {\n"
    "    border: 1px solid #ddd;"
    " box-shadow: none; background: #fff;\n"
    "    animation: none;\n"
    "  }\n"
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

    vulns_count = len(data.get("vulnerabilities", []))
    vulns_link = ""
    if vulns_count > 0:
        vulns_link = (
            '    <a href="#vulnerabilities">Vulns '
            '<span class="cnt">'
            + str(vulns_count) + "</span></a>\n"
        )

    training = data.get("training")
    training_link = ""
    if training is not None:
        training_link = (
            '<a href="#training">Training '
            '<span class="cnt">1</span></a>'
        )

    # Entity type breakdown for sidebar
    entity_counts = summary.get("entity_counts", {})
    entity_parts: list[str] = []
    for etype, ecount in entity_counts.items():
        if ecount > 0:
            entity_parts.append(
                '    <div class="entity-row">'
                '<span class="entity-type">' + _e(etype) + "</span>"
                '<span class="entity-count">'
                + str(ecount) + "</span></div>\n"
            )
    entity_breakdown = ""
    if entity_parts:
        entity_breakdown = (
            '  <div class="entity-breakdown">\n'
            + "".join(entity_parts)
            + "  </div>\n"
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
        + vulns_link
        + '    <a href="#decisions">Decisions '
        '<span class="cnt">'
        + str(decisions_count) + "</span></a>\n"
        '    <a href="#attack-surface">Attack Surface</a>\n'
        '    <a href="#network-map">Network Map'
        + (
            ' <span class="cnt">'
            + str(len(data.get("topology", {})))
            + "</span>"
            if data.get("topology")
            else ""
        )
        + "</a>\n"
        '    <a href="#plugins">Plugins '
        '<span class="cnt">'
        + str(plugins_count) + "</span></a>\n"
        '    <a href="#reasoning">Reasoning</a>\n'
        "    " + training_link + "\n"
        "  </nav>\n"
        + entity_breakdown
        + "</aside>"
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
        "    <span>Termination: "
        + _e(data.get("termination_reason", "") or "\u2014")
        + "</span>\n"
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

    covered_phases = 0
    total_phases = len(_KILL_CHAIN_PHASES)
    phases_parts: list[str] = []
    for i, (name, members) in enumerate(_KILL_CHAIN_PHASES):
        total_members = len(members)
        count = sum(1 for m in members if m in plugin_names)
        if count > 0:
            covered_phases += 1
        active = " active" if count > 0 else ""
        arrow = (
            '<span class="kc-arrow">&#x25B6;</span>'
            if i < len(_KILL_CHAIN_PHASES) - 1
            else ""
        )
        pct = _fmt(count / total_members * 100, ".0f") if total_members > 0 else "0"
        phases_parts.append(
            '<div class="kc-phase' + active + '">\n'
            '      <div class="kc-name">'
            + _e(name) + "</div>\n"
            '      <div class="kc-count">'
            + pct + "%</div>\n"
            '      <div class="kc-label">'
            + str(count) + "/" + str(total_members) + "</div>\n"
            "      " + arrow + "\n"
            "    </div>"
        )
    phases_html = "".join(phases_parts)

    overall_pct = (
        _fmt(covered_phases / total_phases * 100, ".0f")
        if total_phases > 0
        else "0"
    )

    return (
        '<div class="section" id="kill-chain">\n'
        '  <div class="section-title">Kill Chain'
        ' <span style="font-size:var(--text-sm);color:var(--fg-dim)">'
        + overall_pct + "% coverage</span></div>\n"
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
            '<button class="filter-chip active" data-sev="'
            + sev + '" onclick="toggleFilter(this)">'
            + sev + " (" + str(cnt) + ")</button>"
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

        remediation = _e(f.get("remediation", ""))
        fp_risk = _e(f.get("false_positive_risk", "low"))

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
        remediation_html = (
            '<div class="remediation-block">'
            '<strong>Remediation:</strong> ' + remediation + "</div>"
            if remediation
            else ""
        )
        tags_block = (
            '<div style="margin-top:var(--sp-2)">'
            + tags_html + "</div>"
            if tags_html
            else ""
        )
        fp_html = (
            '<span class="fp-risk fp-' + fp_risk + '">'
            "FP risk: " + fp_risk + "</span>"
            if fp_risk and fp_risk != "low"
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
            "    " + fp_html + "\n"
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
            "    " + remediation_html + "\n"
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
        '    <button class="nm-toggle-btn"'
        ' onclick="toggleAll(true)">Expand All</button>\n'
        '    <button class="nm-toggle-btn"'
        ' onclick="toggleAll(false)">'
        "Collapse All</button>\n"
        "  </div>\n"
        '  <div id="findings-list">' + cards + "</div>\n"
        "</div>"
    )


def _vulnerabilities_html(data: dict) -> str:
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return ""

    row_parts: list[str] = []
    for v in vulns:
        sev = _e(v.get("severity", "INFO").upper())
        vtype = _e(v.get("vuln_type", "unknown"))
        surfaces = ", ".join(_e(s) for s in v.get("affected_surfaces", [])[:5])
        conf = _fmt(v.get("confidence_aggregate", 0) * 100, ".0f") + "%"
        proofs = v.get("proofs", [])
        proof_preview = _e(proofs[0][:80] + "..." if proofs and len(proofs[0]) > 80
                          else proofs[0] if proofs else "")
        scenarios = ", ".join(_e(s) for s in v.get("scenarios", []))

        repro_steps = v.get("reproduction_steps", [])
        repro_html = ""
        if repro_steps:
            steps_ol = "<ol>" + "".join(
                "<li>" + _e(s) + "</li>" for s in repro_steps
            ) + "</ol>"
            repro_html = (
                '<tr class="repro-row"><td colspan="6">'
                "<details><summary>"
                + str(len(repro_steps))
                + " reproduction steps</summary>"
                + steps_ol + "</details></td></tr>"
            )

        row_parts.append(
            "<tr>\n"
            '  <td><span class="sev-badge sev-'
            + sev + '">' + sev + "</span></td>\n"
            "  <td>" + vtype + "</td>\n"
            "  <td>" + surfaces + "</td>\n"
            "  <td>" + conf + "</td>\n"
            "  <td>" + scenarios + "</td>\n"
            '  <td style="max-width:200px;overflow:hidden;'
            'text-overflow:ellipsis;white-space:nowrap"'
            ' title="' + proof_preview + '">'
            + proof_preview + "</td>\n"
            "</tr>" + repro_html
        )

    rows = "".join(row_parts)
    return (
        '<div class="section" id="vulnerabilities">\n'
        '  <div class="section-title">'
        "Vulnerabilities (Deduplicated)</div>\n"
        '  <table class="perf-table sortable">\n'
        "    <thead><tr>"
        "<th>Severity</th><th>Type</th>"
        "<th>Affected Surfaces</th><th>Confidence</th>"
        "<th>Scenarios</th><th>Proof</th>"
        "</tr></thead>\n"
        "    <tbody>" + rows + "</tbody>\n"
        "  </table>\n"
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
        duration = d.get("duration", 0)
        new_entities = d.get("new_entities", 0)

        duration_html = (
            '<span class="tl-duration">'
            + _fmt(duration, ".2f") + "s</span>"
            if duration and duration > 0
            else ""
        )
        entities_html = (
            '<span class="tl-entities">+'
            + str(new_entities) + " entities</span>"
            if new_entities and new_entities > 0
            else ""
        )

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
            "    " + duration_html + "\n"
            "    " + entities_html + "\n"
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

    entity_types = [
        ("Hosts", ec.get("host", 0), "--neon-cyan"),
        ("Services", ec.get("service", 0), "--neon-blue"),
        ("Endpoints", ec.get("endpoint", 0), "--neon-green"),
        ("Technologies", ec.get("technology", 0), "--neon-purple"),
        ("Credentials", ec.get("credential", 0), "--neon-orange"),
        ("Findings", ec.get("finding", 0), "--neon-red"),
        ("Vulnerabilities", ec.get("vulnerability", 0), "--neon-pink"),
        ("Containers", ec.get("container", 0), "--neon-yellow"),
        ("Images", ec.get("image", 0), "--neon-cyan"),
    ]

    total = max(sum(c for _, c, _ in entity_types), 1)
    card_parts: list[str] = []
    for label, count, color in entity_types:
        pct = min(count / total * 100, 100)
        bar_w = _fmt(pct, ".0f")
        card_parts.append(
            '<div class="surface-stat">\n'
            '  <div class="surface-stat-header">\n'
            '    <span style="color:var(' + color + ')">'
            + label + "</span>\n"
            '    <span style="color:var(' + color + ");font-weight:700;"
            'font-size:var(--text-lg)">'
            + str(count) + "</span>\n"
            "  </div>\n"
            '  <div class="surface-bar">\n'
            '    <div class="surface-bar-fill" style="width:'
            + bar_w + "%;background:var(" + color + ')">'
            "</div>\n"
            "  </div>\n"
            "</div>"
        )

    cards = "".join(card_parts)
    return (
        '<div class="section" id="attack-surface">\n'
        '  <div class="section-title">'
        "Attack Surface</div>\n"
        '  <div class="surface-stats-grid">\n'
        + cards
        + "\n  </div>\n"
        "</div>"
    )


_SERVICE_BADGE_MAP: dict[str, str] = {
    "http": "nm-svc-http",
    "https": "nm-svc-https",
    "ssh": "nm-svc-ssh",
    "ftp": "nm-svc-ftp",
    "mysql": "nm-svc-mysql",
    "postgres": "nm-svc-postgres",
    "postgresql": "nm-svc-postgres",
    "redis": "nm-svc-redis",
    "smtp": "nm-svc-smtp",
}


def _service_badge_class(service_name: str) -> str:
    """Return CSS badge class for known service names."""
    return _SERVICE_BADGE_MAP.get(service_name.lower().strip(), "")


_PROTOCOL_GROUPS: dict[str, str] = {
    "http": "HTTP", "https": "HTTPS", "ssh": "SSH",
    "ftp": "FTP", "mysql": "DB", "postgres": "DB",
    "postgresql": "DB", "redis": "DB",
}

_PROTOCOL_COLORS: dict[str, str] = {
    "HTTP": "var(--neon-green)", "HTTPS": "var(--neon-cyan)",
    "SSH": "var(--neon-yellow)", "DB": "var(--neon-blue)",
    "FTP": "var(--high)", "Other": "var(--fg-dim)",
}

_SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0,
}

_RISK_WEIGHTS: dict[str, int] = {
    "CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFO": 0,
}


def _host_risk_score(host: str, findings: list[dict]) -> int:
    """Sum severity weights for all findings belonging to host."""
    total = 0
    for f in findings:
        if f.get("host", "") == host:
            sev = f.get("severity", "").upper()
            total += _RISK_WEIGHTS.get(sev, 0)
    return total


def _risk_color_class(score: int) -> str:
    """Return CSS class based on risk score value."""
    if score <= 0:
        return "risk-green"
    if score <= 4:
        return "risk-yellow"
    if score <= 9:
        return "risk-orange"
    return "risk-red"


def _max_severity_for_host(host: str, findings: list[dict]) -> str:
    """Return highest severity for host, or empty string."""
    best = -1
    best_sev = ""
    for f in findings:
        if f.get("host", "") == host:
            sev = f.get("severity", "").upper()
            rank = _SEVERITY_RANK.get(sev, -1)
            if rank > best:
                best = rank
                best_sev = sev
    return best_sev


def _network_map_html(data: dict) -> str:
    """Render per-host network topology: services, endpoints, technologies."""
    topology = data.get("topology", {})
    if not topology:
        return ""

    # Summary stats
    total_hosts = len(topology)
    total_services = sum(
        len(t.get("services", [])) for t in topology.values()
    )
    total_endpoints = sum(
        len(t.get("endpoints", [])) for t in topology.values()
    )
    total_techs = sum(
        len(t.get("technologies", [])) for t in topology.values()
    )

    stats_html = (
        '<div class="nm-stats">\n'
        '  <div class="nm-stat-card">'
        '<div class="nm-stat-value" style="color:var(--neon-cyan)">'
        + str(total_hosts) + "</div>"
        '<div class="nm-stat-label">Hosts</div></div>\n'
        '  <div class="nm-stat-card">'
        '<div class="nm-stat-value" style="color:var(--neon-green)">'
        + str(total_services) + "</div>"
        '<div class="nm-stat-label">Services</div></div>\n'
        '  <div class="nm-stat-card">'
        '<div class="nm-stat-value" style="color:var(--neon-blue)">'
        + str(total_endpoints) + "</div>"
        '<div class="nm-stat-label">Endpoints</div></div>\n'
        '  <div class="nm-stat-card">'
        '<div class="nm-stat-value" style="color:var(--neon-purple)">'
        + str(total_techs) + "</div>"
        '<div class="nm-stat-label">Technologies</div></div>\n'
        "</div>\n"
    )

    # Protocol summary bar
    proto_counts: dict[str, int] = {}
    for topo_entry in topology.values():
        for svc in topo_entry.get("services", []):
            svc_name = str(svc.get("service", "")).lower().strip()
            group = _PROTOCOL_GROUPS.get(svc_name, "Other")
            proto_counts[group] = proto_counts.get(group, 0) + 1

    proto_bar_html = ""
    if proto_counts:
        total_proto = sum(proto_counts.values())
        seg_parts: list[str] = []
        legend_parts: list[str] = []
        for group, cnt in sorted(proto_counts.items(), key=lambda x: -x[1]):
            color = _PROTOCOL_COLORS.get(group, "var(--fg-dim)")
            pct = _fmt(cnt / total_proto * 100, ".1f")
            seg_parts.append(
                '<div class="nm-proto-seg"'
                ' style="width:' + pct + "%;background:" + color + '"'
                ' title="' + group + ": " + str(cnt) + '"></div>'
            )
            legend_parts.append(
                '<span class="nm-proto-legend-item">'
                '<span class="nm-proto-swatch"'
                ' style="background:' + color + '"></span>'
                + group + " (" + str(cnt) + ")</span>"
            )
        proto_bar_html = (
            '<div class="nm-proto-bar">'
            + "".join(seg_parts) + "</div>\n"
            '<div class="nm-proto-legend">'
            + "".join(legend_parts) + "</div>\n"
        )

    # Cross-reference findings by host (count + full list)
    findings_count_by_host: dict[str, int] = {}
    findings_for_host: dict[str, list[dict]] = {}
    for f in data.get("findings", []):
        h = f.get("host", "")
        if h:
            findings_count_by_host[h] = findings_count_by_host.get(h, 0) + 1
            findings_for_host.setdefault(h, []).append(f)

    # Severity distribution for filter chips
    sev_dist: dict[str, int] = {}
    all_findings = data.get("findings", [])
    for host_name in topology:
        ms = _max_severity_for_host(host_name, all_findings)
        bucket = ms if ms else "NONE"
        sev_dist[bucket] = sev_dist.get(bucket, 0) + 1

    # Filter chips
    filter_chip_parts: list[str] = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "NONE"]:
        cnt = sev_dist.get(sev, 0)
        if cnt > 0:
            filter_chip_parts.append(
                '<button class="filter-chip active" data-sev="'
                + sev + '" onclick="toggleHostFilter(this)">'
                + sev + " (" + str(cnt) + ")</button>"
            )
    filter_bar_html = ""
    if filter_chip_parts:
        filter_bar_html = (
            '<div class="nm-filter-bar">'
            + "".join(filter_chip_parts) + "</div>\n"
        )

    # Subdomain grouping: parent → its subdomains → next parent
    parents: list[tuple[str, dict]] = []
    children: dict[str, list[tuple[str, dict]]] = {}
    orphans: list[tuple[str, dict]] = []
    for host_name, topo in sorted(topology.items()):
        if topo.get("is_subdomain"):
            parent_name = topo.get("parent", "")
            if parent_name in topology:
                children.setdefault(parent_name, []).append((host_name, topo))
            else:
                orphans.append((host_name, topo))
        else:
            parents.append((host_name, topo))

    ordered: list[tuple[str, dict]] = []
    for host_name, topo in parents:
        ordered.append((host_name, topo))
        ordered.extend(children.get(host_name, []))
    ordered.extend(orphans)

    # Search input
    search_html = (
        '<input class="nm-search" type="text"'
        ' placeholder="Filter hosts..."'
        ' oninput="applyHostFilters()">\n'
    )

    # Search result counter
    counter_html = (
        '<div class="nm-search-status">Showing '
        '<span id="nm-visible">' + str(total_hosts) + "</span>"
        " of " + str(total_hosts) + " hosts</div>\n"
    )

    # Build cards
    cards: list[str] = []
    max_inline = 5
    for host_name, topo in ordered:
        safe_host = _e(host_name)
        is_sub = topo.get("is_subdomain", False)
        card_class = "host-card subdomain" if is_sub else "host-card"

        # Severity accent
        max_sev = _max_severity_for_host(host_name, all_findings)
        sev_attr = max_sev if max_sev else "NONE"
        if max_sev:
            card_class += " sev-accent-" + max_sev

        # Findings count for data attribute
        fc = findings_count_by_host.get(host_name, 0)

        # Subdomain badge
        subdomain_badge = ""
        if is_sub:
            parent = _e(topo.get("parent", ""))
            subdomain_badge = (
                '<span class="nm-subdomain-badge">'
                "sub of " + parent + "</span>"
            )

        # Findings count badge
        findings_badge = ""
        if fc > 0:
            findings_badge = (
                '<span class="nm-findings-badge">'
                + str(fc) + " finding"
                + ("s" if fc != 1 else "") + "</span>"
            )

        # Service count badge
        svcs = topo.get("services", [])
        svc_count_badge = ""
        if len(svcs) > 0:
            svc_count_badge = (
                '<span class="nm-svc-count-badge">'
                + str(len(svcs)) + " svc"
                + ("s" if len(svcs) != 1 else "") + "</span>"
            )

        # Risk score badge
        risk = _host_risk_score(host_name, all_findings)
        risk_cls = _risk_color_class(risk)
        risk_badge = (
            '<span class="nm-risk-badge ' + risk_cls + '">'
            + str(risk) + "</span>"
        )

        # Services table with port classes and service badges
        services_html = ""
        if svcs:
            svc_rows: list[str] = []
            for svc in svcs:
                port = svc.get("port", 0)
                proto = _e(str(svc.get("protocol", "tcp")))
                svc_name_raw = str(svc.get("service", ""))
                svc_name = _e(svc_name_raw)
                port_class = "nm-port well-known" if port < 1024 else "nm-port high-port"
                badge_cls = _service_badge_class(svc_name_raw)
                badge = ""
                if badge_cls:
                    badge = (
                        '<span class="nm-svc-badge '
                        + badge_cls + '">' + svc_name + "</span>"
                    )
                svc_rows.append(
                    '<tr><td class="' + port_class + '">'
                    + str(port) + "</td>"
                    "<td>" + proto + "</td>"
                    "<td>" + svc_name + badge + "</td></tr>"
                )
            services_html = (
                '<table class="nm-services-table">'
                "<tr><th>Port</th><th>Proto</th><th>Service</th></tr>"
                + "".join(svc_rows) + "</table>"
            )

        # Port distribution bar
        port_bar_html = ""
        if svcs:
            wk = sum(1 for s in svcs if s.get("port", 0) < 1024)
            hp = len(svcs) - wk
            total_p = len(svcs)
            segs = ""
            if wk:
                wk_pct = _fmt(wk / total_p * 100, ".1f")
                segs += (
                    '<div class="nm-port-seg well-known-seg"'
                    ' style="width:' + wk_pct + '%"'
                    ' title="' + str(wk) + ' well-known"></div>'
                )
            if hp:
                hp_pct = _fmt(hp / total_p * 100, ".1f")
                segs += (
                    '<div class="nm-port-seg high-port-seg"'
                    ' style="width:' + hp_pct + '%"'
                    ' title="' + str(hp) + ' high-port"></div>'
                )
            if segs:
                port_bar_html = (
                    '<div class="nm-port-bar">' + segs + "</div>"
                )

        # Endpoints: first 5 inline, rest behind <details>
        endpoints_html = ""
        eps = topo.get("endpoints", [])
        if eps:
            inline = eps[:max_inline]
            ep_items = "".join(
                "<div>" + _e(p) + "</div>" for p in inline
            )
            toggle = ""
            if len(eps) > max_inline:
                remaining = eps[max_inline:]
                remaining_items = "".join(
                    "<div>" + _e(p) + "</div>" for p in remaining
                )
                toggle = (
                    '<details class="nm-endpoints-toggle">'
                    "<summary>" + str(len(remaining))
                    + " more endpoint"
                    + ("s" if len(remaining) != 1 else "")
                    + "</summary>"
                    '<div class="nm-endpoints-list">'
                    + remaining_items + "</div></details>"
                )
            endpoints_html = (
                '<div class="nm-endpoints">'
                + ep_items + toggle + "</div>"
            )

        # Technologies
        tech_html = ""
        techs = topo.get("technologies", [])
        if techs:
            chips: list[str] = []
            for t in techs:
                name = _e(t.get("name", ""))
                ver = _e(t.get("version", ""))
                label = name + (" " + ver if ver else "")
                chips.append(
                    '<span class="nm-tech-chip">'
                    + label + "</span>"
                )
            tech_html = (
                '<div style="margin-top:var(--sp-2)">'
                + "".join(chips) + "</div>"
            )

        # Findings inline preview
        findings_preview_html = ""
        host_findings = findings_for_host.get(host_name, [])
        if host_findings:
            preview_max = 3
            preview_items: list[str] = []
            for fi in host_findings[:preview_max]:
                fi_sev = fi.get("severity", "INFO").upper()
                fi_title = _e(fi.get("title", ""))
                if len(fi_title) > 60:
                    fi_title = fi_title[:60] + "..."
                preview_items.append(
                    '<div class="nm-finding-item">'
                    '<span class="nm-sev-dot dot-' + fi_sev + '"></span>'
                    + fi_title + "</div>"
                )
            more_toggle = ""
            if len(host_findings) > preview_max:
                remaining_f = host_findings[preview_max:]
                rem_items: list[str] = []
                for fi in remaining_f:
                    fi_sev = fi.get("severity", "INFO").upper()
                    fi_title = _e(fi.get("title", ""))
                    if len(fi_title) > 60:
                        fi_title = fi_title[:60] + "..."
                    rem_items.append(
                        '<div class="nm-finding-item">'
                        '<span class="nm-sev-dot dot-' + fi_sev + '"></span>'
                        + fi_title + "</div>"
                    )
                more_toggle = (
                    "<details><summary>"
                    + str(len(remaining_f)) + " more</summary>"
                    + "".join(rem_items) + "</details>"
                )
            findings_preview_html = (
                '<div class="nm-findings-preview">'
                + "".join(preview_items) + more_toggle + "</div>"
            )

        cards.append(
            '<details class="' + card_class + '" open'
            ' data-host="' + safe_host + '"'
            ' data-sev="' + sev_attr + '"'
            ' data-findings="' + str(fc) + '"'
            ' data-risk="' + str(risk) + '">\n'
            '  <summary class="host-summary">'
            '<span class="host-name">'
            + safe_host + subdomain_badge
            + findings_badge + svc_count_badge + risk_badge + "</span>"
            ' <button class="host-copy"'
            " onclick=\"event.stopPropagation();"
            "copyHost(this,'" + safe_host + "')\">"
            "Copy</button>"
            "</summary>\n"
            '  <div class="host-card-body">'
            + services_html + port_bar_html
            + endpoints_html + tech_html
            + findings_preview_html
            + "</div>\n</details>"
        )

    # Sort buttons
    sort_bar = (
        '<span class="nm-sort-bar">'
        '<button class="nm-sort-btn" onclick="sortNetworkHosts(\'severity\')">'
        "Severity</button>"
        '<button class="nm-sort-btn" onclick="sortNetworkHosts(\'findings\')">'
        "Findings</button>"
        '<button class="nm-sort-btn" onclick="sortNetworkHosts(\'name\')">'
        "Name</button>"
        '<button class="nm-sort-btn" onclick="sortNetworkHosts(\'risk\')">'
        "Risk</button>"
        "</span>"
    )

    # Compact table
    compact_rows: list[str] = []
    for host_name, topo in ordered:
        safe_host = _e(host_name)
        h_risk = _host_risk_score(host_name, all_findings)
        h_risk_cls = _risk_color_class(h_risk)
        h_sev = _max_severity_for_host(host_name, all_findings)
        h_sev_attr = h_sev if h_sev else "NONE"
        h_fc = findings_count_by_host.get(host_name, 0)
        h_svcs = topo.get("services", [])
        svc_strs = [
            str(s.get("port", "")) + "/" + str(s.get("service", ""))
            for s in h_svcs[:5]
        ]
        svc_cell = ", ".join(svc_strs)
        if len(h_svcs) > 5:
            svc_cell += " +" + str(len(h_svcs) - 5)
        h_techs = topo.get("technologies", [])
        tech_strs = [_e(t.get("name", "")) for t in h_techs[:4]]
        tech_cell = ", ".join(tech_strs)
        if len(h_techs) > 4:
            tech_cell += " +" + str(len(h_techs) - 4)
        compact_rows.append(
            '<tr data-host="' + safe_host + '"'
            ' data-sev="' + h_sev_attr + '"'
            ' data-findings="' + str(h_fc) + '"'
            ' data-risk="' + str(h_risk) + '">'
            "<td>" + safe_host + "</td>"
            '<td><span class="nm-risk-badge ' + h_risk_cls + '">'
            + str(h_risk) + "</span></td>"
            "<td>" + h_sev_attr + "</td>"
            "<td>" + str(h_fc) + "</td>"
            "<td>" + _e(svc_cell) + "</td>"
            "<td>" + tech_cell + "</td>"
            "</tr>"
        )
    compact_table_html = (
        '<table class="nm-compact-table sortable">\n'
        "<thead><tr>"
        "<th>Host</th><th>Risk</th><th>Severity</th>"
        "<th>Findings</th><th>Services</th><th>Technologies</th>"
        "</tr></thead>\n"
        "<tbody>" + "".join(compact_rows) + "</tbody>\n"
        "</table>\n"
    )

    # Filter indicator
    filter_indicator_html = (
        '<div class="nm-filter-indicator"'
        ' id="nm-filter-indicator"></div>\n'
    )

    # Keyboard hint
    kb_hint_html = (
        '<div class="nm-kb-hint">'
        "<kbd>j</kbd>/<kbd>k</kbd> navigate "
        "<kbd>Enter</kbd> toggle "
        "<kbd>/</kbd> search "
        "<kbd>Esc</kbd> clear"
        "</div>\n"
    )

    return (
        '<div class="section" id="network-map">\n'
        '  <div class="section-title">'
        '<button class="nm-view-btn"'
        ' onclick="toggleCompactView(this)">Compact</button>'
        '<button class="nm-toggle-btn"'
        ' onclick="toggleNetworkCards(false)">Collapse All</button>'
        '<button class="nm-toggle-btn"'
        ' onclick="exportVisibleHosts(this)">Export Hosts</button>'
        + sort_bar
        + "Network Map</div>\n"
        + stats_html
        + proto_bar_html
        + search_html
        + filter_bar_html
        + filter_indicator_html
        + counter_html
        + '  <div class="nm-grid">\n'
        + "".join(cards)
        + "\n  </div>\n"
        + compact_table_html
        + '  <div class="nm-no-matches" id="nm-no-matches">'
        "No hosts match your search</div>\n"
        + kb_hint_html
        + "</div>"
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

    # Build events timeline
    events = r.get("events", [])
    events_html = ""
    if events:
        event_parts: list[str] = []
        for ev in events:
            etype = _e(ev.get("type", ""))
            estep = ev.get("step", 0)
            edata = ev.get("data", {})

            # Color-code by event type
            _ev_colors = {
                "hypothesis_confirmed": "neon-green",
                "hypothesis_rejected": "neon-red",
                "belief_strengthened": "neon-green",
                "belief_weakened": "neon-orange",
            }
            color = _ev_colors.get(etype, "neon-cyan")

            detail_parts: list[str] = []
            for k, v in edata.items():
                detail_parts.append(_e(str(k)) + ": " + _e(str(v)))
            detail = " &middot; ".join(detail_parts) if detail_parts else ""

            event_parts.append(
                '<div class="reasoning-event" style="border-left:3px solid'
                " var(--" + color + ');">\n'
                '  <span class="re-type">' + etype + "</span>\n"
                '  <span class="re-step">step '
                + str(estep) + "</span>\n"
                + ('  <div class="re-detail">'
                   + detail + "</div>\n" if detail else "")
                + "</div>"
            )
        events_html = (
            '<details class="reasoning-events-toggle">\n'
            "  <summary>Events Timeline ("
            + str(len(events)) + ")</summary>\n"
            '  <div class="reasoning-events">\n'
            + "".join(event_parts)
            + "\n  </div>\n"
            "</details>\n"
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
        + events_html
        + "</div>"
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
    "\n"
    "  /* Evidence expand/collapse toggle */\n"
    "  if (block.scrollHeight > block.offsetHeight + 2) {\n"
    "    block.classList.add('overflows');\n"
    "    var toggleBtn = document.createElement('button');\n"
    "    toggleBtn.className = 'evidence-toggle';\n"
    "    toggleBtn.textContent = 'Show more';\n"
    "    toggleBtn.addEventListener('click', function() {\n"
    "      block.classList.toggle('expanded');\n"
    "      toggleBtn.textContent ="
    " block.classList.contains('expanded')"
    " ? 'Show less' : 'Show more';\n"
    "    });\n"
    "    block.appendChild(toggleBtn);\n"
    "  }\n"
    "\n"
    "  /* Copy to clipboard button */\n"
    "  var copyBtn = document.createElement('button');\n"
    "  copyBtn.className = 'evidence-copy';\n"
    "  copyBtn.textContent = 'Copy';\n"
    "  copyBtn.addEventListener('click', function() {\n"
    "    var text = block.textContent"
    ".replace('Show more', '').replace('Show less', '')"
    ".replace('Copy', '').replace('Copied!', '').trim();\n"
    "    navigator.clipboard.writeText(text).then(function() {\n"
    "      copyBtn.textContent = 'Copied!';\n"
    "      setTimeout(function() {"
    " copyBtn.textContent = 'Copy'; }, 1500);\n"
    "    });\n"
    "  });\n"
    "  block.appendChild(copyBtn);\n"
    "});\n"
    "\n"
    "function copyHost(btn, text) {\n"
    "  navigator.clipboard.writeText(text).then(function() {\n"
    "    var o = btn.textContent;\n"
    "    btn.textContent = 'Copied!';\n"
    "    setTimeout(function() { btn.textContent = o; }, 1200);\n"
    "  });\n"
    "}\n"
    "\n"
    "function toggleHostFilter(btn) {\n"
    "  btn.classList.toggle('active');\n"
    "  applyHostFilters();\n"
    "}\n"
    "\n"
    "function applyHostFilters() {\n"
    "  var allChips = document.querySelectorAll('.nm-filter-bar .filter-chip');\n"
    "  var totalChips = allChips.length;\n"
    "  var activeSevs = [];\n"
    "  allChips.forEach(function(c) {\n"
    "    if (c.classList.contains('active')) activeSevs.push(c.dataset.sev);\n"
    "  });\n"
    "  var box = document.querySelector('.nm-search');\n"
    "  var q = box ? box.value.toLowerCase().trim() : '';\n"
    "  var visible = 0;\n"
    "  document.querySelectorAll('.nm-grid .host-card')"
    ".forEach(function(card) {\n"
    "    var text = card.textContent.toLowerCase();\n"
    "    var host = (card.dataset.host || '').toLowerCase();\n"
    "    var sev = card.dataset.sev || 'NONE';\n"
    "    var sevMatch = activeSevs.length === 0"
    " || activeSevs.indexOf(sev) !== -1;\n"
    "    var textMatch = !q || text.indexOf(q) !== -1"
    " || host.indexOf(q) !== -1;\n"
    "    var show = sevMatch && textMatch;\n"
    "    card.style.display = show ? '' : 'none';\n"
    "    if (show) visible++;\n"
    "  });\n"
    "  document.querySelectorAll('.nm-compact-table tbody tr')"
    ".forEach(function(row) {\n"
    "    var host = (row.dataset.host || '').toLowerCase();\n"
    "    var sev = row.dataset.sev || 'NONE';\n"
    "    var sevMatch = activeSevs.length === 0"
    " || activeSevs.indexOf(sev) !== -1;\n"
    "    var textMatch = !q || host.indexOf(q) !== -1;\n"
    "    row.style.display = (sevMatch && textMatch) ? '' : 'none';\n"
    "  });\n"
    "  var counter = document.getElementById('nm-visible');\n"
    "  if (counter) counter.textContent = visible;\n"
    "  var noMatch = document.getElementById('nm-no-matches');\n"
    "  if (noMatch) noMatch.style.display ="
    " visible === 0 ? 'block' : 'none';\n"
    "  var ind = document.getElementById('nm-filter-indicator');\n"
    "  if (ind) {\n"
    "    var parts = [];\n"
    "    if (activeSevs.length > 0 && activeSevs.length < totalChips)"
    " parts.push('Severity: ' + activeSevs.join(', '));\n"
    "    if (q) parts.push('Search: \"' + q + '\"');\n"
    "    if (parts.length > 0) {\n"
    "      ind.innerHTML = parts.join(' &middot; ')"
    " + ' <a onclick=\"clearHostFilters()\">Clear all</a>';\n"
    "      ind.style.display = 'block';\n"
    "    } else { ind.style.display = 'none'; }\n"
    "  }\n"
    "}\n"
    "\n"
    "function sortNetworkHosts(criteria) {\n"
    "  var sevRank = {CRITICAL:4,HIGH:3,MEDIUM:2,LOW:1,INFO:0,NONE:-1};\n"
    "  var grid = document.querySelector('.nm-grid');\n"
    "  if (!grid) return;\n"
    "  var cards = Array.from(grid.querySelectorAll('.host-card'));\n"
    "  cards.sort(function(a, b) {\n"
    "    if (criteria === 'severity') {\n"
    "      return (sevRank[b.dataset.sev]||0)"
    " - (sevRank[a.dataset.sev]||0);\n"
    "    } else if (criteria === 'findings') {\n"
    "      return parseInt(b.dataset.findings||0)"
    " - parseInt(a.dataset.findings||0);\n"
    "    } else if (criteria === 'risk') {\n"
    "      return parseInt(b.dataset.risk||0)"
    " - parseInt(a.dataset.risk||0);\n"
    "    } else {\n"
    "      return (a.dataset.host||'')"
    ".localeCompare(b.dataset.host||'');\n"
    "    }\n"
    "  });\n"
    "  cards.forEach(function(c) { grid.appendChild(c); });\n"
    "  document.querySelectorAll('.nm-sort-btn')"
    ".forEach(function(b) { b.classList.remove('active'); });\n"
    "  var clicked = document.querySelector("
    "'.nm-sort-btn[onclick*=\"' + criteria + '\"]');\n"
    "  if (clicked) clicked.classList.add('active');\n"
    "}\n"
    "\n"
    "function exportVisibleHosts(btn) {\n"
    "  var hosts = [];\n"
    "  document.querySelectorAll('.nm-grid .host-card')"
    ".forEach(function(card) {\n"
    "    if (card.style.display !== 'none') {\n"
    "      hosts.push(card.dataset.host);\n"
    "    }\n"
    "  });\n"
    "  navigator.clipboard.writeText(hosts.join('\\n'))"
    ".then(function() {\n"
    "    var orig = btn.textContent;\n"
    "    btn.textContent = 'Copied!';\n"
    "    setTimeout(function() {"
    " btn.textContent = orig; }, 1500);\n"
    "  });\n"
    "}\n"
    "\n"
    "function toggleNetworkCards(open) {\n"
    "  document.querySelectorAll('.nm-grid .host-card')"
    ".forEach(function(d) {\n"
    "    d.open = open;\n"
    "  });\n"
    "  var btn = document.querySelector('.nm-toggle-btn');\n"
    "  if (btn) {\n"
    "    btn.textContent = open ? 'Collapse All' : 'Expand All';\n"
    "    btn.onclick = function() {"
    " toggleNetworkCards(!open); };\n"
    "  }\n"
    "}\n"
    "\n"
    "function toggleCompactView(btn) {\n"
    "  var grid = document.querySelector('.nm-grid');\n"
    "  var table = document.querySelector('.nm-compact-table');\n"
    "  if (!grid || !table) return;\n"
    "  var showTable = grid.style.display !== 'none';\n"
    "  grid.style.display = showTable ? 'none' : '';\n"
    "  table.style.display = showTable ? 'table' : 'none';\n"
    "  btn.textContent = showTable ? 'Cards' : 'Compact';\n"
    "}\n"
    "\n"
    "function clearHostFilters() {\n"
    "  document.querySelectorAll('.nm-filter-bar .filter-chip')"
    ".forEach(function(c) {\n"
    "    c.classList.add('active');\n"
    "  });\n"
    "  var box = document.querySelector('.nm-search');\n"
    "  if (box) box.value = '';\n"
    "  applyHostFilters();\n"
    "}\n"
    "\n"
    "(function() {\n"
    "  var nmFocusIdx = -1;\n"
    "  function nmVisibleCards() {\n"
    "    return Array.from("
    "document.querySelectorAll('.nm-grid .host-card'))"
    ".filter(function(c) { return c.style.display !== 'none'; });\n"
    "  }\n"
    "  function nmSetFocus(cards, idx) {\n"
    "    document.querySelectorAll('.nm-focused')"
    ".forEach(function(c) { c.classList.remove('nm-focused'); });\n"
    "    if (idx >= 0 && idx < cards.length) {\n"
    "      nmFocusIdx = idx;\n"
    "      cards[idx].classList.add('nm-focused');\n"
    "      cards[idx].scrollIntoView({block:'nearest'});\n"
    "    }\n"
    "  }\n"
    "  document.addEventListener('keydown', function(e) {\n"
    "    var nmSection = document.getElementById('network-map');\n"
    "    if (!nmSection) return;\n"
    "    var tag = (e.target.tagName || '').toUpperCase();\n"
    "    if (tag === 'INPUT' || tag === 'TEXTAREA') {\n"
    "      if (e.key === 'Escape') { e.target.blur(); } return;\n"
    "    }\n"
    "    var cards = nmVisibleCards();\n"
    "    if (e.key === 'j') {\n"
    "      nmSetFocus(cards, Math.min(nmFocusIdx + 1,"
    " cards.length - 1));\n"
    "    } else if (e.key === 'k') {\n"
    "      nmSetFocus(cards, Math.max(nmFocusIdx - 1, 0));\n"
    "    } else if (e.key === 'Enter'"
    " && nmFocusIdx >= 0 && cards[nmFocusIdx]) {\n"
    "      cards[nmFocusIdx].open = !cards[nmFocusIdx].open;\n"
    "    } else if (e.key === '/') {\n"
    "      e.preventDefault();\n"
    "      var sb = document.querySelector('.nm-search');\n"
    "      if (sb) sb.focus();\n"
    "    } else if (e.key === 'Escape') {\n"
    "      nmFocusIdx = -1;\n"
    "      document.querySelectorAll('.nm-focused')"
    ".forEach(function(c) { c.classList.remove('nm-focused'); });\n"
    "    }\n"
    "  });\n"
    "})();\n"
    "</script>"
)
