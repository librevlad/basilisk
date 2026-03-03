"""HTML + JSON report renderer — self-contained cyberpunk dashboard.

Renderers are PURE PRESENTATION. All business logic (risk score, severity counts,
kill chain, etc.) is computed by ReportBuilder. Renderers accept a data dict derived
from a canonical ReportModel and assemble HTML/JSON — nothing more.
"""

from __future__ import annotations

import html
import json
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from basilisk.reporting.builder import KILL_CHAIN_PHASES

if TYPE_CHECKING:
    from basilisk.reporting.model import ReportModel

_VERSION = "4.0.0"



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
                "step": ev.step,
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
    """Render report data as formatted JSON string with sorted keys."""
    return json.dumps(data, indent=2, ensure_ascii=False, default=str, sort_keys=True)


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
        '<a href="#command-center" class="skip-link">'
        "Skip to content</a>\n",
        "<script>const DATA = ",
        safe_json,
        ";</script>\n",
        _sidebar_html(data),
        "\n<main class=\"main\">\n",
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
        '\n<button class="scroll-top"'
        ' aria-label="Scroll to top"'
        " onclick=\"window.scrollTo({top:0,behavior:'smooth'})\""
        ">&uarr;</button>\n"
        "</main>\n",
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
    "@keyframes bar-grow {\n"
    "  from { transform: scaleY(0); transform-origin: bottom; }\n"
    "  to { transform: scaleY(1); transform-origin: bottom; }\n"
    "}\n"
    "@media (prefers-reduced-motion: reduce) {\n"
    "  *, *::before, *::after {\n"
    "    animation-duration: 0.01ms !important;\n"
    "    animation-iteration-count: 1 !important;\n"
    "    transition-duration: 0.01ms !important;\n"
    "  }\n"
    "}\n"
    "\n"
    "*:focus-visible {\n"
    "  outline: 2px solid var(--neon-green);\n"
    "  outline-offset: 2px;\n"
    "}\n"
    "\n"
    ".skip-link {\n"
    "  position: absolute; left: -9999px; top: auto;\n"
    "  width: 1px; height: 1px; overflow: hidden;\n"
    "  z-index: 10000; padding: var(--sp-2) var(--sp-3);\n"
    "  background: var(--bg); color: var(--neon-green);\n"
    "  font-weight: 600; text-decoration: none;\n"
    "  border: 2px solid var(--neon-green);\n"
    "  border-radius: var(--radius-sm);\n"
    "}\n"
    ".skip-link:focus {\n"
    "  position: fixed; left: var(--sp-3); top: var(--sp-3);\n"
    "  width: auto; height: auto;\n"
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
    ".vuln-sev-bar { margin-bottom: var(--sp-3); }\n"
    ".conf-gauge {"
    " vertical-align: middle; margin-right: 4px;"
    " display: inline-block; }\n"
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
    "  position: relative; opacity: 0.8;\n"
    "  animation: bar-grow 0.6s ease-out both;\n"
    "}\n"
    ".growth-bar:nth-child(2) { animation-delay: 0.03s; }\n"
    ".growth-bar:nth-child(3) { animation-delay: 0.06s; }\n"
    ".growth-bar:nth-child(4) { animation-delay: 0.09s; }\n"
    ".growth-bar:nth-child(5) { animation-delay: 0.12s; }\n"
    ".growth-bar:nth-child(6) { animation-delay: 0.15s; }\n"
    ".growth-bar:nth-child(n+7) { animation-delay: 0.18s; }\n"
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
    "  position: sticky; top: 0; z-index: 50;\n"
    "  background: var(--surface-1);\n"
    "  padding: var(--sp-2) 0;\n"
    "  border-bottom: 1px solid transparent;\n"
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
    ".filter-chip:hover { transform: translateY(-1px); }\n"
    ".filter-chip:active { transform: scale(0.95); }\n"
    ".findings-stats {\n"
    "  font-size: var(--text-xs); color: var(--fg-dim);\n"
    "  white-space: nowrap;\n"
    "}\n"
    ".sort-select {\n"
    "  padding: 3px 8px; background: var(--surface-2);\n"
    "  border: 1px solid var(--border);\n"
    "  border-radius: var(--radius-sm); color: var(--fg);\n"
    "  font-size: var(--text-xs); font-family: inherit;\n"
    "  cursor: pointer; outline: none;\n"
    "}\n"
    ".sort-select:focus { border-color: var(--neon-green); }\n"
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
    ".ev-status { color: var(--neon-cyan); font-weight: 700; }\n"
    ".ev-header-name { color: var(--neon-purple); }\n"
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
    ".timeline-item.productive {\n"
    "  border-left: 3px solid var(--neon-green);\n"
    "  background: rgba(0,255,106,0.03);\n"
    "}\n"
    ".timeline-item.unproductive::before {"
    " background: var(--fg-muted); }\n"
    ".timeline-item.unproductive {\n"
    "  border-left: 3px solid var(--fg-muted);\n"
    "  opacity: 0.75;\n"
    "}\n"
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
    ".nm-empty-section {\n"
    "  margin-top: var(--sp-4);\n"
    "}\n"
    ".nm-empty-section summary {\n"
    "  cursor: pointer; color: var(--fg-dim);\n"
    "  font-size: var(--text-sm); font-weight: 600;\n"
    "}\n"
    ".nm-empty-grid {\n"
    "  display: grid;"
    " grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));\n"
    "  gap: var(--sp-1); padding: var(--sp-2) 0;\n"
    "}\n"
    ".nm-empty-chip {\n"
    "  padding: 2px 8px; background: var(--surface-2);\n"
    "  border: 1px solid var(--border);\n"
    "  border-radius: var(--radius-sm);\n"
    "  font-size: var(--text-xs); color: var(--fg-dim);\n"
    "  overflow: hidden; text-overflow: ellipsis;\n"
    "  white-space: nowrap;\n"
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
    ".nm-compact-table tbody tr:nth-child(even) td {"
    " background: rgba(0,255,106,0.015); }\n"
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
    ".perf-table tbody tr:nth-child(even) td {"
    " background: rgba(0,255,106,0.015); }\n"
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
    ".training-table tbody tr:nth-child(even) td {"
    " background: rgba(0,255,106,0.015); }\n"
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
    "  display: flex; justify-content: space-between;"
    " align-items: center;\n"
    "  flex-wrap: wrap; gap: var(--sp-3);"
    " padding: var(--sp-4);\n"
    "  color: var(--fg-muted);"
    " font-size: var(--text-xs);\n"
    "  border-top: 1px solid var(--border);"
    " margin-top: var(--sp-6);\n"
    "}\n"
    ".footer-stats {"
    " display: flex; gap: var(--sp-3); align-items: center; }\n"
    ".footer-meta {"
    " display: flex; gap: var(--sp-2); align-items: center; }\n"
    ".scroll-top {\n"
    "  position: fixed; bottom: 2rem; right: 2rem;\n"
    "  width: 40px; height: 40px; border-radius: 50%;\n"
    "  background: var(--neon-green); color: var(--bg);\n"
    "  border: none; cursor: pointer; font-size: 1.2rem;\n"
    "  font-family: inherit; font-weight: 700;\n"
    "  opacity: 0; visibility: hidden;\n"
    "  transition: opacity 0.25s, visibility 0.25s,"
    " box-shadow 0.2s;\n"
    "  z-index: 90;\n"
    "  box-shadow: 0 2px 8px rgba(0,255,106,0.3);\n"
    "}\n"
    ".scroll-top.show {\n"
    "  opacity: 1; visibility: visible;\n"
    "}\n"
    ".scroll-top:hover {\n"
    "  box-shadow: 0 0 20px rgba(0,255,106,0.5);\n"
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
    ".metric-card, .surface-stat, .reasoning-stat, .kc-phase {\n"
    "  transition: transform 0.2s ease,"
    " box-shadow 0.2s ease, background 0.2s ease;\n"
    "}\n"
    ".metric-card:hover, .surface-stat:hover,\n"
    ".reasoning-stat:hover, .kc-phase:hover {\n"
    "  transform: translateY(-2px);\n"
    "  box-shadow: 0 4px 16px rgba(0,255,106,0.1);\n"
    "}\n"
    ".metric-card:hover { background: var(--surface-3); }\n"
    ".main::after {\n"
    "  content: ''; position: fixed;"
    " left: var(--sidebar-w); right: 0;\n"
    "  height: 4px; z-index: 9998;"
    " pointer-events: none;\n"
    "  background: linear-gradient(180deg,"
    " rgba(0,255,106,0.03) 0%,"
    " rgba(0,229,255,0.02) 50%, transparent 100%);\n"
    "  animation: scan-line 8s linear infinite;\n"
    "}\n"
    ".perf-table tbody tr { transition: background 0.15s; }\n"
    "\n"
    "/* Evidence expand/collapse */\n"
    ".evidence-block { position: relative; transition: max-height 0.3s; }\n"
    ".evidence-block.expanded { max-height: none !important; }\n"
    ".evidence-block.overflows:not(.expanded)::after {\n"
    "  content: ''; position: absolute;"
    " bottom: 0; left: 0; right: 0;\n"
    "  height: 40px; pointer-events: none;\n"
    "  background: linear-gradient(transparent, var(--bg));\n"
    "}\n"
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
    ".re-hypothesis {\n"
    "  color: var(--fg); font-size: var(--text-sm);\n"
    "  margin-top: var(--sp-1); font-style: italic;\n"
    "}\n"
    "\n"
    "/* Gap trajectory in KG Growth */\n"
    ".growth-gap-line {\n"
    "  margin-top: var(--sp-2); position: relative;\n"
    "  height: 40px;\n"
    "}\n"
    ".gap-label {\n"
    "  font-size: var(--text-xs); color: var(--neon-orange);\n"
    "  margin-bottom: 2px;\n"
    "}\n"
    ".growth-summary {\n"
    "  font-size: var(--text-xs); color: var(--fg-dim);\n"
    "  margin-top: var(--sp-2);\n"
    "}\n"
    ".growth-summary span { color: var(--neon-cyan); font-weight: 600; }\n"
    "\n"
    "/* Findings-by-host bars */\n"
    ".findings-host-bar {\n"
    "  display: flex; flex-direction: column; gap: 3px;\n"
    "  margin-bottom: var(--sp-3); padding: var(--sp-2);\n"
    "  background: var(--surface-2); border-radius: var(--radius);\n"
    "}\n"
    ".findings-host-bar .fhb-title {\n"
    "  font-size: var(--text-xs); color: var(--fg-dim);\n"
    "  text-transform: uppercase; margin-bottom: var(--sp-1);\n"
    "}\n"
    ".fhb-item {\n"
    "  display: flex; align-items: center; gap: var(--sp-2);\n"
    "  cursor: pointer; font-size: var(--text-xs);\n"
    "}\n"
    ".fhb-item:hover .fhb-bar { opacity: 1; }\n"
    ".fhb-label {\n"
    "  min-width: 140px; max-width: 180px; overflow: hidden;\n"
    "  text-overflow: ellipsis; white-space: nowrap;\n"
    "  color: var(--fg-dim);\n"
    "}\n"
    ".fhb-bar {\n"
    "  height: 10px; border-radius: 2px; opacity: 0.8;\n"
    "  background: linear-gradient(90deg,"
    " var(--neon-green), var(--neon-cyan));\n"
    "  transition: opacity 0.15s;\n"
    "}\n"
    ".fhb-count {\n"
    "  color: var(--neon-green); font-weight: 600;\n"
    "  min-width: 24px;\n"
    "}\n"
    "\n"
    "/* Severity discovery timeline */\n"
    ".sev-timeline {\n"
    "  position: relative; height: 34px;\n"
    "  margin-bottom: var(--sp-3); padding: var(--sp-1) 0;\n"
    "  background: var(--surface-2); border-radius: var(--radius);\n"
    "  overflow: hidden;\n"
    "}\n"
    ".sev-timeline .stl-label {\n"
    "  position: absolute; top: 2px; left: var(--sp-2);\n"
    "  font-size: var(--text-xs); color: var(--fg-dim);\n"
    "}\n"
    ".sev-dot {\n"
    "  position: absolute; width: 8px; height: 8px;\n"
    "  border-radius: 50%; bottom: 4px;\n"
    "  opacity: 0.85;\n"
    "}\n"
    ".sev-dot:hover { opacity: 1; transform: scale(1.4); }\n"
    "\n"
    "/* Decision stats banner reuses metrics-grid */\n"
    ".decision-stats .metric-value.green { color: var(--neon-green); }\n"
    ".decision-stats .metric-value.red { color: var(--neon-red); }\n"
    ".decision-stats .metric-value.orange { color: var(--neon-orange); }\n"
    "\n"
    "/* Plugin efficiency summary */\n"
    ".perf-summary td {\n"
    "  font-weight: 700; border-top: 2px solid var(--border);\n"
    "  color: var(--neon-cyan);\n"
    "}\n"
    ".perf-top { color: var(--neon-green) !important; font-weight: 700; }\n"
    "\n"
    "/* Plugin severity badges in table */\n"
    ".plugin-sev-cell { white-space: nowrap; }\n"
    ".psev-dot {\n"
    "  display: inline-block; padding: 1px 5px;\n"
    "  border-radius: 3px; font-size: var(--text-xs);\n"
    "  font-weight: 600; margin-right: 2px;\n"
    "}\n"
    ".psev-dot.psev-CRITICAL { background: var(--critical-bg); color: var(--critical); }\n"
    ".psev-dot.psev-HIGH { background: var(--high-bg); color: var(--high); }\n"
    ".psev-dot.psev-MEDIUM { background: var(--medium-bg); color: var(--medium); }\n"
    ".psev-dot.psev-LOW { background: var(--low-bg); color: var(--low); }\n"
    ".psev-dot.psev-INFO { background: var(--info-bg); color: var(--info); }\n"
    "\n"
    "/* Execution cost distribution bar */\n"
    ".cost-dist {\n"
    "  margin-top: var(--sp-3); padding: var(--sp-3);\n"
    "  background: var(--surface-2); border-radius: var(--radius);\n"
    "}\n"
    ".cost-dist-title {\n"
    "  font-size: var(--text-xs); color: var(--fg-dim);\n"
    "  text-transform: uppercase; margin-bottom: var(--sp-2);\n"
    "}\n"
    ".cost-dist-bar {\n"
    "  display: flex; height: 20px; border-radius: 3px;\n"
    "  overflow: hidden; margin-bottom: var(--sp-2);\n"
    "}\n"
    ".cost-seg { height: 100%; transition: opacity 0.15s; }\n"
    ".cost-seg:hover { opacity: 0.85; }\n"
    ".cost-dist-legend {\n"
    "  display: flex; flex-wrap: wrap; gap: var(--sp-2);\n"
    "  font-size: var(--text-xs);\n"
    "}\n"
    ".cost-legend-item { display: flex; align-items: center; gap: 4px; }\n"
    ".cost-swatch {\n"
    "  width: 10px; height: 10px; border-radius: 2px;\n"
    "  display: inline-block;\n"
    "}\n"
    ".cost-outlier {\n"
    "  margin-top: var(--sp-2); padding: var(--sp-1) var(--sp-2);\n"
    "  background: var(--high-bg); border-left: 3px solid var(--high);\n"
    "  font-size: var(--text-xs); color: var(--high);\n"
    "}\n"
    "\n"
    "/* Kill chain plugin drill-down */\n"
    ".kc-plugins {\n"
    "  padding: var(--sp-2); display: flex;\n"
    "  flex-direction: column; gap: 2px;\n"
    "  font-size: var(--text-xs);\n"
    "}\n"
    ".kc-plugin { padding: 1px 0; }\n"
    ".kc-plugin.executed { color: var(--neon-green); }\n"
    ".kc-plugin.executed::before { content: '\\2713 '; }\n"
    ".kc-plugin.skipped { color: var(--fg-muted); }\n"
    ".kc-plugin.skipped::before { content: '\\2717 '; }\n"
    "\n"
    "/* Gap type distribution bars */\n"
    ".gap-dist {\n"
    "  margin-bottom: var(--sp-3); padding: var(--sp-2) var(--sp-3);\n"
    "  background: var(--surface-2); border-radius: var(--radius);\n"
    "}\n"
    ".gap-dist-title {\n"
    "  font-size: var(--text-xs); color: var(--fg-dim);\n"
    "  text-transform: uppercase; margin-bottom: var(--sp-2);\n"
    "}\n"
    ".gap-bar-row {\n"
    "  display: flex; align-items: center; gap: var(--sp-2);\n"
    "  margin-bottom: 3px; font-size: var(--text-xs);\n"
    "}\n"
    ".gap-bar-label {\n"
    "  min-width: 130px; color: var(--fg-dim);\n"
    "  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;\n"
    "}\n"
    ".gap-bar-fill {\n"
    "  height: 10px; border-radius: 2px;\n"
    "  background: linear-gradient(90deg,"
    " var(--neon-purple), var(--neon-blue));\n"
    "  opacity: 0.8; transition: opacity 0.15s;\n"
    "}\n"
    ".gap-bar-fill:hover { opacity: 1; }\n"
    ".gap-bar-count { color: var(--neon-purple); font-weight: 600; }\n"
    "\n"
    "/* Hypothesis category groups */\n"
    ".hyp-categories {\n"
    "  margin-top: var(--sp-3); display: flex;\n"
    "  flex-direction: column; gap: var(--sp-3);\n"
    "}\n"
    ".hyp-cat-group {\n"
    "  background: var(--surface-2); border-radius: var(--radius);\n"
    "  padding: var(--sp-2) var(--sp-3);\n"
    "}\n"
    ".hyp-cat-header {\n"
    "  display: flex; align-items: center; gap: var(--sp-2);\n"
    "  margin-bottom: var(--sp-2);\n"
    "}\n"
    ".hyp-cat-name {\n"
    "  font-weight: 600; font-size: var(--text-sm);\n"
    "  color: var(--neon-cyan);\n"
    "}\n"
    ".hyp-cat-count {\n"
    "  font-size: var(--text-xs); color: var(--fg-dim);\n"
    "  background: var(--bg3); padding: 1px 6px;\n"
    "  border-radius: 8px;\n"
    "}\n"
    ".hyp-cat-item {\n"
    "  font-size: var(--text-sm); padding: 2px 0;\n"
    "  color: var(--fg-dim);\n"
    "}\n"
    ".hyp-cat-item.confirmed { color: var(--neon-green); }\n"
    ".hyp-cat-item.rejected {\n"
    "  color: var(--neon-red); text-decoration: line-through;\n"
    "}\n"
    "\n"
    "/* Entity gain velocity SVG */\n"
    ".gain-velocity {\n"
    "  margin-top: var(--sp-2); position: relative;\n"
    "  height: 50px;\n"
    "}\n"
    ".gain-label {\n"
    "  font-size: var(--text-xs); color: var(--neon-cyan);\n"
    "  margin-bottom: 2px;\n"
    "}\n"
    "\n"
    "/* Cumulative findings curve */\n"
    ".cum-findings {\n"
    "  position: relative; margin-bottom: var(--sp-3);\n"
    "  padding: var(--sp-2); background: var(--surface-2);\n"
    "  border-radius: var(--radius); height: 70px;\n"
    "}\n"
    ".cum-label {\n"
    "  font-size: var(--text-xs); color: var(--fg-dim);\n"
    "  position: absolute; top: 4px; left: var(--sp-2);\n"
    "}\n"
    "\n"
    "/* Subdomain discovery summary */\n"
    ".subdomain-summary {\n"
    "  display: flex; gap: var(--sp-4); flex-wrap: wrap;\n"
    "  margin-bottom: var(--sp-3); padding: var(--sp-2) var(--sp-3);\n"
    "  background: var(--surface-2); border-radius: var(--radius);\n"
    "  font-size: var(--text-sm);\n"
    "}\n"
    ".sub-stat { color: var(--fg-dim); }\n"
    ".sub-stat span { color: var(--neon-cyan); font-weight: 600; }\n"
    ".sub-explored { color: var(--neon-green); }\n"
    "\n"
    "/* Risk score color in command center */\n"
    ".risk-low { color: var(--neon-green); }\n"
    ".risk-medium { color: var(--neon-yellow); }\n"
    ".risk-high { color: var(--neon-orange); }\n"
    ".risk-critical { color: var(--neon-red); }\n"
    "\n"
    "/* Decision timeline extras */\n"
    ".tl-duration { color: var(--fg-dim); font-size: var(--text-xs); }\n"
    ".tl-entities {\n"
    "  color: var(--neon-green); font-size: var(--text-xs);\n"
    "  font-weight: 600;\n"
    "}\n"
    ".decisions-show-more {\n"
    "  display: block; margin: var(--sp-3) auto 0;\n"
    "  padding: var(--sp-2) var(--sp-4);\n"
    "  background: var(--surface-2); color: var(--neon-cyan);\n"
    "  border: 1px solid var(--border); border-radius: var(--radius-sm);\n"
    "  cursor: pointer; font-size: var(--text-sm); font-weight: 600;\n"
    "}\n"
    ".decisions-show-more:hover { border-color: var(--neon-cyan); }\n"
    "\n"
    ".export-json-btn {\n"
    "  display: inline-block; margin-top: var(--sp-2);\n"
    "  padding: var(--sp-1) var(--sp-3);\n"
    "  background: transparent; color: var(--neon-cyan);\n"
    "  border: 1px solid var(--border); border-radius: var(--radius-sm);\n"
    "  cursor: pointer; font-size: var(--text-xs); font-weight: 600;\n"
    "}\n"
    ".export-json-btn:hover { border-color: var(--neon-cyan); }\n"
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
    ".training-table tbody tr:hover td {"
    " background: rgba(0,255,106,0.03); }\n"
    ".training-row-yes {"
    " border-left: 3px solid var(--neon-green); }\n"
    ".training-row-no {"
    " border-left: 3px solid var(--critical); }\n"
    ".step-badge {\n"
    "  display: inline-block;"
    " color: var(--neon-cyan);"
    " background: var(--surface-3);\n"
    "  padding: 1px 6px;"
    " border-radius: var(--radius-sm);"
    " font-size: var(--text-xs);\n"
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
    "  body::before, body::after,"
    " .main::after { display: none !important; }\n"
    "  body { background: #fff; color: #1a1e2e; }\n"
    "  .section {\n"
    "    border: 1px solid #ddd;"
    " box-shadow: none; background: #fff;\n"
    "    animation: none;\n"
    "  }\n"
    "  .filter-bar, .search-box, .nm-sort-bar, .nm-toggle-btn,"
    " .nm-view-btn, .nm-kb-hint,\n"
    "  .evidence-toggle, .evidence-copy, .export-json-btn,"
    " .host-copy, .skip-link,\n"
    "  .decisions-show-more, .scroll-top {"
    " display: none !important; }\n"
    "  .section, .finding-card, .timeline-item {"
    " page-break-inside: avoid; }\n"
    "  details > *:not(summary) {"
    " display: block !important; }\n"
    "  .evidence-block {"
    " max-height: none !important;"
    " overflow: visible !important; }\n"
    "  .sev-badge {\n"
    "    border: 1px solid #666;"
    " color: #1a1e2e !important;"
    " background: transparent !important;\n"
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
        '  <nav aria-label="Report sections">\n'
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
    risk_score = summary.get("risk_score", 0)
    duration = data.get("duration_seconds", 0)

    mins, secs = divmod(int(duration), 60)
    elapsed_str = str(mins) + "m " + str(secs) + "s"
    progress_str = _fmt(progress_pct, ".1f")
    risk_str = _fmt(risk_score, ".1f")
    if risk_score >= 8:
        risk_class = "risk-critical"
    elif risk_score >= 6:
        risk_class = "risk-high"
    elif risk_score >= 3:
        risk_class = "risk-medium"
    else:
        risk_class = "risk-low"

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
                '<div class="seg" title="'
                + sev + ": " + str(cnt) + '" style="width:'
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
        '    <div class="progress-bar" role="progressbar"'
        ' aria-valuenow="' + str(steps) + '"'
        ' aria-valuemax="' + str(max_steps) + '"'
        ' style="width:'
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
        '    <div class="metric-card">'
        '<div class="metric-value ' + risk_class + '">'
        + risk_str + '</div>'
        '<div class="metric-label">Risk Score</div></div>\n'
        "  </div>\n"
        '  <div class="severity-bar">' + sev_bar + "</div>\n"
        "</div>"
    )


def _kill_chain_html(data: dict) -> str:
    plugins = data.get("plugins", [])
    plugin_names = {p["name"] for p in plugins}

    covered_phases = 0
    total_phases = len(KILL_CHAIN_PHASES)
    phases_parts: list[str] = []
    for i, (name, members) in enumerate(KILL_CHAIN_PHASES):
        total_members = len(members)
        count = sum(1 for m in members if m in plugin_names)
        if count > 0:
            covered_phases += 1
        active = " active" if count > 0 else ""
        arrow = (
            '<span class="kc-arrow">&#x25B6;</span>'
            if i < len(KILL_CHAIN_PHASES) - 1
            else ""
        )
        pct = _fmt(count / total_members * 100, ".0f") if total_members > 0 else "0"
        # Plugin drill-down list
        plugin_items: list[str] = []
        for m in members:
            if m in plugin_names:
                plugin_items.append(
                    '<div class="kc-plugin executed">'
                    + _e(m) + "</div>"
                )
            else:
                plugin_items.append(
                    '<div class="kc-plugin skipped">'
                    + _e(m) + "</div>"
                )
        plugins_list = (
            '<div class="kc-plugins">'
            + "".join(plugin_items) + "</div>"
        )
        phases_parts.append(
            '<details class="kc-phase' + active + '">\n'
            "      <summary>\n"
            '        <div class="kc-name">'
            + _e(name) + "</div>\n"
            '        <div class="kc-count">'
            + pct + "%</div>\n"
            '        <div class="kc-label">'
            + str(count) + "/" + str(total_members) + "</div>\n"
            "        " + arrow + "\n"
            "      </summary>\n"
            "      " + plugins_list + "\n"
            "    </details>"
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
            + h_str + '%" title="Step '
            + str(step) + ": +" + str(gained)
            + ' entities">'
            '<span class="tooltip">Step '
            + str(step) + ": +" + str(gained)
            + " entities</span></div>"
        )
    bars_html = "".join(bars_parts)

    # Imp 1: Gap trajectory SVG polyline
    gap_counts = [s.get("gaps", 0) for s in history]
    max_gap = max(gap_counts) if gap_counts else 1
    max_gap = max(max_gap, 1)
    n_points = len(gap_counts)
    svg_w = 600
    svg_h = 36
    gap_points: list[str] = []
    for i, g in enumerate(gap_counts):
        x = int(i / max(n_points - 1, 1) * (svg_w - 4)) + 2
        y = svg_h - 2 - int(g / max_gap * (svg_h - 4))
        gap_points.append(str(x) + "," + str(y))
    polyline = " ".join(gap_points)
    final_gap = gap_counts[-1] if gap_counts else 0
    gap_svg = (
        '<div class="growth-gap-line">\n'
        '  <span class="gap-label">Gaps ('
        + str(final_gap) + " remaining)</span>\n"
        '  <svg width="100%" height="' + str(svg_h)
        + '" viewBox="0 0 ' + str(svg_w) + " " + str(svg_h)
        + '" preserveAspectRatio="none" role="img">\n'
        "    <title>Gap trajectory chart showing remaining gaps"
        " over scan steps</title>\n"
        '    <polyline points="' + polyline + '" fill="none"'
        ' stroke="var(--neon-orange)" stroke-width="2"'
        ' stroke-linejoin="round"/>\n'
        "  </svg>\n"
        "</div>\n"
    )

    # Imp 5: Entity gain velocity SVG with peak/saturation markers
    gains = [s.get("entities_gained", 0) for s in history]
    peak_gain = max(gains) if gains else 0
    peak_idx = gains.index(peak_gain) if gains else 0
    sat_idx = len(gains) - 1
    if peak_gain > 0:
        threshold = peak_gain * 0.05
        for si in range(peak_idx + 1, len(gains)):
            if gains[si] < threshold:
                sat_idx = si
                break
    n_gain_pts = len(gains)
    gv_w = 600
    gv_h = 40
    max_gain_val = max(peak_gain, 1)
    gv_points: list[str] = []
    for gi, gval in enumerate(gains):
        gx = int(gi / max(n_gain_pts - 1, 1) * (gv_w - 4)) + 2
        gy = gv_h - 2 - int(gval / max_gain_val * (gv_h - 4))
        gv_points.append(str(gx) + "," + str(gy))
    gv_polyline = " ".join(gv_points)
    # Peak marker
    peak_x = int(peak_idx / max(n_gain_pts - 1, 1) * (gv_w - 4)) + 2
    peak_y = gv_h - 2 - int(peak_gain / max_gain_val * (gv_h - 4))
    peak_marker = (
        '<circle cx="' + str(peak_x) + '" cy="' + str(peak_y)
        + '" r="4" fill="var(--neon-green)"'
        ' title="Peak: +' + str(peak_gain) + '"/>'
    )
    # Saturation marker
    sat_x = int(sat_idx / max(n_gain_pts - 1, 1) * (gv_w - 4)) + 2
    sat_gain = gains[sat_idx] if sat_idx < len(gains) else 0
    sat_y = gv_h - 2 - int(sat_gain / max_gain_val * (gv_h - 4))
    sat_marker = (
        '<circle cx="' + str(sat_x) + '" cy="' + str(sat_y)
        + '" r="4" fill="var(--neon-orange)"'
        ' title="Saturation: +' + str(sat_gain) + '"/>'
    )
    velocity_svg = (
        '<div class="gain-velocity">\n'
        '  <span class="gain-label">Entity gain velocity'
        ' (peak: +' + str(peak_gain) + ' at step '
        + str(history[peak_idx].get("step", peak_idx))
        + ')</span>\n'
        '  <svg width="100%" height="' + str(gv_h)
        + '" viewBox="0 0 ' + str(gv_w) + " " + str(gv_h)
        + '" preserveAspectRatio="none" role="img">\n'
        "    <title>Entity gain velocity chart showing"
        " discovery rate per step</title>\n"
        '    <polyline points="' + gv_polyline + '" fill="none"'
        ' stroke="var(--neon-cyan)" stroke-width="2"'
        ' stroke-linejoin="round"/>\n'
        '    ' + peak_marker + '\n'
        '    ' + sat_marker + '\n'
        '  </svg>\n'
        '</div>\n'
    )

    # Imp 8: Step history summary text
    first = history[0]
    last = history[-1]
    first_ent = first.get("entities", 0)
    last_ent = last.get("entities", 0)
    last_rel = last.get("relations", 0)
    first_step = first.get("step", 1)
    last_step = last.get("step", len(history))
    delta = last_ent - first_ent
    summary_line = (
        '<div class="growth-summary">'
        "Step <span>" + str(first_step) + "</span>: "
        + str(first_ent) + " entities &rarr; "
        "Step <span>" + str(last_step) + "</span>: "
        + str(last_ent) + " entities"
        " (+" + str(delta) + "). "
        "Relations: <span>" + str(last_rel) + "</span>. "
        "Remaining gaps: <span>" + str(final_gap)
        + "</span>.</div>\n"
    )

    return (
        '<div class="section" id="kg-growth">\n'
        '  <div class="section-title">'
        "Knowledge Graph Growth</div>\n"
        '  <div class="growth-chart">'
        + bars_html + "</div>\n"
        + gap_svg
        + velocity_svg
        + summary_line
        + "</div>"
    )


def _findings_html(data: dict) -> str:
    findings = data.get("findings", [])
    sev_counts = data.get("summary", {}).get("severity_counts", {})

    chip_parts: list[str] = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        cnt = sev_counts.get(sev, 0)
        chip_parts.append(
            '<button class="filter-chip active" aria-pressed="true"'
            ' data-sev="'
            + sev + '" onclick="toggleFilter(this)">'
            + sev + " (" + str(cnt) + ")</button>"
        )
    chips = "".join(chip_parts)

    card_parts: list[str] = []
    for idx, f in enumerate(findings):
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

        conf_attr = _fmt(conf, ".2f")
        card_parts.append(
            '<details class="finding-card" id="finding-'
            + str(idx) + '" data-sev="'
            + sev + '" data-conf="'
            + conf_attr + '" data-host="'
            + host + '" data-step="'
            + str(step) + '">\n'
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

    total_count = len(findings)

    # Imp 1: Cumulative findings curve SVG
    cum_findings_html = ""
    if findings:
        # Group findings by step
        step_sevs: dict[int, list[str]] = {}
        for f in findings:
            fs = f.get("step", 0)
            step_sevs.setdefault(fs, []).append(
                f.get("severity", "INFO").upper()
            )
        sorted_steps = sorted(step_sevs.keys())
        cum_count = 0
        cum_data: list[tuple[int, int, str]] = []  # (step, cumulative, dominant_sev)
        sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        for st in sorted_steps:
            sevs = step_sevs[st]
            cum_count += len(sevs)
            dom = max(sevs, key=lambda s: sev_rank.get(s, 0))
            cum_data.append((st, cum_count, dom))

        if cum_data:
            cf_w = 600
            cf_h = 50
            max_cum = cum_data[-1][1]
            max_cum = max(max_cum, 1)
            max_st = max(d[0] for d in cum_data)
            max_st = max(max_st, 1)
            cf_sev_colors = {
                "CRITICAL": "var(--critical)", "HIGH": "var(--high)",
                "MEDIUM": "var(--medium)", "LOW": "var(--low)",
                "INFO": "var(--info)",
            }
            # Build line segments colored by dominant severity
            cf_segments: list[str] = []
            cf_dots: list[str] = []
            prev_x = prev_y = None
            for cd_step, cd_cum, cd_sev in cum_data:
                cx = int(cd_step / max_st * (cf_w - 4)) + 2
                cy = cf_h - 2 - int(cd_cum / max_cum * (cf_h - 6))
                color = cf_sev_colors.get(cd_sev, "var(--fg-dim)")
                if prev_x is not None:
                    cf_segments.append(
                        '<line x1="' + str(prev_x) + '" y1="'
                        + str(prev_y) + '" x2="' + str(cx)
                        + '" y2="' + str(cy) + '" stroke="'
                        + color + '" stroke-width="2"/>'
                    )
                cf_dots.append(
                    '<circle cx="' + str(cx) + '" cy="' + str(cy)
                    + '" r="3" fill="' + color
                    + '" title="Step ' + str(cd_step) + ": "
                    + str(cd_cum) + ' total"/>'
                )
                prev_x, prev_y = cx, cy

            cum_findings_html = (
                '<div class="cum-findings">\n'
                '  <span class="cum-label">Cumulative Findings ('
                + str(max_cum) + ' total)</span>\n'
                '  <svg width="100%" height="' + str(cf_h)
                + '" viewBox="0 0 ' + str(cf_w) + " " + str(cf_h)
                + '" preserveAspectRatio="none" role="img">\n'
                "    <title>Cumulative findings chart showing"
                " total discoveries over time</title>\n"
                + "".join(cf_segments)
                + "".join(cf_dots)
                + "\n  </svg>\n"
                "</div>\n"
            )

    # Imp 6: Severity discovery timeline dots
    sev_timeline_html = ""
    if findings:
        sev_color_map = {
            "CRITICAL": "var(--critical)", "HIGH": "var(--high)",
            "MEDIUM": "var(--medium)", "LOW": "var(--low)",
            "INFO": "var(--info)",
        }
        max_step = max((f.get("step", 0) for f in findings), default=1)
        max_step = max(max_step, 1)
        dot_parts: list[str] = []
        for f in findings:
            fs = f.get("severity", "INFO").upper()
            fstep = f.get("step", 0)
            left_pct = _fmt(fstep / max_step * 95 + 2.5, ".1f")
            color = sev_color_map.get(fs, "var(--fg-dim)")
            dot_parts.append(
                '<div class="sev-dot" title="'
                + _e(f.get("title", "")) + " (step "
                + str(fstep) + ')" style="left:'
                + left_pct + "%;background:"
                + color + '"></div>'
            )
        sev_timeline_html = (
            '<div class="sev-timeline">\n'
            '  <span class="stl-label">'
            "Severity Timeline</span>\n"
            + "".join(dot_parts)
            + "\n</div>\n"
        )

    # Imp 4: Findings-by-host top 5
    host_bar_html = ""
    if findings:
        host_counts: dict[str, int] = {}
        for f in findings:
            h = f.get("host", "unknown")
            host_counts[h] = host_counts.get(h, 0) + 1
        sorted_hosts = sorted(host_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        if sorted_hosts:
            host_max = sorted_hosts[0][1]
            bar_items: list[str] = []
            for h, cnt in sorted_hosts:
                w_pct = _fmt(cnt / host_max * 100, ".0f")
                bar_items.append(
                    '<div class="fhb-item"'
                    ' onclick="filterByHost(\''
                    + _e(h).replace("'", "\\'") + "')\">\n"
                    '  <span class="fhb-label"'
                    ' title="' + _e(h) + '">' + _e(h) + "</span>\n"
                    '  <span class="fhb-bar"'
                    ' style="width:' + w_pct + '%"></span>\n'
                    '  <span class="fhb-count">' + str(cnt) + "</span>\n"
                    "</div>"
                )
            host_bar_html = (
                '<div class="findings-host-bar">\n'
                '  <span class="fhb-title">Top hosts by findings</span>\n'
                + "".join(bar_items)
                + "\n</div>\n"
            )

    return (
        '<div class="section" id="findings">\n'
        '  <div class="section-title">'
        "Findings (War Board)</div>\n"
        + cum_findings_html
        + sev_timeline_html
        + host_bar_html
        + '  <div class="filter-bar">\n'
        "    " + chips + "\n"
        '    <input type="text" class="search-box"'
        ' aria-label="Search findings"'
        ' placeholder="Search findings..."'
        ' oninput="applyFilters()">\n'
        '    <select class="sort-select"'
        ' aria-label="Sort findings"'
        ' onchange="sortFindings(this.value)">\n'
        '      <option value="discovery">Discovery Order</option>\n'
        '      <option value="severity">Severity</option>\n'
        '      <option value="confidence">Confidence</option>\n'
        '      <option value="host">Host</option>\n'
        "    </select>\n"
        '    <span class="findings-stats">Showing '
        '<span id="findings-visible">'
        + str(total_count) + "</span>"
        " of " + str(total_count) + "</span>\n"
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
        conf_val = v.get("confidence_aggregate", 0)
        conf = _fmt(conf_val * 100, ".0f") + "%"
        # Inline SVG confidence gauge
        circ = 2 * 3.14159 * 8  # circumference for r=8
        dash = _fmt(conf_val * circ, ".1f")
        gap = _fmt(circ, ".1f")
        gauge_color = (
            "var(--neon-green)" if conf_val >= 0.8
            else ("var(--medium)" if conf_val >= 0.5
                  else "var(--critical)")
        )
        gauge_svg = (
            '<svg class="conf-gauge" width="20" height="20"'
            ' viewBox="0 0 20 20" role="img">'
            "<title>Confidence: " + conf + "</title>"
            '<circle cx="10" cy="10" r="8"'
            ' fill="none" stroke="var(--surface-3)"'
            ' stroke-width="3"/>'
            '<circle cx="10" cy="10" r="8"'
            ' fill="none" stroke="' + gauge_color + '"'
            ' stroke-width="3"'
            ' stroke-dasharray="' + dash + " " + gap + '"'
            ' transform="rotate(-90 10 10)"/>'
            "</svg>"
        )
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
            "  <td>" + gauge_svg + conf + "</td>\n"
            "  <td>" + scenarios + "</td>\n"
            '  <td style="max-width:200px;overflow:hidden;'
            'text-overflow:ellipsis;white-space:nowrap"'
            ' title="' + proof_preview + '">'
            + proof_preview + "</td>\n"
            "</tr>" + repro_html
        )

    rows = "".join(row_parts)

    # Severity mini-bar
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sev_colors = {
        "CRITICAL": "var(--critical)", "HIGH": "var(--high)",
        "MEDIUM": "var(--medium)", "LOW": "var(--low)",
        "INFO": "var(--info)",
    }
    sev_counts: dict[str, int] = {}
    for v in vulns:
        s = v.get("severity", "INFO").upper()
        sev_counts[s] = sev_counts.get(s, 0) + 1
    total_vulns = len(vulns)
    seg_parts: list[str] = []
    for s in sev_order:
        cnt = sev_counts.get(s, 0)
        if cnt > 0:
            pct = _fmt(cnt / total_vulns * 100, ".1f")
            seg_parts.append(
                '<div class="seg" style="width:' + pct
                + "%;background:" + sev_colors.get(s, "var(--fg-dim)")
                + '" title="' + s + ": " + str(cnt) + '"></div>'
            )
    sev_bar_html = (
        '  <div class="severity-bar vuln-sev-bar">'
        + "".join(seg_parts) + "</div>\n"
    )

    return (
        '<div class="section" id="vulnerabilities">\n'
        '  <div class="section-title">'
        "Vulnerabilities (Deduplicated)</div>\n"
        + sev_bar_html
        + '  <table class="perf-table sortable">\n'
        "    <caption>Deduplicated vulnerabilities</caption>\n"
        "    <thead><tr>"
        '<th scope="col">Severity</th><th scope="col">Type</th>'
        '<th scope="col">Affected Surfaces</th><th scope="col">Confidence</th>'
        '<th scope="col">Scenarios</th><th scope="col">Proof</th>'
        "</tr></thead>\n"
        "    <tbody>" + rows + "</tbody>\n"
        "  </table>\n"
        "</div>"
    )


def _decisions_html(data: dict) -> str:
    decisions = data.get("decisions", [])

    # Imp 2: Decision summary stats banner
    stats_banner = ""
    if decisions:
        prod_count = sum(1 for d in decisions if d.get("productive", False))
        total_dec = len(decisions)
        prod_pct = prod_count / total_dec * 100 if total_dec > 0 else 0
        prod_color = "green" if prod_pct >= 50 else "red"

        scores = [d.get("score", 0) for d in decisions]
        avg_score = sum(scores) / len(scores) if scores else 0

        total_ent_gained = sum(d.get("new_entities", 0) for d in decisions)

        durations = [d.get("duration", 0) or 0 for d in decisions]
        total_dur = sum(durations)
        dur_mins = int(total_dur // 60)
        dur_secs = int(total_dur % 60)
        dur_str = str(dur_mins) + "m " + str(dur_secs) + "s"

        plugin_prod: dict[str, int] = {}
        for d in decisions:
            if d.get("productive", False):
                p = d.get("plugin", "unknown")
                plugin_prod[p] = plugin_prod.get(p, 0) + 1
        top_plugin = max(plugin_prod, key=plugin_prod.get) if plugin_prod else "\u2014"

        stats_banner = (
            '  <div class="metrics-grid decision-stats">\n'
            '    <div class="metric-card">'
            '<div class="metric-value ' + prod_color + '">'
            + _fmt(prod_pct, ".0f") + '%</div>'
            '<div class="metric-label">Productive</div></div>\n'
            '    <div class="metric-card">'
            '<div class="metric-value">'
            + _fmt(avg_score, ".3f") + '</div>'
            '<div class="metric-label">Avg Score</div></div>\n'
            '    <div class="metric-card">'
            '<div class="metric-value">'
            + str(total_ent_gained) + '</div>'
            '<div class="metric-label">Entities Gained</div></div>\n'
            '    <div class="metric-card">'
            '<div class="metric-value">'
            + dur_str + '</div>'
            '<div class="metric-label">Total Duration</div></div>\n'
            '    <div class="metric-card">'
            '<div class="metric-value" style="font-size:var(--text-sm)">'
            + _e(top_plugin) + '</div>'
            '<div class="metric-label">Top Plugin</div></div>\n'
            "  </div>\n"
        )

    # Imp 3: Gap type distribution bars
    gap_dist_html = ""
    if decisions:
        gap_pattern = re.compile(r"^Gap:\s*(.+?)\.\s+Selected")
        gap_types: dict[str, int] = {}
        _gap_keywords = [
            (["no known services", "services"], "No Services"),
            (["no dns", "dns records"], "No DNS"),
            (["no technology", "technology"], "No Technology"),
            (["no endpoints", "endpoints"], "No Endpoints"),
            (["vulnerability", "vuln testing", "vuln_test"], "Vuln Testing"),
            (["verification", "verify", "confirm"], "Verification"),
            (["container", "docker"], "Containers"),
            (["credential", "cred"], "Credentials"),
            (["forms", "form detection"], "Form Detection"),
            (["version", "fingerprint"], "Version Detection"),
        ]
        for d in decisions:
            reason = d.get("reasoning", "")
            m = gap_pattern.match(reason)
            if m:
                gap_desc = m.group(1).lower()
                categorized = False
                for keywords, cat_name in _gap_keywords:
                    if any(kw in gap_desc for kw in keywords):
                        gap_types[cat_name] = gap_types.get(cat_name, 0) + 1
                        categorized = True
                        break
                if not categorized:
                    gap_types["Other"] = gap_types.get("Other", 0) + 1

        if gap_types:
            sorted_gaps = sorted(gap_types.items(), key=lambda x: x[1], reverse=True)[:8]
            gap_max = sorted_gaps[0][1] if sorted_gaps else 1
            gap_bar_items: list[str] = []
            for gap_name, gap_cnt in sorted_gaps:
                gw = _fmt(gap_cnt / gap_max * 100, ".0f")
                gap_bar_items.append(
                    '<div class="gap-bar-row">\n'
                    '  <span class="gap-bar-label">'
                    + _e(gap_name) + "</span>\n"
                    '  <span class="gap-bar-fill"'
                    ' style="width:' + gw + '%"></span>\n'
                    '  <span class="gap-bar-count">'
                    + str(gap_cnt) + "</span>\n"
                    "</div>"
                )
            gap_dist_html = (
                '  <div class="gap-dist">\n'
                '    <div class="gap-dist-title">'
                "Gap type distribution</div>\n"
                + "".join(gap_bar_items)
                + "\n  </div>\n"
            )

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
        # Split into productive and unproductive groups
        productive_parts: list[str] = []
        unproductive_parts: list[str] = []
        for i, d in enumerate(decisions):
            part = item_parts[i]
            if d.get("productive", False):
                productive_parts.append(part)
            else:
                unproductive_parts.append(part)

        items = ""
        if productive_parts:
            items += "".join(productive_parts)
        if unproductive_parts:
            unprod_label = (
                str(len(unproductive_parts))
                + " unproductive decision"
                + ("s" if len(unproductive_parts) != 1 else "")
            )
            items += (
                '<details id="decisions-unproductive">\n'
                '<summary class="decisions-show-more">'
                + unprod_label + "</summary>\n"
                + "".join(unproductive_parts)
                + "\n</details>"
            )

    return (
        '<div class="section" id="decisions">\n'
        '  <div class="section-title">'
        "Decision Timeline</div>\n"
        + stats_banner
        + gap_dist_html
        + '  <div class="timeline">' + items + "</div>\n"
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
            + bar_w + "%;background:var(" + color + ')"'
            ' title="' + str(count) + " (" + bar_w + '%)">'
            "</div>\n"
            "  </div>\n"
            "</div>"
        )

    cards = "".join(card_parts)

    # Imp 6: Subdomain discovery stats
    subdomain_html = ""
    topology = data.get("topology", {})
    if topology:
        findings_hosts = {
            f.get("host", "") for f in data.get("findings", [])
        }
        root_count = 0
        sub_count = 0
        examined = 0
        for host_name, topo in topology.items():
            is_sub = topo.get("is_subdomain", False)
            if is_sub:
                sub_count += 1
            else:
                root_count += 1
            # Examined = has services or has findings
            has_svcs = bool(topo.get("services"))
            if has_svcs or host_name in findings_hosts:
                examined += 1
        total_hosts = root_count + sub_count
        exam_pct = (
            _fmt(examined / total_hosts * 100, ".0f")
            if total_hosts > 0 else "0"
        )
        subdomain_html = (
            '  <div class="subdomain-summary">\n'
            '    <span class="sub-stat">'
            '<span>' + str(root_count) + '</span> root hosts</span>\n'
            '    <span class="sub-stat">'
            '<span>' + str(sub_count) + '</span> subdomains</span>\n'
            '    <span class="sub-stat sub-explored">'
            '<span>' + exam_pct + '%</span> examined</span>\n'
            '  </div>\n'
        )

    return (
        '<div class="section" id="attack-surface">\n'
        '  <div class="section-title">'
        "Attack Surface</div>\n"
        + subdomain_html
        + '  <div class="surface-stats-grid">\n'
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


def _endpoint_base_url(host: str, services: list[dict]) -> str:
    """Build the best base URL for a host from its services list.

    Prefers https over http, includes non-standard ports.
    Falls back to ``https://<host>`` when no services are known.
    """
    https_port: int | None = None
    http_port: int | None = None
    for svc in services:
        name = str(svc.get("service", "")).lower().strip()
        port = svc.get("port", 0)
        if name in ("https", "https-alt") and https_port is None:
            https_port = port
        elif name in ("http", "http-proxy") and http_port is None:
            http_port = port

    if https_port is not None:
        suffix = "" if https_port == 443 else ":" + str(https_port)
        return "https://" + host + suffix
    if http_port is not None:
        suffix = "" if http_port == 80 else ":" + str(http_port)
        return "http://" + host + suffix
    return "https://" + host


def _endpoint_link(path: str, base_url: str) -> str:
    """Render an endpoint path as a clickable ``<a>`` element."""
    safe_path = _e(path)
    href = _e(base_url + path)
    return (
        '<a href="' + href + '" target="_blank"'
        ' rel="noopener" style="color:var(--neon-cyan);'
        'text-decoration:none">' + safe_path + "</a>"
    )


_INTERESTING_PREFIXES = frozenset({
    "api", "admin", "auth", "login", "logout", "register", "signup",
    "graphql", "swagger", "openapi", "debug", "console", "config",
    "internal", "private", "secret", "token", "oauth", "callback",
    "webhook", "upload", "download", "export", "import", "backup",
    "dashboard", "panel", "manage", "reset", "verify", "confirm",
    ".env", ".git", "wp-admin", "wp-login", "phpmyadmin", "actuator",
})

_INTERESTING_EXTENSIONS = frozenset({
    ".json", ".yaml", ".yml", ".xml", ".env", ".bak", ".sql", ".log",
    ".conf", ".cfg", ".ini", ".php", ".asp", ".aspx", ".jsp",
})


def _is_interesting_endpoint(path: str) -> bool:
    """Return True if path looks security-relevant."""
    low = path.lower().lstrip("/")
    first_seg = low.split("/")[0] if "/" in low else low
    if first_seg in _INTERESTING_PREFIXES:
        return True
    for prefix in _INTERESTING_PREFIXES:
        if first_seg.startswith(prefix):
            return True
    return any(low.endswith(ext) for ext in _INTERESTING_EXTENSIONS)


def _endpoint_tree_html(endpoints: list[str], base_url: str) -> str:
    """Build a grouped tree of endpoints with clickable links.

    Groups by first path segment; interesting groups are expanded.
    """
    # Group by first segment
    groups: dict[str, list[str]] = {}
    root_files: list[str] = []
    for ep in endpoints:
        stripped = ep.lstrip("/")
        if "/" in stripped:
            seg = stripped.split("/", 1)[0]
            groups.setdefault(seg, []).append(ep)
        else:
            root_files.append(ep)

    parts: list[str] = []

    # Root-level files first (always shown)
    interesting_root: list[str] = []
    boring_root: list[str] = []
    for f in root_files:
        if _is_interesting_endpoint(f):
            interesting_root.append(f)
        else:
            boring_root.append(f)

    for f in interesting_root:
        parts.append("<div>" + _endpoint_link(f, base_url) + "</div>")

    if boring_root:
        if len(boring_root) <= 3:
            for f in boring_root:
                parts.append("<div>" + _endpoint_link(f, base_url) + "</div>")
        else:
            items = "".join(
                "<div>" + _endpoint_link(f, base_url) + "</div>"
                for f in boring_root
            )
            parts.append(
                '<details class="nm-endpoints-toggle">'
                "<summary>/" + " (" + str(len(boring_root))
                + " files)</summary>"
                '<div class="nm-endpoints-list">'
                + items + "</div></details>"
            )

    # Sorted groups
    sorted_groups = sorted(groups.items(), key=lambda x: (
        0 if _is_interesting_endpoint("/" + x[0]) else 1, x[0],
    ))

    for seg, paths in sorted_groups:
        interesting = _is_interesting_endpoint("/" + seg)
        count = len(paths)
        items = "".join(
            "<div>" + _endpoint_link(p, base_url) + "</div>"
            for p in paths
        )
        if count <= 3:
            # Inline, no toggle needed
            parts.append(items)
        else:
            open_attr = " open" if interesting else ""
            parts.append(
                '<details class="nm-endpoints-toggle"'
                + open_attr + ">"
                "<summary>/" + _e(seg) + "/ ("
                + str(count) + ")</summary>"
                '<div class="nm-endpoints-list">'
                + items + "</div></details>"
            )

    return '<div class="nm-endpoints">' + "".join(parts) + "</div>"


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
                '<button class="filter-chip active" aria-pressed="true"'
                ' data-sev="'
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
        ' aria-label="Filter hosts"'
        ' placeholder="Filter hosts..."'
        ' oninput="applyHostFilters()">\n'
    )

    # Search result counter
    counter_html = (
        '<div class="nm-search-status">Showing '
        '<span id="nm-visible">' + str(total_hosts) + "</span>"
        " of " + str(total_hosts) + " hosts</div>\n"
    )

    # Split hosts into rich (have data) and empty
    def _is_rich(host_name: str, topo: dict) -> bool:
        if topo.get("services"):
            return True
        if topo.get("endpoints"):
            return True
        if findings_count_by_host.get(host_name, 0) > 0:
            return True
        return bool(topo.get("technologies"))

    rich_ordered = [(h, t) for h, t in ordered if _is_rich(h, t)]
    empty_ordered = [(h, t) for h, t in ordered if not _is_rich(h, t)]

    # Build cards (rich hosts only)
    cards: list[str] = []
    for host_name, topo in rich_ordered:
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

        # Endpoints: grouped tree with clickable links
        endpoints_html = ""
        eps = topo.get("endpoints", [])
        if eps:
            base_url = _endpoint_base_url(host_name, svcs)
            endpoints_html = _endpoint_tree_html(eps, base_url)

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
        "<caption>Network hosts (compact view)</caption>\n"
        "<thead><tr>"
        '<th scope="col">Host</th><th scope="col">Risk</th>'
        '<th scope="col">Severity</th>'
        '<th scope="col">Findings</th><th scope="col">Services</th>'
        '<th scope="col">Technologies</th>'
        "</tr></thead>\n"
        "<tbody>" + "".join(compact_rows) + "</tbody>\n"
        "</table>\n"
    )

    # Filter indicator
    filter_indicator_html = (
        '<div class="nm-filter-indicator"'
        ' id="nm-filter-indicator"></div>\n'
    )

    # Empty hosts collapsed section
    empty_hosts_html = ""
    if empty_ordered:
        chip_parts: list[str] = []
        for h, _t in empty_ordered:
            chip_parts.append(
                '<span class="nm-empty-chip">' + _e(h) + "</span>"
            )
        empty_hosts_html = (
            '<details class="nm-empty-section">\n'
            "  <summary>" + str(len(empty_ordered))
            + " host" + ("s" if len(empty_ordered) != 1 else "")
            + " with no data</summary>\n"
            '  <div class="nm-empty-grid">'
            + "".join(chip_parts) + "</div>\n"
            "</details>\n"
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
        + empty_hosts_html
        + compact_table_html
        + '  <div class="nm-no-matches" id="nm-no-matches">'
        "No hosts match your search</div>\n"
        + kb_hint_html
        + "</div>"
    )


def _plugin_perf_html(data: dict) -> str:
    plugins = data.get("plugins", [])
    findings = data.get("findings", [])

    # Imp 4: Build step→plugin mapping and attribute findings to plugins
    step_plugin: dict[int, str] = {}
    for p in plugins:
        step_plugin[p.get("step", -1)] = p.get("name", "")
    plugin_sevs: dict[str, dict[str, int]] = {}
    for f in findings:
        fstep = f.get("step", -1)
        pname = step_plugin.get(fstep, "")
        if pname:
            if pname not in plugin_sevs:
                plugin_sevs[pname] = {}
            fs = f.get("severity", "INFO").upper()
            plugin_sevs[pname][fs] = plugin_sevs[pname].get(fs, 0) + 1

    row_parts: list[str] = []
    max_findings = max((p.get("findings_count", 0) for p in plugins), default=0)
    for p in plugins:
        name = _e(p.get("name", ""))
        raw_name = p.get("name", "")
        target = _e(p.get("target", ""))
        dur_val = p.get("duration", 0)
        dur = _fmt(dur_val, ".2f")
        fc = p.get("findings_count", 0)
        step = p.get("step", 0)
        fc_style = (
            " style=\"color:var(--neon-green);font-weight:600\""
            if fc > 0
            else ""
        )
        top_class = " class=\"perf-top\"" if fc > 0 and fc == max_findings else ""

        # Imp 3: Efficiency = findings per minute
        if dur_val > 0:
            eff = fc / (dur_val / 60)
            eff_str = _fmt(eff, ".1f")
        else:
            eff_str = "\u2014"

        # Imp 4: Severity breakdown badges
        sev_badges = ""
        psev = plugin_sevs.get(raw_name, {})
        if psev:
            badge_parts: list[str] = []
            for sv in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                sc = psev.get(sv, 0)
                if sc > 0:
                    short = sv[0]
                    badge_parts.append(
                        '<span class="psev-dot psev-' + sv + '">'
                        + str(sc) + short + "</span>"
                    )
            sev_badges = "".join(badge_parts)

        row_parts.append(
            "<tr>\n"
            "  <td" + top_class + ">" + name + "</td>"
            "<td>" + target + "</td>"
            "<td>" + dur + "s</td>\n"
            "  <td" + fc_style + ">"
            + str(fc) + "</td>"
            '<td class="plugin-sev-cell">' + sev_badges + "</td>"
            "<td>" + eff_str + "</td>"
            "<td>" + str(step) + "</td>\n"
            "</tr>"
        )

    # Imp 3: Summary row
    summary_row = ""
    if plugins:
        total_findings = sum(p.get("findings_count", 0) for p in plugins)
        total_dur = sum(p.get("duration", 0) for p in plugins)
        total_dur_str = _fmt(total_dur, ".1f")
        overall_rate = (
            _fmt(total_findings / (total_dur / 60), ".1f") if total_dur > 0 else "\u2014"
        )
        summary_row = (
            '<tr class="perf-summary">'
            "<td>Total</td><td></td>"
            "<td>" + total_dur_str + "s</td>"
            "<td>" + str(total_findings) + "</td>"
            "<td></td><td>" + overall_rate + "</td>"
            "<td></td></tr>"
        )

    if not plugins:
        rows = (
            '<tr><td colspan="7" style="color:var(--fg-dim)">'
            "No plugins executed yet</td></tr>"
        )
    else:
        rows = "".join(row_parts) + summary_row

    # Imp 8: Execution cost distribution stacked bar
    cost_dist_html = ""
    if plugins:
        plugin_durations: dict[str, float] = {}
        for p in plugins:
            pn = p.get("name", "unknown")
            plugin_durations[pn] = plugin_durations.get(pn, 0) + p.get("duration", 0)
        sorted_costs = sorted(
            plugin_durations.items(), key=lambda x: x[1], reverse=True,
        )[:10]
        total_cost = sum(d for _, d in sorted_costs)
        if total_cost > 0:
            _cost_colors = [
                "#4d7cff", "#00e5ff", "#00ff6a", "#b44dff", "#ff8a00",
                "#ffe100", "#ff2d7b", "#ff6b35", "#ff1744", "#6d7a94",
            ]
            seg_parts: list[str] = []
            legend_parts: list[str] = []
            outlier_html = ""
            for ci, (cn, cd) in enumerate(sorted_costs):
                c_pct = cd / total_cost * 100
                c_color = _cost_colors[ci % len(_cost_colors)]
                seg_parts.append(
                    '<div class="cost-seg" style="width:'
                    + _fmt(c_pct, ".1f") + "%;background:"
                    + c_color + '" title="' + _e(cn) + ": "
                    + _fmt(cd, ".1f") + 's"></div>'
                )
                legend_parts.append(
                    '<span class="cost-legend-item">'
                    '<span class="cost-swatch" style="background:'
                    + c_color + '"></span>'
                    + _e(cn) + " (" + _fmt(c_pct, ".0f")
                    + "%)</span>"
                )
                if ci == 0 and c_pct > 50:
                    outlier_html = (
                        '<div class="cost-outlier">'
                        "Outlier: " + _e(cn) + " consumed "
                        + _fmt(c_pct, ".0f")
                        + "% of total runtime</div>"
                    )
            cost_dist_html = (
                '<div class="cost-dist">\n'
                '  <div class="cost-dist-title">'
                "Runtime cost distribution</div>\n"
                '  <div class="cost-dist-bar">'
                + "".join(seg_parts) + "</div>\n"
                '  <div class="cost-dist-legend">'
                + "".join(legend_parts) + "</div>\n"
                + outlier_html
                + "\n</div>\n"
            )

    return (
        '<div class="section" id="plugins">\n'
        '  <div class="section-title">'
        "Plugin Performance</div>\n"
        '  <table class="perf-table sortable">\n'
        "    <caption>Plugin execution performance</caption>\n"
        "    <thead><tr>"
        '<th scope="col">Plugin</th><th scope="col">Target</th>'
        '<th scope="col">Duration</th><th scope="col">Findings</th>'
        '<th scope="col">Sev.</th>'
        '<th scope="col">Eff.</th>'
        '<th scope="col">Step</th>'
        "</tr></thead>\n"
        "    <tbody>" + rows + "</tbody>\n"
        "  </table>\n"
        + cost_dist_html
        + "</div>"
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

            # Imp 7: Extract hypothesis as primary text (fallback to statement key)
            hypothesis = _e(
                str(edata.get("hypothesis", "") or edata.get("statement", ""))
            )
            detail_parts: list[str] = []
            for k, v in edata.items():
                if k in ("hypothesis", "statement", "hypothesis_id"):
                    continue
                detail_parts.append(_e(str(k)) + ": " + _e(str(v)))
            detail = " &middot; ".join(detail_parts) if detail_parts else ""

            hypothesis_html = (
                '  <div class="re-hypothesis">'
                + hypothesis + "</div>\n"
                if hypothesis
                else ""
            )

            event_parts.append(
                '<div class="reasoning-event" style="border-left:3px solid'
                " var(--" + color + ');">\n'
                '  <span class="re-type">' + etype + "</span>\n"
                '  <span class="re-step">step '
                + str(estep) + "</span>\n"
                + hypothesis_html
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

    # Imp 7: Hypothesis category breakdown
    hyp_cats_html = ""
    if events:
        _hyp_cat_keywords = [
            (["spring", "django", "rails", "flask", "express",
              "laravel", "react", "angular", "vue", "framework",
              "wordpress", "joomla", "drupal"], "Framework Detection"),
            (["systematic", "vulnerability", "vuln", "injection",
              "xss", "sqli", "csrf"], "Systematic Vulnerabilities"),
            (["shodan", "wayback", "dns", "asn", "whois",
              "external", "osint", "intelligence", "cert"], "External Intelligence"),
            (["waf", "firewall", "cloudflare", "akamai",
              "security", "protection"], "Security Controls"),
        ]
        cat_groups: dict[str, list[tuple[str, str]]] = {}  # cat -> [(stmt, status)]
        for ev in events:
            etype = ev.get("type", "")
            edata = ev.get("data", {})
            stmt = str(
                edata.get("hypothesis", "") or edata.get("statement", "")
            )
            if not stmt:
                continue
            status = "confirmed" if "confirmed" in etype else (
                "rejected" if "rejected" in etype else "active"
            )
            stmt_lower = stmt.lower()
            categorized = False
            for keywords, cat_name in _hyp_cat_keywords:
                if any(kw in stmt_lower for kw in keywords):
                    cat_groups.setdefault(cat_name, []).append((stmt, status))
                    categorized = True
                    break
            if not categorized:
                cat_groups.setdefault("Other", []).append((stmt, status))

        if cat_groups:
            cat_parts: list[str] = []
            for cat_name, items in cat_groups.items():
                item_htmls: list[str] = []
                for stmt, status in items:
                    item_htmls.append(
                        '<div class="hyp-cat-item ' + status + '">'
                        + _e(stmt) + "</div>"
                    )
                cat_parts.append(
                    '<div class="hyp-cat-group">\n'
                    '  <div class="hyp-cat-header">'
                    '<span class="hyp-cat-name">'
                    + _e(cat_name) + "</span>"
                    '<span class="hyp-cat-count">'
                    + str(len(items)) + "</span></div>\n"
                    + "".join(item_htmls)
                    + "\n</div>"
                )
            hyp_cats_html = (
                '<div class="hyp-categories">\n'
                + "".join(cat_parts)
                + "\n</div>\n"
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
        + hyp_cats_html
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
        step_html = (
            '<span class="step-badge">' + str(step) + "</span>"
            if step is not None
            else "-"
        )
        row_class = "training-row-yes" if disc else "training-row-no"
        row_parts.append(
            '<tr class="' + row_class + '"><td>' + title + "</td>"
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
        "    <caption>Expected findings validation</caption>\n"
        "    <thead><tr>"
        '<th scope="col">Expected Finding</th>'
        '<th scope="col">Severity</th>'
        '<th scope="col">Discovered</th>'
        '<th scope="col">Verified</th>'
        '<th scope="col">Step</th>'
        "</tr></thead>\n"
        "    <tbody>" + rows + "</tbody>\n"
        "  </table>\n"
        "</div>"
    )


def _footer_html(data: dict) -> str:
    ts = _e(data.get("timestamp", ""))
    v = _e(data.get("version", _VERSION))
    summary = data.get("summary", {})
    total_findings = summary.get("total_findings", 0)
    total_entities = summary.get("total_entities", 0)
    risk = summary.get("risk_score", 0)
    risk_str = _fmt(risk, ".1f")
    risk_color = "high" if risk >= 7.0 else ("medium" if risk >= 4.0 else "low")
    return (
        '<div class="footer">\n'
        '  <div class="footer-stats">\n'
        "    <span>Findings: <strong>"
        + str(total_findings) + "</strong></span>\n"
        '    <span>Risk: <strong class="risk-'
        + risk_color + '">' + risk_str + "</strong></span>\n"
        "    <span>Entities: <strong>"
        + str(total_entities) + "</strong></span>\n"
        "  </div>\n"
        '  <div class="footer-meta">\n'
        "    <span>Basilisk v" + v + "</span>\n"
        "    <span>" + ts + "</span>\n"
        "    <span>Confidential</span>\n"
        "  </div>\n"
        '  <button class="export-json-btn"'
        ' onclick="downloadJson()">Export JSON</button>\n'
        "</div>"
    )


# ---------------------------------------------------------------------------
# JavaScript (regular string — no f-string)
# ---------------------------------------------------------------------------

_JS = (
    "<script>\n"
    "function toggleFilter(btn) {\n"
    "  btn.classList.toggle('active');\n"
    "  btn.setAttribute('aria-pressed',"
    " btn.classList.contains('active'));\n"
    "  applyFilters();\n"
    "}\n"
    "\n"
    "function applyFilters() {\n"
    "  var active = [];\n"
    "  document.querySelectorAll('#findings .filter-chip.active')"
    ".forEach(function(c) {\n"
    "    active.push(c.dataset.sev);\n"
    "  });\n"
    "  var q = '';\n"
    "  var box = document.querySelector('.search-box');\n"
    "  if (box) q = box.value.toLowerCase();\n"
    "  var visible = 0;\n"
    "  document.querySelectorAll('.finding-card')"
    ".forEach(function(card) {\n"
    "    var sev = card.dataset.sev;\n"
    "    var text = card.textContent.toLowerCase();\n"
    "    var sevMatch = active.length === 0"
    " || active.indexOf(sev) !== -1;\n"
    "    var textMatch = !q || text.indexOf(q) !== -1;\n"
    "    var show = sevMatch && textMatch;\n"
    "    card.style.display = show ? '' : 'none';\n"
    "    if (show) visible++;\n"
    "  });\n"
    "  var counter = document.getElementById('findings-visible');\n"
    "  if (counter) counter.textContent = visible;\n"
    "}\n"
    "\n"
    "function toggleAll(open) {\n"
    "  document.querySelectorAll('.finding-card')"
    ".forEach(function(d) {\n"
    "    d.open = open;\n"
    "  });\n"
    "}\n"
    "\n"
    "function filterByHost(host) {\n"
    "  var box = document.querySelector('.search-box');\n"
    "  if (box) { box.value = host; }\n"
    "  applyFilters();\n"
    "}\n"
    "\n"
    "function sortFindings(criteria) {\n"
    "  var sevRank = {CRITICAL:4,HIGH:3,MEDIUM:2,LOW:1,INFO:0};\n"
    "  var list = document.getElementById('findings-list');\n"
    "  if (!list) return;\n"
    "  var cards = Array.from(list.querySelectorAll('.finding-card'));\n"
    "  cards.sort(function(a, b) {\n"
    "    if (criteria === 'severity') {\n"
    "      return (sevRank[b.dataset.sev]||0)"
    " - (sevRank[a.dataset.sev]||0);\n"
    "    } else if (criteria === 'confidence') {\n"
    "      return parseFloat(b.dataset.conf||0)"
    " - parseFloat(a.dataset.conf||0);\n"
    "    } else if (criteria === 'host') {\n"
    "      return (a.dataset.host||'')"
    ".localeCompare(b.dataset.host||'');\n"
    "    } else {\n"
    "      return parseInt(a.dataset.step||0)"
    " - parseInt(b.dataset.step||0);\n"
    "    }\n"
    "  });\n"
    "  cards.forEach(function(c) { list.appendChild(c); });\n"
    "}\n"
    "\n"
    "var obs = new IntersectionObserver(function(entries)"
    " {\n"
    "  entries.forEach(function(entry) {\n"
    "    if (entry.isIntersecting) {\n"
    "      var id = entry.target.id;\n"
    "      document.querySelectorAll('.sidebar nav a')"
    ".forEach(function(a) {\n"
    "        var match ="
    " a.getAttribute('href') === '#' + id;\n"
    "        a.classList.toggle('active', match);\n"
    "        if (match) a.setAttribute('aria-current', 'true');\n"
    "        else a.removeAttribute('aria-current');\n"
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
    "      var allRows ="
    " Array.from(tbody.querySelectorAll('tr'));\n"
    "      var asc ="
    " !th.classList.contains('sort-asc');\n"
    "      headers.forEach(function(h) {"
    " h.classList.remove('sort-asc', 'sort-desc'); });\n"
    "      th.classList.add("
    "asc ? 'sort-asc' : 'sort-desc');\n"
    "      var groups = [];\n"
    "      for (var i = 0; i < allRows.length; i++) {\n"
    "        if (allRows[i].classList.contains('repro-row'))"
    " continue;\n"
    "        var group = [allRows[i]];\n"
    "        var j = i + 1;\n"
    "        while (j < allRows.length"
    " && allRows[j].classList.contains('repro-row')) {\n"
    "          group.push(allRows[j]); j++;\n"
    "        }\n"
    "        groups.push(group);\n"
    "      }\n"
    "      groups.sort(function(a, b) {\n"
    "        var av = a[0].cells[idx].textContent.trim();\n"
    "        var bv = b[0].cells[idx].textContent.trim();\n"
    "        var an = parseFloat(av),"
    " bn = parseFloat(bv);\n"
    "        if (!isNaN(an) && !isNaN(bn))"
    " return asc ? an - bn : bn - an;\n"
    "        return asc ?"
    " av.localeCompare(bv) : bv.localeCompare(av);\n"
    "      });\n"
    "      groups.forEach(function(g) {"
    " g.forEach(function(r) {"
    " tbody.appendChild(r); }); });\n"
    "    });\n"
    "  });\n"
    "});\n"
    "\n"
    "document.querySelectorAll('.evidence-block')"
    ".forEach(function(block) {\n"
    "  var h = block.innerHTML;\n"
    "  h = h.replace(/(https?:\\/\\/[^\\s<&]+)/g,\n"
    "    '<a href=\"$1\" target=\"_blank\"'"
    " + ' rel=\"noopener\"'"
    " + ' style=\"color:var(--neon-cyan)\">$1</a>');\n"
    "  /* HTTP header highlighting */\n"
    "  h = h.replace("
    "/^(HTTP\\/[\\d.]+ \\d+ .*)$/gm,\n"
    "    '<span class=\"ev-status\">$1</span>');\n"
    "  h = h.replace("
    "/^([A-Z][A-Za-z0-9-]+)(: )/gm,\n"
    "    '<span class=\"ev-header-name\">$1</span>$2');\n"
    "  block.innerHTML = h;\n"
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
    "  btn.setAttribute('aria-pressed',"
    " btn.classList.contains('active'));\n"
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
    "    c.setAttribute('aria-pressed', 'true');\n"
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
    "\n"
    "function downloadJson() {\n"
    "  var blob = new Blob([JSON.stringify(DATA, null, 2)],"
    " {type: 'application/json'});\n"
    "  var a = document.createElement('a');\n"
    "  a.href = URL.createObjectURL(blob);\n"
    "  a.download = 'basilisk-report.json';\n"
    "  a.click();\n"
    "  URL.revokeObjectURL(a.href);\n"
    "}\n"
    "\n"
    "function toggleDecisions(btn) {\n"
    "  var el = document.getElementById('decisions-overflow');\n"
    "  if (!el) return;\n"
    "  var show = el.style.display === 'none';\n"
    "  el.style.display = show ? '' : 'none';\n"
    "  btn.textContent = show"
    " ? 'Hide extra decisions'"
    " : btn.dataset.label;\n"
    "}\n"
    "\n"
    "/* Scroll-to-top FAB */\n"
    "(function() {\n"
    "  var fab = document.querySelector('.scroll-top');\n"
    "  if (!fab) return;\n"
    "  window.addEventListener('scroll', function() {\n"
    "    if (window.scrollY > 300) fab.classList.add('show');\n"
    "    else fab.classList.remove('show');\n"
    "  }, {passive: true});\n"
    "})();\n"
    "</script>"
)
