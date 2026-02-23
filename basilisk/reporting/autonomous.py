"""Autonomous mode report data preparation.

Converts LoopResult + KnowledgeGraph + Decision history into a flat dict
suitable for the Jinja2 HTML template.  Pipeline mode never calls this module.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from basilisk.knowledge.entities import EntityType


def prepare_autonomous_data(result: Any) -> dict[str, Any]:
    """Build the full autonomous report data dict from a LoopResult.

    Returns keys: steps, total_observations, termination_reason,
    productive_count, productive_pct, total_confidence_gained,
    graph_summary, entity_map, growth, decision_timeline,
    decisions, scoring_insights.
    """
    graph = result.graph
    decisions = result.decisions or []
    history = result.history

    productive_count = 0
    total_confidence_gained = 0.0
    if history is not None:
        productive_count = history.productive_count
        total_confidence_gained = history.total_confidence_gained
    else:
        productive_count = sum(1 for d in decisions if d.was_productive)
        total_confidence_gained = sum(d.outcome_confidence_delta for d in decisions)

    total_decisions = len(decisions)
    productive_pct = (
        round(productive_count / total_decisions * 100, 1)
        if total_decisions > 0
        else 0.0
    )

    return {
        "steps": result.steps,
        "total_observations": result.total_observations,
        "termination_reason": result.termination_reason,
        "productive_count": productive_count,
        "productive_pct": productive_pct,
        "total_confidence_gained": round(total_confidence_gained, 3),
        "graph_summary": _build_graph_summary(graph),
        "entity_map": _build_entity_map(graph),
        "growth": _build_growth_data(decisions, graph),
        "decision_timeline": _build_decision_timeline(decisions),
        "decisions": _build_full_decisions(decisions),
        "scoring_insights": _build_scoring_insights(decisions),
    }


def _build_graph_summary(graph: Any) -> dict[str, int]:
    """Entity counts by type."""
    return {
        "entities": graph.entity_count,
        "relations": graph.relation_count,
        "hosts": len(graph.query(EntityType.HOST)),
        "services": len(graph.query(EntityType.SERVICE)),
        "endpoints": len(graph.query(EntityType.ENDPOINT)),
        "technologies": len(graph.query(EntityType.TECHNOLOGY)),
        "findings": len(graph.query(EntityType.FINDING)),
        "vulnerabilities": len(graph.query(EntityType.VULNERABILITY)),
        "credentials": len(graph.query(EntityType.CREDENTIAL)),
    }


def _build_entity_map(graph: Any) -> list[dict[str, Any]]:
    """Hierarchical host -> services/endpoints/technologies map.

    Traverses two levels: HOST -> SERVICE -> TECHNOLOGY/ENDPOINT,
    because the standard relation model is HOST -EXPOSES-> SERVICE -RUNS-> TECH
    and SERVICE -HAS_ENDPOINT-> ENDPOINT.
    """
    hosts = graph.query(EntityType.HOST)
    entity_map: list[dict[str, Any]] = []

    for host_entity in hosts:
        host_key = host_entity.data.get("host", host_entity.id[:8])

        # Collect neighbors at level 1 (direct from host) and level 2 (from services)
        level1 = graph.neighbors(host_entity.id)

        services: list[dict[str, Any]] = []
        endpoints: list[dict[str, Any]] = []
        technologies: list[dict[str, Any]] = []
        seen_ids: set[str] = set()

        for n in level1:
            seen_ids.add(n.id)
            if n.type == EntityType.SERVICE:
                services.append({
                    "port": n.data.get("port", "?"),
                    "protocol": n.data.get("protocol", "tcp"),
                    "service": n.data.get("service", ""),
                    "confidence": round(n.confidence, 2),
                })
                # Traverse level 2 from service
                for n2 in graph.neighbors(n.id):
                    if n2.id in seen_ids:
                        continue
                    seen_ids.add(n2.id)
                    if n2.type == EntityType.ENDPOINT and len(endpoints) < 50:
                        endpoints.append({
                            "path": n2.data.get("path", "/"),
                            "method": n2.data.get("method", ""),
                            "status": n2.data.get("status", ""),
                            "confidence": round(n2.confidence, 2),
                        })
                    elif n2.type == EntityType.TECHNOLOGY:
                        technologies.append({
                            "name": n2.data.get("name", "?"),
                            "version": n2.data.get("version", ""),
                            "confidence": round(n2.confidence, 2),
                        })
            elif n.type == EntityType.ENDPOINT and len(endpoints) < 50:
                endpoints.append({
                    "path": n.data.get("path", "/"),
                    "method": n.data.get("method", ""),
                    "status": n.data.get("status_code", ""),
                    "confidence": round(n.confidence, 2),
                })
            elif n.type == EntityType.TECHNOLOGY:
                technologies.append({
                    "name": n.data.get("name", "?"),
                    "version": n.data.get("version", ""),
                    "confidence": round(n.confidence, 2),
                })

        entity_map.append({
            "host": host_key,
            "confidence": round(host_entity.confidence, 2),
            "services": services,
            "endpoints": endpoints,
            "technologies": technologies,
        })

    return entity_map


def _build_growth_data(
    decisions: list[Any], graph: Any,
) -> list[dict[str, Any]]:
    """Per-step entity count progression from context snapshots + final state."""
    growth: list[dict[str, Any]] = []
    seen_steps: set[int] = set()

    for d in decisions:
        step = d.step
        if step in seen_steps:
            continue
        seen_steps.add(step)
        ctx = d.context
        growth.append({
            "step": step,
            "entities": ctx.entity_count,
            "relations": ctx.relation_count,
            "hosts": ctx.host_count,
            "services": ctx.service_count,
            "findings": ctx.finding_count,
        })

    # Append final state as last point
    last_step = growth[-1]["step"] + 1 if growth else 1
    growth.append({
        "step": last_step,
        "entities": graph.entity_count,
        "relations": graph.relation_count,
        "hosts": len(graph.query(EntityType.HOST)),
        "services": len(graph.query(EntityType.SERVICE)),
        "findings": len(graph.query(EntityType.FINDING)),
    })

    return growth


def _build_decision_timeline(decisions: list[Any]) -> list[dict[str, Any]]:
    """Simplified timeline for visual display."""
    timeline: list[dict[str, Any]] = []
    for d in decisions:
        timeline.append({
            "step": d.step,
            "plugin": d.chosen_plugin,
            "target": d.chosen_target,
            "goal": d.goal,
            "goal_description": d.goal_description,
            "score": round(d.chosen_score, 3),
            "reasoning": d.reasoning_trace,
            "outcome_observations": d.outcome_observations,
            "outcome_new_entities": d.outcome_new_entities,
            "outcome_confidence_delta": round(d.outcome_confidence_delta, 4),
            "outcome_duration": round(d.outcome_duration, 2),
            "was_productive": d.was_productive,
        })
    return timeline


def _build_full_decisions(decisions: list[Any]) -> list[dict[str, Any]]:
    """Full audit trail with evaluated options (capped at 10 per decision)."""
    result: list[dict[str, Any]] = []
    for d in decisions:
        options: list[dict[str, Any]] = []
        for opt in d.evaluated_options[:10]:
            bd = opt.score_breakdown or {}
            options.append({
                "plugin": opt.plugin_name,
                "target": opt.target_host,
                "score": round(opt.score, 3),
                "novelty": round(bd.get("novelty", 0), 3),
                "knowledge_gain": round(bd.get("knowledge_gain", 0), 3),
                "cost": round(bd.get("cost", 0), 3),
                "noise": round(bd.get("noise", 0), 3),
                "repetition_penalty": round(bd.get("repetition_penalty", 0), 3),
                "was_chosen": opt.was_chosen,
            })

        result.append({
            "id": d.id,
            "step": d.step,
            "timestamp": d.timestamp.isoformat() if d.timestamp else "",
            "goal": d.goal,
            "goal_description": d.goal_description,
            "chosen_plugin": d.chosen_plugin,
            "chosen_target": d.chosen_target,
            "chosen_score": round(d.chosen_score, 3),
            "reasoning_trace": d.reasoning_trace,
            "context": {
                "entities": d.context.entity_count,
                "relations": d.context.relation_count,
                "hosts": d.context.host_count,
                "services": d.context.service_count,
                "findings": d.context.finding_count,
                "gaps": d.context.gap_count,
                "elapsed": round(d.context.elapsed_seconds, 1),
            },
            "evaluated_options": options,
            "outcome": {
                "observations": d.outcome_observations,
                "new_entities": d.outcome_new_entities,
                "confidence_delta": round(d.outcome_confidence_delta, 4),
                "duration": round(d.outcome_duration, 2),
            },
            "was_productive": d.was_productive,
        })
    return result


def _build_scoring_insights(decisions: list[Any]) -> dict[str, Any]:
    """Aggregate scoring stats across all decisions."""
    if not decisions:
        return {
            "avg_score": 0.0,
            "max_score": 0.0,
            "min_score": 0.0,
            "total_evaluated": 0,
            "top_scored_plugins": [],
            "goal_distribution": {},
        }

    all_scores = [d.chosen_score for d in decisions]
    avg_score = round(sum(all_scores) / len(all_scores), 3) if all_scores else 0.0
    max_score = round(max(all_scores), 3) if all_scores else 0.0
    min_score = round(min(all_scores), 3) if all_scores else 0.0

    total_evaluated = sum(len(d.evaluated_options) for d in decisions)

    # Top plugins by average score
    plugin_scores: dict[str, list[float]] = defaultdict(list)
    plugin_chosen: dict[str, int] = defaultdict(int)
    for d in decisions:
        plugin_scores[d.chosen_plugin].append(d.chosen_score)
        plugin_chosen[d.chosen_plugin] += 1

    top_plugins: list[dict[str, Any]] = []
    for plugin, scores in plugin_scores.items():
        top_plugins.append({
            "plugin": plugin,
            "avg_score": round(sum(scores) / len(scores), 3),
            "times_chosen": plugin_chosen[plugin],
        })
    top_plugins.sort(key=lambda x: x["avg_score"], reverse=True)
    top_plugins = top_plugins[:10]

    # Goal distribution
    goal_dist: dict[str, int] = defaultdict(int)
    for d in decisions:
        goal_dist[d.goal or "unknown"] += 1

    return {
        "avg_score": avg_score,
        "max_score": max_score,
        "min_score": min_score,
        "total_evaluated": total_evaluated,
        "top_scored_plugins": top_plugins,
        "goal_distribution": dict(goal_dist),
    }
