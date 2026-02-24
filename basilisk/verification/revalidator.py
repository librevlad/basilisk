"""Revalidator — plan revalidation strategies for findings."""

from __future__ import annotations

import logging
from enum import StrEnum
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from basilisk.knowledge.entities import Entity
    from basilisk.knowledge.vulns.registry import VulnRegistry
    from basilisk.verification.confirmer import FindingConfirmer

logger = logging.getLogger(__name__)


class RevalidationStrategy(StrEnum):
    """How to revalidate a finding."""

    DIFFERENT_PAYLOAD = "different_payload"
    DIFFERENT_TECHNIQUE = "different_technique"
    REPEAT = "repeat"


class RevalidationRequest(BaseModel):
    """A request to revalidate a specific finding."""

    finding_entity_id: str
    strategy: RevalidationStrategy
    target_host: str
    suggested_plugins: list[str] = Field(default_factory=list)


class ReValidator:
    """Plans revalidation strategies for findings.

    Consults VulnRegistry for verification techniques and maps them
    to concrete plugin names via the FindingConfirmer.
    """

    def __init__(
        self,
        confirmer: FindingConfirmer,
        vuln_registry: VulnRegistry | None = None,
    ) -> None:
        self._confirmer = confirmer
        self._registry = vuln_registry

    def plan_revalidation(self, finding_entity: Entity) -> list[RevalidationRequest]:
        """Plan one or more revalidation strategies for a finding.

        Strategy selection:
        1. If VulnRegistry has multiple verification_techniques → DIFFERENT_TECHNIQUE
        2. If verifiers exist → DIFFERENT_PAYLOAD
        3. Fallback → REPEAT
        """
        host = finding_entity.data.get("host", "")
        category = self._confirmer._extract_category(finding_entity)
        verifiers = self._confirmer.suggest_verifiers(finding_entity)
        requests: list[RevalidationRequest] = []

        # Check registry for techniques
        techniques: list[str] = []
        if self._registry and category:
            for vd in self._registry.by_category(category):
                techniques.extend(vd.verification_techniques)

        if len(techniques) >= 2 and verifiers:
            requests.append(RevalidationRequest(
                finding_entity_id=finding_entity.id,
                strategy=RevalidationStrategy.DIFFERENT_TECHNIQUE,
                target_host=host,
                suggested_plugins=verifiers,
            ))
        elif verifiers:
            requests.append(RevalidationRequest(
                finding_entity_id=finding_entity.id,
                strategy=RevalidationStrategy.DIFFERENT_PAYLOAD,
                target_host=host,
                suggested_plugins=verifiers,
            ))
        else:
            requests.append(RevalidationRequest(
                finding_entity_id=finding_entity.id,
                strategy=RevalidationStrategy.REPEAT,
                target_host=host,
                suggested_plugins=[],
            ))

        return requests

    def select_plugins(self, request: RevalidationRequest) -> list[str]:
        """Map a revalidation request to concrete plugin names."""
        if request.suggested_plugins:
            return request.suggested_plugins
        return []
