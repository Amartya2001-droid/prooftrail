"""Agent roles: the named specialists that work a ProofTrail project.

Day 1 of the agent layer registers five roles. Each agent has a stable
id (used in findings, ledger events and run records), a display name,
a one-line role description, and a list of capabilities. The registry
is the single source of truth for which agents exist: the orchestrator
dispatches by id, and the run log records the same ids.

The five roles:

- Trailboss (orchestrator) — coordinates agent teams and merges
  their findings into one report.
- Verity (verifier) — re-verifies hash chains, signatures and
  timestamps against the project's ledger.
- Sleuth (detective) — hunts anomalies: sudden rewrites, authorship
  flips, undeclared AI use, timeline gaps.
- Mapper (cartographer) — maps who wrote what: human vs AI-assisted
  vs imported segments, per actor.
- Scribe (narrator) — turns evidence into a plain-language proof
  narrative.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class AgentRole:
    """One named agent role in the registry."""

    agent_id: str
    name: str
    role: str
    capabilities: list[str] = field(default_factory=list)


ROLES: tuple[AgentRole, ...] = (
    AgentRole(
        "orchestrator",
        "Trailboss",
        "Coordinates agent teams and merges their findings into one report.",
        ["dispatch agent teams", "merge findings",
         "produce agent reports"],
    ),
    AgentRole(
        "verifier",
        "Verity",
        "Re-verifies hash chains, signatures and timestamps.",
        ["verify hash chains", "verify signatures",
         "verify timestamps"],
    ),
    AgentRole(
        "detective",
        "Sleuth",
        "Hunts anomalies: sudden rewrites, authorship flips, "
        "undeclared AI use, timeline gaps.",
        ["detect sudden rewrites", "detect authorship flips",
         "detect undeclared AI use", "detect timeline gaps"],
    ),
    AgentRole(
        "cartographer",
        "Mapper",
        "Maps who wrote what: human vs AI-assisted vs imported "
        "segments, per actor.",
        ["map human-written segments", "map AI-assisted segments",
         "map imported segments", "attribute segments per actor"],
    ),
    AgentRole(
        "narrator",
        "Scribe",
        "Turns evidence into a plain-language proof narrative.",
        ["write plain-language proof narratives",
         "summarise evidence"],
    ),
)

_BY_ID: dict[str, AgentRole] = {role.agent_id: role for role in ROLES}


def get_role(agent_id: str) -> AgentRole:
    """Look up one role by its stable id. Raises KeyError if unknown."""
    return _BY_ID[agent_id]


def list_roles() -> list[AgentRole]:
    """All registered roles, in registry order."""
    return list(ROLES)
