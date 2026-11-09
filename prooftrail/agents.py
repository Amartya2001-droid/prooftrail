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

import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .store import Actor, Project


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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


# -- findings and reports ---------------------------------------------------

@dataclass
class Finding:
    """One thing an agent found while working a project.

    ``status`` is "complete" for a real result and "not_implemented"
    for a specialist whose work is still a stub: a stub never fakes
    a result, it says so plainly.
    """

    agent_id: str
    severity: str  # "info" | "low" | "medium" | "high"
    message: str
    evidence: list[str] = field(default_factory=list)
    status: str = "complete"


@dataclass
class AgentReport:
    """What an orchestrated agent run concluded, in one object."""

    run_id: str
    task_kind: str
    project_id: str
    verdict: str  # "clean" | "issues_found" | "incomplete"
    summaries: dict[str, str]  # agent_id -> one-line summary
    findings: list[Finding] = field(default_factory=list)


# -- orchestrator -----------------------------------------------------------

class Orchestrator:
    """Dispatches a task to the right specialist agents, in order,
    and merges their findings into one AgentReport.

    The orchestrator itself (Trailboss) never judges content: it
    picks the team for the task kind, runs each specialist, and
    derives the verdict from what they return. Verity re-verifies
    the ledger for real; the other specialists are honest stubs
    until their Day 2 work lands.
    """

    # Which specialists work each kind of task, in run order.
    TASK_AGENTS: dict[str, tuple[str, ...]] = {
        "verify_project": ("verifier", "detective", "narrator"),
        "build_dispute_case": ("verifier", "detective", "cartographer",
                               "narrator"),
    }

    def __init__(self, project: Project) -> None:
        self.project = project
        # Signing identities for the agents, created on first use.
        # Ledger actor ids are namespaced ("agent:verity") so an
        # agent can never collide with a human username: a human
        # called "verity" would otherwise share the actor slot and
        # its keys. Each instance mints fresh keys; the ledger keeps
        # every registered key, so events signed under an earlier
        # instance's keys still verify after a restart.
        self._agent_actors: dict[str, Actor] = {}

    def _agent_actor(self, agent_id: str) -> Actor:
        """The signing actor for a role, registered on the ledger."""
        actor = self._agent_actors.get(agent_id)
        if actor is None:
            actor = Actor.create(f"agent:{agent_id}",
                                 get_role(agent_id).name)
            self.project.ledger.register_actor(actor.actor_id,
                                              actor.public_key)
            self._agent_actors[agent_id] = actor
        return actor

    def run(self, task: dict) -> AgentReport:
        """Run a task and return the merged report.

        ``task`` needs a "kind" this orchestrator knows; if it also
        carries a "project_id" it must name this project.

        The run itself is written into the project's signed ledger
        as it happens — started, one event per finding, finished —
        so the run is tamper-evident like everything else: rewriting
        a finding breaks verification.
        """
        kind = task.get("kind")
        if kind not in self.TASK_AGENTS:
            raise ValueError(f"unknown agent task kind: {kind!r}")
        if (task.get("project_id") is not None
                and task["project_id"] != self.project.project_id):
            raise ValueError(
                f"task project {task['project_id']!r} does not match "
                f"project {self.project.project_id!r}")
        run_id = "run-" + secrets.token_hex(8)
        started_at = _now_iso()
        self._append_event(
            "agent_run_started", "orchestrator", started_at,
            {"run_id": run_id, "kind": kind,
             "project_id": self.project.project_id})
        findings: list[Finding] = []
        summaries: dict[str, str] = {}
        for agent_id in self.TASK_AGENTS[kind]:
            agent_findings, summary = self._run_agent(agent_id)
            findings.extend(agent_findings)
            summaries[agent_id] = summary
        verdict = self._verdict(findings)
        for finding in findings:
            self._append_event(
                "agent_finding", finding.agent_id, _now_iso(),
                {"run_id": run_id, "severity": finding.severity,
                 "message": finding.message,
                 "evidence": finding.evidence,
                 "status": finding.status})
        self._append_event(
            "agent_run_finished", "orchestrator", _now_iso(),
            {"run_id": run_id, "verdict": verdict,
             "findings_count": len(findings),
             "agents": list(self.TASK_AGENTS[kind])})
        return AgentReport(run_id=run_id, task_kind=kind,
                           project_id=self.project.project_id,
                           verdict=verdict, summaries=summaries,
                           findings=findings)

    def _append_event(self, event_type: str, agent_id: str,
                      timestamp: str, payload: dict) -> dict:
        """Append one signed agent event to the project ledger."""
        actor = self._agent_actor(agent_id)
        return self.project.ledger.append(
            event_type, actor.actor_id, actor.secret_key,
            timestamp=timestamp, payload=payload)

    def _run_agent(self, agent_id: str) -> tuple[list[Finding], str]:
        """Run one specialist. Returns (findings, one-line summary)."""
        if agent_id == "verifier":
            return self._run_verifier()
        if agent_id in ("detective", "cartographer", "narrator"):
            return self._run_stub(agent_id)
        raise ValueError(f"unknown agent: {agent_id!r}")

    def _run_verifier(self) -> tuple[list[Finding], str]:
        """Verity re-verifies the project's ledger for real."""
        problems = self.project.verify()
        count = len(self.project.ledger.events)
        if not problems:
            return ([Finding(
                "verifier", "info",
                f"Ledger verified: {count} events, chain and "
                "signatures valid.",
                evidence=[f"ledger events: {count}"])],
                f"Verified ledger: {count} events, no problems.")
        return ([Finding("verifier", "high", problem,
                         evidence=["ledger chain"])
                 for problem in problems],
                f"Found {len(problems)} ledger problem(s).")

    def _run_stub(self, agent_id: str) -> tuple[list[Finding], str]:
        """A specialist whose work is not implemented yet.

        The finding says so explicitly instead of inventing a
        result: an honest gap beats a fabricated all-clear.
        """
        role = get_role(agent_id)
        return ([Finding(
            agent_id, "info",
            f"{role.name} ({role.role}) is not yet implemented "
            "for this project.",
            status="not_implemented")],
            "Not yet implemented.")

    @staticmethod
    def _verdict(findings: list[Finding]) -> str:
        if any(f.severity == "high" for f in findings):
            return "issues_found"
        if any(f.status == "not_implemented" for f in findings):
            return "incomplete"
        return "clean"
