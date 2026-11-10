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

from .diffing import diff_texts, split_sentences
from .store import Actor, AgentRun, Project


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


# -- Verity: deep verification ----------------------------------------------

def _parse_timestamp(value: str):
    """Parse an ISO timestamp, tolerating a trailing Z. None if unusable."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _attribute_problems(problems: list[str]) -> tuple[
        dict[int, list[str]], dict[int, list[str]], list[str]]:
    """Split project.verify() problems by event / version index.

    Ledger problems start "event {i}:" and version problems start
    "version {i}:"; anything else is unattributed and belongs to the
    chain finding. Returns (event_problems, version_problems, other).
    """
    event_problems: dict[int, list[str]] = {}
    version_problems: dict[int, list[str]] = {}
    other: list[str] = []
    for problem in problems:
        matched = False
        for prefix, bucket in (("event ", event_problems),
                               ("version ", version_problems)):
            if problem.startswith(prefix):
                rest = problem[len(prefix):]
                index_str, _, _ = rest.partition(":")
                if index_str.isdigit():
                    bucket.setdefault(int(index_str), []).append(problem)
                    matched = True
                    break
        if not matched:
            other.append(problem)
    return event_problems, version_problems, other


def _timestamp_problems(project: Project) -> tuple[
        dict[int, list[str]], dict[int, list[str]]]:
    """Timestamp checks project.verify() does not do.

    Event timestamps must parse and never run backwards along the
    chain; a version must not be timestamped before its parent.
    Empty timestamps are skipped: some event types record none.
    Returns (event_problems, version_problems) keyed by index.
    """
    event_problems: dict[int, list[str]] = {}
    prev_ts = None
    for i, event in enumerate(project.ledger.events):
        raw = event.get("timestamp", "")
        if not raw:
            continue
        ts = _parse_timestamp(raw)
        if ts is None:
            event_problems.setdefault(i, []).append(
                f"event {i}: timestamp {raw!r} is not a valid ISO "
                "timestamp")
            continue
        if prev_ts is not None and ts < prev_ts:
            event_problems.setdefault(i, []).append(
                f"event {i}: timestamp is earlier than the previous "
                "event's timestamp")
        prev_ts = ts
    version_problems: dict[int, list[str]] = {}
    prev_ts = None
    for i, version in enumerate(project.versions):
        ts = _parse_timestamp(version.timestamp)
        if ts is None:
            version_problems.setdefault(i, []).append(
                f"version {i} ({version.label!r}): timestamp "
                f"{version.timestamp!r} is not a valid ISO timestamp")
            continue
        if prev_ts is not None and ts < prev_ts:
            version_problems.setdefault(i, []).append(
                f"version {i} ({version.label!r}): timestamp is "
                "earlier than the previous version's timestamp")
        prev_ts = ts
    return event_problems, version_problems


# -- Sleuth: anomaly detection ----------------------------------------------

# Thresholds for what counts as an anomaly. Deterministic, so two runs
# over the same project always agree.
AUTHOR_FLIP_NEW_PCT = 25.0  # new-sentence share that makes an actor change a flip
UNDECLARED_MIN_SENTENCES = 3  # added sentences before "no declaration" is worth noting
TIMELINE_GAP_DAYS = 30  # days between versions that counts as a gap


def _version_texts(project: Project) -> list[str]:
    """The text of every version, in order."""
    return [project.read(v).decode(errors="replace")
            for v in project.versions]


def _version_events(project: Project) -> list[dict]:
    """The upload/edit/restore ledger events, in version order.

    The i-th version corresponds to the i-th version event: each
    upload appends exactly one of them, in the same order.
    """
    return [e for e in project.ledger.events
            if e["type"] in ("upload", "edit", "restore")]


# -- orchestrator -----------------------------------------------------------

class Orchestrator:
    """Dispatches a task to the right specialist agents, in order,
    and merges their findings into one AgentReport.

    The orchestrator itself (Trailboss) never judges content: it
    picks the team for the task kind, runs each specialist, and
    derives the verdict from what they return. Verity re-verifies
    the ledger per version for real and Sleuth hunts anomalies for
    real; the cartographer and narrator are honest stubs until their
    Day 2 work lands.
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
        finished_at = _now_iso()
        self._append_event(
            "agent_run_finished", "orchestrator", finished_at,
            {"run_id": run_id, "verdict": verdict,
             "findings_count": len(findings),
             "agents": list(self.TASK_AGENTS[kind])})
        self.project.record_agent_run(AgentRun(
            run_id=run_id, task_kind=kind,
            project_id=self.project.project_id,
            agents=list(self.TASK_AGENTS[kind]), status="finished",
            findings_count=len(findings), started_at=started_at,
            finished_at=finished_at))
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
        if agent_id == "detective":
            return self._run_detective()
        if agent_id in ("cartographer", "narrator"):
            return self._run_stub(agent_id)
        raise ValueError(f"unknown agent: {agent_id!r}")

    def _run_verifier(self) -> tuple[list[Finding], str]:
        """Verity re-verifies the project's ledger for real, per version.

        One finding per version (content hash, parent link,
        timestamp) plus one for the ledger chain itself (hashes,
        signatures, event order), so a failure names exactly where
        it is instead of a single pass/fail for the whole project.
        """
        problems = self.project.verify()
        event_problems, version_problems, other = _attribute_problems(
            problems)
        event_ts, version_ts = _timestamp_problems(self.project)
        for index, items in event_ts.items():
            event_problems.setdefault(index, []).extend(items)
        for index, items in version_ts.items():
            version_problems.setdefault(index, []).extend(items)

        findings: list[Finding] = []
        event_count = len(self.project.ledger.events)
        chain_problems = [
            p for items in event_problems.values() for p in items
        ] + other
        if not chain_problems:
            findings.append(Finding(
                "verifier", "info",
                f"Ledger chain verified: {event_count} events, hashes "
                "and signatures valid, timestamps in order.",
                evidence=[f"ledger events: {event_count}"]))
        else:
            findings.append(Finding(
                "verifier", "high",
                f"Ledger chain has {len(chain_problems)} problem(s).",
                evidence=chain_problems))
        for i, version in enumerate(self.project.versions):
            faults = version_problems.get(i, [])
            short = version.content_id[:12]
            if not faults:
                findings.append(Finding(
                    "verifier", "info",
                    f"Version {version.label!r} ({short}…): content "
                    "hash matches, parent link correct, timestamp "
                    "valid.",
                    evidence=[
                        f"content_id: {version.content_id}",
                        f"actor: {version.actor_id}",
                        f"timestamp: {version.timestamp}",
                        f"size: {version.size} bytes",
                    ]))
            else:
                findings.append(Finding(
                    "verifier", "high",
                    f"Version {version.label!r} ({short}…) has "
                    f"{len(faults)} problem(s).",
                    evidence=faults))
        total = len(chain_problems) + sum(
            len(v) for v in version_problems.values())
        if total == 0:
            summary = (f"Verified ledger: {event_count} events, "
                       f"{len(self.project.versions)} version(s), "
                       "no problems.")
        else:
            summary = f"Found {total} ledger problem(s)."
        return findings, summary

    def _run_detective(self) -> tuple[list[Finding], str]:
        """Sleuth hunts anomalies in the version history for real.

        Sudden rewrites and authorship flips come from sentence
        diffs between consecutive versions; undeclared AI use is
        checked against the declarations on record (absence of a
        declaration is reported as such, never as proof of AI use);
        timeline gaps come from version timestamps. A restore is
        named as a restore, not mistaken for a rewrite.
        """
        project = self.project
        versions = project.versions
        texts = _version_texts(project)
        events = _version_events(project)
        by_label: dict[str, list] = {}
        for decl in project.declarations():
            by_label.setdefault(decl.version_label, []).append(decl)
        findings: list[Finding] = []
        for i, version in enumerate(versions):
            label = version.label
            old_text = texts[i - 1] if i else ""
            old_actor = versions[i - 1].actor_id if i else None
            diff = diff_texts(old_text, texts[i])
            is_restore = (i < len(events)
                          and events[i]["type"] == "restore")
            if is_restore:
                findings.append(Finding(
                    "detective", "info",
                    f"Version {label!r} restored an earlier version's "
                    "content; the change is a rollback, not new "
                    "writing.",
                    evidence=[f"content_id: {version.content_id}",
                              f"actor: {version.actor_id}",
                              f"timestamp: {version.timestamp}"]))
                continue
            if diff.intent == "rewrite":
                findings.append(Finding(
                    "detective", "medium",
                    f"Version {label!r} rewrote most of the document: "
                    f"{len(diff.added)} of {diff.new_count} sentences "
                    f"new, {len(diff.removed)} of {diff.old_count} "
                    f"removed ({diff.new_sentence_pct:.0f}% new, "
                    f"{diff.removed_sentence_pct:.0f}% removed).",
                    evidence=[
                        f"actor: {version.actor_id}",
                        f"timestamp: {version.timestamp}",
                        f"added sentences: {len(diff.added)}",
                        f"removed sentences: {len(diff.removed)}",
                    ]))
            if (old_actor is not None
                    and version.actor_id != old_actor
                    and diff.new_sentence_pct >= AUTHOR_FLIP_NEW_PCT):
                findings.append(Finding(
                    "detective", "medium",
                    f"Authorship changed from {old_actor} to "
                    f"{version.actor_id} in version {label!r}: "
                    f"{diff.new_sentence_pct:.0f}% of sentences are new.",
                    evidence=[
                        f"previous actor: {old_actor}",
                        f"actor: {version.actor_id}",
                        f"timestamp: {version.timestamp}",
                    ]))
            # Declarations vs what actually changed in this version.
            decls = by_label.get(label, [])
            added = diff.added
            if decls:
                if not added:
                    tools = ", ".join(sorted({d.tool for d in decls}))
                    findings.append(Finding(
                        "detective", "low",
                        f"Declaration for version {label!r} names "
                        f"{tools} but the version added no new "
                        "sentences, so the declaration covers nothing.",
                        evidence=[f"actor: {version.actor_id}",
                                  f"timestamp: {version.timestamp}"]))
                else:
                    covered: set[int] = set()
                    new_sents = split_sentences(texts[i])
                    added_set = set(added)
                    all_covered = False
                    for decl in decls:
                        if not decl.sentence_indices:
                            all_covered = True
                            break
                        for idx in decl.sentence_indices:
                            if (0 <= idx < len(new_sents)
                                    and new_sents[idx] in added_set):
                                covered.add(idx)
                    covered_count = (len(added) if all_covered
                                     else len(covered))
                    if covered_count < len(added):
                        tools = ", ".join(sorted({d.tool for d in decls}))
                        findings.append(Finding(
                            "detective", "low",
                            f"Declaration for version {label!r} ({tools}) "
                            f"covers {covered_count} of {len(added)} "
                            "added sentences; "
                            f"{len(added) - covered_count} added "
                            "sentence(s) have no declared tool.",
                            evidence=[
                                f"actor: {version.actor_id}",
                                f"timestamp: {version.timestamp}",
                                f"added sentences: {len(added)}",
                                f"declared sentences: {covered_count}",
                            ]))
            # The first version has no prior text to compare against:
            # its sentences are the document's birth, not an edit, so
            # "added without a declaration" is not an anomaly there.
            # A declaration on v1 is still checked for coverage above.
            elif i > 0 and len(added) >= UNDECLARED_MIN_SENTENCES:
                findings.append(Finding(
                    "detective", "low",
                    f"Version {label!r} added {len(added)} sentences "
                    "with no AI-use declaration on record. Absence "
                    "of a declaration is not proof of authorship — "
                    "it only means none was declared.",
                    evidence=[f"actor: {version.actor_id}",
                              f"timestamp: {version.timestamp}",
                              f"added sentences: {len(added)}"]))
        # Timeline gaps between consecutive versions.
        for i in range(1, len(versions)):
            prev_ts = _parse_timestamp(versions[i - 1].timestamp)
            ts = _parse_timestamp(versions[i].timestamp)
            if prev_ts is None or ts is None:
                continue
            gap = ts - prev_ts
            if gap.days < 0:
                findings.append(Finding(
                    "detective", "medium",
                    f"Version {versions[i].label!r} is timestamped "
                    f"{versions[i].timestamp}, before its parent "
                    f"{versions[i - 1].label!r} "
                    f"({versions[i - 1].timestamp}).",
                    evidence=[f"actor: {versions[i].actor_id}"]))
            elif gap.days > TIMELINE_GAP_DAYS:
                findings.append(Finding(
                    "detective", "info",
                    f"{gap.days} days passed between version "
                    f"{versions[i - 1].label!r} and "
                    f"{versions[i].label!r} with no new version.",
                    evidence=[
                        f"from: {versions[i - 1].timestamp}",
                        f"to: {versions[i].timestamp}",
                    ]))
        anomalies = [f for f in findings if f.severity != "info"]
        if not findings:
            findings.append(Finding(
                "detective", "info",
                "No anomalies found: no sudden rewrites, authorship "
                "flips, timeline gaps or undeclared additions.",
                evidence=[f"versions checked: {len(versions)}"]))
            summary = (f"No anomalies found across {len(versions)} "
                       "version(s).")
        else:
            summary = (f"Found {len(anomalies)} anomaly(ies) across "
                       f"{len(versions)} version(s).")
        return findings, summary

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
