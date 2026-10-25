"""AI-involvement transparency and the Human Contribution Map.

ProofTrail never claims a binary "AI wrote this" verdict. Creators
voluntarily declare the tools and prompts used for a version; the map then
correlates those declarations with what actually changed:

- sentences carried over unchanged keep the source they already had
- sentences added in a version with a declaration are shown as AI-assisted
- sentences added without a declaration are shown as human-written, with
  the caveat that absence of a declaration is not proof of authorship
- imported or externally contributed passages can be tagged explicitly

The result is a per-segment timeline a reader can understand at a glance
— and screenshot.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .diffing import split_sentences

SOURCES = ("human", "ai-assisted", "imported", "external")


@dataclass
class Declaration:
    """A voluntary AI-use declaration for one version."""

    version_label: str
    actor_id: str
    tool: str  # e.g. "ChatGPT", "Claude", "Midjourney"
    prompt_summary: str
    # Sentence indices (in the new version) the declaration covers.
    # Empty means "all sentences added in this version".
    sentence_indices: list[int] = field(default_factory=list)


@dataclass
class Segment:
    text: str
    source: str
    first_seen_version: str


@dataclass
class ContributionMap:
    segments: list[Segment]
    declarations: list[Declaration]
    caveat: str = (
        "Sources marked human-written mean no AI use was declared for them; "
        "absence of a declaration is not proof of authorship."
    )

    def coverage(self) -> dict[str, float]:
        """Share of segments by source, as percentages."""
        total = max(1, len(self.segments))
        counts: dict[str, int] = {s: 0 for s in SOURCES}
        for seg in self.segments:
            counts[seg.source] += 1
        return {k: 100.0 * v / total for k, v in counts.items()}

    def render(self) -> str:
        """Plain-text rendering of the map, one segment per line."""
        lines = []
        for seg in self.segments:
            lines.append(f"[{seg.source}] ({seg.first_seen_version}) {seg.text}")
        return "\n".join(lines)


def build_map(
    versions: list[tuple[str, str]],
    declarations: list[Declaration] | None = None,
    overrides: dict[tuple[str, int], str] | None = None,
) -> ContributionMap:
    """Build a contribution map across ordered (label, text) versions.

    ``overrides`` maps (version_label, sentence_index) to a source for
    explicitly tagged passages such as imported or externally contributed
    text.
    """
    declarations = declarations or []
    overrides = overrides or {}
    by_version = {d.version_label: d for d in declarations}

    segments: list[Segment] = []
    prev_text = ""
    prev_sources: list[str] = []
    for label, text in versions:
        sents = split_sentences(text)
        if not prev_text:
            sources = ["human"] * len(sents)
        else:
            # Map unchanged sentences back to their previous source by
            # matching sentence text in order.
            sources = []
            unchanged_pool = list(zip(split_sentences(prev_text), prev_sources))
            for sent in sents:
                match = next(
                    (src for (s, src) in unchanged_pool if s == sent), None
                )
                if match is not None:
                    unchanged_pool.remove(
                        next((s, src) for (s, src) in unchanged_pool if s == sent)
                    )
                    sources.append(match)
                else:
                    sources.append("added")
        decl = by_version.get(label)
        for i, (sent, src) in enumerate(zip(sents, sources)):
            if (label, i) in overrides:
                src = overrides[(label, i)]
            elif src == "added":
                if decl is None:
                    src = "human"
                elif not decl.sentence_indices or i in decl.sentence_indices:
                    src = "ai-assisted"
                else:
                    src = "human"
            segments.append(Segment(sent, src, label))
        prev_text = text
        prev_sources = sources
    # Collapse consecutive same-source segments from the same version for
    # readability is intentionally NOT done: one segment per sentence keeps
    # the map auditable.
    return ContributionMap(segments=segments, declarations=declarations)
