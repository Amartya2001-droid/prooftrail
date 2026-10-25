"""Semantic version diffing.

Splits documents into sentences and computes what actually changed:
how many sentences are new, how many were removed, what share of the new
version is newly introduced, and — the part a human reader cares about —
what *kind* of change it was. Intent is classified from the shape of the
diff, not from a language model, so it is deterministic and explainable:

- rewrite:    most sentences replaced on both sides
- expansion:  mostly additions
- tightening: mostly removals
- rewording:  balanced, moderate churn
- touch-up:   small churn either way
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass

_SENTENCE_RE = re.compile(r"(?<=[.!?])\s+")


def split_sentences(text: str) -> list[str]:
    """Split text into sentences, keeping each sentence intact."""
    parts = [s.strip() for s in _SENTENCE_RE.split(text.strip()) if s.strip()]
    return parts


@dataclass
class DiffResult:
    added: list[str]
    removed: list[str]
    unchanged: list[str]
    old_count: int
    new_count: int
    new_sentence_pct: float  # share of the new version that is newly introduced
    removed_sentence_pct: float  # share of the old version that was removed
    intent: str

    def summary(self) -> str:
        """One plain-language sentence describing the change."""
        if self.intent == "rewrite":
            verb = "was rewritten"
        elif self.intent == "expansion":
            verb = "was expanded"
        elif self.intent == "tightening":
            verb = "was tightened"
        elif self.intent == "rewording":
            verb = "was reworded"
        else:
            verb = "was touched up"
        return (
            f"The document {verb}: {len(self.added)} sentence(s) added, "
            f"{len(self.removed)} removed, "
            f"{self.new_sentence_pct:.0f}% of sentences newly introduced."
        )


def classify(new_pct: float, removed_pct: float) -> str:
    if new_pct >= 50 and removed_pct >= 50:
        return "rewrite"
    if new_pct < 15 and removed_pct < 15:
        return "touch-up"
    if new_pct >= 2 * max(removed_pct, 1) and new_pct >= 25:
        return "expansion"
    if removed_pct >= 2 * max(new_pct, 1) and removed_pct >= 25:
        return "tightening"
    return "rewording"


def diff_texts(old: str, new: str) -> DiffResult:
    """Diff two document texts at sentence granularity."""
    old_sents = split_sentences(old)
    new_sents = split_sentences(new)
    matcher = difflib.SequenceMatcher(a=old_sents, b=new_sents, autojunk=False)
    added: list[str] = []
    removed: list[str] = []
    unchanged: list[str] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            unchanged.extend(old_sents[i1:i2])
        elif tag == "delete":
            removed.extend(old_sents[i1:i2])
        elif tag == "insert":
            added.extend(new_sents[j1:j2])
        else:  # replace
            removed.extend(old_sents[i1:i2])
            added.extend(new_sents[j1:j2])
    new_pct = 100.0 * len(added) / max(1, len(new_sents))
    removed_pct = 100.0 * len(removed) / max(1, len(old_sents))
    return DiffResult(
        added=added,
        removed=removed,
        unchanged=unchanged,
        old_count=len(old_sents),
        new_count=len(new_sents),
        new_sentence_pct=new_pct,
        removed_sentence_pct=removed_pct,
        intent=classify(new_pct, removed_pct),
    )
