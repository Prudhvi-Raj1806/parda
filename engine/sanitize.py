"""Resolve candidate spans and apply them. The only place where text is edited.

Spans come from detection (identifiers, roles, clinical protection, dataset names, dates). Overlaps are
resolved by priority, then length, then position, so a high-confidence identifier beats a name match and
protected clinical text blocks any identifier span that is weaker than an identifier. Edits are applied from
right to left, so earlier offsets stay valid.
"""

from __future__ import annotations

import bisect
from collections import Counter
from dataclasses import dataclass, field

from engine.detection import P_ID, Span


@dataclass
class Result:
    text: str
    applied: Counter = field(default_factory=Counter)     # PII kind -> spans replaced
    protected: int = 0                                     # clinical spans kept
    dropped: int = 0                                       # weaker spans lost to an overlap


def resolve(spans: list[Span]) -> tuple[list[Span], int]:
    """Return (accepted spans sorted by position, number of spans dropped by an overlap)."""
    ordered = sorted(spans, key=lambda s: (-s.priority, -s.length, s.start, s.kind))
    starts: list[int] = []        # sorted starts of accepted spans
    accepted: list[Span] = []
    dropped = 0
    for s in ordered:
        if s.length <= 0:
            continue
        i = bisect.bisect_left(starts, s.start)
        clash = False
        if i > 0 and accepted_end(accepted, i - 1) > s.start:
            clash = True
        if i < len(accepted) and accepted[i].start < s.end:
            clash = True
        if clash:
            dropped += 1
            continue
        starts.insert(i, s.start)
        accepted.insert(i, s)
    return accepted, dropped


def accepted_end(accepted: list[Span], idx: int) -> int:
    return accepted[idx].end


def apply(text: str, spans: list[Span]) -> Result:
    """Replace every non-clinical span (right to left) with its replacement or [KIND]."""
    kept, dropped = resolve(spans)
    result = Result(text=text, dropped=dropped)
    for s in sorted(kept, key=lambda x: x.start, reverse=True):
        if s.kind == "CLINICAL":
            result.protected += 1
            continue
        repl = s.replacement if s.replacement is not None else f"[{s.kind}]"
        text = text[:s.start] + repl + text[s.end:]
        result.applied[s.kind] += 1
    result.text = text
    return result


def identifier_spans(spans: list[Span]) -> list[Span]:
    return [s for s in spans if s.priority == P_ID]
