"""Evidence-based patient identity resolution (no name-only grouping, no unrestricted union-find).

Each record (a unit) gets a profile: global IDs (Aadhaar, ABHA, PAN, e-mail, insurance), hospital-scoped local
IDs (namespace + number), mobile numbers, dates of birth, names (canonical, transliteration-aware), relatives,
locality tokens and age. Candidate pairs come from blocks (shared ID, shared phone, shared name). A pair is
scored with the evidence weights from the plan, and accepted only when it reaches the threshold with
independent corroboration. Contradictions always reject a pair. Clusters grow one pair at a time, and a merge
is refused when any two members would contradict each other.
"""

from __future__ import annotations

import difflib
import re
from collections import defaultdict
from dataclasses import dataclass, field

from engine.config import norm_key

MAX_BLOCK = 60   # oversized blocks are ambiguous: skipped, never compared all-pairs

WEIGHTS = {"global_id": 100, "local_id": 85, "phone": 45, "dob": 35, "name_strong": 35,
           "name_moderate": 20, "relative": 20, "locality": 10, "age": 5}

GLOBAL_RX = {
    "AADHAAR": re.compile(r"(?<![\d-])(\d{4})[ -]?(\d{4})[ -]?(\d{4})(?![\d-])"),
    "ABHA": re.compile(r"(?<![\d-])(\d{2})-(\d{4})-(\d{4})-(\d{4})(?![\d-])"),
    "PAN": re.compile(r"\b([A-Z]{5}\d{4}[A-Z])\b"),
    "EMAIL": re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"),
    "INS": re.compile(r"(PMJAY-[A-Z]{2}-\d+|POL/\d+/\d+)"),
}
LOCAL_RX = re.compile(r"(?<![A-Za-z0-9])([A-Z]{2,6}(?:[-/]\d{2,4}){1,2}[-/]\d{4,}|[A-Z]{2,6}-\d{5,})")
# Episode numbers (one per admission) are not patient-level: two of them can belong to one patient.
EPISODE_FAMILIES = {"IP", "IPD", "ADM", "OPD", "BL", "OP", "RX", "REF", "LAB", "UP", "POL"}  # bills, referrals and orders are per event
PHONE_RX = re.compile(r"(?<![\d-])(?:\+?91[\s-]?)?([6-9]\d{4}[\s-]?\d{5})(?![\d-])")
PHONE_DEVA_RX = re.compile(r"(?<![०-९])[६-९][०-९]{9}(?![०-९])")
DATE_DMY = re.compile(r"(?<![\d/-])(\d{1,2})([/-])(\d{1,2})\2(\d{4})(?![\d/-])")
DATE_ISO = re.compile(r"(?<![\d-])(\d{4})-(\d{2})-(\d{2})(?![\d-])")
DOB_LABEL = re.compile(r"(?i)(?:\bdob\b|date of birth|जन्म तिथि|janm tithi)\s*[:\-]?\s*(\d{1,2}[/-]\d{1,2}[/-]\d{4}|\d{4}-\d{2}-\d{2})")
_DEVA_DIGITS = str.maketrans("०१२३४५६७८९", "0123456789")


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s.translate(_DEVA_DIGITS))


@dataclass
class Profile:
    key: tuple[str, str]                       # (input relative path, locator)
    global_ids: set[str] = field(default_factory=set)   # "AADHAAR:123412341234"
    local_ids: set[str] = field(default_factory=set)    # "SNJ:26064127"
    phones: set[str] = field(default_factory=set)
    dobs: set[str] = field(default_factory=set)         # ISO candidates, both readings of day/month
    names: set[str] = field(default_factory=set)        # canonical
    relatives: set[str] = field(default_factory=set)
    locality: set[str] = field(default_factory=set)
    ages: set[int] = field(default_factory=set)
    ambiguous: bool = False                             # names two patients: never a link source

    def empty(self) -> bool:
        return not (self.global_ids or self.local_ids or self.phones or self.dobs or self.names)


def canonical_name(name: str, variants: dict[str, str]) -> str:
    toks = [variants.get(t, t) for t in norm_key(name).split() if t]
    return " ".join(sorted(toks))


def _date_readings(a: int, b: int, y: int) -> set[str]:
    out = set()
    for mo, d in ((b, a), (a, b)):
        if 1 <= mo <= 12 and 1 <= d <= 31:
            out.add(f"{y:04d}-{mo:02d}-{d:02d}")
    return out


def dob_candidates(value: str) -> set[str]:
    out: set[str] = set()
    for m in DATE_DMY.finditer(value):
        out |= _date_readings(int(m.group(1)), int(m.group(3)), int(m.group(4)))
    for m in DATE_ISO.finditer(value):
        out.add(f"{int(m.group(1)):04d}-{int(m.group(2)):02d}-{int(m.group(3)):02d}")
    return out


def build_profile(key: tuple[str, str], text: str, fields: list[tuple[str, str]], variants: dict[str, str],
                  role_names) -> Profile:
    """fields: (PII kind, raw value) for structured parts of the record; text: the whole record text.
    role_names(text) -> [(name, kind)] for names in running text."""
    p = Profile(key=key)
    for label, rx in GLOBAL_RX.items():
        for m in rx.finditer(text):
            p.global_ids.add(f"{label}:{re.sub(r'[^A-Z0-9]', '', m.group(0).upper())}")
    for m in LOCAL_RX.finditer(text):
        family = re.match(r"[A-Z]+", m.group(1).upper()).group(0)
        number = re.sub(r"\D", "", m.group(1))
        p.local_ids.add(f"{family}:{number}")
    for m in PHONE_RX.finditer(text):
        p.phones.add(_digits(m.group(1))[-10:])
    for m in PHONE_DEVA_RX.finditer(text):
        p.phones.add(_digits(m.group(0))[-10:])
    for m in DOB_LABEL.finditer(text):
        p.dobs |= dob_candidates(m.group(1))
    for kind, value in fields:
        if not value or not value.strip():
            continue
        if kind == "PATIENT_NAME":
            p.names.add(canonical_name(value, variants))
        elif kind == "RELATIVE_NAME":
            p.relatives.add(canonical_name(value, variants))
        elif kind == "DOB":
            p.dobs |= dob_candidates(value)
        elif kind == "ADDRESS":
            for tok in re.findall(r"[a-zऀ-ॿ]{4,}", norm_key(value)):
                p.locality.add(variants.get(tok, tok))
        elif kind == "AGE":
            m = re.match(r"\s*(\d{1,3})(?!\d)", value)
            if m:
                p.ages.add(int(m.group(1)))
        elif kind in ("AADHAAR", "ABHA_NUMBER", "PAN", "EMAIL", "INSURANCE_ID"):
            label = {"AADHAAR": "AADHAAR", "ABHA_NUMBER": "ABHA", "PAN": "PAN", "EMAIL": "EMAIL",
                     "INSURANCE_ID": "INS"}[kind]
            if label == "EMAIL":
                p.global_ids.add("EMAIL:" + value.strip().lower())
            else:  # the same number is written with or without separators: compare the bare characters
                p.global_ids.add(f"{label}:{re.sub(r'[^A-Z0-9]', '', value.upper())}")
        elif kind == "PHONE":
            p.phones.add(_digits(value)[-10:])
    for name, kind in role_names(text):
        canon = canonical_name(name, variants)
        (p.relatives if kind == "RELATIVE_NAME" else p.names).add(canon)
    # Two different patient numbers of one kind in one record: the record names two people. It links nothing.
    type_values: dict[str, set[str]] = defaultdict(set)
    for g in p.global_ids:
        type_values[g.split(":", 1)[0]].add(g)
    for loc in p.local_ids:
        if loc.split(":", 1)[0] not in EPISODE_FAMILIES:
            type_values["LOCAL"].add(loc)
    if any(len(v) > 1 for v in type_values.values()):
        p.ambiguous = True
    p.names = {n for n in p.names if n}
    return p


def _name_similarity(a: str, b: str) -> int:
    """0 none, 1 moderate, 2 strong. Strong: same canonical name. Moderate: close spelling or shared tokens."""
    if a == b:
        return 2
    ta, tb = set(a.split()), set(b.split())
    if ta and tb and len(ta & tb) / len(ta | tb) >= 0.67:
        return 1
    return 1 if difflib.SequenceMatcher(None, a, b).ratio() >= 0.85 else 0


def contradicts(a: Profile, b: Profile) -> bool:
    for kind in ("AADHAAR", "ABHA", "PAN", "EMAIL", "INS"):
        va = {g for g in a.global_ids if g.startswith(kind + ":")}
        vb = {g for g in b.global_ids if g.startswith(kind + ":")}
        if va and vb and not (va & vb):
            return True
    families = {x.split(":", 1)[0] for x in a.local_ids | b.local_ids} - EPISODE_FAMILIES
    for family in families:
        va = {x for x in a.local_ids if x.startswith(family + ":")}
        vb = {x for x in b.local_ids if x.startswith(family + ":")}
        if va and vb and not (va & vb):
            return True
    if a.dobs and b.dobs and not (a.dobs & b.dobs):
        return True
    if a.ambiguous or b.ambiguous:
        return True
    return False


def pair_score(a: Profile, b: Profile) -> tuple[int, bool]:
    """(score, corroborated). Corroborated: a trusted ID, or a strong name with another feature."""
    score, trusted, strong_name, other = 0, False, False, False
    if a.global_ids & b.global_ids:
        score += WEIGHTS["global_id"]
        trusted = True
    if a.local_ids & b.local_ids:
        score += WEIGHTS["local_id"]
        trusted = True
    if a.phones & b.phones:
        score += WEIGHTS["phone"]
        other = True
    if a.dobs & b.dobs:
        score += WEIGHTS["dob"]
        other = True
    best = 0
    for na in a.names:
        for nb in b.names:
            best = max(best, _name_similarity(na, nb))
    if best == 2:
        score += WEIGHTS["name_strong"]
        strong_name = True
    elif best == 1:
        score += WEIGHTS["name_moderate"]
    if a.relatives & b.relatives:
        score += WEIGHTS["relative"]
        other = True
    if a.locality & b.locality:
        score += WEIGHTS["locality"]
    if a.ages & b.ages:
        score += WEIGHTS["age"]
    return score, trusted or (strong_name and other)


def _blocks(p: Profile) -> set[tuple[str, str]]:
    keys = {("G", g) for g in p.global_ids} | {("L", x) for x in p.local_ids} | {("P", x) for x in p.phones}
    keys |= {("N", n) for n in p.names}
    keys |= {("R", r) for r in p.relatives}
    return keys


class Resolver:
    """Builds clusters from profiles. Deterministic: sorted keys, sorted pairs, fixed tie-breakers."""

    def __init__(self, threshold: int) -> None:
        self.threshold = threshold
        self.profiles: dict[tuple[str, str], Profile] = {}
        self.stats = {"pairs_scored": 0, "pairs_accepted": 0, "pairs_rejected_contradiction": 0,
                      "blocks_skipped": 0}

    def add(self, profile: Profile) -> None:
        if not profile.empty():
            self.profiles[profile.key] = profile

    def resolve(self) -> dict[tuple[str, str], int]:
        keys = sorted(self.profiles)
        blocks: dict[tuple[str, str], list[tuple[str, str]]] = defaultdict(list)
        for k in keys:
            for b in _blocks(self.profiles[k]):
                blocks[b].append(k)
        seen: set[tuple[tuple[str, str], tuple[str, str]]] = set()
        candidates = []
        for b in sorted(blocks):
            members = blocks[b]
            if len(members) < 2:
                continue
            if len(members) > MAX_BLOCK:
                self.stats["blocks_skipped"] += 1
                continue
            for i in range(len(members)):
                for j in range(i + 1, len(members)):
                    pair = (members[i], members[j])
                    if pair not in seen:
                        seen.add(pair)
                        candidates.append(pair)
        scored = []
        for a, b in candidates:
            pa, pb = self.profiles[a], self.profiles[b]
            self.stats["pairs_scored"] += 1
            if contradicts(pa, pb):
                self.stats["pairs_rejected_contradiction"] += 1
                continue
            score, corroborated = pair_score(pa, pb)
            if score >= self.threshold and corroborated:
                scored.append((-score, a, b))
        scored.sort()
        parent: dict[tuple[str, str], tuple[str, str]] = {k: k for k in keys}
        members_of: dict[tuple[str, str], list[tuple[str, str]]] = {k: [k] for k in keys}

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        for _, a, b in scored:
            ra, rb = find(a), find(b)
            if ra == rb:
                continue
            # A merge must leave every pair of members consistent, not only the pair that proposed it.
            if any(contradicts(self.profiles[x], self.profiles[y]) for x in members_of[ra] for y in members_of[rb]):
                self.stats["pairs_rejected_contradiction"] += 1
                continue
            if rb < ra:
                ra, rb = rb, ra
            parent[rb] = ra
            members_of[ra].extend(members_of.pop(rb))
            self.stats["pairs_accepted"] += 1
        return {k: find(k) for k in keys if self.profiles[k].empty() is False}

    def anchors(self, clusters: dict[tuple[str, str], tuple[str, str]]) -> dict[tuple[str, str], str]:
        """A cluster's anchor is its smallest trusted identifier (stable), else its smallest record key."""
        by_root: dict[tuple[str, str], list[tuple[str, str]]] = defaultdict(list)
        for unit, root in clusters.items():
            by_root[root].append(unit)
        anchor_of_root = {}
        for root, units in by_root.items():
            ids = sorted({g for u in units for g in self.profiles[u].global_ids | self.profiles[u].local_ids})
            anchor_of_root[root] = ids[0] if ids else "unit|" + "|".join(min(units))
        return {unit: anchor_of_root[root] for unit, root in clusters.items()}
