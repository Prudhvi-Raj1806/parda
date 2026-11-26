"""Record linkage (lane 4): strong identifiers and union-find. Standard library only.

A record is a unit: a CSV row, a JSON record, or a whole document. Two units are linked only when
they share a strong identifier: Aadhaar, ABHA, PAN, e-mail, insurance ID, a hospital ID (UHID, IPD,
ADM...) or a mobile number. A shared name, a shared village or a shared doctor is never enough,
because two people can share those. A unit with no identifier gets no patient (null).

Union-find over identifier nodes can chain two people through a shared number (for example a family
phone). Phone numbers are therefore used only when the phone is not shared with another patient's
hospital ID; see `Linker.finalize`.
"""

from __future__ import annotations

import re
from collections import defaultdict

ID_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AADHAAR", re.compile(r"(?<![\d-])(\d{4})[ -]?(\d{4})[ -]?(\d{4})(?![\d-])")),
    ("ABHA", re.compile(r"(?<![\d-])(\d{2})-(\d{4})-(\d{4})-(\d{4})(?![\d-])")),
    ("PAN", re.compile(r"\b([A-Z]{5}\d{4}[A-Z])\b")),
    ("EMAIL", re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")),
    ("INS", re.compile(r"(PMJAY-[A-Z]{2}-\d+|POL/\d+/\d+)")),
    ("HOSPID", re.compile(r"(?<![A-Za-z0-9])((?:UHID|JJH|SNJ|DHH\d{0,4}|IPD?|ADM|OPD)[-/]?\d[\d/-]*\d)")),
    ("PHONE", re.compile(r"(?<![\d-])(?:\+?91[\s-]?)?([6-9]\d{4}[\s-]?\d{5})(?![\d-])")),
]

# Hospital IDs are per hospital; an IPD number or an ADM number belongs to one admission and is still a
# safe key, because the same number always means the same episode.


def extract_keys(text: str) -> set[str]:
    keys: set[str] = set()
    for kind, rx in ID_PATTERNS:
        for m in rx.finditer(text):
            if kind == "AADHAAR":
                value = "".join(m.groups())
            elif kind == "ABHA":
                value = "".join(m.groups())
            elif kind == "PHONE":
                value = re.sub(r"\D", "", m.group(1))
            elif kind == "HOSPID":
                value = re.sub(r"[^A-Z0-9]", "", m.group(1).upper())
            else:
                value = re.sub(r"\s+", "", m.group(0)).upper()
            keys.add(f"{kind}:{value}")
    # A UHID is a hospital's number: 'SNJ/26/064127' and 'UHID-010607' are not the same key.
    return keys


DATE_DMY_RX = re.compile(r"(?<!\d)(\d{1,2})[/-](\d{1,2})[/-](\d{4})(?!\d)")
DATE_ISO_RX = re.compile(r"(?<!\d)(\d{4})-(\d{1,2})-(\d{1,2})(?!\d)")


def _date_candidates(text: str) -> set[str]:
    """Every reading of the dates in a text: day-first and month-first (the practice data uses both)."""
    out: set[str] = set()
    for m in DATE_DMY_RX.finditer(text):
        a, b, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
        for mo, d in ((b, a), (a, b)):
            if 1 <= mo <= 12 and 1 <= d <= 31:
                out.add(f"{y:04d}-{mo:02d}-{d:02d}")
    for m in DATE_ISO_RX.finditer(text):
        out.add(f"{int(m.group(1)):04d}-{int(m.group(2)):02d}-{int(m.group(3)):02d}")
    return out


def name_dob_keys(text: str) -> set[str]:
    """A second rule for records without an identifier: the same person's name AND date of birth.
    Both must be present in the record, so a common name alone never links anyone."""
    from rakshak.detect_text import find_names  # local import: keeps link.py free of detection at import time

    dates = _date_candidates(text)
    if not dates:
        return set()
    keys: set[str] = set()
    for name, kind in find_names(text):
        if kind != "PATIENT_NAME":
            continue
        tokens = sorted(re.split(r"[\s._,\-/]+", name.casefold()))
        norm = " ".join(t for t in tokens if t)
        if len(norm.split()) < 2:
            continue
        for d in dates:
            keys.add(f"NAMEDOB:{norm}|{d}")
    return keys


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:  # path compression
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            # Deterministic root: the smaller string wins, so output never depends on input order.
            if rb < ra:
                ra, rb = rb, ra
            self.parent[rb] = ra


class Linker:
    def __init__(self) -> None:
        self._uf = _UnionFind()
        self._units: dict[tuple[str, str], set[str]] = {}
        self._pid: dict[tuple[str, str], str | None] = {}

    def add_unit(self, unit: tuple[str, str], keys: set[str]) -> None:
        # A unit that names two different people (a ward sheet, a helpdesk ticket, a bundle with several
        # patients) is not evidence that they are one person: it links nothing.
        kinds: dict[str, set[str]] = defaultdict(set)
        for k in keys:
            kind, _, value = k.partition(":")
            if kind == "HOSPID":
                # Episode numbers (IPD, ADM, OPD) can sit beside a UHID in one record; two different
                # patient numbers (UHID, SNJ, JJH, DHH) cannot.
                if re.match(r"(?:UHID|SNJ|JJH|DHH)", value):
                    kinds["PATIENT_HOSPID"].add(value)
                continue
            kinds[kind].add(value)
        if any(len(values) > 1 for kind, values in kinds.items() if kind not in ("PHONE", "NAMEDOB")):
            self._units[unit] = set()
            return
        node = "U|" + unit[0] + "|" + unit[1]
        self._units[unit] = keys
        self._uf.find(node)
        for k in keys:
            self._uf.union(node, "K|" + k)

    def finalize(self, pseudonym) -> None:
        """Assign each linked cluster one pseudonym from its smallest identifier key."""
        cluster_keys: dict[str, list[str]] = defaultdict(list)
        for unit, keys in self._units.items():
            if keys:
                cluster_keys[self._uf.find("U|" + unit[0] + "|" + unit[1])].append(unit)
        for root, units in cluster_keys.items():
            ids = sorted({k for u in units for k in self._units[u]})
            # The cluster's identity is its smallest key: the same people always get the same pseudonym.
            key = ids[0]
            pid = pseudonym(key)
            for u in units:
                self._pid[u] = pid

    def pid(self, unit: tuple[str, str]) -> str | None:
        return self._pid.get(unit)
