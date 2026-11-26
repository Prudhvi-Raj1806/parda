"""Name registry: names learned in pass 1, removed everywhere in pass 2.

A name is learned from a structured field (name columns, name keys), from a labelled or
honorific mention in text, or from a candidate next to a phone number or contact cue.
Pass 2 replaces every registered name in every channel, with the same matching rules,
so a name found once in one file is also removed from notes, file names and metadata.

Matching: case-insensitive, tokens separated by spaces, dots, underscores, hyphens or slashes,
and never inside a longer word. A name directly after "Dr." is kept (a doctor is not a patient).
"""

from __future__ import annotations

import re
import unicodedata

_SEP = r"[\s._,\-/]+"
# A name never starts or ends inside a longer word. Underscore is a separator (file names).
_WORD_BEFORE = r"(?<![^\W_]|[ऀ-ॿ])"
_WORD_AFTER = r"(?![^\W_]|[ऀ-ॿ])"
# "Dr. Ramesh Srivastava": every part of the doctor's name is kept, so look back over up to two words.
_DOCTOR_BEFORE = re.compile(r"\b(?:Dr|Doctor|Prof)\.?\s+(?:[\w.]+\s+){0,2}$", re.IGNORECASE)

# Single tokens that are common words or programme names: never register them as names.
DOCTOR_WORDS = {"dr", "doctor", "prof"}

# Districts are kept (the policy generalises location to district). Uttar Pradesh district names:
# public geography, not patient data. They are never registered as address literals.
UP_DISTRICTS = {
    "sitapur", "lucknow", "barabanki", "rae bareli", "raebareli", "hardoi", "sultanpur", "unnao",
    "bahraich", "gonda", "lakhimpur kheri", "kanpur", "varanasi", "prayagraj", "allahabad", "agra",
    "meerut", "aligarh", "mathura", "bareilly", "moradabad", "etawah", "auraiya", "jhansi", "lalitpur",
    "mainpuri", "etah", "kannauj", "farrukhabad", "hamirpur", "banda", "chitrakoot", "pratapgarh",
    "jaunpur", "ghazipur", "ballia", "azamgarh", "mau", "deoria", "kushinagar", "gorakhpur", "basti",
    "siddharthnagar", "balrampur", "shravasti", "ayodhya", "faizabad", "ambedkar nagar", "amethi",
    "kaushambi", "fatehpur", "sambhal", "bijnor", "rampur", "shahjahanpur", "pilibhit", "budaun",
    "bulandshahr", "ghaziabad", "gautam buddha nagar", "hathras", "kasganj", "firozabad",
    "saharanpur", "muzaffarnagar", "shamli", "baghpat", "jalaun", "mahoba", "chandauli",
    "sonbhadra", "mirzapur", "bhadohi", "hapur", "maharajganj", "sant kabir nagar",
}

SINGLE_STOP = {
    "asha", "dear", "patient", "doctor", "ward", "bed", "name", "mother", "father", "baby",
    "male", "female", "kumar", "devi", "singh", "lal", "ram", "sharma",
}


def norm_tokens(text: str) -> list[str]:
    text = unicodedata.normalize("NFKC", text).casefold()
    return [t for t in re.split(r"[\s._,\-/]+", text) if t]


class Registry:
    def __init__(self) -> None:
        self._full: dict[str, str] = {}     # "mahesh chauhan" -> PATIENT_NAME
        self._single: dict[str, str] = {}   # "shahid" -> PATIENT_NAME (honorific context only)
        self._rx: re.Pattern | None = None

    def add(self, name: str, kind: str) -> None:
        """Register a person's name. Two-token names are also registered in reverse order (Surname First)."""
        toks = norm_tokens(name)
        if not toks or any(len(t) < 2 for t in toks):
            return
        if toks[0] in DOCTOR_WORDS:
            return  # a doctor is not a patient, whatever column or key holds the name
        if len(toks) >= 2:
            self._full.setdefault(" ".join(toks), kind)
            self._full.setdefault(" ".join(reversed(toks)), kind)
        elif len(toks[0]) >= 4 and toks[0] not in SINGLE_STOP:
            self._single.setdefault(toks[0], kind)
        self._rx = None

    def add_literal(self, value: str, kind: str) -> None:
        """Register an exact address piece or ID (for example 'H.No. 364', 'Mohalla Raja Bazar', '229073')."""
        toks = norm_tokens(value)
        if not toks or sum(len(t) for t in toks) < 4:
            return
        self._full.setdefault(" ".join(toks), kind)
        self._rx = None

    def __len__(self) -> int:
        return len(self._full) + len(self._single)

    def _compile(self) -> re.Pattern | None:
        keys = list(self._full) + list(self._single)
        if not keys:
            return None
        keys.sort(key=lambda k: (-len(k), k))  # longest first: "mahesh chauhan" before "mahesh"
        alts = []
        for k in keys:
            alts.append(_SEP.join(re.escape(t) for t in k.split(" ")))
        return re.compile(_WORD_BEFORE + "(?:" + "|".join(alts) + ")" + _WORD_AFTER,
                          re.IGNORECASE | re.UNICODE)

    def _kind_of(self, matched: str) -> str:
        toks = norm_tokens(matched)
        key = " ".join(toks)
        return self._full.get(key) or self._single.get(key, "PATIENT_NAME")

    def replace(self, text: str) -> tuple[str, int]:
        """Replace every registered name. Returns (text, count)."""
        if not text:
            return text, 0
        if self._rx is None:
            self._rx = self._compile()
            if self._rx is None:
                return text, 0
        count = 0
        out, last = [], 0
        for m in self._rx.finditer(text):
            if _DOCTOR_BEFORE.search(text[max(0, m.start() - 40):m.start()]):
                continue  # "Dr. Ramesh" stays
            out.append(text[last:m.start()])
            out.append(f"[{self._kind_of(m.group(0))}]")
            last = m.end()
            count += 1
        if count == 0:
            return text, 0
        out.append(text[last:])
        return "".join(out), count


def find_spans(self, text: str) -> list[tuple[int, int, str]]:
    """Positions of every registered name or address literal in text: (start, end, kind). Doctors are skipped."""
    if not text:
        return []
    if self._rx is None:
        self._rx = self._compile()
        if self._rx is None:
            return []
    spans = []
    for m in self._rx.finditer(text):
        if _DOCTOR_BEFORE.search(text[max(0, m.start() - 40):m.start()]):
            continue
        spans.append((m.start(), m.end(), self._kind_of(m.group(0))))
    return spans


Registry.find_spans = find_spans
