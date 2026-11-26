"""PII and clinical candidate spans. Detection never edits text: it returns spans, and engine/sanitize.py decides.

Priorities (higher wins an overlap), from the plan's order of evidence:
  5  high-confidence identifiers (Aadhaar, ABHA, PAN, e-mail, hospital numbers, insurance IDs, phones)
  4  contextual roles (labelled names, relatives, honorifics, names next to a phone)
  3  clinical protection (medicines, doses, frequencies, vitals, labs, diagnoses, procedures, doctors)
  2  dataset-derived names (the registry learned from this input)
  1  generic patterns (address literals, dates)
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from engine.config import Rules, norm_key
from engine.names import role_spans

P_ID, P_ROLE, P_CLINICAL, P_DATASET, P_GENERIC = 5, 4, 3, 2, 1


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    kind: str                 # PII kind, or CLINICAL for protected text (never edited)
    priority: int
    replacement: str | None = None   # None: a typed placeholder [KIND]; CLINICAL spans keep their text
    detector: str = ""

    @property
    def length(self) -> int:
        return self.end - self.start


# ---------------------------------------------------------------- structured column and key names
ROLE_KIND = {
    "patient_name": "PATIENT_NAME", "relative_name": "RELATIVE_NAME", "phone": "PHONE", "email": "EMAIL",
    "aadhaar": "AADHAAR", "abha": "ABHA_NUMBER", "pan": "PAN", "hospital_id": "MRN",
    "insurance_id": "INSURANCE_ID", "dob": "DOB", "address": "ADDRESS", "age": "AGE", "date": "DATE",
}
# Checked in this order: a 'Father Name' is a relative before it is a patient name; 'Patient ID' is a hospital ID.
ROLE_ORDER = [
    "relative_name", "hospital_id", "insurance_id", "aadhaar", "abha", "pan", "email", "phone",
    "dob", "age", "date", "address", "patient_name",
]


# A value that reads like a postal address, whatever its column is called: house or plot markers, a mohalla,
# a tehsil or district line, a village or gram name with a PIN. Deliberately strict: clinical notes do not
# use these words, so a clinical cell is never taken for an address.
_ADDRESS_VALUE = re.compile(r"(?i)\b(?:h\.?\s?no\.?|house no|makan no\.?|mohalla|mohal+a|tehsil|tahsil|distt\.?|gram|gaon|pin code|pincode)\b")


def value_kind(value: str) -> str | None:
    """'ADDRESS' for a value that reads as an address, otherwise None (used where a header says nothing)."""
    if len(value) >= 15 and _ADDRESS_VALUE.search(value):
        return "ADDRESS"
    return None


def _squeeze(s: str) -> str:
    return s.replace(" ", "")


class HeaderClassifier:
    """Maps a column header or JSON key to a PII kind using config/aliases.yaml."""

    def __init__(self, rules: Rules) -> None:
        self._aliases = {}
        for role in ROLE_ORDER:
            self._aliases[role] = [_squeeze(a) for a in rules.aliases.get(role, [])]
        self._cache: dict[str, str | None] = {}

    def classify(self, header: str, in_json: bool = False) -> str | None:
        key = header if not in_json else "json|" + header
        if key in self._cache:
            return self._cache[key]
        nk = norm_key(header)
        result = None
        if nk and not (in_json and nk == "name"):  # a bare 'name' key in JSON is decided by its object
            squeezed = _squeeze(nk)
            first = nk.split(" ")[0]
            for role in ROLE_ORDER:
                for alias in self._aliases[role]:
                    if not alias:
                        continue
                    if squeezed == alias or (len(alias) >= 5 and alias in squeezed) or first == alias:
                        result = ROLE_KIND[role]
                        break
                if result:
                    break
        self._cache[key] = result
        return result


# ---------------------------------------------------------------- identifier shapes (free text and cells)
_SHAPES: list[tuple[str, re.Pattern, int]] = [
    ("ABHA_NUMBER", re.compile(r"(?<![\d-])\d{2}-\d{4}-\d{4}-\d{4}(?![\d-])"), P_ID),
    ("AADHAAR_MASKED", re.compile(r"X{4}\s?X{4}\s?\d{4}"), P_ID),
    ("AADHAAR", re.compile(r"(?<![\d-])\d{4}[ -]?\d{4}[ -]?\d{4}(?![\d-])"), P_ID),
    ("PAN", re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"), P_ID),
    ("EMAIL", re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"), P_ID),
    ("INSURANCE_ID", re.compile(r"PMJAY-[A-Z]{2}-\d+"), P_ID),
    ("INSURANCE_ID", re.compile(r"\bPOL/\d+/\d+"), P_ID),
    ("MRN", re.compile(r"(?<![A-Za-z0-9])(?:UHID|JJH|SNJ|DHH\d{0,4})[-/]\d[\d/-]*"), P_ID),
    ("MRN", re.compile(r"(?<![A-Za-z0-9])(?i:IPD?|ADM|OPD?|MRN)[-/]?(?:\d{2,4}[-/])?\d{4,}(?:[-/]\d+)*"), P_ID),
    ("PHONE", re.compile(r"(?<![\d-])(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?![\d-])"), P_ID),
    # Devanagari digits: a 10-digit mobile written in Hindi numerals (mobiles start with 6-9).
    ("PHONE", re.compile(r"(?<![०-९])[६-९][०-९]{9}(?![०-९])"), P_ID),
]

_DATE_DMY = re.compile(r"(?<![\d/-])(\d{1,2})([/-])(\d{1,2})\2(\d{4})(?![\d/-])")
_DATE_ISO = re.compile(r"(?<![\d-])(\d{4})-(\d{2})-(\d{2})(?![\d-])")
PATH_ID = re.compile(r"(?<=[A-Za-z]_)\d{5,8}(?=[\\/_.]|$)")
PIN_LITERAL = re.compile(r"(?<!\d)\d{6}(?!\d)")


def shape_spans(text: str) -> list[Span]:
    out: list[Span] = []
    for kind, rx, prio in _SHAPES:
        for m in rx.finditer(text):
            out.append(Span(m.start(), m.end(), kind, prio, detector="shape"))
    if "\\" in text:  # source paths: the digits after a name are the hospital number
        for m in PATH_ID.finditer(text):
            out.append(Span(m.start(), m.end(), "MRN", P_ID, detector="path"))
    return out


def date_spans(text: str, shift) -> list[Span]:
    """Every date is replaced. `shift(...)` returns the replacement text (a shifted date, or [DATE] when the
    date cannot be read), so an unreadable date is never left in the output."""
    out: list[Span] = []
    for m in _DATE_DMY.finditer(text):
        a, sep, b, y = int(m.group(1)), m.group(2), int(m.group(3)), int(m.group(4))
        if a > 12 and b <= 12:
            month_first = False
        elif b > 12 and a <= 12:
            month_first = True
        else:
            month_first = None  # ambiguous: the caller's hint decides
        new = shift(y, a, b, month_first, "dmy", sep)
        out.append(Span(m.start(), m.end(), "DATE", P_GENERIC, replacement=new, detector="date"))
    for m in _DATE_ISO.finditer(text):
        new = shift(int(m.group(1)), int(m.group(2)), int(m.group(3)), False, "iso", "-")
        out.append(Span(m.start(), m.end(), "DATE", P_GENERIC, replacement=new, detector="date"))
    return out


# ---------------------------------------------------------------- clinical protection
_CLINICAL: list[re.Pattern] = [
    re.compile(r"(?<![\w.])\d+(?:\.\d+)?\s?(?:mg|mcg|µg|ml|IU|units?)\b", re.IGNORECASE),        # doses
    re.compile(r"\b\d\s?-\s?\d\s?-\s?\d\b"),                                                      # 1-0-1
    re.compile(r"\b(?:OD|BD|TDS|QID|HS|SOS|PRN)\b(?:\s*x\s*\d+\s*days?)?", re.IGNORECASE),      # frequencies
    re.compile(r"\bx\s*\d+\s*days?\b", re.IGNORECASE),                                          # course length
    re.compile(r"(?<![\d/])\d{2,3}/\d{2,3}(?![\d/])\s?(?:mmHg)?"),                              # blood pressure
    re.compile(r"\bSpO2\s*:?\s*\d{2,3}\s?%?", re.IGNORECASE),                                     # oxygen saturation
    re.compile(r"\d+(?:\.\d+)?\s?(?:g/dL|mg/dL|mmol/L|%|/cumm|/µL|/uL|mIU/L|ng/mL|U/L|IU/L|mEq/L|fL|pg)\b"),  # labs
    re.compile(r"\b[A-Z]\d{2}(?:\.\d{1,2})?\b"),                                                 # ICD-10 codes
    re.compile(r"\b\d+\s?(?:days?|nights?|hrs?|hours?)\b", re.IGNORECASE),                        # stay length
    re.compile(r"\b[A-Za-z]+(?:pril|sartan|olol|statin|mycin|cillin|prazole|floxacin|cycline|dipine|"
               r"formin|azole|oxacin|tidine|parin|mab|nib)\b", re.IGNORECASE),                    # drug names
    re.compile(r"\bC/O\s+(?:fever|pain|cough|weakness|breathlessness|headache|vomiting|chest pain)\b",
               re.IGNORECASE),                                                                    # complaints
    re.compile(r"\bK/C/O\b|\bH/O\b"),                                                            # history markers
    re.compile(r"\b(?:Dr|Doctor|Prof)\.?\s+[A-Z][\w.]*(?:\s+[A-Z][\w.]*){0,2}(?:\s*\([^)]{1,30}\))?"),  # clinicians
]


def clinical_spans(text: str, terms: list[re.Pattern]) -> list[Span]:
    out: list[Span] = []
    for rx in _CLINICAL:
        for m in rx.finditer(text):
            out.append(Span(m.start(), m.end(), "CLINICAL", P_CLINICAL, detector="clinical"))
    for rx in terms:
        for m in rx.finditer(text):
            out.append(Span(m.start(), m.end(), "CLINICAL", P_CLINICAL, detector="term"))
    return out


def compile_terms(terms: list[str]) -> list[re.Pattern]:
    return [re.compile(r"(?<!\w)" + re.escape(t) + r"(?!\w)", re.IGNORECASE) for t in sorted(set(terms), key=len, reverse=True)]


def role_detected(text: str) -> list[Span]:
    return [Span(s, e, kind, P_ROLE, detector="role") for s, e, kind in role_spans(text)]
