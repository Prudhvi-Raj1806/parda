"""Structured identifier detection: column/key classifier and value patterns.

Lane 2 of the team plan. Standard library only.

Two kinds of rule:
  * header rules: a column (CSV header) or JSON key whose NAME says it holds personal data
    is redacted in every row, whatever the value looks like. Medical columns are never
    matched here.
  * value patterns: identifiers recognised by their shape (Aadhaar, ABHA, PAN, phones,
    e-mail, hospital MRN/UHID, insurance IDs), applied to any text.

Placeholders are typed, e.g. "[PHONE]", so the output shows what was removed.
"""

from __future__ import annotations

import re

# Ordered: the first matching header rule wins.
# Matched against the normalised header: lower case, letters and digits only.
HEADER_RULES: list[tuple[str, re.Pattern]] = [
    # Hindi headers arrive romanised in the practice data: Naam, Pita/Pati ka Naam, Janm Tithi, Pata, Jila.
    ("RELATIVE_NAME", re.compile(r"relativename|guardian|fathername|husbandname|spousename|"
                                 r"mothername|pitaname|patakaname|pitapati|patikanaam")),
    ("PATIENT_NAME", re.compile(r"^patientname$|fullname|firstname|lastname|surname|^naam$|"
                                r"patientsname|^name$|^given$|^family$|^local$")),  # bare "name" is skipped in JSON, see below
    ("DOB", re.compile(r"^dob$|dateofbirth|birthdate|^birth|dobmm|janm")),
    ("AADHAAR", re.compile(r"aadhaar|aadhar|adhar|^uid$")),
    ("ABHA_NUMBER", re.compile(r"abha")),
    ("PAN", re.compile(r"^pan$|payerpan|pannumber")),
    ("EMAIL", re.compile(r"email|mailid")),
    ("PHONE", re.compile(r"mobile|phone|contactno|cellno|^contact$")),
    ("INSURANCE_ID", re.compile(r"pmjay|policyno|insuranceid|ayushman|^policy$")),
    ("MRN", re.compile(r"uhid|^mrn|mrno|ipdno|^ipd$|patientid|^regno|registrationno|regnumber")),
    # District and city are kept: they are the generalised location the policy allows.
    ("ADDRESS", re.compile(r"address|street|village|mohalla|tehsil|tahsil|locality|landmark|"
                           r"housenumber|^house$|^hno$|^gaon$|^pata$|^thana$|^line$|"
                           r"^zip$|pincode|^pin$|^city$")),
]

# A bare "name" key in JSON is often an organisation or a FHIR element, not a person.
JSON_SKIP = {"name"}


def normalise_header(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def classify_header(name: str, in_json: bool = False) -> str | None:
    """Return the PII type a column or key holds by its name, or None."""
    n = normalise_header(name)
    if not n or (in_json and n in JSON_SKIP):
        return None
    for kind, rx in HEADER_RULES:
        if rx.search(n):
            return kind
    return None


# Ordered value patterns: ABHA and masked Aadhaar before the plain 12-digit and phone shapes.
VALUE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("ABHA_NUMBER", re.compile(r"(?<![\d-])\d{2}-\d{4}-\d{4}-\d{4}(?![\d-])")),
    ("AADHAAR_MASKED", re.compile(r"X{4}\s?X{4}\s?\d{4}")),
    ("AADHAAR", re.compile(r"(?<![\d-])\d{4}[ -]?\d{4}[ -]?\d{4}(?![\d-])")),
    ("PAN", re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")),
    ("EMAIL", re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")),
    ("INSURANCE_ID", re.compile(r"PMJAY-[A-Z]{2}-\d+")),
    ("INSURANCE_ID", re.compile(r"\bPOL/\d+/\d+")),
    ("MRN", re.compile(r"(?<![A-Za-z0-9])(?:UHID|JJH|SNJ|DHH\d{0,4})[-/]\d[\d/-]*")),
    ("MRN", re.compile(r"(?<![A-Za-z0-9])(?i:IPD?|ADM|OPD?|MRN)[-/]?(?:\d{2,4}[-/])?\d{4,}(?:[-/]\d+)*")),
    ("PHONE", re.compile(r"(?<![\d-])(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?![\d-])")),
    # Devanagari digits: a 10-digit mobile written in Hindi numerals (phones start with 6-9)
    ("PHONE", re.compile(r"(?<![०-९])[६-९][०-९]{9}(?![०-९])")),
]


def redact_text(text: str) -> tuple[str, int]:
    """Replace identifier shapes in free text. Returns (text, number of replacements)."""
    total = 0
    for kind, rx in VALUE_PATTERNS:
        text, n = rx.subn(f"[{kind}]", text)
        total += n
    return text, total


def placeholder(kind: str) -> str:
    return f"[{kind}]"
