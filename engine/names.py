"""Name discovery in free text (pass 1). Standard library only.

A name is found when it is:
  * after a label: "Name:", "Patient:", "Pt.:", "नाम:";
  * a relative: "S/o X", "D/o X", "W/o X", "C/O X" (C/O with a Title Case name, not a complaint);
  * before an honorific: "Asha ji", "Shahid sahab", "Meera didi";
  * near a phone number or a contact cue ("mob", "called by", "attendant", "guardian").

Words that look like names but are medical, facility or place words are rejected (STOP_TOKENS),
and a name after "Dr." is never registered (doctors are kept).
"""

from __future__ import annotations

import re

LAT_TOK = r"[A-Z][a-zA-Z'\-]{1,}"
CAPS_TOK = r"[A-Z]{2,}"
DEVA_TOK = r"[\u0900-\u097F]{2,}"
NAME_LAT = rf"{LAT_TOK}(?:\s+{LAT_TOK}){{1,2}}"
NAME_CAPS = rf"{CAPS_TOK}(?:\s+{CAPS_TOK}){{1,2}}"
NAME_DEVA = rf"{DEVA_TOK}(?:\s+{DEVA_TOK}){{1,2}}"
NAME_ANY = rf"(?:{NAME_LAT}|{NAME_CAPS}|{NAME_DEVA})"

HONORIFIC = r"(?i:ji|jee|sahab|sahib|didi|bhai|behenji|behen|bhabhi|chachi|mataji|kaka|babu)"

LABEL_RX = re.compile(
    r"(?i:\b(?:name|patient|pt|patient name|pt name|naam)\s*[:\-]\s*)(?P<n>" + NAME_ANY + ")"
    r"|नाम\s*[:\-]\s*(?P<d>" + NAME_DEVA + ")"
)
RELATIVE_RX = re.compile(r"(?<![A-Za-z])(?:S/o|D/o|W/o|S/O|D/O|W/O|s/o|d/o|w/o|C/O|C/o)\s+(?P<n>" + NAME_ANY + ")")
HONORIFIC_RX = re.compile(r"(?P<n>" + NAME_ANY + r"|[A-Z][a-z]{2,})\s+" + HONORIFIC + r"\b")
KIN = r"(?i:chachu|chacha|chachi|mama|mamu|mamaji|papa|papaji|bhaiya|bhaiyya|mausi|masi|dada|dadi|nana|nani|babuji)"
KIN_RX = re.compile(r"(?P<n>" + NAME_ANY + r"|[A-Z][a-z]{2,})\s+" + KIN + r"\b")
# Single first names before an honorific, for redaction in text (not registered: "Asha" is also a programme).
HON_SINGLE_RX = re.compile(r"(?<![\w.])(?P<n>[A-Z][a-z]{2,})(?=\s+(?i:ji|sahab|sahib|didi|bhai|behenji|behen|bhabhi)\b)")
HON_SINGLE_KIN_RX = re.compile(r"(?<![\w.])(?P<n>[A-Z][a-z]{2,})(?=\s+(?i:chachu|chacha|mama|papa|bhaiya|mausi|masi)\b)")
CANDIDATE_RX = re.compile(r"(?<![\w.])(?P<n>" + NAME_ANY + r")(?![\w])")

PHONE_RX = re.compile(r"(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)|\d{2}-\d{4}-\d{4}-\d{4}")
CUE_RX = re.compile(r"(?i)\b(?:mob|mobile|phone|called by|attendant|visitor|guardian|relative|contact)\b")
RELATIVE_CUE_RX = re.compile(r"(?i)\b(?:guardian|relative|attendant|visitor)\b")

STOP_TOKENS = {
    # column and form words that sit next to values in exports
    "reg", "no", "abha", "naam", "ling", "umar", "pata", "gaon", "tehsil", "jila", "pin", "mobile",
    "aadhar", "aadhaar", "policy", "uhid", "ipd", "opd", "mrn", "dob", "sex", "gender", "file", "report",
    # qualifications and specialties that follow a clinician's name
    "md", "ms", "dm", "mbbs", "dnb", "mch", "medicine", "surgery", "neurology", "pulmonary", "pulmonology",
    "cardiology", "gynaecology", "gynecology", "orthopaedics", "orthopedics", "paediatrics", "pediatrics",
    "nephrology", "oncology", "pathology", "radiology", "consultant", "physician", "specialist",
    # places, facility and document words
    "ward", "bed", "hospital", "centre", "center", "clinic", "sadan", "charitable", "trust",
    "multispeciality", "multispecialty", "nursing", "home", "department", "dept", "mohalla",
    "tehsil", "district", "village", "block", "road", "colony", "nagar", "pani", "tanki",
    "mandir", "masjid", "gurudwara", "school", "primary", "bazar", "kotwali", "lab", "report",
    "discharge", "summary", "date", "time", "phone", "mobile", "email", "address", "name",
    "patient", "doctor", "dr", "result", "test", "sample", "collected", "reported", "visit",
    "opd", "ipd", "icu", "ot", "bp", "rx", "name", "relation", "gender", "age", "sex",
    # common clinical words
    "fever", "pain", "cough", "chest", "headache", "vomiting", "weakness", "dizziness",
    "diabetes", "hypertension", "dengue", "anaemia", "anemia", "haemoglobin", "hemoglobin",
    "sugar", "blood", "urine", "stool", "tablet", "tab", "syrup", "injection", "dose",
    "disease", "syndrome", "infection", "fracture", "surgery", "section", "hernia",
    "cholecystectomy", "laparoscopic", "caesarean", "inguinal", "repair", "panel",
    "addison", "parkinson", "parkinsons", "hepatitis", "asthma", "pneumonia", "stroke",
    "ecg", "xray", "ct", "mri", "cbc", "crp", "tsh", "kidney", "liver", "heart",
    "oxygen", "breathlessness", "abdominal", "pain", "sepsis", "malaria", "typhoid",
}
ORG_WORDS = STOP_TOKENS | {"pvt", "ltd", "limited", "health", "institute", "college", "pharmacy"}


def _tokens(s: str) -> list[str]:
    return re.split(r"\s+", s.strip())


# Devanagari label and function words that follow or precede a name in notes (आयु = age, को = to).
STOP_DEVA = {
    "आयु", "वर्ष", "ग्राम", "तारीख", "पता", "उम्र", "लिंग", "मोबाइल", "पिता", "पति", "माता",
    "ओपीडी", "पर्चा", "दिन", "को", "है", "से", "में", "का", "की", "के", "और", "नाम", "गाँव",
    "गांव", "तहसील", "जिला", "पिन", "मोहल्ला", "वार्ड", "बुखार", "दर्द", "जाँच", "रिपोर्ट",
}


def trim_stop(name: str) -> str:
    """Drop label and function words at either end: 'रीना निषाद आयु' -> 'रीना निषाद'."""
    toks = _tokens(name)
    while toks and (toks[-1].lower().strip(".,") in STOP_TOKENS or toks[-1] in STOP_DEVA):
        toks.pop()
    while toks and (toks[0].lower().strip(".,") in STOP_TOKENS or toks[0] in STOP_DEVA):
        toks.pop(0)
    return " ".join(toks)


# Generic-drug endings (ramipril, atorvastatin, azithromycin): a medicine is never a person's name.
DRUG_SUFFIX_RX = re.compile(r"(?:pril|sartan|olol|statin|mycin|cillin|prazole|floxacin|cycline|"
                            r"dipine|formin|azole|oxacin|tidine|parin|mab|nib|zumab)$")


def acceptable(name: str) -> bool:
    toks = [t.lower().strip(".,") for t in _tokens(name)]
    if not toks or any(len(t) < 2 for t in toks):
        return False
    if any(t in STOP_TOKENS or t in STOP_DEVA or DRUG_SUFFIX_RX.search(t) for t in toks):
        return False
    return True


def _after_doctor(text: str, start: int) -> bool:
    return bool(re.search(r"\bDr\.?\s*$", text[max(0, start - 6):start], re.IGNORECASE))


def find_names(text: str) -> list[tuple[str, str]]:
    """Return [(name, kind)] for names found in text. kind is PATIENT_NAME or RELATIVE_NAME."""
    if not text:
        return []
    found: list[tuple[str, str, int]] = []
    for m in LABEL_RX.finditer(text):
        name = m.group("n") or m.group("d")
        found.append((name, "PATIENT_NAME", m.start()))
    for m in RELATIVE_RX.finditer(text):
        found.append((m.group("n"), "RELATIVE_NAME", m.start()))
    for m in HONORIFIC_RX.finditer(text):
        found.append((m.group("n"), "PATIENT_NAME", m.start()))
    for m in KIN_RX.finditer(text):
        found.append((m.group("n"), "RELATIVE_NAME", m.start()))
    for m in CANDIDATE_RX.finditer(text):
        window = text[max(0, m.start() - 60): m.end() + 60]
        if PHONE_RX.search(window) or CUE_RX.search(window):
            kind = "RELATIVE_NAME" if RELATIVE_CUE_RX.search(window) and not PHONE_RX.search(window) else "PATIENT_NAME"
            found.append((m.group("n"), kind, m.start()))
    out, seen = [], set()
    for name, kind, start in found:
        name = trim_stop(name)
        key = (name, kind)
        if key in seen or not acceptable(name) or _after_doctor(text, start):
            continue
        seen.add(key)
        out.append((name, kind))
    return out


def looks_like_person(value: str) -> bool:
    """A whole value that is just a person's name (used for bare JSON 'name' keys)."""
    v = value.strip()
    if not (re.fullmatch(NAME_LAT, v) or re.fullmatch(NAME_CAPS, v) or re.fullmatch(NAME_DEVA, v)):
        return False
    return not any(t.lower() in ORG_WORDS for t in _tokens(v))


def redact_honorific_singles(text: str) -> tuple[str, int]:
    """'Asha ji', 'Jagdish chachu': a first name before an honorific or kin term is a person. Returns (text, n)."""
    n = 0

    def _sub(kind):
        def repl(m):
            nonlocal n
            if not acceptable(m.group("n")):
                return m.group(0)
            n += 1
            return f"[{kind}]"
        return repl

    text = HON_SINGLE_RX.sub(_sub("PATIENT_NAME"), text)
    text = HON_SINGLE_KIN_RX.sub(_sub("RELATIVE_NAME"), text)
    return text, n


def role_spans(text: str) -> list[tuple[int, int, str]]:
    """Positions of person names in running text, with the role they play: (start, end, kind).

    Labels ('Name: X'), relatives ('S/o X'), honorifics ('X ji'), kin terms ('X chachu') and candidates
    next to a phone number or contact cue. A name after 'Dr.' is never returned.
    """
    if not text:
        return []
    out: list[tuple[int, int, str]] = []

    def add(m: re.Match, group: str, kind: str) -> None:
        start, end = m.start(group), m.end(group)
        if start < 0:
            return
        raw = text[start:end]
        name = trim_stop(raw)
        if not name or not acceptable(name) or _after_doctor(text, start):
            return
        # Keep the span on the name's own tokens: label and function words at either end stay visible.
        tokens = list(re.finditer(r"\S+", raw))
        first = next((t for t in tokens if t.group(0).lower().strip(".,") not in STOP_TOKENS and t.group(0) not in STOP_DEVA), None)
        last = next((t for t in reversed(tokens) if t.group(0).lower().strip(".,") not in STOP_TOKENS and t.group(0) not in STOP_DEVA), None)
        if first is None or last is None:
            return
        out.append((start + first.start(), start + last.end(), kind))

    for m in LABEL_RX.finditer(text):
        group = "n" if m.group("n") else "d"
        add(m, group, "PATIENT_NAME")
    for m in RELATIVE_RX.finditer(text):
        add(m, "n", "RELATIVE_NAME")
    for m in HONORIFIC_RX.finditer(text):
        add(m, "n", "PATIENT_NAME")
    for m in KIN_RX.finditer(text):
        add(m, "n", "RELATIVE_NAME")
    for m in HON_SINGLE_RX.finditer(text):
        if acceptable(m.group("n")) and not _after_doctor(text, m.start("n")):
            out.append((m.start("n"), m.end("n"), "PATIENT_NAME"))
    for m in HON_SINGLE_KIN_RX.finditer(text):
        if acceptable(m.group("n")) and not _after_doctor(text, m.start("n")):
            out.append((m.start("n"), m.end("n"), "RELATIVE_NAME"))
    for m in CANDIDATE_RX.finditer(text):
        window = text[max(0, m.start() - 60): m.end() + 60]
        if PHONE_RX.search(window) or CUE_RX.search(window):
            kind = "RELATIVE_NAME" if RELATIVE_CUE_RX.search(window) and not PHONE_RX.search(window) else "PATIENT_NAME"
            add(m, "n", kind)
    return out
