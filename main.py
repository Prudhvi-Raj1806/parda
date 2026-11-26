#!/usr/bin/env python3
"""Secret Wards privacy firewall: entry point.

Two passes, offline, standard library only:
  pass 1 (read only): learn names, addresses and dates from structured fields and labelled text into an
                      in-memory registry; collect strong identifiers per record and link records (rakshak/link.py);
  pass 2 (write):     sanitise every file: column and key rules, identifier shapes, the registry replaced everywhere
                      (values, keys, file names, base64), the patient pseudonym written into each linked record,
                      then sanitized/, report.json and records.jsonl.

Files that cannot be parsed are quarantined, never copied. Nothing personal is printed or logged.
Usage: python main.py --input <input dir> --output <empty output dir>   (needs RAKSHA_SECRET)
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import hmac
import io
import json
import os
import re
import sys
import time
from pathlib import Path

from rakshak.detect_struct import classify_header, redact_text, placeholder
from rakshak.detect_text import find_names, looks_like_person, redact_honorific_singles
from rakshak.hidden import decode_b64_text, encode_b64_text, scrub_rel_path
from rakshak.link import Linker, extract_keys, name_dob_keys
from rakshak.registry import Registry, UP_DISTRICTS


def load_policy(path: Path) -> dict:
    """Tiny `key: value` reader for config/policy.yaml (no PyYAML needed)."""
    policy = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if ":" in line:
                k, v = (x.strip() for x in line.split(":", 1))
                policy[k] = int(v) if v.lstrip("-").isdigit() else v
    return policy


HERE = Path(__file__).resolve().parent
POLICY = load_policy(HERE / "config" / "policy.yaml")
SECRET = os.environ.get("RAKSHA_SECRET", "").encode()  # never print or write this

NAME_KINDS = {"PATIENT_NAME", "RELATIVE_NAME"}
# Keys that show an object describes a person, so its bare "name" key is the person's name.
PERSON_CONTEXT = {"DOB", "MRN", "AADHAAR", "ABHA_NUMBER", "PAN", "EMAIL", "INSURANCE_ID"}

REGISTRY = Registry()   # filled in pass 1, read-only in pass 2
LINKER = Linker()       # filled in pass 1 (strong identifiers), read-only in pass 2
CURRENT_PID: str | None = None  # the patient pseudonym of the unit being written
CURRENT_UNIT_KEY: str | None = None  # fixes this unit's date shift (pseudonym, or the record)
CURRENT_MONTH_FIRST = False  # the column header says MM/DD, so its dates are month-first


# --------------------------------------------------------------------------- pseudonyms & dates
_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # Crockford base32: no I, L, O, U


def pseudonym(patient_key: str) -> str:
    """Stable, non-reversible ID: HMAC-SHA256 keyed with RAKSHA_SECRET (never a plain hash)."""
    digest = hmac.new(SECRET, patient_key.encode("utf-8"), hashlib.sha256).digest()
    n = int.from_bytes(digest[:5], "big")
    code = "".join(_ALPHABET[(n >> (5 * i)) & 31] for i in range(6))
    return f"PSN-{code}"


def date_shift_days(patient_key: str) -> int:
    """Per-patient shift in [-max, +max], never 0. Every date of one patient moves by the same amount."""
    m = int(POLICY.get("date_shift_max_days", 180))
    d = hmac.new(SECRET, b"shift|" + patient_key.encode("utf-8"), hashlib.sha256).digest()
    v = int.from_bytes(d[:4], "big") % (2 * m) - m
    return v if v != 0 else 1


def shift_date(value: dt.date, patient_key: str) -> dt.date:
    return value + dt.timedelta(days=date_shift_days(patient_key))


def age_band(age: int) -> str:
    """Bands that contain the true age."""
    w = int(POLICY.get("age_band_years", 5))
    lo = (age // w) * w
    return f"{lo}-{lo + w - 1}"


# --------------------------------------------------------------------------- cleaning
class Stats:
    identifiers = 0
    records = 0
    linked = 0
    generalized = 0
    suppressed = 0


DATE_DMY_TXT = re.compile(r"(?<![\d/-])(\d{1,2})([/-])(\d{1,2})\2(\d{4})(?![\d/-])")
DATE_ISO_TXT = re.compile(r"(?<![\d-])(\d{4})-(\d{2})-(\d{2})(?![\d-])")


def _shift_one(y: int, m: int, d: int, key: str) -> dt.date | None:
    try:
        return shift_date(dt.date(y, m, d), key)
    except ValueError:
        return None


def shift_dates_in_text(text: str, key: str, month_first_hint: bool = False) -> tuple[str, int]:
    """Move every date in the text by the unit's own offset. Format and separators are kept, so a
    9-day stay is still a 9-day stay. Returns (text, number of dates shifted)."""
    count = 0

    def dmy(m: re.Match) -> str:
        nonlocal count
        a, sep, b, y = int(m.group(1)), m.group(2), int(m.group(3)), int(m.group(4))
        if a > 12 and b <= 12:
            month_first = False  # the first number cannot be a month: day-first
        elif b > 12 and a <= 12:
            month_first = True   # the second number cannot be a month: month-first
        else:
            month_first = month_first_hint
        day, mon = (b, a) if month_first else (a, b)
        shifted = _shift_one(y, mon, day, key)
        if shifted is None:
            return "[DATE]"
        count += 1
        if month_first:
            return f"{shifted.month:02d}{sep}{shifted.day:02d}{sep}{shifted.year}"
        return f"{shifted.day:02d}{sep}{shifted.month:02d}{sep}{shifted.year}"

    def iso(m: re.Match) -> str:
        nonlocal count
        shifted = _shift_one(int(m.group(1)), int(m.group(2)), int(m.group(3)), key)
        if shifted is None:
            return "[DATE]"
        count += 1
        return shifted.isoformat()

    text = DATE_DMY_TXT.sub(dmy, text)
    text = DATE_ISO_TXT.sub(iso, text)
    return text, count


def clean_age(value: str) -> str:
    """Age becomes the 5-year band that contains it: '48' -> '45-49', '65/F' -> '65-69/F'."""
    m = re.match(r"\s*(\d{1,3})(?!\d)", value)
    if not m:
        return "[AGE]"
    return age_band(int(m.group(1))) + value[m.end():]


PATH_ID_RX = re.compile(r"(?<=[A-Za-z]_)\d{5,8}(?=[\\/_.]|$)")


def clean_text(text: str) -> str:
    """Registry names, honorific names, then identifier shapes. Used on every string in every channel."""
    if "\\" in text:  # a source path: the digits after a name are the patient's hospital number
        text = PATH_ID_RX.sub("[MRN]", text)
    text, n_names = REGISTRY.replace(text)
    text, n_hon = redact_honorific_singles(text)
    text, n_shapes = redact_text(text)
    if CURRENT_UNIT_KEY:
        text, n_dates = shift_dates_in_text(text, CURRENT_UNIT_KEY)
        Stats.generalized += n_dates
    Stats.identifiers += n_names + n_hon + n_shapes
    return text


ADDRESS_LABEL_RX = re.compile(r"(?i)(?:\baddress|\baddr\.?|पता|ग्राम|गाँव|गांव)\s*[:\-]\s*([^\n]+)")
ADDRESS_PREFIX_RX = re.compile(r"(?i)^(?:gram|gaon|village|vill\.?|tehsil|teh\.?|mohalla|moh\.?|near|opp\.?)\s+")


def address_in_text(text: str) -> None:
    """'Address: House 364, Ward 20, ...' in free text: the pieces after the label are addresses too."""
    for m in ADDRESS_LABEL_RX.finditer(text):
        add_address(m.group(1))


def add_address(value: str) -> None:
    """Address pieces ('H.No. 364', 'Mohalla Raja Bazar', '229073') become exact literals to remove everywhere.
    'Ward N' is skipped (a hospital ward is medical context). District names are kept (generalised
    location), but a PIN inside the same piece is still removed."""
    for piece in re.split(r"[,;|]", value):
        piece = piece.strip()
        if not piece:
            continue
        for pin in re.findall(r"(?<!\d)\d{6}(?!\d)", piece):
            REGISTRY.add_literal(pin, "PIN")
        if re.match(r"(?i)\s*ward\b", piece) or re.search(r"(?i)\b(?:distt|district|dist)\b", piece):
            continue
        if re.sub(r"[^a-z ]", "", piece.lower()).strip() in UP_DISTRICTS:
            continue
        core = re.sub(r"\s*-?\s*\d{6}\s*$", "", piece)
        REGISTRY.add_literal(core, "ADDRESS")
        bare = ADDRESS_PREFIX_RX.sub("", core)  # "Gram Gopaldih" also means "Gopaldih"
        if bare != core:
            REGISTRY.add_literal(bare, "ADDRESS")


DOCTOR_PREFIX = re.compile(r"^\s*(?:Dr|Doctor|Prof)\.?\s", re.IGNORECASE)


def clean_str(value: str, kind: str | None) -> str:
    """One string. A column or key that holds `kind` is replaced whole; a patient name becomes the
    unit's pseudonym; base64 is decoded and re-encoded."""
    if value.strip() == "":
        return value
    if kind in NAME_KINDS and DOCTOR_PREFIX.match(value):
        kind = None  # "Dr. Ramesh Srivastava" is a doctor: keep the title, scrub only what the registry knows
    if kind == "AGE":
        Stats.generalized += 1
        return clean_age(value)
    if kind in ("DOB", "DATE"):
        if CURRENT_UNIT_KEY:
            shifted, n = shift_dates_in_text(value, CURRENT_UNIT_KEY, CURRENT_MONTH_FIRST)
            Stats.generalized += n
            if n:
                return shifted
        Stats.identifiers += 1
        return placeholder(kind)
    if kind is not None:
        Stats.identifiers += 1
        if kind == "PATIENT_NAME" and CURRENT_PID:
            return CURRENT_PID  # the name field carries the pseudonym inside the record
        return placeholder(kind)
    text = decode_b64_text(value)
    if text is not None:
        cleaned = clean_text(text)
        return encode_b64_text(cleaned) if cleaned != text else value
    return clean_text(value)


def extension_kind(node: dict) -> str | None:
    """A FHIR extension says what its value is: mothers-name, fathers-name, patient-name ..."""
    url = node.get("url")
    if not isinstance(url, str):
        return None
    u = url.lower()
    if any(w in u for w in ("mother", "father", "guardian", "husband", "spouse", "relative")):
        return "RELATIVE_NAME"
    if "name" in u:
        return "PATIENT_NAME"
    return None


def key_kind(key: str, person_here: bool, value) -> str | None:
    """Which PII type a JSON key holds. A bare 'name' key counts only in a person object or as a person-shaped value."""
    kind = classify_header(key, in_json=not person_here)
    if kind is None and re.sub(r"[^a-z]", "", key.lower()) == "name":
        if isinstance(value, str) and looks_like_person(value):
            kind = "PATIENT_NAME"
        elif isinstance(value, (dict, list)):
            kind = "PATIENT_NAME"  # FHIR name objects and {"english", "local"} name blocks
    return kind


def clean_value(v, kind: str | None = None):
    if isinstance(v, str):
        return clean_str(v, kind)
    if isinstance(v, bool) or v is None:
        return v
    if isinstance(v, (int, float)):
        if kind == "AGE":
            return clean_age(str(v))
        # A number under an identifier key (Aadhaar as a JSON number) is still an identifier.
        if kind is not None and kind not in ("ADDRESS",):
            Stats.identifiers += 1
            return placeholder(kind)
        return v
    if isinstance(v, list):
        return [clean_value(x, kind) for x in v]
    if isinstance(v, dict):
        person_here = any(classify_header(k, in_json=True) in PERSON_CONTEXT for k in v)
        ext = extension_kind(v)
        out = {}
        for k, x in v.items():
            kk = key_kind(k, person_here, x)
            if k == "valueString" and ext:
                kk = ext
            if kk is None and kind in NAME_KINDS:
                kk = kind  # children of a name object (FHIR name, {"english": .., "local": ..}) are name parts
            out[clean_text(k)] = clean_value(x, kk)  # keys keep their names; values under PII keys are cleaned
        return out
    return v


def clean_unit(item, pid: str | None, unit_key: str):
    """Clean one record. Its patient name fields carry the pseudonym; its dates use its shift."""
    global CURRENT_PID, CURRENT_UNIT_KEY
    CURRENT_PID, CURRENT_UNIT_KEY = pid, unit_key
    try:
        return clean_value(item)
    finally:
        CURRENT_PID, CURRENT_UNIT_KEY = None, None


# --------------------------------------------------------------------------- pass 1: collect
def decoded_text(value: str) -> str:
    """The text of a string, or the decoded text of a base64 attachment."""
    return decode_b64_text(value) or value


def collect_csv(text: str, delimiter: str) -> None:
    rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=delimiter))
    if len(rows) < 2:
        return
    header, body = rows[0], rows[1:]
    kinds = [classify_header(h) for h in header]
    for row in body:
        for j, cell in enumerate(row):
            kind = kinds[j] if j < len(kinds) else None
            if kind in NAME_KINDS and cell.strip():
                REGISTRY.add(cell, kind)
            elif kind == "ADDRESS" and cell.strip():
                add_address(cell)
            for name, nk in find_names(decoded_text(cell)):  # base64 attachments in cells
                REGISTRY.add(name, nk)
            address_in_text(decoded_text(cell))
        for name, kind in find_names(" | ".join(row)):
            REGISTRY.add(name, kind)


def collect_json(node, kind: str | None = None) -> None:
    if isinstance(node, dict):
        person_here = any(classify_header(k, in_json=True) in PERSON_CONTEXT for k in node)
        ext = extension_kind(node)
        for k, x in node.items():
            kk = key_kind(k, person_here, x)
            if k == "valueString" and ext:
                kk = ext
            if kk is None and kind in NAME_KINDS:
                kk = kind
            collect_json(x, kk)
    elif isinstance(node, list):
        for x in node:
            collect_json(x, kind)  # a list under a PII key holds that kind (e.g. address lines)
    elif isinstance(node, str):
        if kind in NAME_KINDS:
            REGISTRY.add(node, kind)
        elif kind == "ADDRESS":
            add_address(node)
        for name, nk in find_names(decoded_text(node)):
            REGISTRY.add(name, nk)
        address_in_text(decoded_text(node))


def collect_text(text: str) -> None:
    address_in_text(text)
    for name, kind in find_names(text):
        REGISTRY.add(name, kind)


# --------------------------------------------------------------------------- units and linkage
def _pointer(k: str) -> str:
    return k.replace("~", "~0").replace("/", "~1")


def is_json_doc(data) -> bool:
    """A FHIR Bundle or a single object is one record; a dict of record lists is one record per item."""
    return not isinstance(data, dict) or data.get("resourceType") == "Bundle" or not any(
        isinstance(v, list) and v and all(isinstance(x, dict) for x in v) for v in data.values())


def iter_units(ext: str, text: str, delimiter: str):
    """Yield (loc, text) for each record of a file, with the same locators records.jsonl uses."""
    if ext in (".csv", ".tsv"):
        rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=delimiter))
        for i, row in enumerate(rows[1:]):
            yield f"row:{i}", delimiter.join(row)
    elif ext == ".json":
        data = json.loads(text)
        if is_json_doc(data):
            yield "doc", text
        else:
            for k, v in data.items():
                if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                    for i, item in enumerate(v):
                        yield f"/{_pointer(k)}/{i}", json.dumps(item, ensure_ascii=False)
    else:
        yield "doc", text


def link_pass(good) -> None:
    for _, rel, ext, text in good:
        delim = "\t" if ext == ".tsv" else ","
        for loc, unit_text in iter_units(ext, text, delim):
            LINKER.add_unit((rel, loc), extract_keys(unit_text))
    LINKER.finalize(pseudonym)


# --------------------------------------------------------------------------- pass 2: write
def decode(raw: bytes) -> str | None:
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", errors="strict")
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")
    for enc in ("utf-8", "cp1252"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return None


def process_csv(text: str, delimiter: str, rel_in: str, out_rel: str, records: list) -> str:
    global CURRENT_PID, CURRENT_UNIT_KEY, CURRENT_MONTH_FIRST
    rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=delimiter))
    if not rows:
        return ""
    header, body = rows[0], rows[1:]
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=delimiter, lineterminator="\n")
    w.writerow([clean_text(h) for h in header])
    kinds = [classify_header(h) for h in header]  # a column's name decides what it holds
    month_first = ["MM/DD" in h.upper() for h in header]  # 'DOB (MM/DD/YYYY)' is US-style
    for i, row in enumerate(body):
        pid = LINKER.pid((rel_in, f"row:{i}"))
        CURRENT_PID = pid
        CURRENT_UNIT_KEY = pid or f"{rel_in}|row:{i}"
        try:
            cleaned = []
            for j, c in enumerate(row):
                CURRENT_MONTH_FIRST = month_first[j] if j < len(month_first) else False
                cleaned.append(clean_str(c, kinds[j] if j < len(kinds) else None))
        finally:
            CURRENT_PID = None
            CURRENT_UNIT_KEY = None
            CURRENT_MONTH_FIRST = False
        w.writerow(cleaned)
        records.append({"file": f"sanitized/{out_rel}", "loc": f"row:{i}", "patient": pid})
        Stats.records += 1
        Stats.linked += pid is not None
    return buf.getvalue()


def process_json(data, rel_in: str, out_rel: str, records: list) -> str:
    if is_json_doc(data):  # FHIR Bundle or single object: one record for the whole file
        pid = LINKER.pid((rel_in, "doc"))
        records.append({"file": f"sanitized/{out_rel}", "loc": "doc", "patient": pid})
        Stats.records += 1
        Stats.linked += pid is not None
        # TODO(team): FHIR must stay a valid R4 Bundle whose references resolve
        return json.dumps(clean_unit(data, pid, pid or f"{rel_in}|doc"), ensure_ascii=False, indent=2) + "\n"
    person_here = any(classify_header(k, in_json=True) in PERSON_CONTEXT for k in data)
    out = {}
    for k, v in data.items():
        if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
            items = []
            for i, item in enumerate(v):
                loc = f"/{_pointer(k)}/{i}"
                pid = LINKER.pid((rel_in, loc))
                records.append({"file": f"sanitized/{out_rel}", "loc": loc, "patient": pid})
                Stats.records += 1
                Stats.linked += pid is not None
                items.append(clean_unit(item, pid, pid or f"{rel_in}|{loc}"))
            out[clean_text(k)] = items
        else:
            out[clean_text(k)] = clean_value(v, key_kind(k, person_here, v))
    return json.dumps(out, ensure_ascii=False, indent=2) + "\n"


def process_text(text: str, rel_in: str, out_rel: str, records: list) -> str:
    pid = LINKER.pid((rel_in, "doc"))
    records.append({"file": f"sanitized/{out_rel}", "loc": "doc", "patient": pid})
    Stats.records += 1
    Stats.linked += pid is not None
    global CURRENT_UNIT_KEY
    CURRENT_UNIT_KEY = pid or f"{rel_in}|doc"
    try:
        body = clean_text(text)
    finally:
        CURRENT_UNIT_KEY = None
    return (f"Patient ID: {pid}\n" + body) if pid else body


def peak_rss_mb() -> float:
    try:
        import resource
        r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return round(r / 1024 if sys.platform != "darwin" else r / 1048576, 1)
    except Exception:  # noqa: BLE001 - not available on every OS
        return 0.0


def main() -> int:
    ap = argparse.ArgumentParser(description="Secret Wards privacy firewall")
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    a = ap.parse_args()
    t0 = time.monotonic()
    inp, out = Path(a.input), Path(a.output)
    san = out / "sanitized"
    san.mkdir(parents=True, exist_ok=True)
    sys.setrecursionlimit(5000)
    if not SECRET:
        # Refuse to run: pseudonyms and date shifts would be keyed with an empty secret.
        print("error: RAKSHA_SECRET is not set", file=sys.stderr)
        return 2

    # Read every file once: decide quarantine, keep the decoded text for both passes.
    entries, good = [], []  # good: (entry, rel, ext, text)
    for path in sorted(p for p in inp.rglob("*") if p.is_file()):
        rel = path.relative_to(inp).as_posix()
        raw = path.read_bytes()
        entry = {"input_sha256": hashlib.sha256(raw).hexdigest()}
        entries.append(entry)
        ext = path.suffix.lower()
        try:
            if ext not in (".csv", ".tsv", ".json", ".txt"):
                raise ValueError("unsupported_format")
            if not raw.strip():
                raise ValueError("empty_file")
            text = decode(raw)
            if text is None:
                raise ValueError("undecodable_text")
            if ext == ".json":
                json.loads(text)  # validate before anything else
            good.append((entry, rel, ext, text))
        except (ValueError, RecursionError, UnicodeError, csv.Error) as exc:
            # Fail safe: never copy what we could not clean. The reason holds no file content.
            reason = str(exc) if isinstance(exc, ValueError) and str(exc).isidentifier() else type(exc).__name__
            entry.update(output=None, status="quarantined", reason=reason)

    # Pass 1: learn the registry and the strong identifiers (read only).
    for _, _, ext, text in good:
        if ext in (".csv", ".tsv"):
            collect_csv(text, "\t" if ext == ".tsv" else ",")
        elif ext == ".json":
            collect_json(json.loads(text))
        else:
            collect_text(text)
    link_pass(good)

    # Pass 2: sanitise and write.
    records = []
    used_paths: set[str] = set()
    for entry, rel, ext, text in good:
        try:
            out_rel = scrub_rel_path(rel, clean_text)  # file names can hold personal data
            if out_rel in used_paths:
                # Two inputs can scrub to one name: keep both, suffix derived from the input hash (deterministic)
                stem, dot, suffix = out_rel.rpartition(".")
                tag = entry["input_sha256"][:8]
                out_rel = f"{stem}__{tag}.{suffix}" if dot else f"{out_rel}__{tag}"
            used_paths.add(out_rel)
            if ext in (".csv", ".tsv"):
                result = process_csv(text, "\t" if ext == ".tsv" else ",", rel, out_rel, records)
            elif ext == ".json":
                result = process_json(json.loads(text), rel, out_rel, records)
            else:
                result = process_text(text, rel, out_rel, records)
            dest = san / out_rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(result, encoding="utf-8", newline="")
            entry.update(output=f"sanitized/{out_rel}", status="sanitized")
        except (ValueError, RecursionError, UnicodeError, csv.Error) as exc:
            reason = str(exc) if isinstance(exc, ValueError) and str(exc).isidentifier() else type(exc).__name__
            entry.update(output=None, status="quarantined", reason=reason)

    # Records whose file ended up quarantined must not be listed
    exported = {e["output"] for e in entries if e.get("output")}
    records = [r for r in records if r["file"] in exported]

    with open(out / "records.jsonl", "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")

    n_san = sum(e.get("status") == "sanitized" for e in entries)
    report = {
        "schema": "raksha-report/1",
        "files": entries,
        "counts": {
            "files_total": len(entries), "files_sanitized": n_san, "files_quarantined": len(entries) - n_san,
            "records_processed": len(records), "identifiers_detected": Stats.identifiers,
            "records_linked": sum(r["patient"] is not None for r in records),
            "records_generalized": Stats.generalized, "records_suppressed": Stats.suppressed,
            "records_quarantined": 0,
        },
        "timing": {"seconds": round(time.monotonic() - t0, 2)},
        "resources": {"peak_rss_mb": peak_rss_mb()},
    }
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    # Only counts go to stdout: stdout and stderr are scanned for PII.
    print(f"files {len(entries)} sanitized {n_san} quarantined {len(entries) - n_san} records {len(records)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
