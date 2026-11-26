"""Parda pipeline: ingestion, two passes, release gate, truthful report and records.

Pass 1 (read only) learns names, addresses and dates from every record, builds identity profiles, resolves
clusters and derives pseudonyms. Pass 2 sanitises each file into memory, runs the release gate on the bytes
it would publish, and writes only verified files. Failed files are withheld with a reason code.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from engine.config import ROOT, Rules, load_rules, norm_key
from engine.crypto import derive_key, pseudonym
from engine.detection import (P_DATASET, P_GENERIC, P_ID, HeaderClassifier, Span, clinical_spans,
                              compile_terms, date_spans, role_detected, shape_spans, value_kind)
from engine.hidden import decode_b64_text, encode_b64_text
from engine.ingestion import InputFile, ingest
from engine.linkage import Resolver, build_profile
from engine.names import looks_like_person, role_spans
from engine.privacy import DateShifter, age_band, age_text, widen_band
from engine.registry import Registry, UP_DISTRICTS
from engine.sanitize import apply as apply_spans

SCHEMA = "raksha-report/1"
NAME_KINDS = {"PATIENT_NAME", "RELATIVE_NAME"}
PERSON_CONTEXT = {"DOB", "MRN", "AADHAAR", "ABHA_NUMBER", "PAN", "EMAIL", "INSURANCE_ID"}
DOCTOR_PREFIX = re.compile(r"^\s*(?:Dr|Doctor|Prof)\.?\s", re.IGNORECASE)
ADDRESS_LABEL = re.compile(r"(?i)(?:\baddress|\baddr\.?|पता|ग्राम|गाँव|गांव)\s*[:\-]\s*([^\n]+)")
ADDRESS_PREFIX = re.compile(r"(?i)^(?:gram|gaon|village|vill\.?|tehsil|teh\.?|mohalla|moh\.?|near|opp\.?)\s+")
PIN_LITERAL = re.compile(r"(?<!\d)\d{6}(?!\d)")
GENDER_HEADER = re.compile(r"^(?:gender|sex|ling)$")
DATE_TEXT = re.compile(r"\d{1,4}[/-]\d{1,2}[/-]\d{1,4}|(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d|\d\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)")

FHIR_IDENTIFIER_SYSTEM = "urn:parda:pseudonym"


class Ctx:
    """What a unit (record or document) needs while it is written."""

    __slots__ = ("unit_key", "pid", "widened", "month_first")

    def __init__(self, unit_key: str | None, pid: str | None = None, widened: bool = False,
                 month_first: bool = False) -> None:
        self.unit_key = unit_key
        self.pid = pid
        self.widened = widened
        self.month_first = month_first


NO_CTX = Ctx(None)


@dataclass
class Unit:
    rel: str                      # input relative path
    loc: str                      # row:N, JSON pointer, or doc
    fields: list = field(default_factory=list)   # (kind, raw value) for structured parts
    text: str = ""                # text used for role names, identifiers and profile
    patients_named: int = 0       # FHIR Patient resources in the unit (ambiguous when more than one)


class Engine:
    def __init__(self, secret: bytes, rules: Rules) -> None:
        self.rules = rules
        self.policy = rules.policy
        self.secret = secret
        self.keys = {"dates": derive_key(secret, "dates"), "pseudonym": derive_key(secret, "pseudonym")}
        self.registry = Registry()
        self.classifier = HeaderClassifier(rules)
        self.terms = compile_terms(rules.clinical_terms)
        self.shifter = DateShifter(self.keys["dates"], self.policy)
        self.resolver = Resolver(self.policy.link_threshold)
        self.pid_of: dict[str, str] = {}          # unit key (rel|loc) -> pseudonym
        self.widened: set[str] = set()            # unit keys whose age band is widened (small class)
        self.applied = Counter()                  # entity kind -> count
        self.dates_shifted = 0
        self.ages_banded = 0
        self.records_generalized = set()
        self.risk_summary: dict = {}

    # ------------------------------------------------------------ classification helpers
    def key_kind(self, key: str, person_here: bool, value) -> str | None:
        kind = self.classifier.classify(key, in_json=not person_here)
        if kind is None and norm_key(key).replace(" ", "") == "name":
            if isinstance(value, (dict, list)) or (isinstance(value, str) and looks_like_person(value)):
                kind = "PATIENT_NAME"
        return kind

    def person_here(self, node: dict) -> bool:
        return any(self.classifier.classify(k, in_json=True) in PERSON_CONTEXT for k in node)

    def leaves(self, node, kind: str | None, out: list) -> None:
        """Every leaf value with the PII kind its position implies."""
        if isinstance(node, dict):
            ph = self.person_here(node)
            ext = extension_kind(node)
            for k, v in node.items():
                kk = self.key_kind(k, ph, v)
                if k == "valueString" and ext:
                    kk = ext
                if kk is None and kind in NAME_KINDS:
                    kk = kind
                if kk is None and kind == "ADDRESS":
                    kk = "ADDRESS"
                self.leaves(v, kk, out)
        elif isinstance(node, list):
            for v in node:
                self.leaves(v, kind, out)
        elif isinstance(node, (str, int, float)) and not isinstance(node, bool):
            out.append((kind, node if isinstance(node, str) else str(node)))

    # ------------------------------------------------------------ pass 1
    def learn_text(self, text: str) -> None:
        protected = [(sp.start, sp.end) for sp in clinical_spans(text, self.terms)]
        for s, e, k in role_spans(text):
            # A candidate inside clinical text (a clinician's credentials, a diagnosis) is not a patient.
            if any(ps < e and s < pe for ps, pe in protected):
                continue
            self.registry.add(text[s:e], k)
        for m in ADDRESS_LABEL.finditer(text):
            self.add_address(m.group(1))

    def add_address(self, value: str) -> None:
        for piece in re.split(r"[,;|]", value):
            piece = piece.strip()
            if not piece:
                continue
            for pin in PIN_LITERAL.findall(piece):
                self.registry.add_literal(pin, "PIN")
            if re.match(r"(?i)\s*ward\b", piece) or re.search(r"(?i)\b(?:distt|district|dist)\b", piece):
                continue
            if re.sub(r"[^a-z ]", "", piece.lower()).strip() in UP_DISTRICTS:
                continue
            core = re.sub(r"\s*-?\s*\d{6}\s*$", "", piece)
            self.registry.add_literal(core, "ADDRESS")
            bare = ADDRESS_PREFIX.sub("", core)
            if bare != core:
                self.registry.add_literal(bare, "ADDRESS")

    def learn_unit(self, unit: Unit) -> None:
        for kind, value in unit.fields:
            if kind in NAME_KINDS and value.strip():
                self.registry.add(value, kind)
            elif kind == "ADDRESS" and value.strip():
                self.add_address(value)
            if isinstance(value, str):
                plain = decode_b64_text(value)
                if plain:
                    self.learn_text(plain)
        self.learn_text(unit.text)

    def profile_unit(self, unit: Unit) -> None:
        fields = []
        for kind, value in unit.fields:
            if isinstance(value, str):
                fields.append((kind, value))
        text = unit.text + "\n" + "\n".join(v for _, v in fields if decode_b64_text(v))
        profile = build_profile(
            (unit.rel, unit.loc), text, fields,
            self.rules.name_variants,
            lambda t: [(t[s:e], k) for s, e, k in role_spans(t)],
        )
        if unit.patients_named > 1:
            profile.ambiguous = True
        self.resolver.add(profile)

    def assign_pseudonyms(self) -> None:
        clusters = self.resolver.resolve()
        anchors = self.resolver.anchors(clusters)
        taken: dict[str, str] = {}
        length_for: dict[str, int] = {}
        for unit_key in sorted(anchors):
            anchor = anchors[unit_key]
            if anchor not in length_for:
                length_for[anchor] = 6
            while True:
                pid = pseudonym(self.keys["pseudonym"], anchor, length_for[anchor])
                owner = taken.get(pid)
                if owner is None or owner == anchor:
                    taken[pid] = anchor
                    break
                length_for[anchor] += 2  # deterministic: collision on a short code, use a longer one
            self.pid_of[f"{unit_key[0]}|{unit_key[1]}"] = pid

    def plan_quasi_identifiers(self, units: list[Unit]) -> None:
        """Age band and gender per patient. A class (age band, gender) with fewer than k patients is widened."""
        self.risk_summary = {"quasi_identifier": "age band and sex", "k": self.policy.k_anonymity,
                             "classes": 0, "classes_below_k_before": 0, "classes_below_k_after": 0,
                             "units_widened": 0}
        classes: dict[tuple, set[str]] = defaultdict(set)
        member: dict[str, tuple] = {}
        for u in units:
            ages = [v for k, v in u.fields if k == "AGE" and v.strip()]
            genders = [v.strip().upper()[:1] for k, v in u.fields if k == "GENDER" and v.strip()]
            if not ages:
                continue
            m = re.match(r"\s*(\d{1,3})(?!\d)", ages[0])
            if not m:
                continue
            band = age_band(int(m.group(1)), self.policy)
            qi = (band, genders[0] if genders else "")
            key = self.unit_key(u)
            member[key] = qi
            classes[qi].add(self.patient_key(u))
        below = {qi for qi, pats in classes.items() if len(pats) < self.policy.k_anonymity}
        for key, qi in member.items():
            if qi in below:
                self.widened.add(key)
        # After widening, a small class (age band widened to 20 years) can still be small. Those are reported.
        widened_classes: dict[tuple, set[str]] = defaultdict(set)
        for u in units:
            key = self.unit_key(u)
            if key in member:
                qi = member[key]
                if qi in below:
                    lo_s = qi[0].partition("-")[0]
                    wide = widen_band(qi[0], self.policy)
                    widened_classes[(wide, qi[1])].add(self.patient_key(u))
                else:
                    widened_classes[qi].add(self.patient_key(u))
        self.risk_summary.update({
            "classes": len(classes),
            "classes_below_k_before": len(below),
            "classes_below_k_after": sum(1 for pats in widened_classes.values() if len(pats) < self.policy.k_anonymity),
            "units_widened": len(self.widened),
        })

    def unit_key(self, u: Unit) -> str:
        return f"{u.rel}|{u.loc}"

    def patient_key(self, u: Unit) -> str:
        return self.pid_of.get(self.unit_key(u)) or self.unit_key(u)

    def pid(self, rel: str, loc: str) -> str | None:
        return self.pid_of.get(f"{rel}|{loc}")

    # ------------------------------------------------------------ pass 2: text and cells
    def sanitize_text(self, text: str, ctx: Ctx, structural: bool = False) -> str:
        """Clean a string. `structural` marks a key, header or file-name part: only identifier shapes and
        dataset literals apply there, so a column called 'Relative Name' keeps its name."""
        if not text:
            return text
        spans: list[Span] = []
        spans += shape_spans(text)
        if not structural:
            spans += role_detected(text)
        for s, e, kind in self.registry.find_spans(text):
            spans.append(Span(s, e, kind, P_DATASET if kind in NAME_KINDS else P_GENERIC))
        if structural:
            result = apply_spans(text, spans)
            self.applied.update(result.applied)
            return result.text
        clinical = clinical_spans(text, self.terms)
        # A clinical term (a medicine or diagnosis from config) is never a name, even when a name pattern
        # matches it next to a phone or label. Identifiers are not affected.
        terms = [(c.start, c.end) for c in clinical if c.detector == "term"]
        spans = [sp for sp in spans if sp.priority >= P_ID or not any(sp.start < te and ts < sp.end for ts, te in terms)]
        spans += clinical
        if ctx.unit_key:
            spans += date_spans(text, self._date_fn(ctx))
        result = apply_spans(text, spans)
        self.applied.update(result.applied)
        if result.applied.get("DATE"):
            self.dates_shifted += result.applied["DATE"]
            if ctx.unit_key:
                self.records_generalized.add(ctx.unit_key)
        return result.text

    def _date_fn(self, ctx: Ctx):
        def shift(y, a, b, month_first, fmt, sep):
            return self.shifter(y, a, b, month_first, fmt, sep, ctx.unit_key, ctx.month_first)
        return shift

    def transform_value(self, value: str, kind: str | None, ctx: Ctx) -> str:
        if value.strip() == "":
            return value
        if kind in NAME_KINDS and DOCTOR_PREFIX.match(value):
            kind = None  # a doctor keeps the title; only the registry is applied
        if kind in ("PATIENT_NAME", "MRN") and ctx.pid:
            # The name field, or a hospital-number field when there is no name field, carries the pseudonym.
            self.applied[kind] += 1
            return ctx.pid
        if kind == "AGE":
            self.ages_banded += 1
            if ctx.unit_key:
                self.records_generalized.add(ctx.unit_key)
            band = age_text(value, self.policy)
            if ctx.widened and band[:1].isdigit():
                lo, _, rest = band.partition("-")
                hi_part = rest.split("/")[0]
                band = widen_band(f"{lo}-{hi_part}", self.policy) + rest[len(hi_part):]
            return band
        if kind in ("DATE", "DOB"):
            if DATE_TEXT.search(value) or re.search(r"\d{4}-\d{2}-\d{2}", value):
                out = self.sanitize_text(value, ctx)
                if "[DATE]" not in out:
                    return out
            self.applied[kind] += 1
            return f"[{kind}]"
        if kind == "GENDER":
            return value
        if kind is not None:
            self.applied[kind] += 1
            return f"[{kind}]"
        plain = decode_b64_text(value)
        if plain is not None:
            cleaned = self.sanitize_text(plain, ctx)
            return encode_b64_text(cleaned) if cleaned != plain else value
        return self.sanitize_text(value, ctx)

    # ------------------------------------------------------------ pass 2: structures
    def out_node(self, node, kind: str | None, ctx: Ctx):
        if isinstance(node, dict):
            ph = self.person_here(node)
            ext = extension_kind(node)
            out = {}
            for k, v in node.items():
                kk = self.key_kind(k, ph, v)
                if k == "valueString" and ext:
                    kk = ext
                if kk is None and kind in NAME_KINDS:
                    kk = kind
                if kk is None and kind == "ADDRESS":
                    kk = "ADDRESS"
                out[self.sanitize_text(k, NO_CTX)] = self.out_node(v, kk, ctx)
            return out
        if isinstance(node, list):
            return [self.out_node(v, kind, ctx) for v in node]
        if isinstance(node, bool) or node is None:
            return node
        if isinstance(node, (int, float)):
            if kind == "AGE":
                return age_text(str(node), self.policy)
            if kind is not None and kind != "ADDRESS" and kind != "GENDER":
                self.applied[kind] += 1
                return f"[{kind}]"
            return node
        return self.transform_value(node, kind, ctx)


def extension_kind(node: dict) -> str | None:
    url = node.get("url")
    if not isinstance(url, str):
        return None
    u = url.lower()
    if any(w in u for w in ("mother", "father", "guardian", "husband", "spouse", "relative")):
        return "RELATIVE_NAME"
    if "name" in u:
        return "PATIENT_NAME"
    return None


def is_fhir(data) -> bool:
    return isinstance(data, dict) and isinstance(data.get("resourceType"), str)


def is_json_doc(data) -> bool:
    return not isinstance(data, dict) or is_fhir(data) or not any(
        isinstance(v, list) and v and all(isinstance(x, dict) for x in v) for v in data.values())


def pointer_escape(k: str) -> str:
    return k.replace("~", "~0").replace("/", "~1")


def safe_out_path(rel: str) -> bool:
    if not rel or rel.startswith("/") or re.match(r"^[A-Za-z]:", rel):
        return False
    parts = rel.split("/")
    return all(p not in ("", ".", "..") and "\\" not in p for p in parts)


def peak_rss_mb() -> float | None:
    """Peak resident memory of this process, or None where the platform cannot report it (Windows)."""
    try:
        import resource
    except ImportError:
        return None
    r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return round(r / 1024 if sys.platform != "darwin" else r / 1048576, 1)


# =========================================================================== units
def csv_units(f: InputFile, delimiter: str, eng: Engine) -> tuple[list[Unit], list[str]]:
    rows = list(csv.reader(io.StringIO(f.text, newline=""), delimiter=delimiter))
    if not rows:
        return [], []
    header = rows[0]
    kinds = [eng.classifier.classify(h) for h in header]
    gender = [bool(GENDER_HEADER.match(norm_key(h).replace(" ", ""))) for h in header]
    units = []
    for i, row in enumerate(rows[1:]):
        fields = []
        for j, cell in enumerate(row):
            kind = kinds[j] if j < len(kinds) else None
            if kind is None and j < len(gender) and gender[j]:
                kind = "GENDER"
            fields.append((kind or value_kind(cell), cell))
        units.append(Unit(f.rel, f"row:{i}", fields, delimiter.join(row)))
    return units, [norm_key(h) for h in header]


def json_units(f: InputFile, eng: Engine) -> list[Unit]:
    data = f.data
    if f.kind == "fhir" or is_json_doc(data):
        fields: list = []
        eng.leaves(data, None, fields)
        patients = 0
        if f.kind == "fhir" and isinstance(data, dict):
            for entry in data.get("entry") or []:
                if isinstance(entry, dict) and isinstance(entry.get("resource"), dict):
                    if entry["resource"].get("resourceType") == "Patient":
                        patients += 1
            if data.get("resourceType") == "Patient":
                patients = 1
        return [Unit(f.rel, "doc", fields, f.text, patients_named=patients)]
    units = []
    for k, v in data.items():
        if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
            for i, item in enumerate(v):
                fields: list = []
                eng.leaves(item, None, fields)
                units.append(Unit(f.rel, f"/{pointer_escape(k)}/{i}", fields,
                                  json.dumps(item, ensure_ascii=False)))
    return units


def doc_unit(f: InputFile) -> Unit:
    return Unit(f.rel, "doc", [], f.text)


# =========================================================================== run
@dataclass
class Output:
    rel: str            # input path
    out_rel: str        # path under sanitized/
    data: bytes
    records: list
    reason: str | None = None
    protected: Counter = field(default_factory=Counter)   # clinical texts in the input (G4 fingerprint)
    identifiers: list = field(default_factory=list)       # identifier strings in the input (G2 scan)


def run_pipeline(input_dir: Path, output_dir: Path, secret: bytes, rules: Rules | None = None) -> dict:
    t0 = time.monotonic()
    rules = rules or load_rules()
    eng = Engine(secret, rules)

    accepted, quarantined = ingest(input_dir)
    accepted = [f for f in accepted]
    gate_failures: dict[str, str] = {}

    # ---- pass 1: learn (read only), profile, resolve identities, plan
    units_by_file: dict[str, list[Unit]] = {}
    headers_by_file: dict[str, list[str]] = {}
    for f in accepted:
        if f.kind in ("csv", "tsv"):
            units, headers = csv_units(f, "\t" if f.kind == "tsv" else ",", eng)
            headers_by_file[f.rel] = headers
        elif f.kind in ("json", "fhir"):
            units = json_units(f, eng)
        else:
            units = [doc_unit(f)]
        units_by_file[f.rel] = units
        for u in units:
            eng.learn_unit(u)
    for f in accepted:
        for u in units_by_file[f.rel]:
            eng.profile_unit(u)
    eng.assign_pseudonyms()
    all_units = [u for f in accepted for u in units_by_file[f.rel]]
    eng.plan_quasi_identifiers(all_units)

    # ---- pass 2: sanitise in memory, gate, then publish
    planned: dict[str, str] = {}
    used: set[str] = set()
    for f in accepted:
        out_rel = scrub_path(f.rel, eng)
        if out_rel in used or not safe_out_path(out_rel):
            stem, dot, ext = out_rel.rpartition(".")
            tag = f.sha256[:8]
            out_rel = f"{stem}__{tag}.{ext}" if dot else f"{out_rel}__{tag}"
        used.add(out_rel)
        planned[f.rel] = out_rel
    outputs: list[Output] = []
    for f in accepted:
        try:
            outputs.append(render_file(f, units_by_file[f.rel], eng, planned[f.rel]))
        except RecursionError:
            outputs.append(Output(f.rel, planned[f.rel], b"", [], reason="resource_limit"))

    verified: list[Output] = []
    for o in outputs:
        if o.reason is None:
            o.reason = gate(o, eng)
        verified.append(o)

    # ---- records: keep only records of published files
    published = {o.out_rel for o in verified if o.reason is None}
    records = []
    for o in verified:
        if o.reason is None:
            records.extend(o.records)
    records.sort(key=lambda r: (r["file"], r["loc"]))

    # ---- the input must be unchanged: re-read every accepted file and compare its hash
    for f in accepted:
        if hashlib.sha256((input_dir / f.rel).read_bytes()).hexdigest() != f.sha256:
            raise RuntimeError("input changed during the run; nothing was published")

    # ---- write verified bytes, records and report
    output_dir.mkdir(parents=True, exist_ok=True)
    san = output_dir / "sanitized"
    for o in verified:
        if o.reason is None:
            dest = san / o.out_rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(o.data)
    with open(output_dir / "records.jsonl", "w", encoding="utf-8", newline="\n") as fh:
        for r in records:
            fh.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")

    report = build_report(f_all=accepted, quarantined=quarantined, verified=verified, records=records,
                          eng=eng, started=t0)
    report["risk"] = eng.risk_summary
    (output_dir / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                                            encoding="utf-8", newline="\n")
    return report


def render_file(f: InputFile, units: list[Unit], eng: Engine, out_rel: str) -> Output:
    """Sanitise one file into bytes plus its record locators."""
    records: list[dict] = []
    if f.kind in ("csv", "tsv"):
        delim = "\t" if f.kind == "tsv" else ","
        rows = list(csv.reader(io.StringIO(f.text, newline=""), delimiter=delim))
        buf = io.StringIO()
        w = csv.writer(buf, delimiter=delim, lineterminator="\n")
        header = rows[0] if rows else []
        w.writerow([eng.sanitize_text(h, NO_CTX, structural=True) for h in header])
        kinds = [eng.classifier.classify(h) for h in header]
        month_first = ["MM/DD" in h.upper() for h in header]
        for i, row in enumerate(rows[1:]):
            loc = f"row:{i}"
            pid = eng.pid(f.rel, loc)
            key = pid or f"{f.rel}|{loc}"
            widened = key in eng.widened or f"{f.rel}|{loc}" in eng.widened
            cells = []
            for j, cell in enumerate(row):
                kind = kinds[j] if j < len(kinds) else None
                kind = kind or value_kind(cell)
                ctx = Ctx(key, pid, widened, month_first[j] if j < len(month_first) else False)
                cells.append(eng.transform_value(cell, kind, ctx))
            if pid and not any(pid in c for c in cells):
                # No name or hospital-number column was recognised: the pseudonym takes the place of the
                # first hospital-number value in the row, so the record still carries its patient ID.
                for j, cell in enumerate(row):
                    if any(s.kind == "MRN" for s in shape_spans(cell)):
                        cells[j] = pid
                        eng.applied["MRN"] += 1
                        break
            w.writerow(cells)
            records.append(record(f.rel, out_rel, loc, pid))
        data_text = buf.getvalue()
    elif f.kind in ("json", "fhir"):
        data = f.data
        doc_pid = eng.pid(f.rel, "doc")
        if f.kind == "fhir" or is_json_doc(data):
            key = doc_pid or f"{f.rel}|doc"
            ctx = Ctx(key, doc_pid, f"{f.rel}|doc" in eng.widened)
            out = eng.out_node(data, None, ctx)
            if f.kind == "fhir" and isinstance(out, dict) and out.get("resourceType") == "Patient" and doc_pid:
                out.setdefault("identifier", []).append({"system": FHIR_IDENTIFIER_SYSTEM, "value": doc_pid})
            data_text = json.dumps(out, ensure_ascii=False, indent=2) + "\n"
            records.append(record(f.rel, out_rel, "doc", doc_pid))
        else:
            out = {}
            ph = eng.person_here(data)
            for k, v in data.items():
                if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                    items = []
                    for i, item in enumerate(v):
                        loc = f"/{pointer_escape(k)}/{i}"
                        pid = eng.pid(f.rel, loc)
                        key = pid or f"{f.rel}|{loc}"
                        ctx = Ctx(key, pid, f"{f.rel}|{loc}" in eng.widened)
                        items.append(eng.out_node(item, None, ctx))
                        records.append(record(f.rel, out_rel, loc, pid))
                    out[eng.sanitize_text(k, NO_CTX, structural=True)] = items
                else:
                    kk = eng.key_kind(k, ph, v)
                    out[eng.sanitize_text(k, NO_CTX, structural=True)] = eng.out_node(v, kk, Ctx(f"{f.rel}|doc"))
            data_text = json.dumps(out, ensure_ascii=False, indent=2) + "\n"
    else:
        pid = eng.pid(f.rel, "doc")
        ctx = Ctx(pid or f"{f.rel}|doc", pid, f"{f.rel}|doc" in eng.widened)
        body = eng.sanitize_text(f.text, ctx)
        data_text = (f"Patient ID: {pid}\n" + body) if pid else body
        records.append(record(f.rel, out_rel, "doc", pid))
    protected_spans = {(s.start, s.end) for s in clinical_spans(f.text, eng.terms)}  # one per position
    protected = Counter(f.text[a:b].strip() for a, b in protected_spans if f.text[a:b].strip())
    identifiers = sorted({f.text[s.start:s.end] for s in shape_spans(f.text) if s.priority == P_ID
                          and len(re.sub(r"\D", "", f.text[s.start:s.end])) >= 8})
    return Output(f.rel, out_rel, data_text.encode("utf-8"), records, protected=protected,
                  identifiers=identifiers)


def record(rel_in: str, out_rel: str, loc: str, pid: str | None) -> dict:  # rel_in kept for readers
    return {"file": f"sanitized/{out_rel}", "loc": loc, "patient": pid}


def scrub_path(rel: str, eng: Engine) -> str:
    parts = []
    for p in rel.split("/"):
        parts.append(eng.sanitize_text(p, NO_CTX, structural=True))
    out = "/".join(parts)
    return out


# =========================================================================== release gate
def gate(o: Output, eng: Engine) -> str | None:
    """G1-G6 on the bytes to publish. Returns None when the file passes, else a reason code."""
    if not safe_out_path(o.out_rel):                                         # G6 path safety
        return "unsafe_path"
    try:
        text = o.data.decode("utf-8")                                        # G1 format
    except UnicodeDecodeError:
        return "malformed_structure"
    for r in o.records:                                                      # G5 references
        if r["patient"] is not None and r["patient"] not in text:
            r["patient"] = None
    if o.out_rel.lower().endswith(".csv") or o.out_rel.lower().endswith(".tsv"):
        try:
            list(csv.reader(io.StringIO(text, newline=""), delimiter="\t" if o.out_rel.endswith(".tsv") else ","))
        except csv.Error:
            return "malformed_structure"
    if o.out_rel.lower().endswith(".json"):
        try:
            data = json.loads(text)
        except ValueError:
            return "malformed_structure"
        if isinstance(data, dict) and data.get("resourceType") == "Bundle":
            entries = data.get("entry")
            if entries is not None and not isinstance(entries, list):
                return "fhir_validation_failure"
    if residual_identifier(text, eng):                                       # G2/G3 residual PII
        return "unresolved_pii"
    digits_out = re.sub(r"\D", "", text)
    for ident in o.identifiers:                                              # G2 input identifiers
        core = re.sub(r"\D", "", ident)
        if core and core in digits_out:
            return "unresolved_pii"
    for surface, count in o.protected.items():                               # G4 clinical fingerprint
        if text.count(surface) < count:
            return "clinical_integrity_failure"
    return None


def residual_identifier(text: str, eng: Engine) -> bool:
    """Known-identifier scan (dataset names and address literals) plus independent identifier shapes."""
    if eng.registry.find_spans(text):
        return True
    return any(s.priority == P_ID for s in shape_spans(text))


# =========================================================================== report
def build_report(f_all: list[InputFile], quarantined, verified: list[Output], records: list, eng: Engine,
                 started: float) -> dict:
    by_rel = {o.rel: o for o in verified}
    entries = []
    for f in f_all:
        o = by_rel[f.rel]
        if o.reason is None:
            entries.append({"input_sha256": f.sha256, "output": f"sanitized/{o.out_rel}", "status": "sanitized"})
        else:
            entries.append({"input_sha256": f.sha256, "output": None, "status": "quarantined", "reason": o.reason})
    for rel, sha, reason in quarantined:
        entries.append({"input_sha256": sha, "output": None, "status": "quarantined", "reason": reason})
    entries.sort(key=lambda e: (e["input_sha256"], e["status"]))

    n_san = sum(1 for e in entries if e["status"] == "sanitized")
    withheld_records = sum(len(o.records) for o in verified if o.reason is not None)
    linked = sum(1 for r in records if r["patient"] is not None)
    generalized = len(eng.records_generalized) + len(eng.widened)
    report = {
        "schema": SCHEMA,
        "files": entries,
        "counts": {
            "files_total": len(entries),
            "files_sanitized": n_san,
            "files_quarantined": len(entries) - n_san,
            "records_processed": len(records),
            "identifiers_detected": sum(eng.applied.values()),
            "records_linked": linked,
            "records_generalized": generalized,
            "records_suppressed": 0,
            "records_quarantined": withheld_records,
        },
        "entities": dict(sorted(eng.applied.items())),
        "timing": {"seconds": round(time.monotonic() - started, 2)},
        "resources": {"peak_rss_mb": peak_rss_mb()},
    }
    return report
