"""A simplified version of the kit's privacy attacker (docs/ATTACKS.md), for our own measurements.

    python tools/attack.py --release <parda output> --truth <truth.json> --input <practice input>
                           --registry <attacker/registry.csv> --facts <attacker/known_facts.jsonl>
    python tools/attack.py --raw --input <practice input> ...      (the baseline: the raw input as the release)

What it implements (a subset of the kit's attacks, with the same filter order and weights):
  A2/A3 record linkage: candidates from the registry filtered by phone, e-mail, Aadhaar last 4, district,
        sex, age band, village and PIN (a filter that would empty the set is skipped).
  A4    profile aggregation: records sharing a pseudonym are pooled; a patient counts as re-identified when the
        true person has confidence >= 0.5.
  A5    targeted: each known fact (visit date, condition) is matched against profiles; a hit counts when the
        matched profile belongs to the target.
  A6    pseudonym inversion: a pseudonym equal to an unkeyed hash of an original identifier.
The per-release secret keeps pseudonyms unlinkable; the attacker sees only what the release contains.
Counts and rates only; the truth file stays out of the repository.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

PHONE_RX = re.compile(r"(?<!\d)([6-9]\d{9})(?!\d)")
AADHAAR_MASK_RX = re.compile(r"X{4}\s?X{4}\s?(\d{4})")
EMAIL_RX = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
AGE_RX = re.compile(r"(?<![\d-])(\d{1,3})\s?(?:/|\s)\s?([MF])\b")
BAND_RX = re.compile(r"(?<![\d-])(\d{1,3})\s?-\s?(\d{1,3})\s?(?:Yrs)?\s?/\s?([MF])\b")
SEX_RX = re.compile(r"(?<![A-Za-z])([MF])(?![A-Za-z])")
PIN_RX = re.compile(r"(?<!\d)(\d{6})(?!\d)")


def norm(s: str) -> str:
    return " ".join(s.casefold().replace("-", " ").replace("/", " ").split())


def load_registry(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def evidence(text: str, districts: set[str], villages: set[str]) -> dict:
    """What a record reveals: phones, e-mails, last 4 Aadhaar digits, districts, villages, sex, age bands, PINs."""
    ev = {"phones": set(), "emails": set(), "last4": set(), "districts": set(), "villages": set(),
          "sex": set(), "ages": set(), "pins": set()}
    for m in PHONE_RX.finditer(text):
        ev["phones"].add(m.group(1))
    ev["emails"].update(m.group(0).lower() for m in EMAIL_RX.finditer(text))
    ev["last4"].update(m.group(1) for m in AADHAAR_MASK_RX.finditer(text))
    low = norm(text)
    ev["low"] = low
    ev["districts"].update(d for d in districts if d and d in low)
    ev["villages"].update(v for v in villages if v and v in low)
    for m in AGE_RX.finditer(text):
        ev["ages"].add(int(m.group(1)))
        ev["sex"].add(m.group(2))
    for m in BAND_RX.finditer(text):
        lo, hi = int(m.group(1)), int(m.group(2))
        ev["ages"].update(range(lo, hi + 1))
        ev["sex"].add(m.group(3))
    for m in SEX_RX.finditer(text):
        ev["sex"].add(m.group(1))
    ev["pins"].update(m.group(1) for m in PIN_RX.finditer(text))
    return ev


IGNORE: set[str] = set()  # evidence kinds the attacker is not given (for ablation runs)


def candidates(ev: dict, registry: list[dict]) -> list[dict]:
    """Filter the registry by the evidence, in the kit's order; a filter that would empty the set is skipped."""
    pool = registry
    named = [r for r in registry if r["name"] and norm(r["name"]) in ev["low"]]
    if named:  # a full name in the record is the strongest evidence (the attacker's full-name weight)
        pool = named
    checks = [
        ("phone", lambda r: r["phone"] in ev["phones"] if r["phone"] else False, bool(ev["phones"])),
        ("email", lambda r: r["email"].lower() in ev["emails"] if r["email"] else False, bool(ev["emails"])),
        ("last4", lambda r: r["aadhaar_last4"] in ev["last4"] if r["aadhaar_last4"] else False, bool(ev["last4"])),
        ("district", lambda r: norm(r["district"]) in ev["districts"], bool(ev["districts"])),
        ("sex", lambda r: r["gender"] in ev["sex"], bool(ev["sex"])),
        ("age", lambda r: any(abs(int(r["age"] or -99) - a) <= 1 for a in ev["ages"]), bool(ev["ages"])),
        ("village", lambda r: norm(r["village"]) in ev["villages"], bool(ev["villages"])),
        ("pin", lambda r: r["pin"] in ev["pins"], bool(ev["pins"])),
    ]
    for kind, test, applicable in checks:
        if not applicable or kind in IGNORE:
            continue
        kept = [r for r in pool if test(r)]
        if kept:  # a filter that would empty the set is skipped, so contradictory evidence cannot crash the attack
            pool = kept
    return pool


def unit_text(folder: Path, rel: str, loc: str) -> str:
    path = folder / rel
    if loc == "doc":
        return path.read_text(encoding="utf-8", errors="replace")
    if loc.startswith("row:"):
        delim = "\t" if path.suffix == ".tsv" else ","
        rows = list(csv.reader(io.StringIO(path.read_text(encoding="utf-8", errors="replace"), newline=""),
                               delimiter=delim))
        return delim.join(rows[int(loc[4:]) + 1])
    key, _, index = loc.strip("/").partition("/")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return json.dumps(data[key][int(index)], ensure_ascii=False)
    except (ValueError, KeyError, IndexError, TypeError):
        return ""  # a file that cannot be parsed contributes no evidence


def main() -> int:
    ap = argparse.ArgumentParser(description="Simplified privacy attacker")
    ap.add_argument("--release")
    ap.add_argument("--raw", action="store_true", help="attack the raw input instead of a release")
    ap.add_argument("--input", required=True, help="the input folder (for the raw baseline and the truth map)")
    ap.add_argument("--truth", required=True)
    ap.add_argument("--registry", required=True)
    ap.add_argument("--facts", required=True)
    ap.add_argument("--ignore", default="", help="comma list of evidence kinds to withhold, e.g. district,age")
    a = ap.parse_args()
    IGNORE.update(x for x in a.ignore.split(",") if x)

    truth = json.loads(Path(a.truth).read_text(encoding="utf-8"))
    registry = load_registry(Path(a.registry))
    facts = [json.loads(x) for x in Path(a.facts).read_text(encoding="utf-8").splitlines() if x.strip()]
    districts = {norm(r["district"]) for r in registry if r["district"]}
    villages = {norm(r["village"]) for r in registry if r["village"]}
    inp = Path(a.input)
    rid_of_patient = {pt: info["rid"] for pt, info in truth["patients"].items()}

    # Records of the release: (rel input path, loc, pseudonym or None, text, true patient or None)
    records = []
    if a.raw:
        for rel, f in truth["files"].items():
            for loc, unit in f.get("units", {}).items():
                records.append((rel, loc, None, unit_text(inp, rel, loc), unit.get("patient")))
    else:
        rel_out = Path(a.release)
        report = json.loads((rel_out / "report.json").read_text(encoding="utf-8"))
        sha_to_rel = {hashlib.sha256((inp / rel).read_bytes()).hexdigest(): rel
                      for rel in truth["files"]}
        out_to_rel = {e["output"]: sha_to_rel.get(e["input_sha256"]) for e in report["files"] if e.get("output")}
        for line in (rel_out / "records.jsonl").read_text(encoding="utf-8").splitlines():
            r = json.loads(line)
            rel = out_to_rel.get(r["file"])
            if rel is None:
                continue
            true = truth["files"][rel]["units"].get(r["loc"], {}).get("patient")
            text = unit_text(rel_out / "sanitized", r["file"].replace("sanitized/", "", 1), r["loc"]) \
                if (rel_out / r["file"]).exists() else ""
            records.append((rel, r["loc"], r["patient"], text, true))

    if a.raw:
        # Raw records carry no pseudonym, so the attacker joins them on shared identifiers (phone, Aadhaar,
        # hospital number) and treats each joined group as one profile.
        parent = list(range(len(records)))

        def find(x: int) -> int:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        seen: dict[str, int] = {}
        for i, (_, _, _, text, _) in enumerate(records):
            tokens = set(PHONE_RX.findall(text)) | set(re.findall(r"(?<!\d)\d{12}(?!\d)", text))
            tokens |= set(re.findall(r"[A-Z]{2,6}[-/][0-9A-Z/-]{4,}", text))
            for tok in tokens:
                if tok in seen:
                    parent[find(i)] = find(seen[tok])
                else:
                    seen[tok] = i
        records = [(rel, loc, f"raw-{find(i)}", text, true) for i, (rel, loc, _, text, true) in enumerate(records)]

    # A2/A3: record level
    targets = set(rid_of_patient)
    rec_conf = rec_mass = 0
    per_person_profiles: dict[str, list] = defaultdict(list)
    for rel, loc, pid, text, true in records:
        ev = evidence(text, districts, villages)
        cands = candidates(ev, registry)
        true_rid = rid_of_patient.get(true)
        if true_rid and any(c["rid"] == true_rid for c in cands):
            rec_mass += 1 / len(cands)
            if len(cands) == 1:
                rec_conf += 1
        if pid:
            per_person_profiles[pid].append((text, true))

    # A4: profiles (pooled evidence per pseudonym)
    reid_people: set = set()
    present = {true for _, _, _, _, true in records if true}
    profile_truth = {}
    for pid, items in per_person_profiles.items():
        pooled = "\n".join(t for t, _ in items)
        truths = Counter(tr for _, tr in items if tr)
        if not truths:
            continue
        true = truths.most_common(1)[0][0]
        profile_truth[pid] = true
        cands = candidates(evidence(pooled, districts, villages), registry)
        true_rid = rid_of_patient.get(true)
        if true_rid and any(c["rid"] == true_rid for c in cands) and 1 / len(cands) >= 0.5:
            reid_people.add(true)
    reid_rate = len(reid_people) / len(present) if present else 0.0

    # A5: targeted, from known facts (exact visit date or condition text in a profile)
    hits = success = decoy_claims = 0
    for fact in facts:
        target_profiles = []
        for pid, items in per_person_profiles.items():
            pooled = norm("\n".join(t for t, _ in items))
            matched = any(norm(d) in pooled for d in fact.get("visit_dates", []))
            cond = fact.get("condition_hint")
            if cond and norm(cond) in pooled:
                matched = True
            if matched:
                target_profiles.append(pid)
        if not target_profiles:
            continue
        hits += 1
        rids = {rid_of_patient.get(profile_truth.get(p)) for p in target_profiles}
        if fact["rid"] in rids and len(rids) == 1:
            success += 1
        elif fact["rid"] not in {r for r in rids}:
            decoy_claims += 1 if fact["rid"] not in {rid_of_patient.get(t) for t in targets} else 0

    # A6: pseudonym inversion against unkeyed hashes of the patient's identifiers
    inverted = 0
    if not a.raw:
        pids = set(per_person_profiles)
        originals = {}
        for pt, info in truth["patients"].items():
            for ids in info.get("uhids", {}).values():
                for u in ids:
                    originals.setdefault(pt, []).append(re.sub(r"[^A-Za-z0-9]", "", u))
        for pt, vals in originals.items():
            for v in vals:
                for algo in ("md5", "sha1", "sha256"):
                    digest = hashlib.new(algo, v.encode()).hexdigest()
                    if any(p.lower().startswith(digest[:8]) for p in pids):
                        inverted += 1

    out = {
        "records": len(records),
        "present_patients": len(present),
        "record_linkage_risk": round(rec_mass / len(records), 4) if records else 0.0,
        "confident_record_reid": round(rec_conf / len(records), 4) if records else 0.0,
        "patients_reidentified": round(reid_rate, 4),
        "targeted_hits": hits,
        "targeted_success": round(success / hits, 4) if hits else 0.0,
        "decoy_claims": decoy_claims,
        "pseudonym_inversions": inverted,
    }
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
