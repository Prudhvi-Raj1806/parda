"""Second, harder held-out set: other conventions from the first one. Invented names and numbers only.

    python tools/make_holdout2.py --input <new empty folder> --truth <truth.json>

Differences from make_holdout.py: names written as initials or surname first, names split across First and
Last columns, month-name dates, unusual headers (Attendant, Bed No, Chief Complaint), Devanagari names in running
text with no label, bare first names in nursing notes, masked Aadhaar, Plot and Gali addresses, a FHIR Patient,
and records with no name at all (only a hospital number). Scored with tools/score_holdout.py.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import random
from pathlib import Path

FIRST = ["Zarina", "Mohit", "Hemlata", "Aslam", "Reshma", "Kunal", "Farhana", "Bheem", "Sapna", "Nadeem",
         "Chandni", "Omkar", "Shabnam", "Tanmay", "Parveen", "Ritesh", "Gayatri", "Akram", "Mridula", "Sahil",
         "Ruksana", "Pankaj", "Neelam", "Javed", "Kiran", "Waseem", "Madhuri", "Irfan", "Pooja", "Sanjay"]
LAST = ["Hussain", "Dwivedi", "Bano", "Chauhan", "Sheikh", "Bajpai", "Moitra", "Kapoor", "Yadav", "Farooqui",
        "Nagar", "Sahu", "Mahajan", "Rizvi", "Gupta", "Patil", "Lal", "Khan", "Shukla", "Bhatt"]
PLACES = ["Plot No. 14, Sector 9", "Gali No. 3, Lohia Nagar", "H-22 Shastri Colony", "Flat 7, Indira Vihar"]
AREAS = ["Ganj Khurd", "Bairia", "Nizampur", "Rasulabad", "Mauranipur", "Sahjanwa"]
DOCTORS = ["Dr. Sushil Dubey", "Dr. Yasmin Ali", "Dr. Harish Raut", "Dr. Meenal Sood"]
DRUGS = [("Montek", "10 mg", "1-0-1", 5), ("Nexpro", "40 mg", "1-0-0", 14), ("Cefix", "200 mg", "1-0-1", 5),
         ("Rosuvas", "10 mg", "0-0-1", 30), ("Dolo", "650 mg", "1-1-1", 3)]
DIAG = ["Acute gastroenteritis", "Community acquired pneumonia", "Chronic kidney disease stage 3",
        "Hypothyroidism", "Iron deficiency anaemia"]
DEVA_NAMES = ["ज़रीना हुसैन", "मोहित द्विवेदी", "हेमलता बानो", "असलम शेख", "रेशमा बाजपेयी", "कुणाल मोइत्रा"]
MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October",
          "November", "December"]
DEVA_DIGITS = str.maketrans("0123456789", "०१२३४५६७८९")


def phone(rng: random.Random) -> str:
    return str(rng.choice([6, 7, 8, 9])) + "".join(str(rng.randint(0, 9)) for _ in range(9))


def make_patient(rng: random.Random, n: int) -> dict:
    fn, ln = FIRST[n], LAST[(n * 11) % len(LAST)]
    rf, rl = FIRST[(n * 7 + 3) % len(FIRST)], LAST[(n * 13 + 1) % len(LAST)]
    d, m, y = rng.randint(1, 28), rng.randint(1, 12), rng.randint(1948, 2010)
    drug = DRUGS[n % len(DRUGS)]
    return {
        "id": f"K{n:03d}",
        "name": f"{fn} {ln}",
        "initials": f"{fn[0]}. {ln}",
        "surname_first": f"{ln}, {fn}",
        "relative": f"{rf} {rl}",
        "attendant": f"{rf} {rl}",
        "dob_printed": f"{d} {MONTHS[m - 1]} {y}",
        "dob_iso": f"{y}-{m:02d}-{d:02d}",
        "age": 2026 - y,
        "sex": "M" if n % 2 else "F",
        "phone": phone(rng),
        "aadhaar": "".join(str(rng.randint(0, 9)) for _ in range(12)),
        "uhid": f"NRG-{rng.randint(100, 999)}-{rng.randint(10000, 99999)}",
        "village": AREAS[n % len(AREAS)],
        "place": PLACES[n % len(PLACES)],
        "pin": f"{rng.randint(226001, 226999)}",
        "doctor": DOCTORS[n % len(DOCTORS)],
        "drug": drug,
        "diag": DIAG[n % len(DIAG)],
        "hb": f"{rng.randint(60, 150) / 10:.1f} g/dL",
        "bp": f"{rng.randint(104, 178)}/{rng.randint(62, 108)}",
        "deva_name": DEVA_NAMES[n % len(DEVA_NAMES)],
        "bare_first": fn,
        "bed": f"B-{rng.randint(1, 40)}",
    }


def surfaces(p: dict) -> list[dict]:
    rows = [("PATIENT_NAME", p["name"]), ("PATIENT_NAME", p["initials"]), ("PATIENT_NAME", p["surname_first"]),
            ("PATIENT_NAME", p["deva_name"]), ("RELATIVE_NAME", p["relative"]), ("PHONE", p["phone"]),
            ("AADHAAR", p["aadhaar"]), ("MRN", p["uhid"]), ("VILLAGE", p["village"]), ("PIN", p["pin"]),
            ("DOB", p["dob_printed"]), ("ADDRESS", p["place"])]
    return [{"type": t, "surface": s, "patient": p["id"]} for t, s in rows]


def build(rng: random.Random, patients: list[dict], root: Path) -> list[dict]:
    units = []
    for d in ("ward", "lab", "fhir", "notes", "referrals"):
        (root / d).mkdir(parents=True)

    # 1. CSV: First/Last split, initials and surname-first names, month-name dates, unusual headers
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["First Name", "Last Name", "Attendant", "Bed No", "Chief Complaint", "Dob", "Gender",
                "Mobile", "Govt ID", "Registration No", "Locality", "Pin", "Medicine", "Discharge"])
    for i, p in enumerate(patients):
        if i % 4 == 0:
            continue
        fn, ln = p["name"].split(" ", 1)
        w.writerow([fn, ln, p["attendant"], p["bed"], p["diag"], p["dob_printed"], p["sex"], p["phone"],
                    p["aadhaar"], p["uhid"], p["place"], p["pin"],
                    f"{p['drug'][0]} {p['drug'][1]} {p['drug'][2]} x {p['drug'][3]} days",
                    f"{rng.randint(1, 28)} {MONTHS[i % 12]} 2026"])
        units.append({"file": "ward/roster.csv", "loc": f"row:{len(units)}", "patient": p["id"]})
    (root / "ward" / "roster.csv").write_text(buf.getvalue(), encoding="utf-8")

    # 2. TSV lab feed: hospital number on every row, initials on some rows, no name on others
    lines = ["sample_no\tpatient\ttest\tresult\tunit\tcollected"]
    row = 0
    for i, p in enumerate(patients):
        for k in range(2):
            who = p["initials"] if (i + k) % 3 == 0 else ""
            lines.append(f"L{i:03d}{k}\t{who}\tHemoglobin\t{p['hb'].split()[0]}\tg/dL\t{p['dob_iso']}")
            units.append({"file": "lab/feed.tsv", "loc": f"row:{row}", "patient": p["id"]})
            row += 1
    # the TSV has no hospital number, so the numbers come from the notes and the FHIR bundle
    (root / "lab" / "feed.tsv").write_text("\n".join(lines) + "\n", encoding="utf-8")

    # 3. Nested JSON referrals with arrays of identifiers and a surname-first name
    refs = []
    for i, p in enumerate(patients):
        if i % 5 == 2:
            continue
        refs.append({"patient_record": {"names": {"surname_first": p["surname_first"]},
                                        "contact": {"mobile_no": p["phone"]},
                                        "ids": [{"type": "govt", "value": p["aadhaar"]},
                                                {"type": "hospital", "value": p["uhid"]}]},
                     "notes": f"Attended by {p['attendant']}. Referred for {p['diag'].lower()}.",
                     "vitals": {"bp": p["bp"], "unit": "mmHg"}})
        units.append({"file": "referrals/cases.json", "loc": f"/cases/{len(refs) - 1}", "patient": p["id"]})
    (root / "referrals" / "cases.json").write_text(json.dumps({"cases": refs}, ensure_ascii=False, indent=2),
                                                   encoding="utf-8")

    # 4. Nursing notes with bare first names, Devanagari names with no label, a masked Aadhaar
    for i, p in enumerate(patients):
        if i % 3 == 1:
            continue
        text = (f"Shift note {i:03d}. {p['bare_first']} ji ne khana khaya. Bed {p['bed']}.\n"
                f"{p['deva_name']} ka BP {p['bp']} mmHg, sugar normal.\n"
                f"Attendant {p['attendant']} called at {p['phone'][:5]} {p['phone'][5:]}. "
                f"Aadhaar XXXX XXXX {p['aadhaar'][-4:]} on file.\n"
                f"Dawa {p['drug'][0]} {p['drug'][1]} {p['drug'][2]} x {p['drug'][3]} days. "
                f"Dr: {p['doctor']}.\n")
        name = f"nursing_{i:03d}.txt"
        (root / "notes" / name).write_text(text, encoding="utf-8")
        units.append({"file": f"notes/{name}", "loc": "doc", "patient": p["id"]})

    # 5. FHIR Patient resources, one per patient, with a telecom and an address
    for i, p in enumerate(patients):
        if i % 6 == 3:
            continue
        ln, fn = p["surname_first"].split(", ")
        bundle = {"resourceType": "Patient", "id": f"pt-{i:03d}",
                  "name": [{"use": "official", "family": ln, "given": [fn]}],
                  "telecom": [{"system": "phone", "value": p["phone"]}],
                  "birthDate": p["dob_iso"],
                  "identifier": [{"system": "urn:aadhaar", "value": p["aadhaar"]}],
                  "address": [{"line": [p["place"]], "district": p["village"], "postalCode": p["pin"]}],
                  "gender": "male" if p["sex"] == "M" else "female"}
        name = f"patient_{i:03d}.json"
        (root / "fhir" / name).write_text(json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8")
        units.append({"file": f"fhir/{name}", "loc": "doc", "patient": p["id"]})
    return units


def main() -> int:
    ap = argparse.ArgumentParser(description="Harder held-out synthetic set")
    ap.add_argument("--input", required=True)
    ap.add_argument("--truth", required=True)
    a = ap.parse_args()
    root = Path(a.input)
    if root.exists() and any(root.iterdir()):
        raise SystemExit("input folder must be empty")
    root.mkdir(parents=True, exist_ok=True)
    rng = random.Random(7741)
    patients = [make_patient(rng, n) for n in range(30)]
    units = build(rng, patients, root)
    truth = {
        "patients": [{"id": p["id"], "medical": [p["diag"], p["doctor"],
                                                  f"{p['drug'][0]} {p['drug'][1]} {p['drug'][2]} x {p['drug'][3]} days",
                                                  p["hb"], f"BP {p['bp']}"]} for p in patients],
        "surfaces": [s for p in patients for s in surfaces(p)],
        "units": units,
    }
    Path(a.truth).write_text(json.dumps(truth, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"patients {len(patients)} units {len(units)} surfaces {len(truth['surfaces'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
