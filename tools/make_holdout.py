"""Generate a held-out synthetic test set with a truth file. Invented names and numbers only.

    python tools/make_holdout.py --input <new empty folder> --truth <truth.json>

The names, places and formats are written for this test and are not the practice data. Every personal
surface is recorded in the truth file, with the medical values that must survive. Keep the truth file out
of the repository; score with tools/score_holdout.py.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import random
from pathlib import Path

FIRST = ["Imran", "Rukmini", "Gulshan", "Parvez", "Lakshmi", "Dhruv", "Sunaina", "Yusuf", "Tara", "Bhola",
         "Nazia", "Hemant", "Priyanka", "Faisal", "Anjali", "Raghav", "Shobha", "Mehboob", "Kamini", "Tejpal",
         "Zoya", "Arvind", "Meher", "Ratan", "Sabiha", "Vikram", "Lata", "Ayaan", "Savita", "Naveen"]
LAST = ["Qureshi", "Joshi", "Khatun", "Mishra", "Pathan", "Rawat", "Dsouza", "Agrawal", "Siddiqui", "Bhadauria",
        "Kushwaha", "Lodha", "Sengar", "Tripathi", "Ansari", "Gaur", "Pandit", "Chaudhari", "Sethi", "Mirza"]
VILLAGES = ["Kakrauli", "Naugawan", "Maholi Khurd", "Harsaulli", "Bhatpur Dehat", "Sarainan", "Jhalu", "Rampuria"]
MOHALLAS = ["Qazi Mohalla", "Teliwara", "Khadi Bazar", "Sadar Ganj", "Nai Basti", "Chandni Chowk Gali"]
LANDMARKS = ["near Bus Stand", "opp. Govt Girls School", "near Peepal Chowk", "behind Shiv Temple", "near Jama Masjid"]
DOCTORS = ["Dr. Ankit Bhatnagar", "Dr. Nusrat Jahan", "Dr. Girish Malhotra", "Dr. Pooja Ranawat"]
DRUGS = [("Telma", "40 mg", "1-0-1", 3), ("Glimy", "2 mg", "1-0-0", 5), ("Azee", "500 mg", "0-0-1", 3),
         ("Pantop", "40 mg", "1-0-1", 7), ("Ecosprin", "75 mg", "0-1-0", 30)]
DIAG = ["Typhoid fever", "Type 2 diabetes mellitus", "Essential (primary) hypertension", "Dengue, unspecified",
        "Anaemia, unspecified"]
HINDI_NAMES = ["इमरान कुरैशी", "रुक्मिणी जोशी", "परवेज़ खातून", "लक्ष्मी मिश्रा", "ध्रुव पठान", "सुनैना रावत"]
MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October",
          "November", "December"]
DEVA_DIGITS = str.maketrans("0123456789", "०१२३४५६७८९")


def phone(rng: random.Random) -> str:
    return str(rng.choice([6, 7, 8, 9])) + "".join(str(rng.randint(0, 9)) for _ in range(9))


def aadhaar(rng: random.Random) -> str:
    return "".join(str(rng.randint(0, 9)) for _ in range(12))


def abha(rng: random.Random) -> str:
    d = "".join(str(rng.randint(0, 9)) for _ in range(14))
    return f"{d[:2]}-{d[2:6]}-{d[6:10]}-{d[10:14]}"


def dob(rng: random.Random) -> tuple[str, str]:
    y, m, d = rng.randint(1950, 2005), rng.randint(1, 12), rng.randint(1, 28)
    return f"{d:02d}/{m:02d}/{y}", f"{y}-{m:02d}-{d:02d}"


def make_patient(rng: random.Random, n: int) -> dict:
    fn, ln = FIRST[n % len(FIRST)], LAST[(n * 7) % len(LAST)]
    rel_first = FIRST[(n * 3 + 5) % len(FIRST)]
    dob_printed, dob_iso = dob(rng)
    drug = DRUGS[n % len(DRUGS)]
    p = {
        "id": f"H{n:03d}",
        "name": f"{fn} {ln}",
        "name_alt": f"{ln.upper()} {fn.upper()}",
        "initial": f"{fn} {ln[0]}.",
        "relative": f"{rel_first} {ln}",
        "dob_printed": dob_printed,
        "dob_iso": dob_iso,
        "age": 2026 - int(dob_iso[:4]),
        "sex": "F" if n % 2 else "M",
        "phone": phone(rng),
        "aadhaar": aadhaar(rng),
        "abha": abha(rng),
        "uhid": f"KMR/25/{rng.randint(10000, 99999)}",
        "village": VILLAGES[n % len(VILLAGES)],
        "house": f"House {rng.randint(10, 499)}",
        "mohalla": MOHALLAS[n % len(MOHALLAS)],
        "landmark": LANDMARKS[n % len(LANDMARKS)],
        "pin": f"{rng.randint(200000, 289999)}",
        "doctor": DOCTORS[n % len(DOCTORS)],
        "drug": drug,
        "diag": DIAG[n % len(DIAG)],
        "hb": f"{rng.randint(70, 145) / 10:.1f} g/dL",
        "bp": f"{rng.randint(100, 170)}/{rng.randint(60, 105)}",
        "hindi_name": HINDI_NAMES[n % len(HINDI_NAMES)],
        "month_date": f"{rng.randint(1, 28)} {MONTHS[n % 12]} 2026",
    }
    p["medical"] = [p["diag"], p["doctor"], f"{drug[0]} {drug[1]} {drug[2]} x {drug[3]} days",
                    p["hb"], f"BP {p['bp']}"]
    return p


def surfaces(p: dict) -> list[dict]:
    out = []

    def add(kind: str, text: str) -> None:
        if text:
            out.append({"type": kind, "surface": text, "patient": p["id"]})

    add("PATIENT_NAME", p["name"])
    add("PATIENT_NAME", p["name_alt"])
    add("PATIENT_NAME", p["hindi_name"])
    add("RELATIVE_NAME", p["relative"])
    add("PHONE", p["phone"])
    add("AADHAAR", p["aadhaar"])
    add("ABHA_NUMBER", p["abha"])
    add("MRN", p["uhid"])
    add("VILLAGE", p["village"])
    add("HOUSE", p["house"])
    add("LANDMARK", p["landmark"])
    add("PIN", p["pin"])
    add("DOB", p["dob_printed"])
    return out


def build(rng: random.Random, patients: list[dict], root: Path) -> dict:
    (root / "ward").mkdir(parents=True)
    (root / "lab").mkdir()
    (root / "referrals").mkdir()
    (root / "notes").mkdir()
    truth_units = []

    # 1. CSV with unfamiliar headers: census of the ward
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["Pt Nm", "Guardian Full Name", "Date Of Birth", "Yrs", "Sex", "Contact Number", "Govt ID",
                "Hospital Ref", "Street/Lane", "Village", "PIN", "Diagnosis", "Medicine", "Discharge Date"])
    for i, p in enumerate(patients):
        if i % 3 == 0:
            continue
        w.writerow([p["name"], p["relative"], p["dob_printed"], p["age"], p["sex"],
                    p["phone"], p["aadhaar"], p["uhid"], f"{p['house']}, {p['mohalla']}, {p['landmark']}",
                    p["village"], p["pin"], p["diag"],
                    f"{p['drug'][0]} {p['drug'][1]} {p['drug'][2]} x {p['drug'][3]} days", p["month_date"]])
        truth_units.append({"file": "ward/census.csv", "loc": f"row:{len(truth_units)}", "patient": p["id"]})
    (root / "ward" / "census.csv").write_text(buf.getvalue(), encoding="utf-8")

    # 2. TSV lab feed: name only on some rows, UHID on all
    lines = ["sample\tmrn_no\tname_of_patient\ttest\tvalue\tunit"]
    row = 0
    for i, p in enumerate(patients):
        for k in range(2):
            name = p["name"] if (i + k) % 2 == 0 else ""
            lines.append(f"S{i:03d}{k}\t{p['uhid']}\t{name}\tHaemoglobin\t{p['hb'].split()[0]}\tg/dL")
            truth_units.append({"file": "lab/feed.tsv", "loc": f"row:{row}", "patient": p["id"]})
            row += 1
    (root / "lab" / "feed.tsv").write_text("\n".join(lines) + "\n", encoding="utf-8")

    # 3. Nested JSON referrals with a subject object
    refs = []
    for i, p in enumerate(patients):
        if i % 4 == 1:
            continue
        refs.append({"subject": {"full_name": p["name"], "dob": p["dob_iso"], "mobile": p["phone"],
                                 "identity": {"aadhaar_number": p["aadhaar"], "abha": p["abha"]}},
                     "clinic_ref": p["uhid"],
                     "findings": [{"text": f"Referred by {p['doctor']}. {p['diag']}. BP {p['bp']} mmHg."}],
                     "address": {"line": f"{p['house']}, {p['mohalla']}, {p['village']}, PIN {p['pin']}"}})
        truth_units.append({"file": "referrals/referrals.json", "loc": f"/referrals/{len(refs) - 1}",
                            "patient": p["id"]})
    (root / "referrals" / "referrals.json").write_text(
        json.dumps({"referrals": refs}, ensure_ascii=False, indent=2), encoding="utf-8")

    # 4. Free-text notes in mixed style: labels, Hinglish, Devanagari, relatives
    for i, p in enumerate(patients):
        if i % 2:
            continue
        text = (f"Pt: {p['name']} | S/o {p['relative'].split()[0]} | Umr {p['age']} | {p['sex']}\n"
                f"Address - {p['house']}, {p['mohalla']}, {p['village']}, {p['landmark']}\n"
                f"Mob {p['phone']}; Aadhaar {p['aadhaar']}\n"
                f"Consultant {p['doctor']}. {p['diag']}. {p['name'].split()[0]} bhai ka BP {p['bp']}, "
                f"dawa {p['drug'][0]} {p['drug'][1]} {p['drug'][2]} x {p['drug'][3]} days.\n"
                f"नाम - {p['hindi_name']}\n"
                f"Admitted {p['month_date']}. Hb {p['hb']}.\n")
        name = f"ward_note_{p['id']}.txt"
        (root / "notes" / name).write_text(text, encoding="utf-8")
        truth_units.append({"file": f"notes/{name}", "loc": "doc", "patient": p["id"]})

    return {"units": truth_units}


def main() -> int:
    ap = argparse.ArgumentParser(description="Held-out synthetic test set")
    ap.add_argument("--input", required=True)
    ap.add_argument("--truth", required=True)
    a = ap.parse_args()
    root = Path(a.input)
    if root.exists() and any(root.iterdir()):
        raise SystemExit("input folder must be empty")
    rng = random.Random(2026)
    patients = [make_patient(rng, n) for n in range(40)]
    units = build(rng, patients, root)
    truth = {"patients": [{k: v for k, v in p.items() if k != "medical"} | {"medical": p["medical"]}
                          for p in patients],
             "surfaces": [s for p in patients for s in surfaces(p)],
             "units": units["units"]}
    Path(a.truth).write_text(json.dumps(truth, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"patients {len(patients)} units {len(units['units'])} surfaces {len(truth['surfaces'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
