"""Live demo: cross-script match, a rejected false merge, and a preserved dose. Invented data only.

    python tools/demo.py

Builds three tiny records in a temporary folder, runs Parda on them, and prints what it did and why.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from engine.pipeline import run_pipeline  # noqa: E402

REGISTRATION = (
    "UHID,Patient Name,Gender,Age,Mobile,Aadhaar No,Village/Mohalla\n"
    "SNJ/26/000111,Anil Verma,M,47,9811122233,4455 6677 8899,Rampur Kalan\n"
    "SNJ/26/000222,Anil Verma,M,47,9000011122,1234 5678 9012,Shivpur\n"
)
# A prescription written in Hindi: Devanagari name, no Latin name at all, the same Aadhaar as the first row.
PRESCRIPTION = (
    "नाम: अनिल वर्मा   आयु: 47 वर्ष\n"
    "आधार 4455 6677 8899\n"
    "Rx: Dolo 650 mg 1-0-1 x 5 days. BP 150/90.\n"
)


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        src = root / "in"
        (src / "registration").mkdir(parents=True)
        (src / "prescriptions").mkdir()
        (src / "registration" / "census.csv").write_text(REGISTRATION, encoding="utf-8")
        (src / "prescriptions" / "rx_0001.txt").write_text(PRESCRIPTION, encoding="utf-8")

        out = root / "out"
        report = run_pipeline(src, out, b"demo-only-secret")  # a demo secret: never a real one
        records = [json.loads(x) for x in (out / "records.jsonl").read_text(encoding="utf-8").splitlines()]

        print("1. Cross-script match")
        print("   The Latin registration row and the Hindi prescription share an Aadhaar number.")
        row0 = next(r for r in records if r["loc"] == "row:0")
        rx = next(r for r in records if r["file"].endswith("rx_0001.txt"))
        print(f"   registration row 0 -> {row0['patient']}   prescription -> {rx['patient']}   "
              f"same person: {row0['patient'] == rx['patient']}")

        print("\n2. Rejected false merge")
        print("   The second row has the same name, a different UHID and a different Aadhaar.")
        row1 = next(r for r in records if r["loc"] == "row:1")
        print(f"   row 0 -> {row0['patient']}   row 1 -> {row1['patient']}   "
              f"merged: {row0['patient'] == row1['patient']}")

        print("\n3. Preserved dose and vitals (what the release says)")
        text = (out / "sanitized" / "prescriptions" / "rx_0001.txt").read_text(encoding="utf-8")
        for line in text.splitlines():
            print("   " + line)

        print("\nReport: " + json.dumps({k: report["counts"][k] for k in
                                        ("files_total", "files_sanitized", "records_linked")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
