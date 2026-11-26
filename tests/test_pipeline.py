"""Smoke tests for the pipeline. Standard library only: python -m unittest discover -s tests

Each test writes a small synthetic input (invented names and numbers) to a temporary folder and runs
main.py on it, so the tests never touch the practice data or any real record.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAIN = ROOT / "main.py"

REGISTRATION = (
    "UHID,Patient Name,Gender,Age,DOB,Relative Name,Mobile,Aadhaar No,Village/Mohalla\n"
    "SNJ/26/000111,Anil Verma,M,47,12/04/1977,Sunita Verma,9811122233,4455 6677 8899,Rampur Kalan\n"
    "SNJ/26/000222,Kiran Dubey,F,33,01/02/1990,Mohan Dubey,9000011122,,Shivpur\n"
)
# The same person as in REGISTRATION (same UHID), in a lab file that has no name column.
LAB = (
    "sample_id,uhid,test,result,unit,collected_on\n"
    "S1,SNJ/26/000111,Haemoglobin,10.2,g/dL,24/09/2026\n"
    "S2,SNJ/26/000222,Haemoglobin,13.1,g/dL,25/09/2026\n"
)
DISCHARGE = (
    "Patient: Anil Verma, age 47\n"
    "Consultant: Dr. Ramesh Srivastava (MD Medicine)\n"
    "Medication: Dolo 650 1-0-1 x 5 days\n"
    "Admitted 24/09/2026, discharged 26/09/2026\n"
)


def run_pipeline(input_dir: Path, output_dir: Path, secret: str = "test-secret") -> subprocess.CompletedProcess:
    env = dict(os.environ, RAKSHA_SECRET=secret, PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1")
    return subprocess.run(
        [sys.executable, str(MAIN), "--input", str(input_dir), "--output", str(output_dir)],
        capture_output=True, text=True, env=env, timeout=120,
    )


def make_input(root: Path) -> Path:
    src = root / "in"
    (src / "registration").mkdir(parents=True)
    (src / "lab").mkdir()
    (src / "notes").mkdir()
    (src / "misc").mkdir()
    (src / "registration" / "reg.csv").write_text(REGISTRATION, encoding="utf-8")
    (src / "lab" / "lab.csv").write_text(LAB, encoding="utf-8")
    (src / "notes" / "discharge.txt").write_text(DISCHARGE, encoding="utf-8")
    (src / "misc" / "scan.pdf").write_bytes(b"%PDF-1.4 Anil Verma 9811122233")  # unsupported: must be quarantined
    return src


class PipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.tmp = Path(cls._tmp.name)
        cls.src = make_input(cls.tmp)
        cls.out = cls.tmp / "out"
        result = run_pipeline(cls.src, cls.out)
        assert result.returncode == 0, result.stderr

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def read_out(self, rel: str) -> str:
        return (self.out / "sanitized" / rel).read_text(encoding="utf-8")

    def test_no_personal_data_left_in_csv(self) -> None:
        text = self.read_out("registration/reg.csv")
        for leaked in ("Anil Verma", "Sunita Verma", "9811122233", "4455 6677 8899", "Rampur Kalan"):
            self.assertNotIn(leaked, text)

    def test_unsupported_file_is_quarantined_not_copied(self) -> None:
        report = json.loads((self.out / "report.json").read_text(encoding="utf-8"))
        pdf = [e for e in report["files"] if e["input_sha256"] == hashlib.sha256(
            (self.src / "misc" / "scan.pdf").read_bytes()).hexdigest()]
        self.assertEqual(pdf[0]["status"], "quarantined")
        self.assertFalse((self.out / "sanitized" / "misc" / "scan.pdf").exists())

    def test_same_uhid_links_across_files(self) -> None:
        rows = [json.loads(line) for line in (self.out / "records.jsonl").read_text(encoding="utf-8").splitlines()]
        reg = {r["loc"]: r["patient"] for r in rows if r["file"].endswith("registration/reg.csv")}
        lab = {r["loc"]: r["patient"] for r in rows if r["file"].endswith("lab/lab.csv")}
        self.assertIsNotNone(reg["row:0"])
        self.assertEqual(reg["row:0"], lab["row:0"])          # Anil Verma in both files
        self.assertNotEqual(reg["row:0"], reg["row:1"])        # two different people stay apart
        self.assertIn(reg["row:0"], self.read_out("registration/reg.csv"))  # the ID is inside the record

    def test_medical_values_and_doctor_survive(self) -> None:
        text = self.read_out("notes/discharge.txt")
        self.assertIn("Dr. Ramesh Srivastava", text)
        self.assertIn("Dolo 650 1-0-1 x 5 days", text)
        self.assertNotIn("Anil Verma", text)
        self.assertIn("10.2", self.read_out("lab/lab.csv"))

    def test_dates_shift_but_keep_their_gap(self) -> None:
        text = self.read_out("notes/discharge.txt")
        self.assertNotIn("24/09/2026", text)
        self.assertNotIn("26/09/2026", text)
        import re
        dates = re.findall(r"\d{2}/\d{2}/\d{4}", text)
        self.assertEqual(len(dates), 2)
        from datetime import date
        d1, d2 = (date(int(d[6:]), int(d[3:5]), int(d[:2])) for d in dates)
        self.assertEqual((d2 - d1).days, 2)  # the stay is still two days

    def test_ages_become_bands_that_contain_the_age(self) -> None:
        text = self.read_out("registration/reg.csv")
        self.assertIn("45-49", text)
        self.assertNotIn(",47,", text)

    def test_same_secret_gives_identical_output(self) -> None:
        second = self.tmp / "out2"
        self.assertEqual(run_pipeline(self.src, second).returncode, 0)
        self.assertEqual(
            (self.out / "records.jsonl").read_text(encoding="utf-8"),
            (second / "records.jsonl").read_text(encoding="utf-8"),
        )
        self.assertEqual(
            self.read_out("registration/reg.csv"),
            (second / "sanitized" / "registration" / "reg.csv").read_text(encoding="utf-8"),
        )

    def test_different_secret_changes_pseudonyms(self) -> None:
        other = self.tmp / "out3"
        self.assertEqual(run_pipeline(self.src, other, secret="another-secret").returncode, 0)
        first = (self.out / "records.jsonl").read_text(encoding="utf-8")
        second = (other / "records.jsonl").read_text(encoding="utf-8")
        self.assertNotEqual(first, second)

    def test_refuses_to_run_without_secret(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != "RAKSHA_SECRET"}
        result = subprocess.run(
            [sys.executable, str(MAIN), "--input", str(self.src), "--output", str(self.tmp / "out4")],
            capture_output=True, text=True, env=env, timeout=120,
        )
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Anil", result.stderr)


if __name__ == "__main__":
    unittest.main()
