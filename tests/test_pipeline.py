"""End-to-end tests of Parda on invented data. Run with: python tests/test_pipeline.py"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from helpers import make_input, run_parda  # noqa: E402


class PipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.tmp = Path(cls._tmp.name)
        cls.src = make_input(cls.tmp)
        cls.out = cls.tmp / "out"
        result = run_parda(cls.src, cls.out)
        assert result.returncode == 0, result.stderr
        cls.report = json.loads((cls.out / "report.json").read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def read_out(self, rel: str) -> str:
        return (self.out / "sanitized" / rel).read_text(encoding="utf-8")

    def records(self) -> list[dict]:
        return [json.loads(x) for x in (self.out / "records.jsonl").read_text(encoding="utf-8").splitlines()]

    def test_no_personal_data_left_in_csv(self) -> None:
        text = self.read_out("registration/reg.csv")
        for leaked in ("Anil Verma", "Sunita Verma", "9811122233", "4455 6677 8899", "Rampur Kalan"):
            self.assertNotIn(leaked, text)

    def test_unsupported_file_is_quarantined_not_copied(self) -> None:
        sha = hashlib.sha256((self.src / "misc" / "scan.pdf").read_bytes()).hexdigest()
        entry = [e for e in self.report["files"] if e["input_sha256"] == sha][0]
        self.assertEqual(entry["status"], "quarantined")
        self.assertEqual(entry["reason"], "unsupported_attachment")
        self.assertFalse((self.out / "sanitized" / "misc" / "scan.pdf").exists())

    def test_every_input_file_is_accounted_for(self) -> None:
        self.assertEqual(len(self.report["files"]), 4)
        self.assertEqual(self.report["counts"]["files_total"], 4)
        self.assertEqual(self.report["counts"]["files_sanitized"] + self.report["counts"]["files_quarantined"], 4)

    def test_same_uhid_links_across_files_and_is_inside_the_record(self) -> None:
        recs = {(r["file"], r["loc"]): r["patient"] for r in self.records()}
        reg0 = recs[("sanitized/registration/reg.csv", "row:0")]
        lab0 = recs[("sanitized/lab/lab.csv", "row:0")]
        reg1 = recs[("sanitized/registration/reg.csv", "row:1")]
        self.assertIsNotNone(reg0)
        self.assertEqual(reg0, lab0)                 # Anil Verma in both files
        self.assertNotEqual(reg0, reg1)              # two different people stay apart
        self.assertIn(reg0, self.read_out("registration/reg.csv"))
        self.assertIn(reg0, self.read_out("lab/lab.csv"))

    def test_medical_values_and_doctor_survive(self) -> None:
        text = self.read_out("notes/discharge.txt")
        self.assertIn("Dr. Ramesh Srivastava", text)
        self.assertIn("Dolo 650 1-0-1 x 5 days", text)
        self.assertNotIn("Anil Verma", text)
        self.assertIn("10.2", self.read_out("lab/lab.csv"))

    def test_dates_shift_but_keep_their_gap(self) -> None:
        text = self.read_out("notes/discharge.txt")
        self.assertNotIn("24/09/2026", text)
        dates = re.findall(r"\d{2}/\d{2}/\d{4}", text)
        self.assertEqual(len(dates), 2)
        d1, d2 = (date(int(d[6:]), int(d[3:5]), int(d[:2])) for d in dates)
        self.assertEqual((d2 - d1).days, 2)          # the stay is still two days

    def test_ages_become_bands_that_contain_the_age(self) -> None:
        text = self.read_out("registration/reg.csv")
        self.assertNotIn(",47,", text)
        row = text.split("\n")[1].split(",")
        band = [c for c in row if "-" in c and c[:1].isdigit()][0]
        lo, hi = (int(x) for x in band.split("/")[0].split("-"))
        self.assertTrue(lo <= 47 <= hi)              # the band contains the true age

    def test_same_secret_gives_identical_output(self) -> None:
        second = self.tmp / "out2"
        self.assertEqual(run_parda(self.src, second).returncode, 0)
        for rel in ("records.jsonl", "sanitized/registration/reg.csv", "sanitized/notes/discharge.txt"):
            self.assertEqual((self.out / rel).read_bytes(), (second / rel).read_bytes(), rel)

    def test_different_secret_changes_pseudonyms_and_dates(self) -> None:
        other = self.tmp / "out3"
        self.assertEqual(run_parda(self.src, other, secret="another-secret").returncode, 0)
        self.assertNotEqual((self.out / "records.jsonl").read_text(encoding="utf-8"),
                            (other / "records.jsonl").read_text(encoding="utf-8"))
        self.assertNotEqual(self.read_out("notes/discharge.txt"),
                            (other / "sanitized" / "notes" / "discharge.txt").read_text(encoding="utf-8"))

    def test_refuses_to_run_without_secret(self) -> None:
        result = run_parda(self.src, self.tmp / "out4", secret=None)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Anil", result.stderr)

    def test_report_counts_match_what_was_written(self) -> None:
        published = [e for e in self.report["files"] if e["status"] == "sanitized"]
        for e in published:
            self.assertTrue((self.out / e["output"]).is_file())
        self.assertEqual(self.report["counts"]["files_sanitized"], len(published))
        self.assertEqual(self.report["counts"]["records_processed"], len(self.records()))
        linked = sum(1 for r in self.records() if r["patient"])
        self.assertEqual(self.report["counts"]["records_linked"], linked)


if __name__ == "__main__":
    unittest.main()
