"""Shared helpers for the test suite: synthetic inputs only (invented names and numbers)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAIN = ROOT / "main.py"

REGISTRATION = (
    "UHID,Patient Name,Gender,Age,DOB,Relative Name,Mobile,Aadhaar No,Village/Mohalla\n"
    "SNJ/26/000111,Anil Verma,M,47,12/04/1977,Sunita Verma,9811122233,4455 6677 8899,Rampur Kalan\n"
    "SNJ/26/000222,Kiran Dubey,F,33,01/02/1990,Mohan Dubey,9000011122,,Shivpur\n"
)
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


def make_input(root: Path) -> Path:
    src = root / "in"
    for d in ("registration", "lab", "notes", "misc"):
        (src / d).mkdir(parents=True, exist_ok=True)
    (src / "registration" / "reg.csv").write_text(REGISTRATION, encoding="utf-8")
    (src / "lab" / "lab.csv").write_text(LAB, encoding="utf-8")
    (src / "notes" / "discharge.txt").write_text(DISCHARGE, encoding="utf-8")
    (src / "misc" / "scan.pdf").write_bytes(b"%PDF-1.4 Anil Verma 9811122233")
    return src


def run_parda(input_dir: Path, output_dir: Path, secret: str = "test-secret") -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1")
    if secret is not None:
        env["RAKSHA_SECRET"] = secret
    else:
        env.pop("RAKSHA_SECRET", None)
    return subprocess.run(
        [sys.executable, str(MAIN), "--input", str(input_dir), "--output", str(output_dir)],
        capture_output=True, text=True, env=env, timeout=300,
    )
