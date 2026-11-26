"""Run Parda twice on a folder and report time, memory and determinism. Prints counts only.

    RAKSHA_SECRET=... python tools/benchmark.py --input <folder>

Peak memory is read from the operating system; it is reported as null where the platform cannot
measure it (Windows). Nothing here is hard-coded: every number is measured on this machine.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from engine.pipeline import run_pipeline  # noqa: E402


def tree_hash(folder: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(q for q in folder.rglob("*") if q.is_file()):
        rel = p.relative_to(folder).as_posix()
        if rel == "report.json":
            continue  # timings differ between runs by design; the release bytes must not
        h.update(rel.encode())
        h.update(p.read_bytes())
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="Parda benchmark")
    ap.add_argument("--input", required=True)
    args = ap.parse_args()
    secret = os.environ.get("RAKSHA_SECRET")
    if not secret:
        print("error: set RAKSHA_SECRET", file=sys.stderr)
        return 2
    inp = Path(args.input)
    with tempfile.TemporaryDirectory() as tmp:
        runs = []
        for name in ("a", "b"):
            out = Path(tmp) / name
            t0 = time.monotonic()
            report = run_pipeline(inp, out, secret.encode("utf-8"))
            runs.append({"seconds": round(time.monotonic() - t0, 2), "hash": tree_hash(out),
                         "peak_rss_mb": report["resources"]["peak_rss_mb"], "files": report["counts"]["files_total"],
                         "sanitized": report["counts"]["files_sanitized"],
                         "records": report["counts"]["records_processed"]})
    summary = {"runs": runs, "deterministic": runs[0]["hash"] == runs[1]["hash"]}
    print(json.dumps(summary, indent=2))
    return 0 if summary["deterministic"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
