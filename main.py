"""Secret Wards privacy firewall: entry point.

Skeleton only. It writes a valid output layout and quarantines every input file, so it never
copies raw data. Detection, linkage and privacy steps are added by the team (see TEAM.md).

Usage: python main.py --input <input_dir> --output <output_dir>
Requires the RAKSHA_SECRET environment variable. The secret is never written or logged.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run(input_dir: Path, output_dir: Path) -> None:
    started = time.time()
    (output_dir / "sanitized").mkdir(parents=True, exist_ok=True)

    files = []
    for path in sorted(p for p in input_dir.rglob("*") if p.is_file()):
        # Fail safe: nothing is copied until a real sanitiser exists for the format.
        files.append({
            "input_sha256": sha256_file(path),
            "output": None,
            "status": "quarantined",
            "reason": "pipeline not yet implemented for this file",
        })

    quarantined = sum(1 for f in files if f["status"] == "quarantined")
    report = {
        "files": files,
        "counts": {
            "files_total": len(files),
            "files_sanitized": len(files) - quarantined,
            "files_quarantined": quarantined,
            "records_processed": 0,
            "identifiers_detected": 0,
            "records_linked": 0,
            "records_generalized": 0,
            "records_suppressed": 0,
            "records_quarantined": 0,
        },
        "timing": {"seconds": round(time.time() - started, 2)},
        "resources": {"peak_rss_mb": None},
    }
    (output_dir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (output_dir / "records.jsonl").write_text("", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Secret Wards privacy firewall")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    if not os.environ.get("RAKSHA_SECRET"):
        # Do not echo any path or value here: error messages must not leak data.
        print("error: RAKSHA_SECRET is not set", file=sys.stderr)
        return 2
    if not args.input.is_dir():
        print("error: input directory not found", file=sys.stderr)
        return 2

    args.output.mkdir(parents=True, exist_ok=True)
    run(args.input, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
