#!/usr/bin/env python3
"""Parda: offline privacy firewall for clinical records. Entry point for `run` in raksha.toml.

Usage:  RAKSHA_SECRET=... python main.py --input <input dir> --output <empty output dir>

Only counts are printed: stdout and stderr are scanned for personal data.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from engine.pipeline import run_pipeline


def main() -> int:
    ap = argparse.ArgumentParser(description="Parda privacy firewall")
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    secret = os.environ.get("RAKSHA_SECRET", "")
    if not secret:
        # Refuse to run: pseudonyms and date shifts would be keyed with an empty secret.
        print("error: RAKSHA_SECRET is not set", file=sys.stderr)
        return 2
    inp, out = Path(args.input), Path(args.output)
    if not inp.is_dir():
        print("error: input folder not found", file=sys.stderr)
        return 2

    report = run_pipeline(inp, out, secret.encode("utf-8"))
    c = report["counts"]
    print(f"files {c['files_total']} sanitized {c['files_sanitized']} "
          f"quarantined {c['files_quarantined']} records {c['records_processed']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
