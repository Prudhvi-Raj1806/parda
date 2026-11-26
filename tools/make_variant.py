"""Make a changed-format copy of an input folder, to test the rules on data they were not tuned on.

    python tools/make_variant.py --input <practice input> --output <new empty folder>

Every CSV/TSV header is replaced by a neutral name (field_0, field_1 ...), so the column rules must work from
the values and the text alone. The copy keeps every value, so the answer key still applies to the same records.
Writes a copy only; the input is never modified.
"""

from __future__ import annotations

import argparse
import csv
import io
import shutil
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser(description="Changed-format copy of a folder")
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    a = ap.parse_args()
    src, dst = Path(a.input), Path(a.output)
    if dst.exists() and any(dst.iterdir()):
        raise SystemExit("output folder must be empty")
    dst.mkdir(parents=True, exist_ok=True)
    renamed = 0
    for path in sorted(p for p in src.rglob("*") if p.is_file()):
        rel = path.relative_to(src)
        target = dst / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if path.suffix.lower() in (".csv", ".tsv"):
            raw = path.read_bytes()
            try:
                text = raw.decode("utf-8-sig")
            except UnicodeDecodeError:
                shutil.copyfile(path, target)
                continue
            delim = "\t" if path.suffix.lower() == ".tsv" else ","
            rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=delim))
            if len(rows) >= 2:
                rows[0] = [f"field_{i}" for i in range(len(rows[0]))]
                renamed += 1
                buf = io.StringIO()
                csv.writer(buf, delimiter=delim, lineterminator="\n").writerows(rows)
                target.write_text(buf.getvalue(), encoding="utf-8", newline="")
                continue
        shutil.copyfile(path, target)
    print(f"copied with {renamed} renamed tables")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
