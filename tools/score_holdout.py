"""Score a Parda output folder against a held-out truth file (see tools/make_holdout.py).

    python tools/score_holdout.py --input <holdout input folder> --output <parda output> --truth <truth.json>

Reports: personal surfaces still visible (overall and per type), medical values kept, and pairwise linking
precision and recall. Counts only; the truth file is never copied anywhere.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path

TEXT_SUFFIXES = (".csv", ".tsv", ".json", ".txt")


def norm(text: str) -> str:
    t = unicodedata.normalize("NFKC", text).casefold()
    return " ".join(t.replace("-", " ").replace("/", " ").split())


def pairs(n: int) -> int:
    return n * (n - 1) // 2


def read_all(folder: Path) -> str:
    parts = []
    for p in sorted(folder.rglob("*")):
        if p.is_file():
            parts.append(p.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(parts)


def unit_text(inp: Path, unit: dict) -> str:
    """The text of one input record: a CSV or TSV row, one JSON item, or the whole document."""
    path = inp / unit["file"]
    loc = unit["loc"]
    if loc == "doc":
        return path.read_text(encoding="utf-8", errors="replace")
    if loc.startswith("row:"):
        import csv
        import io
        delim = "	" if path.suffix == ".tsv" else ","
        rows = list(csv.reader(io.StringIO(path.read_text(encoding="utf-8", errors="replace"), newline=""),
                               delimiter=delim))
        return delim.join(rows[int(loc[4:]) + 1])
    key, _, index = loc.strip("/").partition("/")
    data = json.loads(path.read_text(encoding="utf-8"))
    return json.dumps(data[key][int(index)], ensure_ascii=False)


def main() -> int:
    ap = argparse.ArgumentParser(description="Score a Parda run on the held-out set")
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--truth", required=True)
    a = ap.parse_args()
    inp, out = Path(a.input), Path(a.output)
    truth = json.loads(Path(a.truth).read_text(encoding="utf-8"))
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))

    release = norm(read_all(out / "sanitized"))
    source = norm("\n".join(
        p.read_text(encoding="utf-8", errors="replace") for p in sorted(inp.rglob("*"))
        if p.is_file() and p.suffix in TEXT_SUFFIXES))

    total, visible = Counter(), Counter()
    for s in truth["surfaces"]:
        total[s["type"]] += 1
        if norm(s["surface"]) in release:
            visible[s["type"]] += 1
    all_total, all_visible = sum(total.values()), sum(visible.values())

    # A medical value counts only where the input itself contains it.
    med_total = med_kept = 0
    for p in truth["patients"]:
        for m in p["medical"]:
            if norm(m) not in source:
                continue
            med_total += 1
            med_kept += norm(m) in release

    # Linking: map truth units to output records through the input file hashes.
    sha_to_out = {e["input_sha256"]: e.get("output") for e in report["files"]}
    recs = {}
    for line in (out / "records.jsonl").read_text(encoding="utf-8").splitlines():
        r = json.loads(line)
        recs[(r["file"], r["loc"])] = r["patient"]
    by_pid: dict[str, Counter] = defaultdict(Counter)
    linked_units = 0
    for u in truth["units"]:
        sha = hashlib.sha256((inp / u["file"]).read_bytes()).hexdigest()
        target = sha_to_out.get(sha)
        pid = recs.get((target, u["loc"])) if target else None
        if pid is None:
            continue
        linked_units += 1
        by_pid[pid][u["patient"]] += 1
    same_pid = sum(pairs(sum(c.values())) for c in by_pid.values())
    correct = sum(pairs(n) for c in by_pid.values() for n in c.values())
    # A pair is linkable only when the data itself holds evidence for it (an identifier in that record),
    # as the kit's scoring does; a record with only a first name is not counted against recall.
    id_surfaces = defaultdict(list)
    for s_ in truth["surfaces"]:
        if s_["type"] in ("PHONE", "AADHAAR", "MRN", "ABHA_NUMBER"):
            id_surfaces[s_["patient"]].append(norm(s_["surface"]))
    linkable_units = Counter()
    for u in truth["units"]:
        text = unit_text(inp, u)
        if any(x in norm(text) for x in id_surfaces[u["patient"]]):
            linkable_units[u["patient"]] += 1
    linkable = sum(pairs(n) for n in linkable_units.values())
    precision = correct / same_pid if same_pid else 1.0
    recall = correct / linkable if linkable else 0.0

    print("personal surfaces still visible:", f"{all_visible} of {all_total} ({all_visible / all_total:.1%})")
    for t in sorted(total):
        print(f"  {t:<14} {visible[t]:>3} of {total[t]:<3} {visible[t] / total[t]:.1%}")
    print(f"medical values kept: {med_kept} of {med_total} ({med_kept / med_total:.1%})")
    print(f"linking: precision {precision:.2f}, recall {recall:.2f}; units linked {linked_units} of {len(truth['units'])}")
    print(f"files withheld: {report['counts']['files_quarantined']} of {report['counts']['files_total']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
