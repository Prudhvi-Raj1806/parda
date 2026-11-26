# Secret Wards: offline privacy firewall for synthetic hospital records

Yugaantar 2026 · DevForge, Track 3. A CPU-only, LLM-free pipeline that removes personal
information from synthetic Indian hospital records (English, Hindi, Hinglish), keeps medical data
intact, links the same patient across files and languages, and leaks nothing.

## Status

Skeleton only. `main.py` writes the required output layout and quarantines every input file, so it
never copies raw data. Detection, linkage and privacy steps are still to be built.

## Setup

```bash
pip install -r requirements.txt
export RAKSHA_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"   # keep private
python main.py --input path/to/input --output path/to/output
```

On Windows PowerShell, set the variable with `$env:RAKSHA_SECRET = "..."`.

## Output contract

`output/` gets `sanitized/` (same folders and formats as the input), `report.json` (SHA-256 of each
input file, counts, timing) and `records.jsonl` (record to fake patient ID). See the competition brief
for the full contract. Run the organizers' `validate_output.py` before submitting.

## Team

See [TEAM.md](TEAM.md) for the task split.

## Models

No LLMs. Rules, gazetteers and classical methods only (declare any trained model here).
