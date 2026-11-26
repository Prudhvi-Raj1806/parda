# Team plan: Parda (Track 3, Secret Wards)

Team: the collectors (Prudhvi, Prahlad, Sanskar). Prahlad and Sanskar are helping on Parda (Track 3).
Submission deadline: 8:05 PM IST. Only the last commit on `main` at the deadline is scored.
Current status and open items: see README.md (Limitations) and docs/parda_brief.html.

Read the competition brief's submission format (`raksha.toml`, `report.json`, `records.jsonl`, and the
`validate_output.py` checker) before writing code. The skeleton in `main.py` already writes this layout.

## Ownership

### Prahlad: detection engine
- Owns `detect/` (identifier and name detection for English, Devanagari and Hinglish).
- Regex and rule-based patterns for phones, Aadhaar-like IDs, ABHA, UHID/MRN, PAN, insurance IDs, dates and addresses.
- Name handling: honorifics (ji, sahab, didi), relatives (S/o, D/o, W/o), initials, surname-first order.
- Gazetteers for names and transliteration variants (Mohammad / Md. / मोहम्मद).
- Meaning traps: keep doses (Dolo 650 BD x 5 days, 1-0-1), medical terms, doctor names ("Dr. Ramesh"), and "C/O fever" vs "C/O Ramesh".

### Sanskar: linkage and pseudonyms
- Owns `link/` (record clustering) and `pseudo/` (pseudonym issuance).
- Blocking plus fuzzy and phonetic matching, comparing across scripts. Avoid transitive over-merging: different people with the same name must stay separate.
- Stable pseudonyms with keyed HMAC (`RAKSHA_SECRET`), never plain hashes. Per-patient date shifts derived from the same key.
- When evidence is weak, leave `"patient": null`. A wrong link costs more than no link.

### Prudhvi: ingestion, privacy layer, security and submission
- Owns `main.py`, `ingest/`, `privacy/`, `config/policy.yaml`, the report, and the brief.
- Ingestion for CSV, TSV, JSON, FHIR R4 and text, with encoding detection. Quarantine anything unsupported. Never copy a file we could not process.
- Privacy layer: age banding (the real age must stay inside its band), location generalisation, rare-value suppression, and a measured re-identification risk (k-anonymity on quasi-identifiers).
- Security: no PII in logs, error messages or temp files. Write temp files only in a private directory and delete them. Keys never go in data files.
- Writes the README, the 2-page brief, and runs the organizers' checker before each push.

## Working rules
- Agree the record format between `ingest/` and `detect/` early: one common structure per record with its file and location.
- Commit small and often. Keep `main` runnable.
- Never commit real or raw patient data, practice-data copies or secrets. The repo is public. `dev/` and `.env` are git-ignored.
- Do not use LLMs or pretrained transformers above 50M parameters.
