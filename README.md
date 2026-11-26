# Parda

An offline privacy firewall for clinical records. Yugaantar 2026 · DevForge, Track 3 (Secret Wards).

Parda reads a messy folder of hospital exports (CSV and TSV in UTF-8, UTF-16 or cp1252; nested JSON; FHIR R4
bundles; text notes; base64 attachments), removes personal information in English, Hindi and Hinglish,
keeps medical values intact, links the same patient across files on evidence, and writes a verified release,
a truthful report and a record map. It runs on the Python standard library plus PyYAML. It never calls a
model, the network, or any service.

## Run

```bash
pip install -r requirements.txt                       # PyYAML only (setup step; network allowed)
export RAKSHA_SECRET="a-long-random-secret"           # PowerShell: $env:RAKSHA_SECRET = "..."
python main.py --input path/to/input --output path/to/empty-output
```

Parda refuses to run without `RAKSHA_SECRET`. The secret keys the pseudonyms and the date offsets, and it is
never written to the output or to any log. stdout shows counts only.

Checks:

```bash
python tests/test_units.py        # unit tests: ingestion, detection, linkage, privacy, security helpers
python tests/test_pipeline.py     # end-to-end tests on invented data
python tools/benchmark.py --input path/to/input     # time and determinism (needs RAKSHA_SECRET)
python tools/make_variant.py --input path/to/input --output path/to/copy   # changed-format copy for testing
python tools/demo.py                          # live demo: cross-script match, rejected false merge, preserved dose
python tools/attack.py --release path/to/output --input path/to/input --truth T --registry R --facts F   # simplified privacy attacker
```

## Output

```
output/
  sanitized/       same folders and formats as the input; file names scrubbed too
  report.json      SHA-256 of every input file, its status and reason, counts, entities, risk, timing
  records.jsonl    one line per record: file, input locator (row:N, JSON pointer or doc), pseudonym or null
```

Files that cannot be processed are quarantined with a reason code (`unsupported_format`,
`unsupported_attachment`, `unsafe_encoding`, `malformed_structure`, `resource_limit`, `empty_file`,
`unsafe_path`, `unresolved_pii`, `clinical_integrity_failure`, `fhir_validation_failure`). They are listed in the
report and never copied.

## How it works

Two passes. The first only reads.

1. **Ingestion.** Files are discovered in sorted order and hashed. Symlinks are refused. Text is decoded
   strictly (BOM-aware UTF-8 and UTF-16, then strict UTF-8, then cp1252 only when every byte is defined). JSON
   is parsed with duplicate-key rejection and a depth limit. Anything uncertain is quarantined.
2. **Pass 1, learn.** Names, addresses and dates of birth are read from column headers and JSON keys (matched
   through `config/aliases.yaml`, English and romanised or Devanagari Hindi), from labels and relatives in text,
   and from values that read as an address. Each record gets an identity profile: global IDs (Aadhaar, ABHA,
   PAN, e-mail, insurance), hospital-scoped numbers (UHID, SNJ, JJH, DHH, IPD, ADM), mobile numbers, dates of
   birth, canonical names (transliteration-aware via `config/name_variants.yaml`), relatives, locality and age.
3. **Identity resolution.** Candidate pairs come from shared blocks (an ID, a phone, a name). Each pair gets an
   evidence score: trusted global ID 100, namespaced local ID 85, mobile 45, date of birth 35, strong name 35 or
   moderate name 20, relative 20, locality 10, age 5. A pair links only when it reaches 85 and has independent
   corroboration. Contradictions always reject a pair: two different Aadhaar or hospital numbers of one kind,
   incompatible dates of birth, or a record that names two patients. A merge is refused when any two members
   of the resulting cluster would contradict each other. A shared phone or name alone never links anyone.
4. **Pass 2, sanitise and gate.** Each file is rendered in memory as a set of candidate spans: identifier
   shapes, role names, dataset names, address literals, dates, and clinical protection (doses, frequencies,
   BP, SpO2, lab values, stay lengths, diagnoses, procedures, drug names, clinicians). Overlaps are resolved by
   priority: high-confidence identifiers, then contextual roles, then clinical protection, then dataset names,
   then generic patterns. Edits are applied right to left. Dates shift by one offset per patient. Ages become
   bands that contain the true age. Pseudonyms are written inside the record, in the name field or the
   hospital-number field, or into the first line of a note.
5. **Release gate.** Each file's bytes are checked before anything is written: the output re-parses (G1); no
   dataset name, identifier shape or input identifier remains (G2, G3); every clinical fingerprint from the
   input is still present (G4); every pseudonym written into the record is present in it (G5, or the record's
   link is withdrawn); the path is safe (G6). A failed file is withheld with its reason. Only then are files
   written. The input is re-hashed first, and the run stops if it changed.

### Keys and pseudonyms

`RAKSHA_SECRET` yields independent keys per purpose, so a pseudonym can never be confused with a date offset
(`engine/crypto.py`). A pseudonym is `PSN-` plus six base32 characters of HMAC over the cluster's smallest
identifier, and it is lengthened deterministically if two clusters would collide. A date offset is 30 to 365
days, nonzero, fixed per patient, and applied to every date of that patient. An unlinked record gets its own
offset. HMAC is pseudonymisation, not anonymity: anyone holding the secret can recompute a pseudonym from a
known identifier.

## Files

| Path | Role |
| --- | --- |
| `main.py` | Entry point (`run` in `raksha.toml`) |
| `engine/pipeline.py` | Two passes, the release gate, records and the report |
| `engine/ingestion.py` | Discovery, hashing, strict decoding, parsing, reason codes |
| `engine/detection.py` | Header classifier, identifier shapes, clinical protection, date spans |
| `engine/names.py` | Name discovery in running text: labels, relatives, honorifics, phone context |
| `engine/registry.py` | Names and address literals learned from the input, matched across channels |
| `engine/linkage.py` | Identity profiles, evidence scores, contradictions, cluster merging |
| `engine/sanitize.py` | Span resolution and editing (the only place text is changed) |
| `engine/privacy.py` | Date offsets, age bands, widening |
| `engine/crypto.py` | Domain-separated keys, pseudonyms, date offsets |
| `engine/config.py` | Loads the policy and rule files |
| `engine/hidden.py` | Base64 attachments |
| `config/policy.yaml` | Date range, age bands, k, link threshold |
| `config/aliases.yaml` | Field names in English and Hindi, by role |
| `config/name_variants.yaml` | Spelling variants used for matching only |
| `config/clinical_terms.txt` | Clinical terms protected from being read as names |
| `tests/` | Unit and end-to-end tests on invented data |
| `tools/` | Benchmark, changed-format copy |
| `docs/brief.pdf` | Two-page project brief |

## Measured results

Measured on this machine (Windows 11, Python 3.12) on the practice data, using the kit's checker with a local
copy that maps files by the hash of the file on disk. The kit's answer key does not match 172 of its 200 input
hashes, so the official checker may score differently. These are rough guides, not the official score.

| Check | Practice data | Changed headers (copy) |
| --- | --- | --- |
| Personal data still visible | 0.6% (20 of 3,230) | 1.2% (40 of 3,230) |
| Planted canaries in output | 0 of 4 | 0 of 4 |
| Medical values kept | 99.8% (4,844 of 4,855) | 99.8% |
| Linking precision / recall (F0.5) | 1.00 / 0.84 (0.96) | 1.00 / 0.83 (0.96) |
| Files quarantined | 6 (all expected: pdf, jpg, xml, empty, deep, truncated) | 6 |
| Records linked | 753 of 822 | 753 of 822 |

Run: about 5 seconds for 200 files, identical output on a repeat run. Peak memory is not measured on Windows.

Re-identification risk (`report.json` → `risk`). The quasi-identifier is age band and sex. Before widening,
24 of 29 classes had fewer than 5 distinct patients. Widening the age band to 20 years for those units brings
the count to 12 classes still below k. Those classes remain small, and the report says so.

## Limitations

- **Names in unlabelled text.** A name with no label, honorific or nearby phone (for example a bare first name
  in a nursing note) is not discovered. Devanagari names in running text are found only after a label or next
  to a phone number.
- **Ward numbers.** A hospital ward is kept as clinical context, so a ward number written as an address can
  still appear in a discharge note.
- **Linking recall.** Records with no identifier and no DOB are left unlinked (`patient: null`), which costs
  recall and not precision. One patient's records are sometimes split into several clusters.
- **Dates.** Dates in unfamiliar formats are not recognised. Dates of birth in free text are shifted only when
  they are written day-month-year or month-day-year.
- **FHIR.** Bundles keep their JSON structure, and references are not rewritten. Validation is structural
  (resourceType and entry shape), not full R4 validation.
- **Column rules** depend on the aliases file. An unfamiliar header falls back to value-level checks, which
  leak more (1.2% against 0.6% above).
- **Learned names over-match.** A name learned from one record is removed everywhere in the input, including
  other people's notes that contain the same words. This favours privacy over utility.
- **Tuning.** The rules were tuned on the practice data; the changed-header copy is the closest test we have
  of how they transfer.
- **Not run:** `check_submission.py` from the kit (it fails on Windows paths), and any Linux or offline clean-machine test.

## Security design

- The secret comes from the environment. It is never printed, logged or written. The run refuses to start without it.
- stdout and stderr show counts only. Errors show exception classes and input hashes, never content.
- No temporary files. The registry, profiles and outputs live in memory until the gate passes.
- Unreadable or unsafe inputs are quarantined. Nothing is copied raw. Symlinks are refused.
- Output is deterministic: the same input and secret give byte-identical `sanitized/` and `records.jsonl`. A
  different secret changes every pseudonym and date offset.

## Team

See [TEAM.md](TEAM.md).
