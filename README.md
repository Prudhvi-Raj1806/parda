# Secret Wards: offline privacy firewall for hospital records

Yugaantar 2026 · DevForge, Track 3. A CPU-only, offline, LLM-free pipeline that removes personal
information from synthetic Indian hospital records (English, Hindi and Hinglish), keeps medical values
intact, links the same patient across files, and writes a report that the checker can verify.

Standard library only. No model, no network, no downloads.

## Setup and run

```bash
export RAKSHA_SECRET="a-long-random-secret"      # PowerShell: $env:RAKSHA_SECRET = "..."
python main.py --input path/to/input --output path/to/empty-output
```

The pipeline refuses to run without `RAKSHA_SECRET`. The secret keys the pseudonyms and the date
shifts, and it is never written to the output or to any log.

Check the output format with the organizers' `validate_output.py`, and the leak numbers with `check_dev.py`.

## Output

```
output/
  sanitized/       same folders and formats as the input; file names scrubbed too
  report.json      SHA-256 of every input file, honest counts, timing, memory
  records.jsonl    one line per record: file, locator (row:N, /json/pointer or doc), patient pseudonym or null
```

Unreadable or unsupported files are quarantined: they are listed in the report and never copied.

## How it works

Two passes over the input, both read-only in the first:

1. **Learn (pass 1).** Every file is read once. Names come from name columns and name keys, from
   labels (`Name:`, `नाम:`), relatives (`S/o`, `D/o`, `W/o`, `C/O <name>`), honorifics (`ji`, `sahab`,
   `didi`, `chachu`) and from candidates next to a phone number or a contact cue. Addresses come
   from address columns and `Address:` lines. Strong identifiers are collected per record.
2. **Sanitise (pass 2).** Every string goes through the same channels, in this order:
   the name registry (case-insensitive, separators and underscores included, never inside a longer
   word; a name after `Dr.` is kept), honorific names, identifier shapes (Aadhaar, masked Aadhaar,
   ABHA, PAN, e-mail, hospital numbers, insurance IDs, phones in Latin and Devanagari digits), dates
   shifted by the record's offset, and finally the file name, JSON keys, headers and base64 attachments.
   Columns and keys whose name says what they hold are replaced whole (`rakshak/detect_struct.py`).

### Files

| File | Role |
| --- | --- |
| `main.py` | Entry point, both passes, report and records |
| `rakshak/detect_struct.py` | Column and key rules, identifier shapes, age and date columns |
| `rakshak/detect_text.py` | Name discovery in free text (labels, relatives, honorifics, phone context) |
| `rakshak/registry.py` | Learned names and address literals, matched across all channels; districts are kept |
| `rakshak/link.py` | Strong identifiers and union-find linking |
| `rakshak/hidden.py` | Base64 attachments and file-name scrubbing |
| `config/policy.yaml` | Age band width and maximum date shift |
| `tests/test_pipeline.py` | Smoke tests on invented data (`python tests/test_pipeline.py`) |

## Linking

Records are linked only by evidence that identifies one person:

- strong identifiers: Aadhaar, ABHA, PAN, e-mail, insurance IDs, hospital numbers (UHID, SNJ, JJH, DHH);
  IPD and ADM episode numbers are also used, since one admission has one number;
- mobile numbers, used as link keys;
- a record that names two different patients (a ward sheet, a helpdesk ticket, a bundle with several
  patients) links nothing, so it cannot merge two people.

A shared name, village or doctor never links records. A name together with a date of birth was tried
as a second rule; on the practice data it produced two wrong merges, so it is switched off
(`name_dob_keys` in `rakshak/link.py` is kept but unused).

The pseudonym is `HMAC-SHA256(RAKSHA_SECRET, smallest identifier key of the cluster)`, written into the
patient's name field (CSV) or name key (JSON), and into the first line of a text note.

## Privacy and utility choices

| Item | Choice |
| --- | --- |
| Patient name | Pseudonym where the record is linked, otherwise `[PATIENT_NAME]` |
| Relative name | `[RELATIVE_NAME]` |
| Doctor name | Kept (`Dr. ...` is never registered as a patient) |
| Dates | One offset per patient (per record when unlinked); format and gaps are kept, so a 2-day stay stays 2 days |
| Date of birth | Shifted like any date (not removed), so the policy's "shift" option is used |
| Age | 5-year band that contains the true age (`48` becomes `45-49`) |
| Village, house, locality, landmark | Removed (`[ADDRESS]`, or removed from free text by literal match) |
| PIN | Removed |
| District | Kept (the generalised location) |
| Hospital ward (`Ward 4` in a discharge) | Kept, since it is medical context; a `Ward N` in an address is therefore not removed |
| Medicines, doses, `1-0-1`, lab values, diagnoses | Never touched |

## Security design

- Nothing personal is printed. Stdout shows counts only; error messages show exception class and file hash.
- Unparseable files are quarantined, never copied. Files whose names collide after scrubbing get a
  suffix taken from the input hash, so no file is overwritten.
- No temporary files: the registry and the linker live in memory.
- The secret is read from the environment and is never written.
- Output is deterministic: the same input and secret give byte-identical output.

## Measured on the practice data (rough guide, not the official score)

Measured with `check_dev.py` after a local fix to the checker (see limits):

| Check | Result |
| --- | --- |
| Personal data still visible | 0.6% (20 of 3,230 pieces), down from 100% |
| Canaries found in the output | 0 of 4 |
| Medical values kept | 99.4% (4,825 of 4,855) |
| Linking (precision / recall) | 1.00 / 0.90 |
| Smoke tests | 9 of 9 pass |

Renaming all CSV headers in a copy of the practice data raised leaks to 4.4% (the rules depend on header
names). See limitations.

## Limitations

- **Header dependence.** Column rules recognise common English and romanised-Hindi headers. Unknown
  headers rely on text-level rules, so an address column with an unfamiliar name can leak (4.4% with
  renamed headers versus 0.6% with the original headers).
- **Names without a label or a phone number** are not discovered (for example a bare first name in a note,
  or a Devanagari name in running text). These are the largest remaining leaks.
- **Dates** in an unfamiliar format are not shifted. Only day-month-year, month-day-year when the header says
  `MM/DD`, and ISO dates are handled.
- **FHIR** is kept as JSON with the same structure, but references and coding are not validated against R4.
- **Checker mismatch (practice data).** 172 of the 200 hashes in `dev/truth/truth.json` do not match the input
  files on disk, so `check_dev.py` cannot map most renamed outputs. The numbers above use a local copy of the
  checker that maps by the hash of the file on disk. The official scorer may differ.
- **Tuned on practice data.** Name and address rules were adjusted against the practice data. Hidden data may do
  worse, and the header-rename test above is the best measure we have of that.
- The first hidden-data run is the real test. We have not run the official `check_submission.py`
  (it failed on Windows paths because of how it quotes the output folder).

## Team

See [TEAM.md](TEAM.md).
