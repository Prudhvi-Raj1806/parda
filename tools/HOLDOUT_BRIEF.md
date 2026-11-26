# Independent held-out set: brief for a teammate

Goal: a third test set that someone other than the author of Parda writes, so the rules are checked against
conventions we did not choose. Synthetic data only. No real patient data, ever.

## What to produce

1. An input folder (empty to start) with at least four kinds of file:
   - a CSV with headers the author chooses (not `Patient Name` or `UHID`), with names split across columns
     or written as initials, and dates written as month names;
   - a TSV or JSON lab feed where some rows carry only a hospital number and no name;
   - a nested JSON or FHIR `Patient` resource with names, phones and an Aadhaar number;
   - text notes that mix English, Hindi (Devanagari) and Hinglish, with labels the author invents.
2. A truth file in the same format as `tools/make_holdout.py` writes: `patients` (id and medical values that
   must survive), `surfaces` (each personal value with its type and the patient it belongs to) and `units`
   (each record's file, locator and patient). Copy the structure from `make_holdout.py`.
3. Keep the truth file out of the repository.

## How to score it

```
python tools/score_holdout.py --input <your input folder> --output <parda output folder> --truth <your truth.json>
```

Report the four numbers the scorer prints: personal surfaces visible, medical values kept, linking precision
and recall, and files withheld. Send them to the team with the truth file kept privately.

## Rules for the author

- Do not look at `engine/`, the existing held-out sets, or the practice data while writing. That is what makes
  the set independent.
- Include at least three patients whose names appear in a different script than their records.
- Include at least two different people with the same name.
