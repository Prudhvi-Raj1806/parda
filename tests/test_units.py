"""Unit tests for ingestion, detection, linkage, privacy and security helpers. Run: python tests/test_units.py"""

from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from engine.config import Policy, load_rules  # noqa: E402
from engine.crypto import date_offset, derive_key, pseudonym  # noqa: E402
from engine.detection import (HeaderClassifier, clinical_spans, compile_terms, shape_spans)  # noqa: E402
from engine.ingestion import Quarantine, decode_strict, ingest, parse_file, strict_json  # noqa: E402
from engine.linkage import Profile, contradicts, pair_score, Resolver  # noqa: E402
from engine.privacy import DateShifter, age_band, age_text  # noqa: E402
from engine.sanitize import apply as apply_spans  # noqa: E402

RULES = load_rules()


class IngestionTests(unittest.TestCase):
    def test_bom_and_utf16_decode(self) -> None:
        self.assertEqual(decode_strict(b"\xef\xbb\xbfa,b\n"), "a,b\n")
        self.assertEqual(decode_strict("a,b\n".encode("utf-16")), "a,b\n")

    def test_cp1252_accepted_when_every_byte_is_defined(self) -> None:
        self.assertEqual(decode_strict("Rs 5 é".encode("cp1252")), "Rs 5 é")

    def test_undefined_bytes_are_refused(self) -> None:
        with self.assertRaises(Quarantine) as ctx:
            decode_strict(b"\x81\x8d\x8f\x90\x9d")
        self.assertEqual(ctx.exception.reason, "unsafe_encoding")

    def test_duplicate_json_keys_are_refused(self) -> None:
        with self.assertRaises(Quarantine) as ctx:
            strict_json('{"a": 1, "a": 2}')
        self.assertEqual(ctx.exception.reason, "malformed_structure")

    def test_truncated_json_is_refused(self) -> None:
        with self.assertRaises(Quarantine):
            parse_file("x.json", b'{"visits": [{"a": 1}')

    def test_very_deep_json_is_a_resource_limit(self) -> None:
        deep = "[" * 1500 + "]" * 1500
        with self.assertRaises(Quarantine) as ctx:
            parse_file("deep.json", deep.encode())
        self.assertEqual(ctx.exception.reason, "resource_limit")

    def test_binary_and_unknown_extensions_are_quarantined(self) -> None:
        with self.assertRaises(Quarantine) as a:
            parse_file("scan.txt", b"%PDF-1.4 data")
        self.assertEqual(a.exception.reason, "unsupported_attachment")
        with self.assertRaises(Quarantine) as b:
            parse_file("note.xml", b"<a/>")
        self.assertEqual(b.exception.reason, "unsupported_format")

    def test_empty_file(self) -> None:
        with self.assertRaises(Quarantine) as ctx:
            parse_file("empty.csv", b"  \n")
        self.assertEqual(ctx.exception.reason, "empty_file")

    def test_ingest_lists_every_file_in_sorted_order(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "b").mkdir()
            (root / "b" / "x.txt").write_text("hello", encoding="utf-8")
            (root / "a.csv").write_text("h\nv\n", encoding="utf-8")
            (root / "c.pdf").write_bytes(b"%PDF")
            accepted, quarantined = ingest(root)
            self.assertEqual([f.rel for f in accepted], ["a.csv", "b/x.txt"])
            self.assertEqual([q[0] for q in quarantined], ["c.pdf"])


class DetectionTests(unittest.TestCase):
    def test_aliases_classify_english_and_romanised_hindi_headers(self) -> None:
        clf = HeaderClassifier(RULES)
        self.assertEqual(clf.classify("Patient Name"), "PATIENT_NAME")
        self.assertEqual(clf.classify("Relative Name"), "RELATIVE_NAME")
        self.assertEqual(clf.classify("Pita/Pati ka Naam"), "RELATIVE_NAME")
        self.assertEqual(clf.classify("Janm Tithi"), "DOB")
        self.assertEqual(clf.classify("Aadhaar No"), "AADHAAR")
        self.assertEqual(clf.classify("PatientID"), "MRN")
        self.assertEqual(clf.classify("Haemoglobin"), None)
        self.assertEqual(clf.classify("ref_doctor"), None)

    def test_identifier_shapes(self) -> None:
        kinds = {s.kind for s in shape_spans("PAN DCSPS3454E, ABHA 91-7938-3729-8403, Aadhaar 8799 6191 4045, "
                                             "mob +91 72864 90658, UHID-010607, a@example.com")}
        self.assertTrue({"PAN", "ABHA_NUMBER", "AADHAAR", "PHONE", "MRN", "EMAIL"} <= kinds)

    def test_devanagari_mobile_is_detected(self) -> None:
        self.assertIn("PHONE", {s.kind for s in shape_spans("फोन ८९२१६७८५४१")})

    def test_medicines_doses_and_vitals_are_protected(self) -> None:
        text = "Ramipril 5 mg, Dolo 650 1-0-1 x 5 days, BP 150/90, SpO2 98%, Haemoglobin 10.2 g/dL, Parkinson's disease"
        protected = [text[s.start:s.end] for s in clinical_spans(text, compile_terms(RULES.clinical_terms))]
        for expected in ("5 mg", "1-0-1", "x 5 days", "150/90", "SpO2 98%", "10.2 g/dL", "Parkinson's disease"):
            self.assertTrue(any(expected in p for p in protected), expected)

    def test_doctor_is_protected_so_a_name_inside_is_not_removed(self) -> None:
        text = "Dr. Ramesh Srivastava (MD Medicine)"
        spans = clinical_spans(text, [])
        self.assertTrue(any(text[s.start:s.end].startswith("Dr. Ramesh") for s in spans))

    def test_clinical_span_blocks_a_weaker_name_match(self) -> None:
        from engine.detection import Span
        text = "Dr. Ramesh Srivastava"
        clinical = clinical_spans(text, [])
        name = Span(4, 10, "PATIENT_NAME", 2)  # 'Ramesh' matched as a dataset name
        out = apply_spans(text, clinical + [name])
        self.assertEqual(out.text, text)

    def test_identifier_beats_clinical_protection(self) -> None:
        from engine.detection import Span
        text = "x 9811122233 y"
        ident = Span(2, 12, "PHONE", 5)
        clin = Span(0, 14, "CLINICAL", 3)
        out = apply_spans(text, [clin, ident])
        self.assertIn("[PHONE]", out.text)


class LinkageTests(unittest.TestCase):
    def profile(self, key, **kw) -> Profile:
        p = Profile(key=key)
        for k, v in kw.items():
            setattr(p, k, v)
        return p

    def test_name_alone_never_links(self) -> None:
        a = self.profile(("a", "1"), names={"anil verma"})
        b = self.profile(("b", "1"), names={"anil verma"})
        self.assertEqual(pair_score(a, b)[0], 35)
        self.assertFalse(pair_score(a, b)[1])        # 35 and no corroboration

    def test_shared_phone_alone_does_not_link(self) -> None:
        a = self.profile(("a", "1"), phones={"9811122233"})
        b = self.profile(("b", "1"), phones={"9811122233"})
        self.assertEqual(pair_score(a, b)[0], 45)
        r = Resolver(85)
        r.add(a)
        r.add(b)
        clusters = r.resolve()
        self.assertNotEqual(clusters[("a", "1")], clusters[("b", "1")])

    def test_shared_global_id_links(self) -> None:
        a = self.profile(("a", "1"), global_ids={"AADHAAR:123412341234"})
        b = self.profile(("b", "1"), global_ids={"AADHAAR:123412341234"}, names={"x y"})
        r = Resolver(85)
        r.add(a)
        r.add(b)
        clusters = r.resolve()
        self.assertEqual(clusters[("a", "1")], clusters[("b", "1")])

    def test_two_different_aadhaar_numbers_contradict(self) -> None:
        a = self.profile(("a", "1"), global_ids={"AADHAAR:111111111111"}, phones={"9811122233"})
        b = self.profile(("b", "1"), global_ids={"AADHAAR:222222222222"}, phones={"9811122233"})
        self.assertTrue(contradicts(a, b))

    def test_incompatible_dates_of_birth_contradict(self) -> None:
        a = self.profile(("a", "1"), dobs={"1977-04-12"}, local_ids={"SNJ:26000111"})
        b = self.profile(("b", "1"), dobs={"1990-01-02"}, local_ids={"SNJ:26000111"})
        self.assertTrue(contradicts(a, b))

    def test_record_naming_two_patients_is_ambiguous(self) -> None:
        a = self.profile(("a", "1"), local_ids={"SNJ:26000111", "SNJ:26000222"})
        a.ambiguous = True
        b = self.profile(("b", "1"), local_ids={"SNJ:26000111"})
        self.assertTrue(contradicts(a, b))


class PrivacyTests(unittest.TestCase):
    policy = Policy()

    def test_offsets_are_nonzero_and_within_range(self) -> None:
        key = derive_key(b"secret", "dates")
        for i in range(300):
            d = date_offset(key, f"anchor{i}", 30, 365)
            self.assertTrue(30 <= abs(d) <= 365)

    def test_stay_length_is_preserved(self) -> None:
        shifter = DateShifter(derive_key(b"secret", "dates"), self.policy)
        a = shifter.shift_parts("PSN-AAAAAA", 2026, 9, 24)
        b = shifter.shift_parts("PSN-AAAAAA", 2026, 9, 26)
        self.assertEqual((date.fromisoformat(b) - date.fromisoformat(a)).days, 2)

    def test_age_bands_contain_the_age(self) -> None:
        for age in (0, 4, 5, 17, 18, 39, 40, 47, 89, 90):
            lo, hi = (int(x) for x in age_band(age, self.policy).split("-"))
            self.assertTrue(lo <= age <= hi)

    def test_age_text_keeps_the_sex_suffix(self) -> None:
        self.assertTrue(age_text("65/F", self.policy).endswith("/F"))

    def test_pseudonym_is_keyed_and_stable(self) -> None:
        k1, k2 = derive_key(b"one", "pseudonym"), derive_key(b"two", "pseudonym")
        self.assertEqual(pseudonym(k1, "anchor"), pseudonym(k1, "anchor"))
        self.assertNotEqual(pseudonym(k1, "anchor"), pseudonym(k2, "anchor"))
        self.assertRegex(pseudonym(k1, "anchor"), r"^PSN-[0-9A-HJKMNP-TV-Z]{6}$")


class ContractTests(unittest.TestCase):
    def test_raksha_toml_declares_the_entry_point(self) -> None:
        text = (ROOT / "raksha.toml").read_text(encoding="utf-8")
        self.assertIn('run   = "python main.py --input {input} --output {output}"', text)

    def test_policy_and_rule_files_load(self) -> None:
        self.assertGreater(len(RULES.aliases), 5)
        self.assertGreater(len(RULES.clinical_terms), 5)
        self.assertEqual(RULES.policy.k_anonymity, 5)


if __name__ == "__main__":
    unittest.main()
