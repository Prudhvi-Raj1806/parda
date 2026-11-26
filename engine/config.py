"""Loads the policy and rule files in config/. PyYAML is pinned in requirements.txt."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONFIG_DIR = ROOT / "config"


def norm_key(text: str) -> str:
    """Lower case, letters, digits and Devanagari only, single spaces: 'Patient Name' -> 'patient name'."""
    t = re.sub(r"[^0-9a-zऀ-ॿ]+", " ", text.lower())
    return " ".join(t.split())


@dataclass(frozen=True)
class Policy:
    date_shift_min_days: int = 30
    date_shift_max_days: int = 365
    age_band_adult_years: int = 10
    age_band_minor_years: int = 5
    minor_age_threshold: int = 18
    k_anonymity: int = 5
    widened_age_band_years: int = 20
    link_threshold: int = 85


@dataclass
class Rules:
    policy: Policy
    aliases: dict[str, list[str]] = field(default_factory=dict)
    name_variants: dict[str, str] = field(default_factory=dict)   # variant -> canonical
    clinical_terms: list[str] = field(default_factory=list)


def load_rules(config_dir: Path = CONFIG_DIR) -> Rules:
    raw_policy = yaml.safe_load((config_dir / "policy.yaml").read_text(encoding="utf-8")) or {}
    policy = Policy(**{k: int(v) for k, v in raw_policy.items() if k in Policy.__dataclass_fields__})

    raw_aliases = yaml.safe_load((config_dir / "aliases.yaml").read_text(encoding="utf-8")) or {}
    aliases = {role: [norm_key(a) for a in items] for role, items in raw_aliases.items()}

    raw_variants = yaml.safe_load((config_dir / "name_variants.yaml").read_text(encoding="utf-8")) or {}
    variants: dict[str, str] = {}
    for canonical, spellings in raw_variants.items():
        variants[norm_key(canonical)] = norm_key(canonical)
        for s in spellings:
            variants[norm_key(s)] = norm_key(canonical)

    terms = []
    for line in (config_dir / "clinical_terms.txt").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            terms.append(line)
    return Rules(policy=policy, aliases=aliases, name_variants=variants, clinical_terms=terms)
