"""Privacy transforms: patient-specific date offsets, truthful age bands, location policy.

A date offset is fixed per patient (or per record when the record is not linked), so every date of one
patient moves by the same amount and a stay keeps its length. Offsets are nonzero and within the policy range.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from engine.config import Policy
from engine.crypto import date_offset


@dataclass
class DateShifter:
    key: bytes          # derive_key(secret, "dates")
    policy: Policy

    def offset(self, anchor: str) -> int:
        return date_offset(self.key, anchor, self.policy.date_shift_min_days, self.policy.date_shift_max_days)

    def shift_parts(self, anchor: str, y: int, m: int, d: int) -> str | None:
        try:
            day = dt.date(y, m, d)
        except ValueError:
            return None
        return (day + dt.timedelta(days=self.offset(anchor))).isoformat()

    def __call__(self, y: int, a: int, b: int, month_first, fmt: str, sep: str, anchor: str, hint: bool = False) -> str:
        """Return the replacement for a date written as a/b/y (dmy, or iso when fmt == 'iso').

        `month_first` is True or False when the numbers settle the order, None when they do not; then
        `hint` (the column header says MM/DD) decides, and day-first is the default.
        """
        if fmt == "iso":
            shifted = self.shift_parts(anchor, y, a, b)
            return shifted if shifted else "[DATE]"
        order_month_first = hint if month_first is None else month_first
        day, mon = (b, a) if order_month_first else (a, b)
        shifted = self.shift_parts(anchor, y, mon, day)
        if shifted is None:
            return "[DATE]"
        s = dt.date.fromisoformat(shifted)
        if order_month_first:
            return f"{s.month:02d}{sep}{s.day:02d}{sep}{s.year}"
        return f"{s.day:02d}{sep}{s.month:02d}{sep}{s.year}"


def age_band(age: int, policy: Policy) -> str:
    """A band that always contains the true age. Minors get narrower bands than adults."""
    width = policy.age_band_minor_years if age < policy.minor_age_threshold else policy.age_band_adult_years
    lo = (age // width) * width
    return f"{lo}-{lo + width - 1}"


def age_text(value: str, policy: Policy) -> str:
    """'48' -> '40-49'; '65/F' -> '60-69/F'. Anything without a leading age becomes [AGE]."""
    import re
    m = re.match(r"\s*(\d{1,3})(?!\d)", value)
    if not m:
        return "[AGE]"
    return age_band(int(m.group(1)), policy) + value[m.end():]


def widen_band(band: str, policy: Policy) -> str:
    """Used for quasi-identifier classes smaller than k: a 20-year band that still contains the age."""
    lo_s, _, hi_s = band.partition("-")
    lo = int(lo_s)
    width = policy.widened_age_band_years
    lo2 = (lo // width) * width
    return f"{lo2}-{lo2 + width - 1}"
