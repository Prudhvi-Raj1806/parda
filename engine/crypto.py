"""Keys, pseudonyms and date offsets. Standard library only (hmac, hashlib).

One secret (RAKSHA_SECRET) yields independent keys per purpose, so a pseudonym can never be confused with
a date offset or any other derived value. HMAC is pseudonymisation, not anonymity: anyone holding the secret
can recompute a pseudonym from a known identifier.
"""

from __future__ import annotations

import hashlib
import hmac

_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # Crockford base32: no I, L, O, U


def derive_key(secret: bytes, purpose: str) -> bytes:
    """Domain separation: HMAC(secret, purpose) gives an independent key per purpose."""
    return hmac.new(secret, ("parda|" + purpose).encode("utf-8"), hashlib.sha256).digest()


def pseudonym(key: bytes, anchor: str, length: int = 6) -> str:
    """'PSN-' plus `length` Crockford base32 characters of HMAC(key, anchor)."""
    digest = hmac.new(key, anchor.encode("utf-8"), hashlib.sha256).digest()
    n = int.from_bytes(digest[:10], "big")
    chars = []
    for _ in range(length):
        chars.append(_ALPHABET[n & 31])
        n >>= 5
    return "PSN-" + "".join(chars)


def date_offset(key: bytes, anchor: str, lo: int, hi: int) -> int:
    """A nonzero offset in [lo, hi] (or its negative), fixed by (key, anchor)."""
    digest = hmac.new(key, anchor.encode("utf-8"), hashlib.sha256).digest()
    magnitude = lo + int.from_bytes(digest[:8], "big") % (hi - lo + 1)
    return magnitude if digest[8] & 1 else -magnitude
