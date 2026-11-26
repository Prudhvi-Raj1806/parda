"""Hidden channels: base64 attachments and file names. Standard library only."""

from __future__ import annotations

import base64
import binascii
import re

_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def decode_b64_text(value: str) -> str | None:
    """If the whole value is base64 of UTF-8 text, return that text; otherwise None."""
    s = value.strip()
    if len(s) < 16 or len(s) % 4 != 0 or not _B64.fullmatch(s):
        return None
    try:
        raw = base64.b64decode(s, validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    if not text.strip() or any(ord(c) < 9 for c in text):
        return None
    return text


def encode_b64_text(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def scrub_rel_path(rel: str, clean) -> str:
    """Clean every part of a relative path (folders and file name). `clean` maps str -> str."""
    return "/".join(clean(part) for part in rel.split("/"))
