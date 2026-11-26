"""Secure ingestion: discover files, hash raw bytes, decode strictly, parse or quarantine.

Nothing is fetched, executed or deserialised. Symlinks are never followed. A file that cannot be parsed
with certainty is quarantined with a reason code (see SPEC section 5), and its bytes are never copied.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
from dataclasses import dataclass
from pathlib import Path

MAX_FILE_BYTES = 50 * 1024 * 1024
MAX_JSON_DEPTH = 200

# Magic numbers of formats we do not process: such a file is never parsed as text or copied.
BINARY_MAGIC = (b"%PDF", b"\x89PNG", b"\xff\xd8\xff", b"PK\x03\x04", b"GIF8", b"\x7fELF", b"MZ")

TEXT_EXTENSIONS = {".csv": "csv", ".tsv": "tsv", ".json": "json", ".txt": "text"}


class Quarantine(Exception):
    """A file that must be withheld. `reason` is a fixed code from SPEC section 5."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class InputFile:
    rel: str            # path relative to the input root, POSIX style (used internally, never published)
    sha256: str         # of the raw bytes
    kind: str           # csv | tsv | json | fhir | text
    text: str           # decoded text
    data: object = None  # parsed JSON for json and fhir


def decode_strict(raw: bytes) -> str:
    """BOM-aware UTF-8 / UTF-16, then strict UTF-8, then cp1252 only when every byte is defined."""
    if raw.startswith(b"\xef\xbb\xbf"):
        try:
            return raw[3:].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise Quarantine("unsafe_encoding") from exc
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return raw.decode("utf-16")
        except UnicodeDecodeError as exc:
            raise Quarantine("unsafe_encoding") from exc
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    try:
        return raw.decode("cp1252")
    except UnicodeDecodeError as exc:
        raise Quarantine("unsafe_encoding") from exc


def _reject_duplicate_keys(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise Quarantine("malformed_structure")
        obj[key] = value
    return obj


def _depth(node, limit: int) -> int:
    """Nesting depth, computed without recursion; stops early once `limit` is exceeded."""
    deepest = 0
    stack = [(node, 1)]
    while stack:
        cur, d = stack.pop()
        if d > deepest:
            deepest = d
            if deepest > limit:
                return deepest
        if isinstance(cur, dict):
            stack.extend((v, d + 1) for v in cur.values())
        elif isinstance(cur, list):
            stack.extend((v, d + 1) for v in cur)
    return deepest


def strict_json(text: str):
    try:
        data = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except Quarantine:
        raise
    except RecursionError as exc:
        raise Quarantine("resource_limit") from exc
    except (ValueError, TypeError) as exc:
        raise Quarantine("malformed_structure") from exc
    if _depth(data, MAX_JSON_DEPTH) > MAX_JSON_DEPTH:
        raise Quarantine("resource_limit")
    return data


def _is_fhir(data) -> bool:
    return isinstance(data, dict) and isinstance(data.get("resourceType"), str)


def parse_file(rel: str, raw: bytes) -> InputFile:
    """Decode and parse one file's bytes. Raises Quarantine with the reason when it cannot be processed."""
    if len(raw) > MAX_FILE_BYTES:
        raise Quarantine("resource_limit")
    if not raw.strip():
        raise Quarantine("empty_file")
    if raw.startswith(BINARY_MAGIC):
        raise Quarantine("unsupported_attachment")
    ext = os.path.splitext(rel)[1].lower()
    kind = TEXT_EXTENSIONS.get(ext)
    if kind is None:
        raise Quarantine("unsupported_format")
    text = decode_strict(raw)
    if "\x00" in text:
        raise Quarantine("unsafe_encoding")
    sha = hashlib.sha256(raw).hexdigest()
    if kind == "json":
        data = strict_json(text)
        return InputFile(rel, sha, "fhir" if _is_fhir(data) else "json", text, data)
    if kind in ("csv", "tsv"):
        try:
            list(csv.reader(io.StringIO(text, newline=""), delimiter="\t" if kind == "tsv" else ","))
        except csv.Error as exc:
            raise Quarantine("malformed_structure") from exc
    return InputFile(rel, sha, kind, text)


def discover(root: Path):
    """Yield (relative POSIX path, absolute path, reason-or-None) in sorted order. Symlinks are refused."""
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            if path.is_symlink():
                yield rel, path, "unsafe_path"
            else:
                yield rel, path, None


def ingest(root: Path):
    """Return (accepted InputFile list, quarantined list of (rel, sha256, reason)). Both sorted by path."""
    accepted, quarantined = [], []
    for rel, path, pre in discover(root):
        raw = b""
        if pre is None:
            try:
                raw = path.read_bytes()
            except OSError:
                pre = "unsafe_path"
        if pre is not None:
            quarantined.append((rel, hashlib.sha256(raw).hexdigest() if raw else "", pre))
            continue
        try:
            accepted.append(parse_file(rel, raw))
        except Quarantine as q:
            quarantined.append((rel, hashlib.sha256(raw).hexdigest(), q.reason))
    return accepted, quarantined
