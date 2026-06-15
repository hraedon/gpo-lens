"""Parser for Microsoft PReg (Policy Registry) binary format.

Parses ``Registry.pol`` files found in GPO SYSVOL at
``Policies\\{GUID}\\Machine\\Registry.pol`` and ``User\\Registry.pol``.

Per [MS-GPREG] / the Registry Policy File Format, the file is an 8-byte header
(``50 52 65 67 01 00 00 00`` — the ``PReg`` signature DWORD plus a version
DWORD) followed by a sequence of records::

    [key;value_name;type;size;data]

The literal ``[``, ``;`` and ``]`` delimiters are themselves UTF-16LE
characters (two bytes each: ``5B 00``, ``3B 00``, ``5D 00``). ``key`` and
``value_name`` are null-terminated UTF-16LE strings. ``type`` and ``size`` are
each a 4-byte little-endian DWORD (``size`` is the byte length of ``data``).
``data`` is ``size`` raw bytes and is followed immediately by ``]`` (there is
no separator between ``data`` and the closing bracket).

Tolerant of a missing header and a truncated trailing record — returns every
complete record found without raising.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# REG type constants
# ---------------------------------------------------------------------------

REG_TYPE_NAMES: dict[int, str] = {
    0: "REG_NONE",
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    5: "REG_DWORD_BIG_ENDIAN",
    7: "REG_MULTI_SZ",
    11: "REG_QWORD",
}

_SIGNATURE = b"PReg"
_HEADER_LEN = 8  # 4-byte signature DWORD + 4-byte version DWORD
# Delimiters are UTF-16LE characters (two bytes each), not single ANSI bytes.
_OPEN = b"\x5b\x00"   # '['
_CLOSE = b"\x5d\x00"  # ']'
_SEP = b"\x3b\x00"    # ';'
_NULL_TERM = b"\x00\x00"  # UTF-16LE null terminator


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PregRecord:
    """One registry setting from a Registry.pol file."""

    key: str               # registry key path, e.g. r"Software\Policies\Acme"
    value_name: str        # value name, e.g. "EnableFoo"
    type_code: int         # REG_* code (4 = DWORD, 1 = SZ, ...)
    type_name: str         # human label, e.g. "REG_DWORD"
    size: int              # byte count of the original data
    data: bytes            # raw data bytes
    display_value: str     # decoded representation per the type table


# ---------------------------------------------------------------------------
# Value decoding
# ---------------------------------------------------------------------------

def decode_value(type_code: int, data: bytes) -> str:
    """Decode *data* bytes according to the REG *type_code*.

    Returns a human-readable string representation suitable for display.
    """
    if type_code == 0:  # REG_NONE
        return ""
    if type_code in (1, 2):  # REG_SZ, REG_EXPAND_SZ
        return _decode_utf16(data)
    if type_code == 3:  # REG_BINARY
        return data.hex()
    if type_code == 4:  # REG_DWORD
        if len(data) >= 4:
            return str(struct.unpack_from("<I", data)[0])
        return data.hex()
    if type_code == 5:  # REG_DWORD_BIG_ENDIAN
        if len(data) >= 4:
            return str(struct.unpack_from(">I", data)[0])
        return data.hex()
    if type_code == 7:  # REG_MULTI_SZ
        return _decode_multi_sz(data)
    if type_code == 11:  # REG_QWORD
        if len(data) >= 8:
            return str(struct.unpack_from("<Q", data)[0])
        return data.hex()
    # Unknown type — fall back to hex
    return data.hex()


def _decode_utf16(data: bytes) -> str:
    """Decode UTF-16LE bytes, stripping trailing null characters."""
    text = data.decode("utf-16-le", errors="replace")
    return text.rstrip("\x00")


def _decode_multi_sz(data: bytes) -> str:
    """Decode REG_MULTI_SZ: UTF-16LE, split on nulls, drop empties."""
    text = data.decode("utf-16-le", errors="replace")
    # The double-null terminator produces empty strings after split; drop them.
    parts = [p for p in text.split("\x00") if p]
    return "; ".join(parts)


# ---------------------------------------------------------------------------
# Helpers for reading UTF-16LE null-terminated strings from a byte buffer
# ---------------------------------------------------------------------------

def _read_utf16_null(buf: bytes, offset: int) -> tuple[str, int]:
    """Read a UTF-16LE null-terminated string starting at *offset*.

    Returns ``(decoded_string, new_offset)`` where *new_offset* is positioned
    right after the null terminator (i.e. after the 2-byte ``0x00 0x00``).
    """
    # Scan for the null terminator (0x00 0x00 on an even boundary).
    pos = offset
    while pos + 1 < len(buf):
        if buf[pos] == 0 and buf[pos + 1] == 0:
            # Found terminator — decode everything before it.
            raw = buf[offset:pos]
            text = raw.decode("utf-16-le", errors="replace")
            return text, pos + 2  # skip past the 2-byte terminator
        pos += 2  # UTF-16LE code units are 2 bytes
    # No null terminator found — treat rest of buffer as the string.
    raw = buf[offset:]
    text = raw.decode("utf-16-le", errors="replace")
    return text, len(buf)


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

def parse_registry_pol(data: bytes) -> list[PregRecord]:
    """Parse a Registry.pol file's bytes into records.

    Tolerant of a missing PReg signature and a truncated trailing record.
    Returns every complete record found (may be empty).
    """
    if not data:
        return []

    n = len(data)
    pos = 0

    # Header: 8 bytes (signature DWORD + version DWORD). Tolerate a missing
    # header by starting at offset 0 rather than raising.
    if data[:4] == _SIGNATURE:
        pos = _HEADER_LEN

    records: list[PregRecord] = []

    while pos + 1 < n:
        # Each record opens with a UTF-16LE '['. Tolerate stray bytes between
        # records by advancing until the next opener.
        if data[pos : pos + 2] != _OPEN:
            pos += 1
            continue
        pos += 2  # consume '['

        # --- key (UTF-16LE, null-terminated) ---
        key, pos = _read_utf16_null(data, pos)
        if data[pos : pos + 2] != _SEP:
            break
        pos += 2

        # --- value_name (UTF-16LE, null-terminated) ---
        value_name, pos = _read_utf16_null(data, pos)
        if data[pos : pos + 2] != _SEP:
            break
        pos += 2

        # --- type (4-byte little-endian DWORD) ---
        if pos + 4 > n:
            break
        type_code = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        if data[pos : pos + 2] != _SEP:
            break
        pos += 2

        # --- size (4-byte little-endian DWORD: byte length of data) ---
        if pos + 4 > n:
            break
        size = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        if data[pos : pos + 2] != _SEP:
            break
        pos += 2

        # --- data (exactly *size* bytes, immediately followed by ']') ---
        if pos + size > n:
            break  # truncated data
        raw_data = data[pos : pos + size]
        pos += size

        # --- closing bracket ---
        if data[pos : pos + 2] != _CLOSE:
            break
        pos += 2

        # Build the record
        type_name = REG_TYPE_NAMES.get(type_code, f"REG_UNKNOWN_{type_code}")
        display_value = decode_value(type_code, raw_data)
        records.append(
            PregRecord(
                key=key,
                value_name=value_name,
                type_code=type_code,
                type_name=type_name,
                size=size,
                data=raw_data,
                display_value=display_value,
            )
        )

    return records
