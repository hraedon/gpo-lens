"""Tests for the PReg (Registry.pol) binary parser."""

from __future__ import annotations

import struct

import pytest

from gpo_lens.registry_pol import (
    REG_TYPE_NAMES,
    PregRecord,
    decode_value,
    parse_registry_pol,
)

# ---------------------------------------------------------------------------
# Test helpers — build exact PReg byte sequences
# ---------------------------------------------------------------------------


def _encode_str_utf16_null(s: str) -> bytes:
    """Encode *s* as UTF-16LE with a null terminator (0x00 0x00)."""
    return s.encode("utf-16-le") + b"\x00\x00"


_W_OPEN = b"\x5b\x00"   # '[' UTF-16LE
_W_CLOSE = b"\x5d\x00"  # ']' UTF-16LE
_W_SEP = b"\x3b\x00"    # ';' UTF-16LE
_HEADER = b"PReg\x01\x00\x00\x00"  # signature DWORD + version DWORD


def _encode_record(
    key: str,
    value_name: str,
    type_code: int,
    data: bytes,
) -> bytes:
    """Build one real-format PReg record: ``[key;value_name;type;size;data]``.

    Delimiters are UTF-16LE chars; ``type`` and ``size`` are 4-byte LE DWORDs;
    ``data`` is immediately followed by the closing bracket (no separator).
    """
    parts: list[bytes] = [
        _W_OPEN,
        _encode_str_utf16_null(key),
        _W_SEP,
        _encode_str_utf16_null(value_name),
        _W_SEP,
        struct.pack("<I", type_code),
        _W_SEP,
        struct.pack("<I", len(data)),
        _W_SEP,
        data,
        _W_CLOSE,
    ]
    return b"".join(parts)


def _build_file(*records: bytes, signature: bool = True) -> bytes:
    """Assemble a full Registry.pol byte sequence from encoded records."""
    prefix = _HEADER if signature else b""
    return prefix + b"".join(records)


# ---------------------------------------------------------------------------
# 1. Empty file → []
# ---------------------------------------------------------------------------


def test_empty_file() -> None:
    assert parse_registry_pol(b"") == []


# ---------------------------------------------------------------------------
# 2. Just the signature → []
# ---------------------------------------------------------------------------


def test_signature_only() -> None:
    assert parse_registry_pol(b"PReg") == []


# ---------------------------------------------------------------------------
# 3. Single REG_DWORD record
# ---------------------------------------------------------------------------


def test_single_dword() -> None:
    data = struct.pack("<I", 1)
    rec_bytes = _encode_record(
        r"Software\Policies\Acme\Foo", "EnableFoo", 4, data,
    )
    result = parse_registry_pol(_build_file(rec_bytes))
    assert len(result) == 1
    r = result[0]
    assert r.key == r"Software\Policies\Acme\Foo"
    assert r.value_name == "EnableFoo"
    assert r.type_code == 4
    assert r.type_name == "REG_DWORD"
    assert r.size == 4
    assert r.data == data
    assert r.display_value == "1"


# ---------------------------------------------------------------------------
# 4. Single REG_SZ record
# ---------------------------------------------------------------------------


def test_single_sz() -> None:
    raw = "Hello".encode("utf-16-le") + b"\x00\x00"  # null-terminated
    rec_bytes = _encode_record(
        r"Software\Policies\Acme\Bar", "Greeting", 1, raw,
    )
    result = parse_registry_pol(_build_file(rec_bytes))
    assert len(result) == 1
    r = result[0]
    assert r.type_code == 1
    assert r.type_name == "REG_SZ"
    assert r.display_value == "Hello"


# ---------------------------------------------------------------------------
# 5. REG_MULTI_SZ with two strings
# ---------------------------------------------------------------------------


def test_multi_sz() -> None:
    # Multi-SZ: "Alpha\0Beta\0\0" in UTF-16LE
    raw = (
        "Alpha".encode("utf-16-le")
        + b"\x00\x00"
        + "Beta".encode("utf-16-le")
        + b"\x00\x00"
        + b"\x00\x00"  # double-null terminator
    )
    rec_bytes = _encode_record(
        r"Software\Policies\Acme\Multi", "Items", 7, raw,
    )
    result = parse_registry_pol(_build_file(rec_bytes))
    assert len(result) == 1
    assert result[0].display_value == "Alpha; Beta"


# ---------------------------------------------------------------------------
# 6. REG_BINARY → lowercase hex
# ---------------------------------------------------------------------------


def test_binary() -> None:
    raw = bytes([0x00, 0xFF, 0x10, 0xAB])
    rec_bytes = _encode_record(
        r"Software\Policies\Acme\Bin", "RawData", 3, raw,
    )
    result = parse_registry_pol(_build_file(rec_bytes))
    assert len(result) == 1
    assert result[0].display_value == "00ff10ab"


# ---------------------------------------------------------------------------
# 7. REG_QWORD (type 11, 8 bytes)
# ---------------------------------------------------------------------------


def test_qword() -> None:
    raw = struct.pack("<Q", 2**32 + 42)
    rec_bytes = _encode_record(
        r"Software\Policies\Acme\Q", "BigNum", 11, raw,
    )
    result = parse_registry_pol(_build_file(rec_bytes))
    assert len(result) == 1
    assert result[0].display_value == str(2**32 + 42)


# ---------------------------------------------------------------------------
# 8. Multiple records in one file → order preserved
# ---------------------------------------------------------------------------


def test_multiple_records() -> None:
    r1 = _encode_record(r"K1", "V1", 4, struct.pack("<I", 10))
    r2 = _encode_record(r"K2", "V2", 1, _encode_str_utf16_null("two"))
    r3 = _encode_record(r"K3", "V3", 3, b"\xDE\xAD")
    result = parse_registry_pol(_build_file(r1, r2, r3))
    assert len(result) == 3
    assert result[0].key == "K1"
    assert result[0].display_value == "10"
    assert result[1].key == "K2"
    assert result[1].display_value == "two"
    assert result[2].key == "K3"
    assert result[2].display_value == "dead"


# ---------------------------------------------------------------------------
# 9. Truncated trailing record → earlier records returned, no exception
# ---------------------------------------------------------------------------


def test_truncated_trailing_record() -> None:
    r1 = _encode_record(r"K1", "V1", 4, struct.pack("<I", 5))
    good = _build_file(r1)
    # Append a partial record (just the opening bracket and part of a key)
    truncated = good + b"[" + _encode_str_utf16_null("Orphan")[:-2]
    result = parse_registry_pol(truncated)
    assert len(result) == 1
    assert result[0].key == "K1"


# ---------------------------------------------------------------------------
# 10. No PReg signature but valid bracketed records → parsed
# ---------------------------------------------------------------------------


def test_no_signature() -> None:
    r1 = _encode_record(r"K", "V", 4, struct.pack("<I", 99))
    result = parse_registry_pol(_build_file(r1, signature=False))
    assert len(result) == 1
    assert result[0].display_value == "99"


# ---------------------------------------------------------------------------
# 11. decode_value unit tests for each type code in the table
# ---------------------------------------------------------------------------


class TestDecodeValue:
    """Unit tests for ``decode_value`` covering every known type code."""

    def test_reg_none(self) -> None:
        assert decode_value(0, b"\x01\x02") == ""

    def test_reg_sz(self) -> None:
        raw = "Test".encode("utf-16-le") + b"\x00\x00"
        assert decode_value(1, raw) == "Test"

    def test_reg_sz_no_trailing_null(self) -> None:
        raw = "Test".encode("utf-16-le")
        assert decode_value(1, raw) == "Test"

    def test_reg_expand_sz(self) -> None:
        raw = "%SystemRoot%".encode("utf-16-le") + b"\x00\x00"
        assert decode_value(2, raw) == "%SystemRoot%"

    def test_reg_binary(self) -> None:
        assert decode_value(3, b"\xAB\xCD\xEF") == "abcdef"

    def test_reg_dword(self) -> None:
        assert decode_value(4, struct.pack("<I", 255)) == "255"

    def test_reg_dword_big_endian(self) -> None:
        assert decode_value(5, struct.pack(">I", 256)) == "256"

    def test_reg_multi_sz(self) -> None:
        raw = (
            "A".encode("utf-16-le")
            + b"\x00\x00"
            + "B".encode("utf-16-le")
            + b"\x00\x00"
            + b"\x00\x00"
        )
        assert decode_value(7, raw) == "A; B"

    def test_reg_multi_sz_single(self) -> None:
        raw = "Only".encode("utf-16-le") + b"\x00\x00" + b"\x00\x00"
        assert decode_value(7, raw) == "Only"

    def test_reg_qword(self) -> None:
        assert decode_value(11, struct.pack("<Q", 123456789012345)) == "123456789012345"

    def test_unknown_type_falls_back_to_hex(self) -> None:
        assert decode_value(99, b"\xBE\xEF") == "beef"

    def test_dword_short_data_falls_back_to_hex(self) -> None:
        assert decode_value(4, b"\x01\x02") == "0102"

    def test_dword_big_endian_short_data_falls_back_to_hex(self) -> None:
        assert decode_value(5, b"\x01") == "01"

    def test_qword_short_data_falls_back_to_hex(self) -> None:
        assert decode_value(11, b"\x01\x02\x03") == "010203"

    def test_reg_none_empty_data(self) -> None:
        assert decode_value(0, b"") == ""

    def test_reg_binary_empty_data(self) -> None:
        assert decode_value(3, b"") == ""

    def test_reg_sz_empty_data(self) -> None:
        assert decode_value(1, b"") == ""


# ---------------------------------------------------------------------------
# 12. REG_TYPE_NAMES contains the expected constants
# ---------------------------------------------------------------------------


class TestRegTypeNames:
    """Verify ``REG_TYPE_NAMES`` covers the documented type codes."""

    @pytest.mark.parametrize(
        ("code", "name"),
        [
            (0, "REG_NONE"),
            (1, "REG_SZ"),
            (2, "REG_EXPAND_SZ"),
            (3, "REG_BINARY"),
            (4, "REG_DWORD"),
            (5, "REG_DWORD_BIG_ENDIAN"),
            (7, "REG_MULTI_SZ"),
            (11, "REG_QWORD"),
        ],
    )
    def test_known_type(self, code: int, name: str) -> None:
        assert REG_TYPE_NAMES[code] == name

    def test_no_extra_keys(self) -> None:
        expected = {0, 1, 2, 3, 4, 5, 7, 11}
        assert set(REG_TYPE_NAMES.keys()) == expected


# ---------------------------------------------------------------------------
# Additional edge-case tests
# ---------------------------------------------------------------------------


def test_preg_record_is_frozen() -> None:
    """PregRecord is frozen — attribute assignment raises FrozenInstanceError."""
    rec = PregRecord(
        key="K", value_name="V", type_code=4, type_name="REG_DWORD",
        size=4, data=b"\x01\x02\x03\x04", display_value="1",
    )
    with pytest.raises(AttributeError):
        rec.key = "other"  # type: ignore[misc]


def test_zero_size_data() -> None:
    """A record with size=0 still parses (empty data directly before ']')."""
    rec_bytes = _encode_record(r"K", "V", 0, b"")
    result = parse_registry_pol(_build_file(rec_bytes))
    assert len(result) == 1
    assert result[0].size == 0
    assert result[0].data == b""
    assert result[0].display_value == ""


def test_type_name_unknown() -> None:
    """An unknown type_code gets a REG_UNKNOWN_N type_name."""
    rec_bytes = _encode_record(r"K", "V", 99, b"\xAB")
    result = parse_registry_pol(_build_file(rec_bytes))
    assert result[0].type_name == "REG_UNKNOWN_99"


def test_sz_with_multiple_trailing_nulls() -> None:
    """display_value strips all trailing null characters."""
    raw = "Hi".encode("utf-16-le") + b"\x00\x00\x00\x00"  # two null chars
    rec_bytes = _encode_record(r"K", "V", 1, raw)
    result = parse_registry_pol(_build_file(rec_bytes))
    assert result[0].display_value == "Hi"
