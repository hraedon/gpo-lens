# Work Item: PReg binary parser (`Registry.pol`)

## Dependencies

- `interface_ref`: none at runtime — the module is fully stdlib-only
  (`struct`, `dataclasses`). It is a leaf parser.
- Consumer: `ingest.augment_blocked_registry_from_pol` (the only in-tree
  caller; resolves `<Blocked/>` Registry CSE extensions, see AC-09).
- Reference: there is **no dedicated plan file** for `registry_pol.py`. The
  format reference is [MS-GPREG] (the Registry Policy File Format) and the
  module docstring; this spec is the first formal contract.
- `docs/spec/export-format.md:207` lists `Registry.pol` as a SYSVOL input
  shape consumed by `parse_registry_pol`.

## Notes

This module is the binary parser for Microsoft PReg (`Registry.pol`) files
found in GPO SYSVOL at `Policies\\{GUID}\\Machine\\Registry.pol` and
`User\\Registry.pol`. It is a **core module** (in `tests/_arch.py::
CORE_MODULES`); being stdlib-only and a leaf, it cannot violate the
import boundary.

Per [MS-GPREG], the file is an 8-byte header
(`50 52 65 67 01 00 00 00` — the `PReg` signature DWORD plus a version
DWORD) followed by a sequence of records:

```
[key;value_name;type;size;data]
```

The literal `[`, `;` and `]` delimiters are themselves UTF-16LE
characters (two bytes each: `5B 00`, `3B 00`, `5D 00`). `key` and
`value_name` are null-terminated UTF-16LE strings. `type` and `size` are
each a 4-byte little-endian DWORD (`size` is the byte length of `data`).
`data` is `size` raw bytes followed immediately by `]` — there is **no
separator** between `data` and the closing bracket.

### Design stance — tolerant parsing

The parser is deliberately tolerant: it never raises on truncated,
missing-header, or stray-garbage input. It returns every *complete*
record found and stops at the first unrecoverable structural break
inside a record. This matches the AGENTS.md "Coverage honesty" stance:
report what was decodable, surface the gap (the consumer in `ingest`
keeps the `source_state="blocked"` placeholder when no records are
produced — AC-09).

### Known simplifications / surprising behavior

- **Header check is signature-only, not version.** `parse_registry_pol`
  checks `data[:4] == b"PReg"` and skips 8 bytes; the version DWORD
  (bytes 4–7) is never inspected. A file with the right signature but a
  non-zero version mismatch is still parsed.
- **Stray bytes between records are tolerated by single-byte forward
  scan.** The outer loop advances `pos += 1` until it sees a UTF-16LE
  `[`, so an extra NUL byte or padding between records does not abort
  parsing. This is a deliberate robustness choice; it is not strictly
  format-compliant.
- **Short DWORD/QWORD data falls back to hex, not zero-pad.** `decode_value`
  for type 4/5/11 requires `len(data) >= 4` (DWORD) or `>= 8` (QWORD).
  Below that threshold the data is rendered as `data.hex()` — i.e. the
  *raw short bytes* as hex, not a zero-padded numeric value
  (`test_dword_short_data_falls_back_to_hex`,
  `test_qword_short_data_falls_back_to_hex`). A 2-byte DWORD becomes
  `"0102"`, not the integer value 258 or the zero-padded `"0x00000102"`.
- **UTF-16 decoding uses `errors="replace"`.** Invalid UTF-16LE sequences
  in a string field become U+FFFD replacement characters rather than
  raising. This is the only decoding failure mode; it never aborts a
  record.
- **REG_TYPE_NAMES omits codes 6, 8, 9, 10.** Microsoft reserves
  `REG_LINK` (6) and other less-common types; the parser's table does
  not include them. An unknown code renders `type_name =
  f"REG_UNKNOWN_{type_code}"` and `display_value = data.hex()` (the
  catch-all branch).
- **No `__all__`.** Public exports are implicit: `REG_TYPE_NAMES`,
  `PregRecord`, `decode_value`, `parse_registry_pol`. The `_decode_*`
  and `_read_utf16_null` helpers are private but tested.
- **The `_read_utf16_null` no-terminator path consumes the rest of the
  buffer.** If no `0x00 0x00` terminator is found, the function returns
  `(rest_of_buffer_decoded, len(buf))`, which terminates the outer parse
  loop on the next iteration. A truncated key/value thus ends parsing
  rather than producing a partial record.

## Module map

`src/gpo_lens/registry_pol.py` — stdlib-only leaf parser. Core module
(`tests/_arch.py`); no I/O (operates on `bytes`, not file paths — file
reading is the caller's job).

| Public surface | Role |
|----------------|------|
| `REG_TYPE_NAMES` (`dict[int, str]`) | Type-code → label table. 8 entries (AC-01). |
| `PregRecord` (frozen dataclass) | One decoded registry setting. 7 fields (AC-02). |
| `decode_value(type_code, data) -> str` | Pure value decoder per type code (AC-04). |
| `parse_registry_pol(data: bytes) -> list[PregRecord]` | Tolerant binary parser (AC-05..AC-08). |

Module constants: `_SIGNATURE = b"PReg"`, `_HEADER_LEN = 8`,
`_OPEN = b"\x5b\x00"`, `_CLOSE = b"\x5d\x00"`, `_SEP = b"\x3b\x00"`,
`_NULL_TERM = b"\x00\x00"`. Renaming any of these changes the wire
format the parser accepts.

---

## AC-01: `REG_TYPE_NAMES` covers exactly 8 type codes

`REG_TYPE_NAMES: dict[int, str]` has exactly these entries
(`test_no_extra_keys`):

| Code | Name |
|------|------|
| 0 | `REG_NONE` |
| 1 | `REG_SZ` |
| 2 | `REG_EXPAND_SZ` |
| 3 | `REG_BINARY` |
| 4 | `REG_DWORD` |
| 5 | `REG_DWORD_BIG_ENDIAN` |
| 7 | `REG_MULTI_SZ` |
| 11 | `REG_QWORD` |

The set of keys is exactly `{0, 1, 2, 3, 4, 5, 7, 11}`. Codes 6, 8, 9,
10 are deliberately absent (see Notes); they fall through to the
unknown-type branch in `decode_value` and `parse_registry_pol`.

## AC-02: `PregRecord` dataclass shape

`@dataclass(frozen=True)` — attribute assignment raises
`AttributeError` (`test_preg_record_is_frozen`).

| Field | Type | Source |
|-------|------|--------|
| `key` | `str` | Decoded UTF-16LE key path, null terminator stripped. e.g. `r"Software\Policies\Acme"`. |
| `value_name` | `str` | Decoded UTF-16LE value name, null terminator stripped. |
| `type_code` | `int` | Raw REG type code as a 4-byte LE DWORD (one of the codes in AC-01 or any other int). |
| `type_name` | `str` | `REG_TYPE_NAMES[type_code]` if known, else `f"REG_UNKNOWN_{type_code}"` (`test_type_name_unknown`). |
| `size` | `int` | Byte length of the original `data` (the DWORD from the record). |
| `data` | `bytes` | Raw data bytes, exactly `size` long. |
| `display_value` | `str` | Decoded representation per AC-04. |

## AC-03: String decoding helpers

`_decode_utf16(data) -> str` decodes UTF-16LE with `errors="replace"`
and `rstrip("\x00")` — **all** trailing NUL characters are stripped, not
just one (`test_sz_with_multiple_trailing_nulls`). An empty input
returns `""` (`test_reg_sz_empty_data`).

`_decode_multi_sz(data) -> str` decodes UTF-16LE, splits on `"\x00"`,
drops empty parts (which collapses the double-null terminator), and
joins the survivors with `"; "`. A single-string MULTI_SZ returns just
that string (`test_reg_multi_sz_single`); an empty input returns `""`.

`_read_utf16_null(buf, offset) -> tuple[str, int]` scans two bytes at a
time looking for `0x00 0x00` on an even boundary. On hit: returns
`(decoded_string_before_terminator, terminator_pos + 2)`. On no-hit:
returns `(buf[offset:].decode("utf-16-le", errors="replace"), len(buf))`
(see Notes — consumes the rest of the buffer).

## AC-04: `decode_value` per-type semantics

```python
def decode_value(type_code: int, data: bytes) -> str: ...
```

Pure function. Behavior by `type_code`:

| Code | Behavior |
|------|----------|
| 0 (REG_NONE) | Always returns `""`, ignoring `data` entirely. |
| 1 (REG_SZ) | `_decode_utf16(data)`. |
| 2 (REG_EXPAND_SZ) | `_decode_utf16(data)`. |
| 3 (REG_BINARY) | `data.hex()` (lowercase hex string). Empty data → `""`. |
| 4 (REG_DWORD) | If `len(data) >= 4`: `str(struct.unpack_from("<I", data)[0])`. Else: `data.hex()` (short-data fallback — see Notes). |
| 5 (REG_DWORD_BIG_ENDIAN) | If `len(data) >= 4`: `str(struct.unpack_from(">I", data)[0])`. Else: `data.hex()`. |
| 7 (REG_MULTI_SZ) | `_decode_multi_sz(data)`. |
| 11 (REG_QWORD) | If `len(data) >= 8`: `str(struct.unpack_from("<Q", data)[0])`. Else: `data.hex()`. |
| any other | `data.hex()` (catch-all, including codes 6/8/9/10). |

The `struct.unpack_from` calls use `<I` (unsigned LE) for DWORD,
`>I` (unsigned BE) for BIG_ENDIAN, `<Q` (unsigned LE) for QWORD.
Signedness is unsigned — a DWORD with the high bit set is rendered as a
large positive integer, not a negative number.

## AC-05: `parse_registry_pol` — header handling and empty input

```python
def parse_registry_pol(data: bytes) -> list[PregRecord]: ...
```

- Empty input `b""` returns `[]` immediately (`test_empty_file`).
- If `data[:4] == _SIGNATURE` (`b"PReg"`): the parser starts at offset
  `_HEADER_LEN = 8` (skipping signature DWORD + version DWORD). The
  version DWORD is never inspected (see Notes).
- Otherwise: the parser starts at offset 0 (header-less file still
  parsed, `test_no_signature`).
- A 3-byte input `b"PReg"` (signature only, no version DWORD, no body)
  returns `[]` — the header check `data[:4] == b"PReg"` is False
  (length mismatch), so `pos` stays at 0, and the outer loop's
  `pos + 1 < n` guard is False (`test_signature_only`).

## AC-06: `parse_registry_pol` — record structure and field order

The outer loop runs while `pos + 1 < n`. Each record must match the
exact sequence:

1. **Open bracket**: `data[pos:pos+2] == _OPEN` (`b"\x5b\x00"`). If not,
   advance `pos += 1` and retry (tolerates stray bytes — see Notes). On
   match: `pos += 2`.
2. **Key**: `_read_utf16_null(data, pos)`. If `data[pos:pos+2] != _SEP`:
   `break` (structural break — parsing stops).
3. **Separator**: consume `;` (`pos += 2`).
4. **Value name**: `_read_utf16_null`. Same `_SEP` check, same `break`
   on mismatch.
5. **Separator**: consume `;`.
6. **Type code**: if `pos + 4 > n`: `break`. Read
   `struct.unpack_from("<I", data, pos)[0]`. If next 2 bytes `!= _SEP`:
   `break`.
7. **Separator**: consume `;`.
8. **Size**: if `pos + 4 > n`: `break`. Read another `<I` DWORD. Same
   `_SEP` check, same `break`.
9. **Separator**: consume `;`.
10. **Data**: if `pos + size > n`: `break` (truncated data — the record
    is incomplete and parsing stops). Else `raw_data = data[pos:pos+size]`,
    `pos += size`.
11. **Close bracket**: `data[pos:pos+2] == _CLOSE` (`b"\x5d\x00"`). If
    not: `break`. On match: `pos += 2`.
12. Build the `PregRecord`:
    - `type_name = REG_TYPE_NAMES.get(type_code, f"REG_UNKNOWN_{type_code}")`.
    - `display_value = decode_value(type_code, raw_data)`.
    - Append to the result list.

There is no separator between `data` and the closing `]` — the parser
relies on `size` to know where data ends, then expects `]` immediately
after. A record with `size=0` is valid (empty data directly before `]`,
`test_zero_size_data`).

## AC-07: `parse_registry_pol` — tolerance and truncation

- **Truncated trailing record** (e.g. an open bracket followed by a
  partial key): earlier complete records are returned, no exception is
  raised, and parsing stops at the structural break
  (`test_truncated_trailing_record`).
- **Stray bytes between records** (e.g. a NUL or padding byte): the
  outer loop advances `pos += 1` until it finds the next `_OPEN`. The
  stray bytes do not produce a record and do not abort parsing.
- **Missing PReg header**: handled per AC-05. A header-less file with
  valid bracketed records parses normally.
- **No raises.** The function never raises on input shape; only
  `struct.unpack_from` could theoretically raise, but the `pos + 4 > n`
  guards prevent out-of-range reads.

## AC-08: `parse_registry_pol` — multi-record order preservation

Multiple records in one file are returned in file order
(`test_multiple_records`). Each record is independent — a record with
an unknown type code does not affect the parsing of subsequent records.
The result list is a 1:1 mapping of the records in the order they
appear in the byte stream.

## AC-09: Consumer contract — `ingest.augment_blocked_registry_from_pol`

The only in-tree caller is `ingest.augment_blocked_registry_from_pol(gpos)`.
For each GPO with a `sysvol_path` and one or more Registry CSE settings
tagged `source_state="blocked"`:

1. Resolve the side directory case-insensitively: Computer → `Machine/`,
   User → `User/`. Look for `Registry.pol` (case-insensitive) under
   `<sysvol_path>/<side_dir>/`.
2. If the file is absent or unreadable (`OSError`/`ValueError`), keep
   the blocked placeholder unchanged (the gap is surfaced, not papered
   over — see AGENTS.md "Coverage honesty").
3. Otherwise call `parse_registry_pol(pol.read_bytes())`. If it returns
   `[]`, treat as unresolved (keep the placeholder).
4. For each `PregRecord`, build a `Setting`:
   - `cse="Registry"`, `side=<original side>`, `gpo_id=<gpo id>`.
   - `identity = f"{rec.key}:{rec.value_name}"` when both are non-empty,
     else `rec.key or rec.value_name` (single-segment identity).
   - `display_name = rec.value_name or rec.key`.
   - `display_value = rec.display_value` (the decoded value from AC-04).
   - `raw = {"key":..., "value_name":..., "type_code":...,
     "type_name":..., "size":..., "source":"registry_pol"}`.
   - `source_state="registry_pol"`, `from_disabled_side=False`.
5. If at least one side resolved, drop the blocked placeholders for the
   resolved sides and append the new `Setting`s. Unresolved sides keep
   their placeholder (`test_blocked_kept_when_pol_absent`,
   `test_no_sysvol_path_is_noop`, `test_no_blocked_extension_is_noop`).

This contract is the load-bearing integration: any change to
`PregRecord` field names, `decode_value` output, or
`parse_registry_pol`'s tolerance affects what `ingest` produces.
