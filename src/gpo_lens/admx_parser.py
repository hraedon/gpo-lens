"""ADMX/ADML template parser for policy crosswalk.

Parses ``.admx`` (policy definitions) and ``.adml`` (language resources)
from a ``PolicyDefinitions`` directory to build a registry-path → policy-name
crosswalk.  Used by the baseline-diff feature to map raw registry settings
back to their ADMX policy definitions.

ADMX files are XML with the namespace
``http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions``.

Each ``<policy>`` element carries:
- ``name`` — the policy identifier
- ``class`` — ``"Machine"``, ``"User"``, or ``"Both"``
- ``key`` — the registry key path (relative to HKLM/HKCU)
- ``valueName`` — the registry value name
- ``displayName`` — a ``$(string.xxx)`` reference resolved via ADML

The crosswalk maps ``(key, valueName)`` → policy display name, which lets
the baseline diff convert raw registry identities (e.g.
``Software\\Policies\\Microsoft\\...:NoControlPanel``) back to human-readable
policy names.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import defusedxml.ElementTree as ET

from gpo_lens.normalize import localname

_ADMX_NS = "http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions"

_localname = localname


@dataclass(frozen=True)
class AdmxPolicy:
    """One ADMX policy definition."""

    name: str
    class_scope: str        # "Machine", "User", "Both"
    key: str                # registry key path
    value_name: str         # registry value name (may be empty)
    display_name_ref: str   # raw $(string.xxx) reference
    display_name: str       # resolved display name from ADML
    explain_text: str       # resolved explain text from ADML


@dataclass
class PolicyDefinitions:
    """Parsed contents of a PolicyDefinitions directory."""

    policies: list[AdmxPolicy] = field(default_factory=list)
    _by_registry_key: dict[str, list[AdmxPolicy]] = field(
        default_factory=dict, repr=False,
    )

    def lookup(self, key: str, value_name: str) -> list[AdmxPolicy]:
        """Find policies matching a registry key and value name.

        ``key`` is the full hive-relative path (e.g.
        ``Software\\Microsoft\\...``).  ``value_name`` is the value
        (e.g. ``NoControlPanel``).  Matching is case-insensitive.
        """
        norm_key = key.lower().strip("\\")
        norm_val = value_name.lower()
        results: list[AdmxPolicy] = []
        for p in self.policies:
            if p.key.lower().strip("\\") == norm_key:
                if not p.value_name or p.value_name.lower() == norm_val:
                    results.append(p)
        return results

    def resolve_display_name(self, identity: str) -> str | None:
        """Given a setting identity like ``key:valueName``, return the
        ADMX policy display name or None."""
        parts = identity.split(":", 1)
        key = parts[0] if parts else identity
        val = parts[1] if len(parts) > 1 else ""
        matches = self.lookup(key, val)
        if matches:
            return matches[0].display_name
        return None


def _ref_to_key(ref: str) -> str:
    """Extract the string id from a ``$(string.xxx)`` reference.

    ADMX uses ``$(string.LockoutPolicy)`` which maps to the ADML
    ``<string id="LockoutPolicy">`` element.  Strip the ``string.``
    prefix if present.
    """
    if ref.startswith("$(") and ref.endswith(")"):
        inner = ref[2:-1]
        if inner.startswith("string."):
            return inner[7:]
        return inner
    return ref


def _parse_adml_strings(adml_path: Path) -> dict[str, str]:
    """Parse an ADML file and return {string_id: text}."""
    tree = ET.parse(adml_path)
    root = tree.getroot()
    if root is None:
        return {}
    strings: dict[str, str] = {}
    ns = _ADMX_NS
    for st in root.iter(f"{{{ns}}}stringTable"):
        for s in st.iter(f"{{{ns}}}string"):
            sid = s.get("id", "")
            if sid and s.text:
                strings[sid] = s.text.strip()
    return strings


def parse_admx_dir(policy_defs_dir: str | Path) -> PolicyDefinitions:
    """Parse all ``.admx`` and ``.adml`` files in a PolicyDefinitions directory.

    Resolves ``$(string.xxx)`` references using the ``en-US`` ADML files
    (falls back to the first available locale if en-US is missing).
    """
    base = Path(policy_defs_dir)
    try:
        if not base.is_dir():
            return PolicyDefinitions()
    except OSError:
        return PolicyDefinitions()

    # 1. Parse ADML strings — prefer en-US, fall back to first locale
    adml_strings: dict[str, str] = {}
    en_us = base / "en-US"
    try:
        adml_dir = en_us if en_us.is_dir() else None
    except OSError:
        adml_dir = None
    if adml_dir is None:
        # Find first locale directory
        try:
            children = sorted(base.iterdir())
        except OSError:
            children = []
        for child in children:
            try:
                if child.is_dir() and any(child.glob("*.adml")):
                    adml_dir = child
                    break
            except OSError:
                continue
    if adml_dir is not None:
        try:
            adml_files = list(adml_dir.glob("*.adml"))
        except OSError:
            adml_files = []
        for adml_file in adml_files:
            try:
                adml_strings.update(_parse_adml_strings(adml_file))
            except (ET.ParseError, OSError):
                continue

    # 2. Parse ADMX files
    policies: list[AdmxPolicy] = []
    try:
        admx_files = sorted(base.glob("*.admx"))
    except OSError:
        admx_files = []
    for admx_file in admx_files:
        try:
            tree = ET.parse(admx_file)
        except (ET.ParseError, OSError):
            continue
        root = tree.getroot()
        if root is None:
            continue
        ns = _ADMX_NS
        for pol in root.iter(f"{{{ns}}}policy"):
            name = pol.get("name", "")
            class_scope = pol.get("class", "Both")
            key = pol.get("key", "")
            value_name = pol.get("valueName", "")
            display_ref = pol.get("displayName", "")
            explain_ref = pol.get("explainText", "")

            display_name = adml_strings.get(_ref_to_key(display_ref), display_ref)
            explain_text = adml_strings.get(_ref_to_key(explain_ref), "")

            policies.append(AdmxPolicy(
                name=name,
                class_scope=class_scope,
                key=key,
                value_name=value_name,
                display_name_ref=display_ref,
                display_name=display_name,
                explain_text=explain_text,
            ))

    pd = PolicyDefinitions(policies=policies)
    return pd
