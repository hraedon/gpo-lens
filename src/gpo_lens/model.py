"""Normalized data model for a Group Policy estate.

This is the contract. Implementations (ingest, store, queries) populate and read
these structures; their shape is fixed here so behavior specs in ``docs/spec/``
can reference concrete fields. See ``docs/tier1-normalized-model.md`` for the
mapping from collector outputs (GPO report XML, GPInheritance/metadata JSON,
SYSVOL) to these types, and the join-key normalization rules.

All GPO ids are *canonical*: lowercase, braces stripped (see
``normalize.canonical_guid``). Joins across report/topology/SYSVOL use that key.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

Side = str  # "Computer" | "User"


@dataclass(frozen=True)
class GpoLink:
    """One ``GPO/LinksTo`` element — where a GPO is linked."""

    gpo_id: str
    som_name: str           # LinksTo/SOMName
    som_path: str           # LinksTo/SOMPath
    link_enabled: bool      # LinksTo/Enabled
    enforced: bool          # LinksTo/NoOverride  (this is the enforced flag)


@dataclass
class Setting:
    """One leaf setting inside ``<Side>/ExtensionData/Extension``.

    Each CSE (``cse``) has a different child schema, so ``raw`` preserves the
    CSE-specific subtree losslessly while ``display_*`` give a flattened
    projection used for search and conflict detection.
    """

    gpo_id: str
    side: Side
    cse: str                # ExtensionData/Name (e.g. "Registry", "Security")
    identity: str           # CSE-specific natural key (conflict identity)
    display_name: str
    display_value: str
    raw: dict[str, object]  # preserved CSE-specific subtree
    from_disabled_side: bool  # side's Enabled=false but settings present
    source_state: str = "normal"   # "normal" | "blocked" (<Blocked/> extension)


@dataclass(frozen=True)
class DelegationEntry:
    """One trustee permission, parsed from ``SecurityDescriptor/Permissions``.

    Powers the delegation audit and the MS16-072 check (a GPO missing
    Authenticated Users / Domain Computers read/apply).
    """

    gpo_id: str
    trustee: str
    trustee_sid: str | None
    permission: str         # normalized label, e.g. "Apply Group Policy", "Read"
    allowed: bool


@dataclass
class Gpo:
    """One ``GPO`` element, enriched with metadata + SYSVOL path."""

    id: str                 # canonical guid
    name: str
    domain: str
    created: datetime | None
    modified: datetime | None
    read: datetime | None
    computer_enabled: bool
    user_enabled: bool
    computer_ver_ds: int | None
    computer_ver_sysvol: int | None
    user_ver_ds: int | None
    user_ver_sysvol: int | None
    sddl: str | None
    owner: str | None
    filter_data_available: bool
    wmi_filter: str | None              # from gpo-metadata.json
    sysvol_path: str | None             # matched SYSVOL-Policies/{GUID} dir
    links: list[GpoLink] = field(default_factory=list)
    settings: list[Setting] = field(default_factory=list)
    delegation: list[DelegationEntry] = field(default_factory=list)

    @property
    def computer_version_skew(self) -> bool:
        return self.computer_ver_ds != self.computer_ver_sysvol

    @property
    def user_version_skew(self) -> bool:
        return self.user_ver_ds != self.user_ver_sysvol


@dataclass(frozen=True)
class SomLink:
    """One entry of a SOM's resolved, ordered, inheritance-aware GPO chain."""

    gpo_id: str
    order: int              # precedence order (platform-resolved)
    enabled: bool
    enforced: bool
    target: str             # DN the link originates from


@dataclass
class Som:
    """One scope-of-management node from the GPInheritance dump."""

    path: str
    name: str
    container_type: str
    inheritance_blocked: bool
    links: list[SomLink] = field(default_factory=list)


@dataclass(frozen=True)
class WmiFilter:
    """A WMI filter with its name and query text, from ``wmi-filters.json``."""

    name: str
    query: str


@dataclass(frozen=True)
class OuRecord:
    """One OU from the raw ``ou-tree.json`` (gPLink / gPOptions)."""

    dn: str
    name: str
    gp_link: str | None       # raw gPLink attribute (DN-list of GUIDs)
    gp_options: int | None    # gPOptions: 0=not blocked, 1=block inheritance


@dataclass
class Estate:
    """The whole normalized estate for one domain snapshot."""

    domain: str = ""
    gpos: list[Gpo] = field(default_factory=list)
    soms: list[Som] = field(default_factory=list)
    wmi_filters: list[WmiFilter] = field(default_factory=list)
    ou_tree: list[OuRecord] = field(default_factory=list)

    def gpo_by_id(self, gpo_id: str) -> Gpo | None:
        return next((g for g in self.gpos if g.id == gpo_id), None)
