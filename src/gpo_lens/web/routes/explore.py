"""Explore and Tools — organizing destinations (Plan 025 WI-3).

Two question-oriented landing pages that organize the existing specialist
workbenches without removing or renaming any route:

- ``/explore`` answers "why is this setting what it is here?" by grouping the
  exploration surfaces (dossiers, directory, resultant, search, conflicts,
  delegation).
- ``/tools`` answers "what specialist operation do I need?" by grouping the
  operational workbenches (ingest, baseline, golden, ADMX coverage, exports,
  narration).

The destination registry below is the single source of truth: handlers resolve
every entry through ``app.url_path_for`` at request time, so a renamed or
removed route fails loudly (and in tests) instead of shipping a dead link.
These pages read nothing from the estate database — they are pure directory
pages, which is what keeps them deterministic and instant.

Plan 025 sequencing gate 3 ships this as an opt-in destination; the primary
navigation switch is WI-4 and deliberately not part of this change.

Handlers are plain ``def`` (not ``async def``) so FastAPI runs them in its
threadpool, consistent with the rest of the web surface.
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from gpo_lens.web.auth import Permission, Principal, requires


@dataclass(frozen=True, slots=True)
class Destination:
    """One organized destination: a named route and what it answers."""

    route_name: str
    title: str
    description: str


@dataclass(frozen=True, slots=True)
class DirectorySection:
    """A titled group of destinations on a directory page."""

    title: str
    destinations: tuple[Destination, ...]


EXPLORE_SECTIONS: tuple[DirectorySection, ...] = (
    DirectorySection(
        "The estate",
        (
            Destination(
                "gpo_list",
                "Inventory",
                "Every GPO in the estate; each opens its dossier with the "
                "settings ledger, links, filtering, and history.",
            ),
            Destination(
                "ou_list",
                "Directory",
                "The OU tree with linked GPOs, inheritance blocking, and enforcement.",
            ),
            Destination(
                "search",
                "Search",
                "Estate-wide search across GPOs, OUs, and configured settings.",
            ),
        ),
    ),
    DirectorySection(
        "Workbenches",
        (
            Destination(
                "resultant_form",
                "Resultant",
                "What applies at a scope, computed from links, enforcement, and filtering.",
            ),
            Destination(
                "conflicts",
                "Conflicts",
                "Where two GPOs configure the same setting differently, and which value wins.",
            ),
            Destination(
                "danger_list",
                "Dangerous settings",
                "Configured settings matching the dangerous-configuration detectors.",
            ),
            Destination(
                "delegation",
                "Delegation",
                "Who holds which rights on which GPOs — trustees across the estate.",
            ),
        ),
    ),
)

TOOLS_SECTIONS: tuple[DirectorySection, ...] = (
    DirectorySection(
        "Snapshots",
        (
            Destination(
                "ingest_get",
                "Ingest",
                "Load an estate export and manage snapshots.",
            ),
        ),
    ),
    DirectorySection(
        "Comparisons",
        (
            Destination(
                "baseline_get",
                "Baseline",
                "Compare the estate against a baseline definition; runs are "
                "persisted and linkable.",
            ),
            Destination(
                "golden_diff_get",
                "Golden diff",
                "Diff a GPO against its designated golden copy.",
            ),
            Destination(
                "admx_coverage",
                "ADMX coverage",
                "Which configured settings the loaded ADMX catalogue can "
                "name — and which it cannot.",
            ),
        ),
    ),
    DirectorySection(
        "Output",
        (
            Destination(
                "export_findings",
                "Findings export",
                "Deterministic export of the findings ledger. Dossier and OU "
                "exports live on their own pages.",
            ),
            Destination(
                "ask_get",
                "Ask (narration)",
                "Exploratory narration over deterministic facts. The pages "
                "are authoritative; the model output is a labeled "
                "projection.",
            ),
        ),
    ),
)


def register(app: FastAPI, templates: Jinja2Templates) -> None:

    def _resolved(
        sections: tuple[DirectorySection, ...],
    ) -> list[dict[str, object]]:
        """Resolve route names to paths; a missing route raises loudly."""
        return [
            {
                "title": section.title,
                "destinations": [
                    {
                        "href": app.url_path_for(dest.route_name),
                        "title": dest.title,
                        "description": dest.description,
                    }
                    for dest in section.destinations
                ],
            }
            for section in sections
        ]

    @app.get("/explore", response_class=HTMLResponse, name="explore")
    def explore_page(
        request: Request,
        _principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            "directory.html",
            {
                "page_title": "Explore",
                "eyebrow": "Why is this setting what it is here?",
                "intro": (
                    "The analytical surfaces, organized. Everything here is "
                    "read-only analysis over the ingested snapshots; nothing "
                    "on this page mutates the estate."
                ),
                "sections": _resolved(EXPLORE_SECTIONS),
            },
        )

    @app.get("/tools", response_class=HTMLResponse, name="tools")
    def tools_page(
        request: Request,
        _principal: Principal = Depends(requires(Permission.VIEW)),
    ) -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            "directory.html",
            {
                "page_title": "Tools",
                "eyebrow": "What specialist operation do I need?",
                "intro": (
                    "Operations and workbenches. Everything here states what "
                    "it reads and what it writes; ingest is the only surface "
                    "that changes stored snapshots."
                ),
                "sections": _resolved(TOOLS_SECTIONS),
            },
        )
