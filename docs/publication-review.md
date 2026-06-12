# Publication Review: WI-R.1

**Review date:** 2026-06-10
**Work item:** WI-R.1 (retrospective publication review per Plan 010 WI-0.4)
**Decision:** Full scrub + git history rewrite was performed before the repository was made public.

## What was found (before scrub)

A systematic audit of the full commit history identified the following categories of potentially identifying information:

- **Work domain name.** The real domain name (now replaced with `WORK-DOMAIN.local`) appeared in 8 committed files across docs, test fixtures, and reflections.
- **Aggregate counts.** Exact GPO, SOM, and MS16-072 counts from the work domain estate formed a fingerprint in docs, reflections, and test files.
- **DN paths.** Distinguished name paths containing the real domain (`dc=work-domain,dc=local` form) appeared in 2 test files.
- **Lab domain name.** The real lab domain (now replaced with `lab.example.com`) appeared in 5 files.
- **No real OU paths, GPO display names, hostnames, or usernames** were found in the repository.
- **Author/org handle.** The handle `hraedon` appeared in LICENSE, pyproject.toml, and CHANGELOG. This is an org identity, not a work-domain identifier, and was retained.

## What was scrubbed

The following changes were applied across all commits via `git-filter-repo`:

- Work domain name replaced with the placeholder `WORK-DOMAIN.local` in all affected files.
- Lab domain name replaced with the placeholder `lab.example.com` in all affected files.
- DN paths updated to match the replacement domain names.
- Sample directory identifiers in `conftest.py` (the original work-domain handle / `hraedon`) replaced with generic labels `WORKDOMAIN`/`LABDOMAIN`.

## What was kept

- **Exact calibration counts in test files.** These are assertion values that must match the `samples/` data at runtime. The counts themselves are not identifying (they are aggregate totals, not object names), and the tests are gated behind the `samples` marker which only runs when the gitignored sample data is present.
- **Author/org handle `hraedon`.** Retained in LICENSE (copyright), pyproject.toml (author field), and the GitHub URL. This is a public org identity, not derived from any work domain.
- **Aggregate count ranges in docs/reflections.** Phase R scrubbed exact counts from docs and reflections; only approximate ranges remain where needed for narrative context.

## Rules for future sessions

The following rules are enforced to prevent re-introduction of identifying information:

1. **Reflections must not name work-domain objects.** Use placeholders (`WORK-DOMAIN.local`, `LABDOMAIN`) when referencing the sample estate.
2. **Test fixture data must use synthetic names only.** No real GPO names, OU paths, or domain names in committed test files.
3. **Docs may reference aggregate count ranges, not exact counts.** Write "approximately 130 GPOs", not "129 GPOs", in documentation and reflections. Exact counts are permitted only in test assertions that validate against `samples/`.
4. **The `samples/` directory is gitignored and must never be committed.** It contains the real SYSVOL exports and is excluded from version control via `.gitignore`.

## Audit trail

- Pre-scrub audit: full `git log` and `grep` pass across all branches.
- Scrub tool: `git-filter-repo` with blob replacement expressions.
- Post-scrub verification: clean `grep` for the original domain names returned zero hits across the full history.
