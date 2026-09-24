# AGENTS.md

This repository contains the snap packaging (and colocated YARF UI tests) for
the **element-desktop** snap, published by kenvandine.

## Automated maintenance

This repository is maintained in part by the `automated-ken` fleet-maintenance
system (https://github.com/kenvandine/automated-ken). Automated agents may:

- Open pull requests bumping the packaged application/runtime version
- Queue YARF UI test runs on a registered remote runner (real hardware polling the
  automated-ken dashboard for jobs) against candidate/edge builds before promoting a
  release
- Review and comment on PRs, including AI-assisted screenshot review of UI test
  results

## Tests

YARF UI test suites belong under `tests/suite/` in this repository. They are
executed by a registered remote runner (physical/real hardware enrolled with the
automated-ken dashboard), which polls the dashboard for queued jobs, downloads/
installs the target snap build, runs the YARF suite locally, and uploads
screenshots/results directly back to the dashboard. No GitHub Actions workflow is
involved in running tests.

## Conventions

- Do not remove the `tests/suite/` directory; it is required for automated release
  validation. There is no test-running GitHub Actions workflow in this repo by
  design — tests run on a registered remote runner.
- Redundant upstream-polling / sync-release workflows that duplicate automated-ken's
  own version-bump automation should be removed to avoid conflicting/duplicate PRs.

## Upstream release detection

This snap repackages the **official element-desktop `.deb`** from
`https://packages.element.io/debian/pool/main/e/element-desktop/...`,
whose version tracks the upstream `vector-im/element-web` GitHub
repository's releases — **not** any URL actually referenced in
`snap/snapcraft.yaml` (none of its `source:` fields point at
`vector-im/element-web`; they point at the `.deb` URL itself and a
separate `patch-desktop-file-name` helper repo).

To check for a new version:

- Query `https://api.github.com/repos/vector-im/element-web/releases/latest`
  (excludes drafts/prereleases) and strip the leading `v` from
  `tag_name` to get the version.
- Compare against the top-level `version:` field in `snap/snapcraft.yaml`.
- If different, update `version:` — the `.deb` download URL uses
  `$SNAPCRAFT_PROJECT_VERSION`, which is derived from this field, so
  bumping it is sufficient to pull the matching release artifact.

**Important**: automated-ken's generic upstream checker
(`snap_dashboard.snapcraft.upstream.get_latest_version`) infers the
upstream repo from a part's `source:` URL and cannot discover
`vector-im/element-web` from this repo's snapcraft.yaml alone. Until the
dashboard supports an explicit per-snap "upstream override" source,
automated version-bump detection for this snap needs this repo/URL
special-cased, or the check performed manually using the logic above.
