---
description: "Walk through the full oauthlib release process for a specific version, step by step"
argument-hint: "Version number to release (e.g. 3.3.2)"
---

You are the oauthlib maintainer. Prepare and walk through a complete release of version **${input:version:Version to release (e.g. 3.3.2)}** following [docs/release_process.rst](../../docs/release_process.rst).

## Determine Release Type

Based on `${input:version}`, confirm the semver type and expectations:
- **Patch** (`x.y.Z`): bug fixes only, must be fully backwards-compatible.
- **Minor** (`x.Y.0`): new non-breaking features; API-stable.
- **Major** (`X.0.0`): may introduce breaking changes; requires explicit downstream notice.

## Step 1 — Classify & Scope

- Read `CHANGELOG.rst` and list all unreleased entries to be included.
- Read `oauthlib/__init__.py` and confirm the current version.
- List all open GitHub Issues and PRs targeting the milestone for `${input:version}`.

## Step 2 — Create Release Branch

```bash
cd ~/oauthlib/oauthlib
git fetch origin
git checkout -b ${input:version}-release origin/master
```

For a patch release, rebase off the relevant stable branch rather than `master` if applicable.

## Step 3 — Bump Version

In `oauthlib/__init__.py`, update `__version__` to `${input:version}`.

Verify:
```bash
python -c "import oauthlib; print(oauthlib.__version__)"
```

## Step 4 — Update CHANGELOG.rst

- Move all unreleased entries under a new section heading `${input:version} (YYYY-MM-DD)` with today's date.
- Ensure the section follows the existing format.
- Leave the `Unreleased` section empty (or remove it if convention dictates).

## Step 5 — Milestone Hygiene

- Confirm all merged Issues and PRs are assigned to the `${input:version}` milestone on GitHub.
- Move or close any issues that won't make this release.

## Step 6 — Upstream Test Suite

```bash
cd ~/oauthlib/oauthlib
uvx --with tox-uv tox
```

All tests must pass before proceeding.

## Step 7 — Downstream Testing

Run all downstream targets in isolated worktrees from `~/oauthlib/oauthlib`:

```bash
# Create a clean worktree for downstream tests
git worktree add ~/oauthlib/oauthlib-${input:version}-ds ${input:version}-release
cd ~/oauthlib/oauthlib-${input:version}-ds

# Run all downstream suites (can run each target in a separate terminal in parallel)
make bottle
make django
make requests
make dance
```

For each failing target:
1. Determine if the regression was caused by this release.
2. Either fix forward in the release branch, or file an issue in the downstream project.
3. DO NOT proceed to publish if a regression is unresolved and unwaived.

## Step 8 — Heads-Up PR & Downstream Notice

Create the release PR from `${input:version}-release` → `master` with:
- Title: `Release ${input:version}`
- Body: changelog excerpt for `${input:version}`, list of downstream test results, and @-mentions of downstream primary contacts (see `Makefile` comments for contact names).
- **Wait at least 2 days** for downstream maintainers to respond before merging (per release_process.rst).

## Step 9 — Tag & Publish (requires explicit confirmation)

> ⚠️ Tagging triggers the trusted-publisher PyPI workflow. Only proceed after user says "go ahead and tag".

```bash
git tag ${input:version}
git push origin ${input:version}-release
git push origin ${input:version}
```

CI/CD (GitHub Actions trusted publisher) will publish to PyPI automatically.

**Manual fallback** (only if CI/CD fails):
```bash
pip install build twine
python -m build
twine check dist/*
twine upload dist/*
```

## Step 10 — GitHub Release

Create a GitHub Release for tag `${input:version}` with the changelog section as the release notes body.

## Step 11 — Merge & Close

- Merge the release PR into `master`.
- Close the `${input:version}` GitHub milestone.
- Remove the release worktree:
  ```bash
  git worktree remove ~/oauthlib/oauthlib-${input:version}-ds
  ```

## Checklist Summary

Print a final checklist with ✅/❌ status for each step above based on what was completed in this session.
