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

- Move all unreleased entries from the top `Unreleased` section into a new dated section `${input:version} (YYYY-MM-DD)` when cutting the release.
- Keep `Unreleased` at the top of the file for future work and leave it empty.
- Ensure the release section follows the existing format.

### Step 4bis — Cross-check changelog against milestone

For each issue/PR assigned to the `${input:version}` milestone on GitHub:

1. Verify it has an explicit `#N` reference in the changelog section (entries without a
   number are acceptable only if the change is genuinely internal, e.g. typo fixes).
2. Verify the attribution is correct: confirm via `gh api repos/oauthlib/oauthlib/pulls/<N>`
   that the referenced PR is actually the one that introduced the change (e.g. a Python
   version drop belongs to the CI PR, not the devcontainer PR).
3. In the other direction, verify each changelog entry references a real, merged PR or a
   closed issue: `gh api "search/issues?q=repo:oauthlib/oauthlib+milestone:${input:version}"`
4. Use multi-line entries with 2-space continuation indent for readability, and keep the
   `OAuth2.0 Provider:` / `Misc:` section structure of previous releases.
5. Explicitly mark behavior-changing entries with `**Breaking**` and describe the
   observable impact (e.g. error code changes), not just the internal refactor.

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

1. Determine if the regression was caused by this release. To distinguish a pre-existing
   downstream failure from a regression introduced by this release, re-run the failing
   test with the previously published oauthlib version in an isolated environment:

   ```bash
   # Example: compare against the last released version
   uv run --with "oauthlib==<previous-version>" --with <target-deps> \
     --no-project python -m pytest <failing-test> -q
   ```

   - Fails with the old version too → pre-existing downstream issue (document it, do not block the release).
   - Passes with the old version, fails with the release candidate → regression caused by oauthlib.
   - If it is a regression, bisect the release branch commits to identify the culprit PR.

2. Either fix forward in the release branch, or file an issue in the downstream project.
3. DO NOT proceed to publish if a regression is unresolved and unwaived.
4. Environmental failures (missing browser/selenium, network access) are not oauthlib
   regressions: document them and exclude them from the verdict.

Known baseline expectations (update after each release):

- `requests-oauthlib` py38 env fails: expected when oauthlib drops an EOL Python
  (metadata `requires-python` correctly excludes it).
- `django-oauth-toolkit` dj42 envs: pre-existing `pytest_django`/Django 4.2
  incompatibility, unrelated to oauthlib.
- `flask-dance` `test_no_verify_api_call`: pre-existing failure, unrelated to oauthlib.

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
- Close the `${input:version}` GitHub milestone:

  ```bash
  gh api --method PATCH repos/oauthlib/oauthlib/milestones/<milestone-number> -f state=closed
  ```

  Some agent environments block mutating GitHub API calls (milestone edits via
  `gh issue edit` still work). If the milestone cannot be closed programmatically,
  hand the exact command above to the user for manual execution, or direct them to
  https://github.com/oauthlib/oauthlib/milestones (Close button next to the milestone).

- Remove the release worktree:
  ```bash
  git worktree remove ~/oauthlib/oauthlib-${input:version}-ds
  ```

## Checklist Summary

Print a final checklist with ✅/❌ status for each step above based on what was completed in this session.
