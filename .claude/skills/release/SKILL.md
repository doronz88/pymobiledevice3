---
name: release
description: Cut a new pymobiledevice3 release — create the GitHub release (which publishes to PyPI) with a curated Highlights section. Use when asked to "release vX.Y.Z", "cut a release", or "publish a new version".
---

# Releasing pymobiledevice3

## How releasing works here

- **Version is derived from the git tag** via `setuptools_scm` (`pyproject.toml` →
  `[tool.setuptools_scm]`, `version = { attr = "pymobiledevice3._version.__version__" }`).
  There is **no version string to bump** in any file — the tag *is* the version.
- **PyPI publish is triggered by creating a GitHub release**, not by pushing a tag.
  See `.github/workflows/python-publish.yml` (`on: release: types: [created]`). It runs
  `uv build` (needs full history for `setuptools_scm`) and publishes via trusted publishing.
- Tags are `vMAJOR.MINOR.PATCH` (e.g. `v9.32.1`). Patch = bug-fix-only; minor = new features.

## Steps

1. **Confirm the tree is clean and pushed.** `git status` should be clean and up to date with
   `origin/master`. The release is cut from `master`.

2. **Review what's shipping** so you can write accurate highlights:
   ```shell
   PREV=$(git tag --sort=-creatordate | head -1)
   git log $PREV..HEAD --oneline
   git show <sha>   # inspect each meaningful change to describe it correctly
   ```

3. **Create the release** (this triggers the PyPI publish). Use `--target master`, **not** a raw
   SHA — targeting a bare commit SHA fails with `Release.target_commitish is invalid`:
   ```shell
   gh release create vX.Y.Z --target master --title vX.Y.Z --generate-notes
   ```

4. **Add a curated `## Highlights` section** above `## What's Changed`.
   `--generate-notes` alone does NOT include highlights — every prior release has a hand-written
   one, so always add it. Match the house style (see `gh release view v9.32.0`):
   - One `###` subsection per notable change, prefixed with an emoji:
     `✨` new feature · `🐛` bug fix · `📚`/`📝` docs · other emoji as fitting.
   - A short prose paragraph explaining the user-visible impact, plus a fenced ```shell``` example
     for new commands/features.

5. **Rewrite `## What's Changed` as a commit history**, not the PR-link list `--generate-notes`
   produces. One line per commit since the previous tag, formatted
   `* <shortsha8> <subject> (#<pr>) (@<committer>)`:
   ```shell
   for sha in $(git log $PREV..HEAD --format='%H'); do
     short=$(git rev-parse --short=8 $sha)
     subj=$(git show -s --format='%s' $sha)
     login=$(gh api repos/doronz88/pymobiledevice3/commits/$sha --jq '.author.login')
     pr=$(gh api repos/doronz88/pymobiledevice3/commits/$sha/pulls --jq '.[0].number')
     echo "* $short $subj (#$pr) (@$login)"
   done
   ```
   Keep the generated `## New Contributors` and `**Full Changelog**` lines.

   Write the full body (Highlights + What's Changed + New Contributors + Full Changelog) to a file
   and apply it:
   ```shell
   gh release edit vX.Y.Z --notes-file /tmp/rel_notes.md
   ```
   Editing notes does **not** re-trigger the publish workflow — it already fired on creation.

6. **Verify the publish workflow.**
   ```shell
   gh run list --workflow=python-publish.yml --limit 3
   ```
   Watch it to `completed / success` if the user wants confirmation it landed on PyPI.

## Notes

- `gh` must be installed and authenticated (`gh auth status`).
- Don't create the tag manually with `git tag` — `gh release create` creates both the tag and the
  release. A lone tag push will not publish to PyPI.
