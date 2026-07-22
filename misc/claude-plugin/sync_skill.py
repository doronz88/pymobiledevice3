#!/usr/bin/env python3
"""Mirror the canonical device-operator skill into the Claude Code plugin package.

The plugin at ``misc/claude-plugin/`` ships REAL copies of the skill files rather than a
git symlink: consumers that flatten symlinks (GitHub ZIP archives, plugin review
pipelines) would otherwise see a one-line text file instead of the skill content. The
canonical files stay in ``.codex/skills/pymobiledevice3-device-operator/`` — edit those
only; the pre-commit hook runs this script to refresh the vendored copy, and CI runs it
with ``--check`` to block out-of-sync merges.
"""

import argparse
import filecmp
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CANONICAL = REPO_ROOT / ".codex" / "skills" / "pymobiledevice3-device-operator"
VENDORED = REPO_ROOT / "misc" / "claude-plugin" / "skills" / "pymobiledevice3-device-operator"


def relative_files(root: Path) -> set[Path]:
    return {path.relative_to(root) for path in root.rglob("*") if path.is_file()}


def find_drift() -> list[Path]:
    canonical_files = relative_files(CANONICAL)
    vendored_files = relative_files(VENDORED) if VENDORED.exists() else set()
    drifted = canonical_files ^ vendored_files
    for rel in canonical_files & vendored_files:
        if not filecmp.cmp(CANONICAL / rel, VENDORED / rel, shallow=False):
            drifted.add(rel)
    return sorted(drifted)


def sync() -> None:
    if VENDORED.exists():
        shutil.rmtree(VENDORED)
    shutil.copytree(CANONICAL, VENDORED)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify the vendored copy matches without writing")
    args = parser.parse_args()

    drifted = find_drift()
    if not drifted:
        return 0
    for rel in drifted:
        print(f"out of sync: {rel}", file=sys.stderr)
    if args.check:
        print("run misc/claude-plugin/sync_skill.py to refresh the vendored copy", file=sys.stderr)
        return 1
    sync()
    print(f"synced {CANONICAL} -> {VENDORED}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
