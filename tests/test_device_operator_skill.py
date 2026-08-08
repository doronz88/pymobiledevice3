"""Drift checks for the device-operator skill's task map.

The skill routes agent intent to CLI command groups. New top-level groups must be
reflected there, or agents fall through to source-scanning to discover them.
"""

from pathlib import Path

import pytest

from pymobiledevice3.__main__ import CLI_GROUPS

pytestmark = [pytest.mark.cli]

TASK_MAP = Path(__file__).parent.parent / ".codex/skills/pymobiledevice3-device-operator/references/task-map.md"

# Groups deliberately absent from the task map: no on-device task routes to them.
TASK_MAP_EXEMPT = {"version"}


def test_task_map_mentions_every_cli_group():
    task_map = TASK_MAP.read_text()
    missing = [group for group in CLI_GROUPS if group not in TASK_MAP_EXEMPT and f"`{group}" not in task_map]
    assert not missing, (
        f"CLI groups missing from the device-operator task map: {missing}. "
        f"Add them to {TASK_MAP} (the sync hook refreshes the plugin copy)."
    )


def test_task_map_exemptions_are_still_real_groups():
    stale = TASK_MAP_EXEMPT - CLI_GROUPS.keys()
    assert not stale, f"TASK_MAP_EXEMPT entries no longer exist in CLI_GROUPS: {stale}"
