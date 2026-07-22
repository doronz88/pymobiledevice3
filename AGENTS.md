# AGENTS

Guidance for AI coding agents and automation contributors working in this repository.

## Scope

- Keep changes small, targeted, and testable.
- Do not refactor unrelated areas in the same change.
- Prefer extending existing modules/patterns over introducing new abstractions.

## Commit Expectations

- Use scoped commit subjects consistent with repository history, for example
  `dtx: Fix queue shutdown on Python 3.12`.
- Keep a behavior change and its corresponding tests in the same commit.
- Split unrelated documentation or contributor-guidance changes into their own
  commits.

## Project Conventions

- Python: 3.9+. No `X | Y` union syntax in annotations evaluated at runtime (use
  `Optional`/`Union`); builtin generics (`list[str]`, `dict[str, int]`) are fine.
- The repository must stay pyright-clean: `pyright --venvpath .` (pinned to 1.1.411 in CI) must
  report 0 errors after any change. Suppressions must be rule-specific
  (`# pyright: ignore[ruleName]`) and reserved for inherently dynamic APIs.
- CLI commands are Typer-based and typically use dependency injection via
  `ServiceProviderDep` from `pymobiledevice3/cli/cli_common.py`.
- Async CLI handlers should use `@async_command`.
- Device-facing logic should live in `pymobiledevice3/services/*`, not directly in CLI handlers.
- Use async context managers (`async with`) for long-lived service connections.

## Where To Add Things

- New CLI command in existing group:
  - Update or add function in `pymobiledevice3/cli/<group>.py`.
- New top-level CLI group:
  - Add module under `pymobiledevice3/cli/`.
  - Register group in `CLI_GROUPS` in `pymobiledevice3/__main__.py`.
- New protocol/service integration:
  - Add service wrapper under `pymobiledevice3/services/` (usually subclassing `LockdownService`).
- DVT-related functionality:
  - Use `DtxServiceProvider`/`DvtProvider` patterns in `pymobiledevice3/services/dvt/`.

## Running Developer Commands Against Devices

- Developer/DVT commands on iOS 17+ devices require an RSD tunnel. Prefer
  `--userspace` over a `tunneld` tunnel: it establishes the tunnel in-process
  with a pure-Python userspace network stack and needs **no `sudo`/root**, so
  agents can run unattended.
  - Example: `pymobiledevice3 developer dvt oslog --userspace`.
  - You can also set `PYMOBILEDEVICE3_USERSPACE=1` instead of passing the flag.
- Only fall back to a privileged `tunneld` (which needs root) when `--userspace`
  is not viable — e.g. when you need higher host->device throughput, since
  userspace host->device transfers (DDI mounts, file pushes) are deliberately
  slower.
- `--userspace` is mutually exclusive with `--rsd`/`--tunnel`.

## Testing Expectations

- Add or update tests when behavior changes.
- Prefer tests that exercise real physical devices over monkeypatched or
  fully mocked coverage when the behavior depends on device interaction.
- Reuse fixtures from `tests/conftest.py`, especially `service_provider`.
- Run at least targeted tests for touched areas; run full `pytest` when practical.
- Verify relevant linting for touched files when practical.

## Skills

Repo-local agent skills (`SKILL.md` + optional `references/`) are discoverable by both
Claude Code and Codex: `.claude/skills/` and `.codex/skills/` mirror each other via
relative symlinks. Each skill has exactly one canonical directory — the other tree holds
a symlink to it — so edit the canonical files only:

- `.codex/skills/pymobiledevice3-device-operator/` — operate a connected device through
  the local checkout (task routing, transport selection, safety gates).
- `.codex/skills/tss-batch-prefetch/` — maintain `PREFETCHABLE_UPDATERS` in
  `pymobiledevice3/restore/tss.py`.
- `.claude/skills/release/` — cut a GitHub release (which publishes to PyPI).

When adding a skill, create it in one tree and symlink it from the other. When changing
user-facing CLI layout, transports, or safety-relevant behavior, review whether the
device-operator skill guidance needs updating.

## Documentation Expectations

- Update docs for user-facing command/API changes.
- Keep root `README.md` concise; place deep guides under `docs/guides/`.
- Add new guides to the `nav` section of `mkdocs.yml`.

## Safety

- Avoid destructive actions (for example wiping/restoring devices) unless explicitly requested.
- Do not commit secrets, pair records, or device-identifying artifacts.
