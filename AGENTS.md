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
- On Python 3.15+ the CLI and the test suite run with PEP 810 lazy imports, scoped so
  that only imports performed by pymobiledevice3's own modules are deferred
  (`pymobiledevice3/_lazy_imports.py`; `__main__` and `tests/conftest.py` import it first
  in their first-party block — isort keeps it there). A module-level import may not
  execute until first use, so never rely on another module's import-time side effects;
  anything that must run eagerly belongs in an explicit call. No-op on Python <= 3.14.
- CLI commands are Typer-based and typically use dependency injection via
  `ServiceProviderDep` from `pymobiledevice3/cli/cli_common.py`.
- Never import `click` or `typer._click` in package code. Typer (>= 0.20) vendors click
  privately, so real-click classes/exceptions are the wrong types at runtime (e.g. a real
  `click.UsageError` escapes Typer's handler as a raw traceback). Stay on Typer's public
  API: `typer.Context` (+ `ctx.fail()` for usage errors), `typer.BadParameter`,
  `typer.Exit`, `typer.Abort`, `typer.CallbackParam`, `typer.echo`/`secho`. Where a
  click-typed parameter has no public Typer alias (e.g. `TyperGroup` method overrides),
  annotate it `Any`. Sole exception: interop with a click-based library goes through that
  library's namespace (see `_ls_cli_click` in `pymobiledevice3/services/afc.py`).
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

- Developer/DVT commands on iOS 17+ devices require an RSD tunnel, and every
  command that requires one **already establishes it in-process by default**,
  with a pure-Python userspace network stack and **no `sudo`/root**. Just run
  the command — do not reach for a flag.
  - Example: `pymobiledevice3 developer dvt oslog`, `pymobiledevice3 cryptex list`.
- `--userspace` only *forces* that path; it is redundant on a required-RSD
  command. It matters on iOS 17.0-17.3, which the default deliberately routes to
  `tunneld` instead (those versions predate CoreDeviceProxy, so the no-root path
  is the fragile Wi-Fi-only RemotePairing one). `PYMOBILEDEVICE3_USERSPACE=1` is
  the env-var equivalent.
- Use a privileged `tunneld` (needs root) only when the userspace tunnel is not
  viable — e.g. when you need higher host->device throughput, since userspace
  host->device transfers (DDI mounts, file pushes) are deliberately slower.
  `PYMOBILEDEVICE3_PREFER_TUNNELD=1` opts out of the userspace default entirely.
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

The device-operator skill is also published as a Claude Code plugin: the repo is a
plugin marketplace (`.claude-plugin/marketplace.json`) whose plugin package at
`misc/claude-plugin/` ships a **vendored real copy** of the skill (symlinks get
flattened by ZIP-based consumers such as plugin review pipelines). The canonical files
remain the single source of truth: after editing them, the `sync-claude-plugin-skill`
pre-commit hook refreshes the copy (`misc/claude-plugin/sync_skill.py`), and CI blocks
out-of-sync merges.

## Documentation Expectations

- Update docs for user-facing command/API changes.
- Keep root `README.md` concise; place deep guides under `docs/guides/`.
- Add new guides to the `nav` section of `mkdocs.yml`.

## Safety

- Avoid destructive actions (for example wiping/restoring devices) unless explicitly requested.
- Do not commit secrets, pair records, or device-identifying artifacts.
