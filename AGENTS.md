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

- Python: 3.9+.
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

## Documentation Expectations

- Update docs for user-facing command/API changes.
- Keep root `README.md` concise; place deep guides under `docs/guides/`.
- Add links in `docs/README.md` for new guides.

## Safety

- Avoid destructive actions (for example wiping/restoring devices) unless explicitly requested.
- Do not commit secrets, pair records, or device-identifying artifacts.
