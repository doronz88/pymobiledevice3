# AGENTS

Guidance for AI coding agents and automation contributors working in this repository.

## Scope

- Keep changes small, targeted, and testable.
- Do not refactor unrelated areas in the same change.
- Prefer extending existing modules/patterns over introducing new abstractions.

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

## Testing Expectations

- Add or update tests when behavior changes.
- Prefer tests that exercise real physical devices over monkeypatched or fully mocked coverage when the behavior depends on device interaction.
- Reuse fixtures from `tests/conftest.py`, especially `service_provider`.
- Run at least targeted tests for touched areas; run full `pytest` when practical.

## Documentation Expectations

- Update docs for user-facing command/API changes.
- Keep root `README.md` concise; place deep guides under `docs/guides/`.
- Add links in `docs/README.md` for new guides.

## Safety

- Avoid destructive actions (for example wiping/restoring devices) unless explicitly requested.
- Do not commit secrets, pair records, or device-identifying artifacts.
