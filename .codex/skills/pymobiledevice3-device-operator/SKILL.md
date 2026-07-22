---
name: pymobiledevice3-device-operator
description: Operate iOS and iPadOS devices with pymobiledevice3, from a local checkout or straight from PyPI via uvx on a fresh workstation. Use when an agent needs to inspect a connected device, collect logs or crash data, browse or copy files, manage apps, profiles, or backups, use developer services such as DDI/DVT/tunnels/sysmon/screenshots/simulated location, automate Safari or WebViews through WebInspector or WDA, write Python scripts against the pymobiledevice3 library, or add a thin repo-native device command on top of existing services. Prefer existing CLI and service modules, choose USB vs --rsd/--tunnel correctly, and require explicit user intent before state-changing or destructive actions.
---

# PyMobileDevice3 Device Operator

## Overview

Use this skill to translate a user goal into the smallest correct `pymobiledevice3` action, then execute it — from a local checkout when one is present, or via the PyPI release (`uvx pymobiledevice3`) on a fresh workstation — or extend the repo with a thin CLI wrapper when the capability already exists in services.

## Default Operating Pattern

Inside a pymobiledevice3 checkout, run commands from the repository root with `uvx --from . pymobiledevice3 ...` so the local checkout is used. On a workstation **without** a checkout, run `uvx pymobiledevice3 ...` instead — `uvx` fetches the released package from PyPI on first use, so nothing needs to be installed beforehand except `uv` itself (`uv tool install pymobiledevice3` gives a persistent install). Everywhere this skill's references show `uvx --from . pymobiledevice3 ...`, drop the `--from .` when there is no checkout. Fall back to `python3 -m pymobiledevice3 ...` only if `uvx` is unavailable or the user explicitly wants the current interpreter environment.

If `uv` itself is missing, bootstrap one of the two paths first (neither needs root):

- Install uv: `curl -LsSf https://astral.sh/uv/install.sh | sh` (macOS/Linux) or
  `powershell -c "irm https://astral.sh/uv/install.ps1 | iex"` (Windows), then use `uvx` as above.
- Or skip uv entirely: `python3 -m pip install -U pymobiledevice3`, then run
  `python3 -m pymobiledevice3 ...` everywhere the references show `uvx ... pymobiledevice3 ...`.

Start with the least invasive command that proves connectivity or surfaces missing prerequisites:

```shell
uvx --from . pymobiledevice3 usbmux list
uvx --from . pymobiledevice3 lockdown info
```

Prefer existing CLI commands first. Prefer reading local docs and CLI source over invoking `--help`. Only write code when the library already exposes the underlying service but lacks the exact CLI/API path needed.

## Workflow

1. Classify the request as one of: inspect, collect, modify, automate, developer-instrument, or extend-the-repo.
2. Confirm transport before doing anything expensive. USB is the default. For iOS 17+ developer services, read `references/transport-and-safety.md`.
3. Discover the narrowest command by checking `docs/guides/cli-recipes.md`, `pymobiledevice3/__main__.py`, and the relevant CLI module under `pymobiledevice3/cli/`. Use `rg` to locate command names, options, and transport flags quickly. Without a checkout, use `--help` discovery and the published docs (<https://doronz88.github.io/pymobiledevice3/>) instead.
4. Use `uvx --from . pymobiledevice3 <group> --help` only as a fallback when code and docs are ambiguous, or as a final verification step before suggesting an exact command to the user.
5. Execute a reversible or read-only step first, then escalate to state-changing actions only if the user asked for them.
6. For long-lived streams or interactive shells, keep the process attached instead of replacing it with one-shot polling.
7. If the CLI is missing a path that clearly exists in services, add a thin command using `ServiceProviderDep`, `@async_command`, and a service class under `pymobiledevice3/services/` — commands live on an `InjectingTyper` app (from `typer_injector`). Read `docs/guides/writing-commands-with-service-provider.md`.

## Safety Rules

Require explicit user intent before any command that changes device state, including:

- restore, erase, recovery, reboot, restart, unpair, pair-supervised
- app install or uninstall
- file push, rm, or app container mutation
- profile or provisioning changes
- developer mode toggles, mounting, simulated location, signals, kill/pkill, or automation that taps/types/swipes

Do not invent prerequisites. If a developer service fails, inspect developer-mode, DDI, and tunnel requirements before changing code.

Do not expose or commit pair records, crash artifacts, backups, or other device-identifying material.

## Task Routing

Read `references/quick-recipes.md` for the exact invocation of the most common tasks
(screenshot, syslog search, crash pull, file copy, app listing) and for the
syslog-first troubleshooting technique.

Read `references/python-scripting.md` before writing Python code against the library —
the API went async incrementally over many releases, so memorized/older API shapes are
usually stale.

Read `references/task-map.md` when you need to map a user goal to a command group or service module.

Read `references/transport-and-safety.md` when the task touches iOS 17+ developer services, tunnels, `--rsd`, `--tunnel`, or destructive operations.

## Source Files To Prefer

These paths are relative to a pymobiledevice3 checkout; without one, use the published
docs site (<https://doronz88.github.io/pymobiledevice3/>) and `--help` output instead.

- `docs/guides/cli-recipes.md` for common end-user commands
- `docs/guides/ios17-tunnels.md` for tunnel setup and `--rsd` usage
- `docs/guides/writing-commands-with-service-provider.md` for repo-native command additions
- `pymobiledevice3/__main__.py` for top-level CLI groups
- `pymobiledevice3/cli/cli_common.py` for transport resolution and dependency injection

## Typical Triggers

- "Pull crash logs from the connected iPhone."
- "List installed apps and copy an app container file."
- "Take a screenshot with developer services."
- "Start a tunnel and run DVT sysmon on an iOS 17 device."
- "Open Safari automation and inspect tabs."
- "Add a new CLI command for an existing service."
