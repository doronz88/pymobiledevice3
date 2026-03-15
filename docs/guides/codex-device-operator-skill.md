# Codex Device Operator Skill

This repository includes a repo-local Codex skill for device-facing work:

- Skill file: `.codex/skills/pymobiledevice3-device-operator/SKILL.md`
- Reference file: `.codex/skills/pymobiledevice3-device-operator/references/task-map.md`
- Reference file:
  `.codex/skills/pymobiledevice3-device-operator/references/transport-and-safety.md`

## Use From GitHub

If someone is using Codex against the GitHub repository and wants a copy-pasteable reference, point them at these URLs:

- Skill URL:
  `https://github.com/doronz88/pymobiledevice3/blob/master/.codex/skills/pymobiledevice3-device-operator/SKILL.md`
- Task map URL:
  `https://github.com/doronz88/pymobiledevice3/blob/master/.codex/skills/pymobiledevice3-device-operator/references/task-map.md`
- Transport and safety URL:
  `https://github.com/doronz88/pymobiledevice3/blob/master/.codex/skills/pymobiledevice3-device-operator/references/transport-and-safety.md`

Example prompt:

```text
Use the pymobiledevice3 device-operator skill:
https://github.com/doronz88/pymobiledevice3/blob/master/.codex/skills/pymobiledevice3-device-operator/SKILL.md
Also use its references:
https://github.com/doronz88/pymobiledevice3/blob/master/.codex/skills/pymobiledevice3-device-operator/references/task-map.md
https://github.com/doronz88/pymobiledevice3/blob/master/.codex/skills/pymobiledevice3-device-operator/references/transport-and-safety.md
```

Use this skill when Codex needs to operate a connected iPhone or iPad through the local `pymobiledevice3` checkout, including:

- connectivity and transport selection
- crash/log/file collection
- app/container operations
- DVT and other developer services
- WebInspector and WDA automation
- thin CLI additions on top of existing services

## What The Skill Enforces

- Prefer existing CLI commands and service modules over new abstractions.
- Prefer `uvx --from . pymobiledevice3 ...` for local-checkout CLI execution.
- Prefer reading local docs and CLI source before invoking `--help`.
- Treat `--help` as a fallback or final verification step.
- Require explicit user intent before state-changing or destructive device actions.
- Check transport, developer-mode, image-mount, and tunnel prerequisites before assuming a code bug.

## Transport Notes

For iOS 17+ developer services, the skill routes users through the project tunnel documentation and transport rules in:

- [iOS 17+ tunnels](ios17-tunnels.md)
- `.codex/skills/pymobiledevice3-device-operator/references/transport-and-safety.md`

If `lockdown start-tunnel` or `remote start-tunnel` fails because
tunnel interface creation needs elevated privileges, the skill is expected
to consider retrying with `sudo`.

For Codex-driven tunnel startup, the skill should prefer
`lockdown start-tunnel --script-mode` or `remote start-tunnel --script-mode`,
then read the RSD connection details from stdout and feed those exact values
into later `--rsd HOST PORT` commands.

## When Updating The Project

If you add, remove, or substantially change device-facing CLI behavior,
update the skill guidance when needed so Codex keeps routing requests
correctly.

In practice, review the skill when changes affect:

- top-level or nested CLI command layout
- transport selection (`USB`, `--rsd`, `--tunnel`)
- iOS version-specific command routing
- safety expectations for state-changing commands
- preferred service module or CLI entry point for a task
