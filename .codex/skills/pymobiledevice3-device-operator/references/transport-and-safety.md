# Transport And Safety

## Use This File

Read this file when the request touches transport selection, iOS 17+ developer services, or actions that can mutate device state.

## Transport Selection

- USB lockdown is the default path for most commands.
- `ServiceProviderDep` already resolves USB, `--rsd`, and `--tunnel` flows for repo-native CLI commands.
- `--rsd HOST PORT` is for a specific RemoteServiceDiscovery endpoint.
- `--tunnel ''` or `--tunnel <UDID>` targets a device already exposed by `tunneld`.

Use `uvx --from . pymobiledevice3 usbmux list` first for direct USB discovery.

## iOS 17+ Developer Service Checklist

Many `developer dvt` and related developer commands need all of the following:

1. Developer Mode enabled:
   `uvx --from . pymobiledevice3 amfi enable-developer-mode`
2. Developer image mounted:
   `uvx --from . pymobiledevice3 mounter auto-mount`
3. A CoreDevice transport path:
   `uvx --from . pymobiledevice3 lockdown start-tunnel --script-mode`
   or
   `uvx --from . pymobiledevice3 remote start-tunnel --script-mode`
   or an already-running `tunneld`

`start-tunnel` commands may need to be executed as the `root` user via `sudo` so tunnel interface setup succeeds.

If a developer command fails with service-availability errors, retry with `--tunnel ''` before assuming the code is broken.

## Tunnel Notes

- Tunnel creation can require elevated privileges because it creates a TUN/TAP interface.
- `lockdown start-tunnel` is the preferred path on iOS 17.4+.
- `remote start-tunnel` is the fallback for iOS 17.0 through 17.3.1.
- For Codex-driven tunnel setup, invoke `lockdown start-tunnel` or `remote start-tunnel` with `--script-mode`.
- If tunnel creation fails on permissions, retry `lockdown start-tunnel --script-mode` or `remote start-tunnel --script-mode` with `sudo`.
- Read the RSD host and port from the command's stdout and reuse those exact values in later commands.

See `docs/guides/ios17-tunnels.md` for the repo’s detailed guidance.

## Safety Gates

Ask before running commands that can:

- erase, restore, reboot, or move the device into or out of recovery
- install or remove apps, profiles, provisioning data, or activation state
- write or delete files on AFC or app containers
- toggle Developer Mode, mount developer images, simulate location, or signal/kill processes
- drive the UI through WDA or automation sessions in ways that change app/device state

If the user only asked to inspect or debug, stay read-only unless the task cannot progress without a change and the user approves it.

## Troubleshooting Order

When a command fails, check in this order:

1. Device presence and pairing: `usbmux list`, `lockdown info`
2. Correct transport: USB vs `--rsd` vs `--tunnel`
3. Developer prerequisites: Developer Mode, mounted image, tunnel, and sufficient privileges for `start-tunnel` such as `sudo`
4. Capability location: existing CLI command vs service method vs unsupported feature

Only after those checks should you consider implementing new code.
