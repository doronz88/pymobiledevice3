# Transport And Safety

## Use This File

Read this file when the request touches transport selection, iOS 17+ developer services, or actions that can mutate device state.

## Transport Selection

- USB lockdown is the default path for most commands.
- `ServiceProviderDep` already resolves USB, `--rsd`, `--tunnel`, and `--userspace` flows for repo-native CLI commands.
- When a command requires an RSD tunnel and no transport flag is given, a **no-root
  in-process userspace tunnel** is established automatically on iOS 17.4+ — no `sudo`,
  no `start-tunnel`, no `tunneld`. This is the preferred path for agents.
- `--userspace` forces the userspace tunnel explicitly (`PYMOBILEDEVICE3_USERSPACE=1` is
  equivalent); it is mutually exclusive with `--rsd`/`--tunnel`.
- `--rsd HOST PORT` is for a specific RemoteServiceDiscovery endpoint.
- `--tunnel ''` or `--tunnel <UDID>` targets a device already exposed by `tunneld`.

Use `uvx --from . pymobiledevice3 usbmux list` first for direct USB discovery.

## iOS 17+ Developer Service Checklist

Many `developer dvt` and related developer commands need all of the following:

1. Developer Mode enabled:
   `uvx --from . pymobiledevice3 amfi enable-developer-mode`
2. Developer image mounted:
   `uvx --from . pymobiledevice3 mounter auto-mount`
3. A CoreDevice transport path. On iOS 17.4+ this needs **no setup**: the no-root
   userspace tunnel is established automatically when the command runs. Only iOS
   17.0-17.3 devices (which predate CoreDeviceProxy) route to `tunneld` and need a
   privileged daemon: `sudo uvx --from . pymobiledevice3 remote tunneld` in the
   background, then pass `--tunnel ''` or `--tunnel <UDID>`.

If a developer command fails with service-availability errors, verify Developer Mode and
the mounted image before assuming the code is broken.

## Tunnel Notes

- The userspace tunnel is the default; prefer it. Fall back to a privileged tunnel only
  when userspace is not viable: sustained host->device throughput (DDI mounts and large
  file pushes are deliberately slower over userspace), `debugserver start-server`
  without `--local-port`, or iOS 17.0-17.3.
- Privileged options: an already-running `tunneld`, or a one-off
  `lockdown start-tunnel` (iOS 17.4+) / `remote start-tunnel` (iOS 17.0-17.3.1).
- Privileged tunnel creation can require `sudo` because it creates a TUN/TAP interface.
- For agent-driven `start-tunnel`, use `--script-mode`, read the RSD host and port from
  stdout, and reuse those exact values in later commands via `--rsd HOST PORT`.
- `PYMOBILEDEVICE3_PREFER_TUNNELD=1` opts out of the userspace default entirely.

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

The device often logs the real reason for a failure in its own syslog. When an error is
opaque, reproduce it while watching `syslog live -m <term>` (or
`--process-name <daemon>`) — see `references/quick-recipes.md` — and read the
device-side message before guessing.

When a command fails, check in this order:

1. Device presence and pairing: `usbmux list`, `lockdown info`
2. Correct transport: USB vs `--rsd` vs `--tunnel`
3. Developer prerequisites: Developer Mode, mounted image, and — only on iOS 17.0-17.3 or when a privileged tunnel is explicitly used — a running `tunneld` / sufficient privileges for `start-tunnel` such as `sudo`
4. Capability location: existing CLI command vs service method vs unsupported feature

Only after those checks should you consider implementing new code.
