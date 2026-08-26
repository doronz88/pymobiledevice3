# Transport And Safety

## Use This File

Read this file when the request touches transport selection, iOS 17+ developer services, or actions that can mutate device state.

## Transport Selection

- USB lockdown is the default path for most commands.
- `ServiceProviderDep` already resolves USB, `--rsd`, `--tunnel`, `--userspace`, and `--native` flows for repo-native CLI commands.
- When a command requires an RSD tunnel and no transport flag is given, a **no-root tunnel** is
  established automatically — the native tunnel on macOS, the in-process userspace tunnel elsewhere — no `sudo`,
  no `start-tunnel`, no `tunneld`. This is the preferred path for agents.
- `--userspace` forces the userspace tunnel explicitly (`PYMOBILEDEVICE3_USERSPACE=1` is
  equivalent).
- `--native` (**macOS only, the macOS default**) forces the no-root native tunnel that piggybacks
  Apple's `remoted` (`PYMOBILEDEVICE3_NATIVE=1` is equivalent): no `sudo`, no entitlement, no Xcode,
  `remoted` left running, faster host->device and lower latency than the userspace stack.
- `--rsd`, `--tunnel`, `--userspace`, and `--native` are mutually exclusive.
- `--rsd HOST PORT` is for a specific RemoteServiceDiscovery endpoint.
- `--tunnel ''` or `--tunnel <UDID>` targets a device already exposed by `tunneld`.
- With multiple devices attached, always pass `--udid <UDID>` (or set
  `PYMOBILEDEVICE3_UDID`). Without a TTY the interactive device chooser does not prompt —
  it exits 1 and prints the candidate devices on stderr.

Use `uvx --from . pymobiledevice3 usbmux list` first for direct USB discovery.

## iOS 17+ Developer Service Checklist

Many `developer dvt` and related developer commands need all of the following:

1. Developer Mode enabled:
   `uvx --from . pymobiledevice3 amfi enable-developer-mode`
2. Developer image mounted:
   `uvx --from . pymobiledevice3 mounter auto-mount`
   On iOS 17+ the same image can instead be installed as a cryptex, bypassing the image
   mounter: `uvx --from . pymobiledevice3 cryptex auto-install` (needs RSD; both cache the
   download under `~/.pymobiledevice3` and end up mounted at `/System/Developer`).
3. A CoreDevice transport path. On iOS 17.4+ this needs **no setup**: a no-root tunnel is
   established automatically when the command runs — the native `remoted` tunnel on macOS,
   the in-process userspace tunnel elsewhere. iOS 17.0-17.3 devices (which predate
   CoreDeviceProxy) route automatically to the no-root `--native` tunnel on macOS; on other
   hosts they route to `tunneld`, which needs a privileged daemon:
   `sudo uvx --from . pymobiledevice3 remote tunneld` in the background, then pass
   `--tunnel ''` or `--tunnel <UDID>`.

If a developer command fails with service-availability errors, verify Developer Mode and
the mounted image before assuming the code is broken.

## Tunnel Notes

- The default no-root tunnel is native on macOS and userspace elsewhere; prefer the default. The
  native tunnel rides Apple's `remoted` at kernel-tunnel throughput (faster host->device, lower
  latency) and needs no root. Fall back to a privileged `tunneld` only when no no-root path is
  viable: non-macOS iOS 17.0-17.3, `debugserver start-server` without `--local-port`, or a tunnel
  that must be shared across processes.
- On macOS, `remote start-tunnel` publishes Apple's own kernel-routable tunnel with no sudo (the
  native path is the macOS default) — prefer it over the privileged options below when another
  process just needs an `--rsd HOST PORT` address. `remote browse` likewise lists the devices
  `remotepairingd` sees with no root on macOS. `--no-native` (or any classic-tunnel option, e.g.
  `-t wifi`) routes `start-tunnel` to the classic root tunnel.
- Privileged options: an already-running `tunneld`, or a one-off
  `lockdown start-tunnel` (iOS 17.4+) / `remote start-tunnel` (iOS 17.0-17.3.1).
- Privileged tunnel creation can require `sudo` because it creates a TUN/TAP interface.
- For agent-driven `start-tunnel`, use `--script-mode`, read the RSD host and port from
  stdout, and reuse those exact values in later commands via `--rsd HOST PORT`.
- `PYMOBILEDEVICE3_DEFAULT_FALLBACK=native|userspace|tunneld` overrides which transport the automatic
  selection prefers (the required-RSD default and the CLI retry). Built-in default: `native` on
  macOS, `userspace` elsewhere. Set `userspace` to opt back out of the macOS native default, or
  `tunneld` to opt out of the no-root default entirely.

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
3. Developer prerequisites: Developer Mode, mounted image, and — only on non-macOS iOS 17.0-17.3 or when a privileged tunnel is explicitly used — a running `tunneld` / sufficient privileges for `start-tunnel` such as `sudo`
4. Capability location: existing CLI command vs service method vs unsupported feature

Only after those checks should you consider implementing new code.
