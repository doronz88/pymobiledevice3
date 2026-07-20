# iOS 17+ Developer Services via Tunnel

Starting with iOS 17.0, Apple moved developer service access to CoreDevice/RemoteXPC flows, so
`developer` commands (and a few others) need an RSD tunnel to the device.

**By default pymobiledevice3 establishes this tunnel for you — in-process, with no root/admin.**
Just run the command; there is nothing to start beforehand:

```shell
python3 -m pymobiledevice3 developer dvt ls /
```

A privileged `tunneld` is only needed for specific cases (external tools such as `lldb`, a
shared/persistent tunnel, or iOS 17.0-17.3.1 — see
[When you still need `tunneld`](#when-you-still-need-a-privileged-tunneld)).

!!! tip "Working from Python?"
    See [Choosing a connection](python-api.md#1-connect-to-a-device) in the Python API guide for
    when to use lockdown vs an RSD tunnel (userspace vs `tunneld`).

Reference protocol details:
[RemoteXPC](../internals/remotexpc.md)

## The default: a no-root tunnel, automatically

When a developer command needs an RSD tunnel and you passed none of `--rsd` / `--tunnel` /
`--userspace`, pymobiledevice3 brings up an **in-process userspace tunnel** using a pure-Python
network stack (PyTCP) — no kernel interface, so **no root/admin**. The tunnel is built when the
command starts and torn down when it exits.

This covers iOS 17.4+ over USB on macOS, Linux and Windows with no privileges (it uses the
CoreDeviceProxy lockdown service). iOS 17.0-17.3.1 is handled differently — see the note below.

!!! warning "iOS 17.0-17.3.1 uses `tunneld` by default"
    These versions predate the CoreDeviceProxy service, so the userspace tunnel can only reach them
    over the RemotePairing path — which is Wi-Fi-only and, on macOS, races `remoted` (the no-root
    path can't suspend it without root). Rather than depend on that fragile path, pymobiledevice3
    **routes iOS 17.0-17.3.1 to `tunneld` on every platform**, so keep one running:

    ```shell
    sudo python3 -m pymobiledevice3 remote tunneld
    ```

    You can still force the no-root path with `--userspace` where it applies (a device on Wi-Fi;
    unreliable on macOS).

## Support Notes

| Host OS | iOS 17.0-17.3.1 | iOS 17.4+ |
| --- | --- | --- |
| macOS | Uses `tunneld` (root) | Supported (no-root) |
| Windows | Uses `tunneld` (root) + additional drivers | Supported (no-root) |
| Linux | Uses `tunneld` (root) | Supported (no-root) |

## When you still need a privileged `tunneld`

The in-process tunnel's device address lives **only inside the pymobiledevice3 process**, so it is
not reachable from any other process on your machine. Use a kernel-routable tunnel (the sections
below) when:

- **An external tool must reach the device** — `developer debugserver lldb`, or `developer
  debugserver start-server` without `--local-port`, drive an external `lldb` and therefore refuse
  over the userspace tunnel. Pass `--tunnel` (or `--local-port` for `start-server`, which forwards
  to a local port and *does* work over the userspace tunnel).
- **You want one shared/persistent tunnel** reused across many invocations instead of rebuilding it
  per command.
- **iOS 17.0-17.3.1** (any host OS) — routed to `tunneld` automatically; see the warning above.

## Running `tunneld`

```shell
# If the device supports remote pairing (for example, Corellium/Apple TV), pair first.
# Standard iOS devices usually do not need this step.
python3 -m pymobiledevice3 remote pair

# On Windows, run from a privileged shell.
sudo python3 -m pymobiledevice3 remote tunneld
```

With `tunneld` running, point a command at it with `--tunnel` (empty value = pick automatically, or
pass a UDID):

```shell
python3 -m pymobiledevice3 developer dvt ls / --tunnel ''
```

To make `tunneld` the **default** fallback again — so commands route to it automatically without
passing `--tunnel`, restoring the pre-userspace-default behavior — set the
`PYMOBILEDEVICE3_PREFER_TUNNELD` environment variable (any non-empty value):

```shell
export PYMOBILEDEVICE3_PREFER_TUNNELD=1
python3 -m pymobiledevice3 developer dvt ls /
```

## Starting a tunnel manually

```shell
# Optional for remote-pairing devices.
python3 -m pymobiledevice3 remote pair

# iOS 17.4+ (faster lockdown tunnel)
sudo python3 -m pymobiledevice3 lockdown start-tunnel

# Optional: allow Wi-Fi connections over lockdown
python3 -m pymobiledevice3 lockdown wifi-connections on

# iOS 17.0-17.3.1 fallback
# Add `-t wifi` to force Wi-Fi transport.
sudo python3 -m pymobiledevice3 remote start-tunnel
```

Example output:

```text
Interface: utun6
RSD Address: fd7b:e5b:6f53::1
RSD Port: 64337
Use the following connection option:
--rsd fd7b:e5b:6f53::1 64337
```

The tunnel creation command must run with elevated privileges because it creates a TUN/TAP interface.

!!! tip "Bootstrap the RemotePairing record over USB (no Trust dialog)"

    `remote start-tunnel` (the RSD/Wi-Fi path) needs a RemotePairing pair record. You can create it
    over USB, promptlessly, via the `com.apple.dt.remotepairingdeviced.lockdown` control channel:

    ```shell
    python3 -m pymobiledevice3 lockdown remotepairing --pair
    ```

    Because this runs over the already-trusted lockdownd (USB) transport, pairing is promptless (no
    on-device Trust dialog) and writes the same pair record `remote start-tunnel` / `remote pair` use.
    Without `--pair` the command just performs a handshake and prints the device's control-channel info
    (add `--raw` to keep the `deviceKVSData` blob base64-encoded). This control channel does not create
    tunnels itself.

## Forcing the userspace tunnel (`--userspace`)

The userspace tunnel is already the default, so you rarely need the flag. Pass `--userspace`
explicitly to **force** the no-root in-process tunnel and skip the automatic `tunneld` fallback
(iOS 17.0-17.3.1) — any establishment failure is then surfaced as an error rather than masked:

```shell
python3 -m pymobiledevice3 developer dvt ls / --userspace
```

Requirements:

- **Python >= 3.9** — the `pmd-pytcp` dependency that powers the userspace stack is installed on
  every supported interpreter, so the userspace tunnel is always available.
- **iOS 17.0+** over USB (uses the CoreDeviceProxy lockdown service on 17.4+, or RemotePairing over
  bonjour/Wi-Fi on 17.0-17.3.1).

What works over the userspace tunnel: the host-initiated developer services (`dvt`, `fetch-symbols`,
`core-device …`), and the device-initiated AV/HID paths — `display serve-web`, `display serve-vnc`,
`display start-video-stream` / `start-audio-stream`, and the HID gesture commands.

### Limitation: in-process only

The device's tunnel address lives only inside the pymobiledevice3 process, so it is **not reachable
from any other process** on your machine. Commands that hand the device address to an external tool
therefore cannot use the userspace tunnel — see
[When you still need `tunneld`](#when-you-still-need-a-privileged-tunneld).

Because the tunnel is rebuilt per invocation (no persistent daemon), expect a little extra startup
latency compared with attaching to an already-running `tunneld`.

### From Python

To establish this tunnel programmatically, use the `UserspaceRsdTunnel` handle — see the
[`UserspaceRsdTunnel` example](../internals/idevice-protocol-layers.md#remotexpc) in the
protocol-layers guide, listed there alongside the other ways to obtain an RSD. The in-process-only
limitation above applies equally to the Python API.

## Use tunnel details in commands

```shell
# Default: no flag, no root — an in-process userspace tunnel is established automatically
python3 -m pymobiledevice3 developer dvt ls /

# Force the no-root tunnel (skip the automatic tunneld fallback)
python3 -m pymobiledevice3 developer dvt ls / --userspace

# Use a running tunneld ('' = pick automatically, or pass a UDID)
python3 -m pymobiledevice3 developer dvt ls / --tunnel ''

# Use manual RSD connection details (from `start-tunnel`)
python3 -m pymobiledevice3 developer dvt ls / --rsd fd7b:e5b:6f53::1 64337

# Non-developer command over a running tunneld
python3 -m pymobiledevice3 syslog live --tunnel ''
```

## Troubleshooting

- Most developer commands need no flag — the no-root tunnel is established for you. If one fails to
  establish a tunnel, the two explicit routes are `--tunnel ''` (uses a running `tunneld`) or
  `--userspace` (forces the no-root in-process tunnel and surfaces the real error).
- iOS 17.0-17.3.1 is routed to `tunneld` on every platform (the no-root path only reaches those
  over the fragile Wi-Fi RemotePairing route), so start one. `--userspace` can still force that
  no-root path over Wi-Fi if you prefer.
- Verify the tunnel process is running and the device is trusted/paired.
- On Windows for iOS 17.0-17.3.1, ensure required additional drivers are installed.
