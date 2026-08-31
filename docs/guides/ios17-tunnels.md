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

!!! tip
    For diagrams of what each transport path looks like under the hood — usbmux, Wi-Fi
    lockdown, kernel tunnels, and the userspace tunnel — see
    [Understanding the network stacks](network-stacks.md).

## The default: a no-root tunnel, automatically

When a developer command needs an RSD tunnel and you passed no transport flag (`--rsd` /
`--tunnel` / `--userspace` / `--native`), pymobiledevice3 brings up a **no-root tunnel** for you,
built when the command starts and torn down when it exits. The kind depends on the host:

- **macOS** rides Apple's own `remoted` tunnel (the **native** path) by piggybacking
  `remotepairingd` — no root, no Xcode, and `remoted` is left running so it coexists with
  Xcode/`devicectl`. Its address is kernel-routable, so it is faster host->device and lower
  latency than the userspace stack. See
  [Native remoted tunnel](network-stacks.md#native-remoted-tunnel-macos-only).
- **Linux/Windows** bring up an **in-process userspace tunnel** using a pure-Python network stack
  (PyTCP) — no kernel interface, so no root/admin either.

If the native path is unavailable on macOS it falls back automatically (userspace, then `tunneld`).
Either way you just run the command. This covers iOS 17.4+ over USB with no privileges (it uses the
CoreDeviceProxy lockdown service); iOS 17.0-17.3.1 is handled differently — see the note below.
Set `PYMOBILEDEVICE3_DEFAULT_FALLBACK=native|userspace|tunneld` to change which transport the
automatic selection prefers (see [Environment variables](environment-variables.md) for every
variable the CLI honors).

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

`tunneld` binds `127.0.0.1:49151` by default. To relocate it, pass `--host`/`--port`; the
`--tunnel` value accepts the matching `UDID:PORT` suffix (the UDID part may be empty).

When the client cannot reach the tunnel interface `tunneld` created — for example, `tunneld` runs
in a different docker network stack, or on a different host altogether — the RSD addresses reported
over `GET /` are unreachable. The `/connect` websocket endpoint bridges into the tunnel through the
HTTP API instead: binary websocket messages are forwarded as-is over a TCP connection opened on the
device's tunnel address (to `?port=`, defaulting to the RSD port), and vice versa:

```python
import websockets  # any websocket client works

async with websockets.connect(f'ws://127.0.0.1:49151/connect?udid={udid}') as websocket:
    # speak RSD (RemoteXPC) over the websocket, or pass ?port=<service-port>
    # to reach any other service published over the tunnel
    ...
```

!!! warning
    Like the rest of the `tunneld` HTTP API, `/connect` is unauthenticated — anyone able to reach
    the listener gains access to the services exposed over the tunnel, so only bind non-loopback
    addresses on trusted networks.

!!! note
    `/connect` only bridges into tunnels established by this `tunneld` instance. A device that
    appears in `GET /` through a registered upstream `tunneld` is not reachable through this
    instance's `/connect` — connect to the upstream's own `/connect` endpoint instead.

To make `tunneld` the **default** fallback — so commands route to it automatically without passing
`--tunnel`, restoring the pre-userspace-default behavior — set
`PYMOBILEDEVICE3_DEFAULT_FALLBACK=tunneld`:

```shell
export PYMOBILEDEVICE3_DEFAULT_FALLBACK=tunneld
python3 -m pymobiledevice3 developer dvt ls /
```

## Starting a tunnel manually

```shell
# macOS (the default there): no sudo — publishes Apple's own remoted tunnel
# (kernel-routable, so other tools can use the printed --rsd too). See "Native
# remoted tunnel" in the network stacks guide.
python3 -m pymobiledevice3 remote start-tunnel

# Optional for remote-pairing devices.
python3 -m pymobiledevice3 remote pair

# iOS 17.4+ (faster lockdown tunnel)
sudo python3 -m pymobiledevice3 lockdown start-tunnel

# Optional: allow Wi-Fi connections over lockdown
python3 -m pymobiledevice3 lockdown wifi-connections on

# iOS 17.0-17.3.1 fallback, and the default off macOS.
# Add `-t wifi` to force Wi-Fi transport (on macOS this routes to this classic
# tunnel automatically, as does --no-native or any other classic-tunnel option).
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

The classic tunnel creation command must run with elevated privileges because it creates a TUN/TAP
interface. The native path (`--native`, the macOS default) is the exception: it rides Apple's
already-existing tunnel instead of creating one, so it needs no privileges. Device selection there
is by `--udid`; the classic-tunnel-shaping options (`--protocol`/`--secrets`/`--max-idle-timeout`/
`-t`) don't apply to it, and passing one routes the command to the classic tunnel (as does
`--no-native`, or `PYMOBILEDEVICE3_DEFAULT_FALLBACK` set to anything but `native`). The same
default applies to `remote browse`: on macOS it lists devices via `remotepairingd` with no root
(`--no-native` forces the bonjour browse, which needs root to suspend `remoted`).

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

Service connections are handed off in-process over unix-socket relays; on Windows (no `AF_UNIX`)
the relays use loopback TCP instead. Set `PYMOBILEDEVICE3_USERSPACE_TCP_RELAY` (any non-empty
value) to force the loopback-TCP relays on any platform — useful for reproducing Windows-specific
relay behavior elsewhere.

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
