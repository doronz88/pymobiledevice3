# iOS 17+ Developer Services via Tunnel

Starting with iOS 17.0, Apple moved developer service access to CoreDevice/RemoteXPC flows.
To use many `developer dvt` commands, establish a trusted tunnel first — with root via `tunneld`
(Option 1) or a manual tunnel (Option 2), or with **no root at all** via the in-process
`--userspace` tunnel on Python 3.14+ (Option 3).

Reference protocol details:
[RemoteXPC](../../misc/RemoteXPC.md)

## Support Notes

| Host OS | iOS 17.0-17.3.1 | iOS 17.4+ |
| --- | --- | --- |
| macOS | Supported | Supported |
| Windows | Supported (requires additional drivers) | Supported |
| Linux | Limited | Supported (lockdown tunnel) |

## Option 1: Run `tunneld` (automatic)

```shell
# If the device supports remote pairing (for example, Corellium/Apple TV), pair first.
# Standard iOS devices usually do not need this step.
python3 -m pymobiledevice3 remote pair

# On Windows, run from a privileged shell.
sudo python3 -m pymobiledevice3 remote tunneld
```

With `tunneld` running, many developer commands can auto-connect via `--tunnel`.

## Option 2: Start a tunnel manually

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

## Option 3: No-root userspace tunnel (`--userspace`)

Options 1 and 2 need root/admin because they create a kernel TUN/TAP interface. `--userspace`
instead establishes the iOS 17+ tunnel **in-process** using a pure-Python network stack (PyTCP),
so it needs **no root/admin at all**. Just add the flag to a developer command:

```shell
python3 -m pymobiledevice3 developer dvt ls / --userspace
```

There is no separate tunnel process to start — the flag builds the tunnel inside the command and
tears it down when it exits.

Requirements:

- **Python >= 3.14** (the `pmd-pytcp` dependency ships only on 3.14+). On older interpreters the
  flag is unavailable and the command falls back to `tunneld`.
- **iOS 17.0+** over USB (uses the CoreDeviceProxy lockdown service on 17.4+, or RemotePairing over
  bonjour/Wi-Fi on 17.0–17.3.1).

What works over `--userspace`: the host-initiated developer services (`dvt`, `fetch-symbols`,
`core-device …`), and the device-initiated AV/HID paths — `display serve-web`, `display serve-vnc`,
`display start-video-stream` / `start-audio-stream`, and the HID gesture commands.

### Limitation: in-process only

The device's tunnel address lives only inside the pymobiledevice3 process, so it is **not reachable
from any other process** on your machine. Commands that hand the device address to an external tool
therefore cannot use the userspace tunnel:

- `developer debugserver lldb` and `developer debugserver start-server` (without `--local-port`)
  **refuse** over `--userspace`, since they drive an external `lldb` that cannot reach the in-process
  address. Use a kernel-routable tunnel (Option 1/2) for these — or, for `start-server`, pass
  `--local-port`, which forwards debugserver to a local port and *does* work over `--userspace`.

Because the tunnel is rebuilt per invocation (no persistent daemon), expect a little extra startup
latency compared with attaching to an already-running `tunneld`.

### From Python

To establish this tunnel programmatically, use the `UserspaceRsdTunnel` handle — see the
[`UserspaceRsdTunnel` example](../../misc/understanding_idevice_protocol_layers.md#remotexpc) in the
protocol-layers guide, listed there alongside the other ways to obtain an RSD. The in-process-only
limitation above applies equally to the Python API.

## Use tunnel details in commands

```shell
# DVT with automatic tunnel selection
python3 -m pymobiledevice3 developer dvt ls / --tunnel ''

# If tunneld is already running, this may work without --tunnel
python3 -m pymobiledevice3 developer dvt ls /

# No-root in-process tunnel (Python 3.14+); no tunneld/root required
python3 -m pymobiledevice3 developer dvt ls / --userspace

# Use manual RSD connection details
python3 -m pymobiledevice3 developer dvt ls / --rsd fd7b:e5b:6f53::1 64337

# Non-developer command over tunnel
python3 -m pymobiledevice3 syslog live --tunnel ''
```

## Troubleshooting

- If a developer command fails with service availability errors, retry with `--tunnel ''`.
- Verify the tunnel process is running and the device is trusted/paired.
- On Windows for iOS 17.0-17.3.1, ensure required additional drivers are installed.
