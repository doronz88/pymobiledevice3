# iOS 17+ Developer Services via Tunnel

Starting with iOS 17.0, Apple moved developer service access to CoreDevice/RemoteXPC flows.
To use many `developer dvt` commands, establish a trusted tunnel first.

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

## Use tunnel details in commands

```shell
# DVT with automatic tunnel selection
python3 -m pymobiledevice3 developer dvt ls / --tunnel ''

# If tunneld is already running, this may work without --tunnel
python3 -m pymobiledevice3 developer dvt ls /

# Use manual RSD connection details
python3 -m pymobiledevice3 developer dvt ls / --rsd fd7b:e5b:6f53::1 64337

# Non-developer command over tunnel
python3 -m pymobiledevice3 syslog live --tunnel ''
```

## Troubleshooting

- If a developer command fails with service availability errors, retry with `--tunnel ''`.
- Verify the tunnel process is running and the device is trusted/paired.
- On Windows for iOS 17.0-17.3.1, ensure required additional drivers are installed.
