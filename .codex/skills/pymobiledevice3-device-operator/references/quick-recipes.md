# Quick Recipes

## Use This File

Read this file for the exact invocation of the most common device tasks. All commands run
from the repository root; on iOS 17.4+ the `developer` commands establish a no-root
userspace tunnel automatically, so run them as-is — no `sudo`, no tunnel setup.

## Screenshot

```shell
uvx --from . pymobiledevice3 developer dvt screenshot ./screen.png
```

Requires Developer Mode and a mounted DDI (`amfi enable-developer-mode`,
`mounter auto-mount`). WDA-based UI automation has its own screenshot:
`developer wda screenshot`.

## Search The Device Syslog

```shell
# Live syslog filtered to lines containing a term (repeatable, case-sensitive)
uvx --from . pymobiledevice3 syslog live -m <term>

# Case-insensitive match / filter by process
uvx --from . pymobiledevice3 syslog live --match-insensitive <term>
uvx --from . pymobiledevice3 syslog live --process-name <name>
uvx --from . pymobiledevice3 syslog live --pid <pid>
```

Structured os_log (with subsystem/category metadata) via developer services:

```shell
uvx --from . pymobiledevice3 developer dvt oslog
```

## Troubleshoot With The Syslog First

When something on-device misbehaves — a service refuses to start, an app dies on launch,
a developer command fails opaquely — the device usually logs the real reason in its
syslog. Before changing code or guessing at prerequisites, reproduce the failure while
watching:

```shell
uvx --from . pymobiledevice3 syslog live -m <bundle-id-or-daemon-or-error-term>
```

Filter by the daemon that owns the failing service (`--process-name`) when you know it.
The device-side error message is frequently more specific than the host-side exception.

## Crash Reports

```shell
uvx --from . pymobiledevice3 crash ls
uvx --from . pymobiledevice3 crash pull <target-dir>
uvx --from . pymobiledevice3 crash watch
```

## Apps

```shell
uvx --from . pymobiledevice3 apps list
uvx --from . pymobiledevice3 apps query <bundle-id>
```

## Files (media domain via AFC)

```shell
uvx --from . pymobiledevice3 afc ls /
uvx --from . pymobiledevice3 afc pull <device-path> <local-path>
uvx --from . pymobiledevice3 afc push <local-path> <device-path>
```

App containers go through the `apps` group / `house_arrest` service instead of plain AFC.

## Device Info And Processes

```shell
uvx --from . pymobiledevice3 lockdown info
uvx --from . pymobiledevice3 developer dvt sysmon process single
uvx --from . pymobiledevice3 developer dvt sysmon process monitor process --filter name=<name> --key name --key cpuUsage
```
