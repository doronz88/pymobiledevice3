# Quick Recipes

## Use This File

Read this file for the exact invocation of the most common device tasks. Commands are
shown for a repository checkout (`uvx --from . pymobiledevice3`); on a workstation
without one, drop the `--from .` so `uvx` fetches the PyPI release. On iOS 17.4+ the
`developer` commands establish a no-root userspace tunnel automatically, so run them
as-is — no `sudo`, no tunnel setup.

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

## Trace What The System Is Doing (strace-like)

When the syslog does not explain it, trace the syscalls and system library events of every
process, Apple's daemons included, live and decoded: paths, arguments, errnos. No jailbreak and no
change to the traced processes. Reproduce the failure while tracing:

```shell
# Every syscall of every process; keeps pace with the device even while apps launch
uvx --from . pymobiledevice3 developer dvt core-profile-session parse-live --bsc

# One process, the syscalls that take a path: which file does it fail to open (errno: ENOENT)?
uvx --from . pymobiledevice3 developer dvt core-profile-session parse-live --fs --process <name-or-pid>

# Who talks to whom: XPC messages and transactions (also --dispatch, --runloop, --dyld)
uvx --from . pymobiledevice3 developer dvt core-profile-session parse-live --xpc --process <name>

# One syscall (with its _nocancel variant), or one event by its trace code name
uvx --from . pymobiledevice3 developer dvt core-profile-session parse-live -s open -s openat
uvx --from . pymobiledevice3 developer dvt core-profile-session events dlsym    # finds the name
uvx --from . pymobiledevice3 developer dvt core-profile-session parse-live -e DBG_DYLD_TIMING_DLSYM
```

Groups (`--fs`, `--net`, `--proc`, `--io`, `--mem`, `--signal`, `--cred`, `--sync`, `--mach`,
`--dyld`, `--xpc`, `--dispatch`, `--runloop`), `-s` and `-e` add up. `events` takes the same options
and lists exactly what will be captured (`events --fs`, `events -s open`), before you trace. Add `--json` for one JSON object per trace, and `-c N` to stop after N traces.
Without any filter the output falls behind and fails once it is `--max-lag` (2s) behind; narrow the
trace, or pass `--skip-behind` to skip ahead instead (with a `Skipped N events` warning on stderr).
On exit, stderr tells whether it kept up: `Read N events, the kernel dropped events N times, N events
were skipped to catch up`. What a trace contains:
`docs/guides/kdebug.md`.

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
