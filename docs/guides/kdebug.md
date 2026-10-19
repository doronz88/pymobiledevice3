# Tracing with kdebug

kdebug is the kernel's event tracing facility: the kernel and many system libraries record
fixed-size events into it, and a trace session collects them from every process at once. It needs
no entitlement, no jailbreak and no change to the traced processes, so it is the main way to watch
what platform binaries (daemons, SpringBoard, Apple's apps) do on a stock device.

`pymobiledevice3 developer dvt core-profile-session` drives the same trace sessions as Instruments.
See [CLI recipes](cli-recipes.md) for the commands; this guide covers what is in a trace and how to
get at it.

## Commands

| Command | Prints |
| --- | --- |
| `parse-live` | Decoded traces (strace-like): syscalls with their arguments and paths, dyld image loads, process and thread lifecycle. Selects events by group and name (`--fs`, `--xpc`, `-s`, `-e`, ...; see below). |
| `live` | Every raw event: time, event name, start/end, thread, process and the four raw arguments. Selects events by class and subclass. |
| `callstacks-live` | User space call stacks sampled from the running threads. |
| `save` | The raw trace, to parse later. |
| `stackshot` | The call stacks of every thread of every process, once. |

## Event ids

Every event is a 32-bit debugid:

```text
| class (8) | subclass (8) | code (14) | function (2) |
```

The class names the component (`0x04` BSD, `0x29` XPC, ...), the subclass a part of it, and the
function bits mark whether the event starts (`1`) or ends (`2`) an interval. The eventid is the
debugid without the function bits, and is what trace codes name (`0x29000044` is
`XPC_connection_send_message`).

`live` filters on the device by class (`-cf 0x29`) and by class and subclass together
(`-sf 0x0301`, the class in the high byte), which also keeps the device from sending what is
filtered out:

```shell
# XPC and libdispatch events of every process
pymobiledevice3 developer dvt core-profile-session live -cf 0x29 -cf 0x2e

# file lookups only (VFS_LOOKUP lives in class 0x03, subclass 0x01)
pymobiledevice3 developer dvt core-profile-session live -sf 0x0301
```

## Selecting events in parse-live

| Option | Selects |
| --- | --- |
| `--fs`, `--net`, `--proc`, `--io`, `--mem`, `--signal`, `--cred`, `--sync`, `--mach` | A group of syscalls and Mach traps |
| `--dyld` | dyld image loads and timing (`dlopen`, `dlsym`, ...) |
| `--xpc`, `--dispatch`, `--runloop` | The XPC, libdispatch and CoreFoundation run loop events of every process, printed as their name and raw arguments |
| `-s NAME` | One syscall, with its `_nocancel` variant (`-s open`) |
| `-e NAME` | One event, by its trace code name (`-e DBG_DYLD_TIMING_DLSYM`) |

They all add up, and `--process` narrows the result to one process. The device filters by subclass
at best, so the host drops the rest right after decoding. `events` takes the same options and lists
exactly the events `parse-live` prints with them (`events --fs`, `events -s open`), and
`events dlsym` finds a name by text. A class or subclass filter (`--bsc`, `-cf`, `-sf`, `--dyld`)
prints only the events pykdebugparser decodes: `events -cf 0x29` lists nothing, while `--xpc`
selects the same XPC events by id.

```shell
# the XPC traffic of SpringBoard
pymobiledevice3 developer dvt core-profile-session parse-live --xpc --process SpringBoard

# every dlsym, in every process
pymobiledevice3 developer dvt core-profile-session events dlsym
pymobiledevice3 developer dvt core-profile-session parse-live -e DBG_DYLD_TIMING_DLSYM
```

## Events every process emits

These are recorded by the kernel or by system libraries in every process, gated only by the trace
session's class filter. They were all seen in traces of an iPhone on iOS 27.2.

| Class | Source | Events | What they show |
| --- | --- | --- | --- |
| `0x03` | kernel | `VFS_LOOKUP` | The full path of every file lookup, in every process |
| `0x04` | kernel | BSD syscalls | Every syscall with its arguments (`parse-live` decodes them) |
| `0x07` | kernel | thread and process lifecycle | New threads, execs and thread names |
| `0x1f` | dyld | image map (`DYLD_uuid_map_a/b`) and timing | The UUID and load address of every image of every process, and dyld's launch phases |
| `0x29` | libxpc | `XPC_*` | Messages sent and received, transactions, the process becoming dirty or clean |
| `0x2e` | libdispatch | `DISPATCH_MACH_MSG_hdr_move`, `DISPATCH_PERF_*` | Mach messages received through dispatch, queue misuse |
| `0x21`, `0x14` | CoreFoundation | `CFRL_*` | Run loop iterations, waits, sources, timers, observers and blocks |

The XPC events carry a per-connection id and the message size (on the end of a send), not the
service name. The run loop events show when a main thread is busy and with what kind of callout,
which helps find hangs.

`callstacks-live` samples user space call stacks of the same processes. It prints them as raw
addresses; the dyld image map above tells which image each one falls in.

## Events that need a setting

Some system libraries emit events only when a setting enables them, on top of the trace's class
filter.

| Class | Source | Enabled by |
| --- | --- | --- |
| `0x33` | libsystem_malloc: every `malloc`, `calloc`, `realloc`, `free` (zone, size, pointer) | The `MallocTracing` environment variable, read when the process starts |
| `0x2b` (subclasses `0x1d`, `0x13`, `0x29`) | Network.framework, libquic, CFNetwork and BoringSSL: connections, TLS handshakes, QUIC packet protection | networkd's `enable_signposts` setting, which only networkd's privileged clients can set |

`MallocTracing` can be passed to apps, including Apple's own, by launching them through
pymobiledevice3:

```shell
pymobiledevice3 developer dvt launch --kill-existing --env MallocTracing=1 com.apple.Preferences
pymobiledevice3 developer dvt core-profile-session live -cf 0x33
```

Launching only works for apps. Daemons and SpringBoard are started by launchd with launchd's
environment, so there is no way to pass them `MallocTracing` on a stock device. CoreDevice can
spawn arbitrary executables with an environment, but only on Apple internal builds.

## What kdebug does not show

- Mach message send and receive in the kernel (`MACH_IPC_msg_send`/`_recv`): the iOS 27.2 release
  kernel does not emit them. The XPC and libdispatch events cover most of that traffic from user space.
- Message contents, XPC service names and TLS plaintext: no event carries them.
