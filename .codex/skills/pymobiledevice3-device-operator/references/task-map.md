# Task Map

## Use This File

Read this file when the user asks to do something on-device and you need to map intent to the correct `pymobiledevice3` command group or code entry point.

## Connectivity And Discovery

- `usbmux`: list devices, forward ports, inspect basic connectivity.
- `bonjour`: discover RemoteXPC and related network-visible services.
- `lockdown`: inspect values, pair or unpair, start tunnels, toggle Wi-Fi connections, basic device settings.
- `remote`: remote pairing and tunnel helpers for CoreDevice flows.

Start here when the task is blocked on "find the device", "connect to the device", "`--rsd` details", or "start a tunnel".

For `lockdown start-tunnel` and `remote start-tunnel`, use `--script-mode`, parse the RSD host and port from stdout, and be ready to use `sudo` if tunnel interface creation fails for permission reasons.

## Files, Containers, And App Data

- `afc`: media-domain shell, pull, push, ls, rm.
- `apps`: list/query/install/uninstall apps and work with app AFC/container helpers.
- `crash`: browse, pull, clear, watch crash reports and sysdiagnose artifacts.
- Services to inspect when extending: `services/afc.py`, `services/house_arrest.py`, `services/installation_proxy.py`, `services/crash_reports.py`.

Use these for browsing files, copying artifacts, or handling app containers.

## Device State, Logs, And Diagnostics

- `syslog`: live logs and collection.
- `diagnostics`: restart, shutdown, info, battery-related flows under `pymobiledevice3/cli/diagnostics/`.
- `notification`: observe or post Darwin notifications.
- `pcap`: capture network traffic.
- `power-assertion`: keep the device awake for a task.
- `processes`: process inspection helpers outside full DVT flows.

Use these for observability, troubleshooting, and health checks.

## Apps, Profiles, Provisioning, And Activation

- `apps`: install, uninstall, query.
- `profile`: configuration profile management.
- `provision`: provisioning profile helpers.
- `activation`: activation-related actions.
- `amfi`: Developer Mode enablement.
- `idam`: account/device-association flows when relevant.

Treat most of these as state-changing. Do not run them unless the user clearly asked.

## Backup, Restore, Recovery

- `backup2`: backup, restore, list, encryption and password flows.
- `restore`: recovery, ramdisk, TSS, update, erase, reboot, shell.
- Supporting code: `pymobiledevice3/restore/` and `pymobiledevice3/cli/restore.py`.

These are the highest-risk areas. Ask before destructive actions and prefer inspection first.

## SpringBoard, UI, And Browser Automation

- `springboard`: icon state, orientation, wallpapers, shell.
- `webinspector`: opened tabs, JS shell, launch, automation shell, CDP server.
- `developer wda`: launch/tap/press/unlock/list-items/screenshot/type/swipe/window-size/status.
- Services to inspect: `services/webinspector.py`, `services/web_protocol/*`, `services/wda.py`, `services/springboard.py`.

Use WebInspector for Safari/WebView automation and WDA for device UI automation.

## Developer Services And Instrumentation

- `mounter`: mount developer images.
- `developer dvt`: screenshot, sysmon, process control, oslog, device info, netstat, HAR, energy, location simulation, xcuitest, profiling.
- `developer core-device`: file/process/app/device-info operations through CoreDevice flows.
- `developer debugserver`: debugserver launch and LLDB bridging.
- `developer fetch-symbols`: symbol acquisition.
- `developer accessibility`: audits, settings, notifications, item listing.
- Supporting code: `pymobiledevice3/cli/developer/` and `pymobiledevice3/services/dvt/`.

Read `references/transport-and-safety.md` before using these on iOS 17+.

## When The CLI Is Close But Not Exact

If the user needs a variation that the CLI does not expose:

1. Search the matching service under `pymobiledevice3/services/`.
2. Keep transport logic in `ServiceProviderDep`.
3. Add a thin async CLI wrapper instead of embedding protocol logic in the command handler.
4. Reuse existing patterns from `docs/guides/writing-commands-with-service-provider.md`.
