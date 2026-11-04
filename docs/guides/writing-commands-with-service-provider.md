# Writing Commands with `service_provider`

This guide shows how to add a CLI command to pymobiledevice3 that talks to a device. Commands
receive a `LockdownServiceProvider` (the `service_provider` parameter) by dependency injection,
so the handler never deals with how the device is reached.

Work from an editable checkout (see [Installation: From source](../installation.md#from-source)),
and read the repository's [agent and contributor guidance](../project/agents.md) for the
conventions summarized here. For the library side (service providers and services), see the
[Python API](python-api.md) guide.

## 1. Use the standard CLI command pattern

CLI modules are [Typer](https://typer.tiangolo.com/) apps built with `InjectingTyper`. Declare the
device as a `ServiceProviderDep` parameter and decorate async handlers with `@async_command`:

```python
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, async_command, print_json
from pymobiledevice3.services.installation_proxy import InstallationProxyService

cli = InjectingTyper(name="my-group", help="Example commands.", no_args_is_help=True)


@cli.command("my-command")
@async_command
async def my_command(service_provider: ServiceProviderDep) -> None:
    """List installed apps."""
    async with InstallationProxyService(service_provider) as installation_proxy:
        print_json(await installation_proxy.get_apps())
```

Why this pattern:

- `ServiceProviderDep` adds the standard device options (`--udid`, `--rsd`, `--tunnel`,
  `--userspace`, `--native`, `--mobdev2`, `--usbmux`) and resolves them into a connected
  provider: a lockdown client over USB by default, or an RSD when a tunnel option is given.
- Use `RSDServiceProviderDep` instead when the command only works over an iOS 17+ RSD tunnel;
  with no transport flag it establishes a no-root tunnel automatically.
- `@async_command` runs the coroutine on the CLI's event loop and turns Ctrl-C into a clean exit.
- Never import `click` in package code; stay on Typer's public API (`typer.Option`,
  `typer.Argument`, `typer.BadParameter`, `typer.Exit`, ...).

## 2. Put protocol logic in a service class

Device-facing logic belongs in a service class under `pymobiledevice3/services/`; the CLI handler
only calls it. Reuse an existing service when one covers the protocol.

A typical service wrapper:

```python
from pymobiledevice3.services.lockdown_service import LockdownService


class ExampleService(LockdownService):
    SERVICE_NAME = "com.apple.example"
    RSD_SERVICE_NAME = "com.apple.example.shim.remote"

    async def get_data(self) -> dict:
        return await self.service.send_recv_plist({"Command": "GetData"})
```

`LockdownService` picks `SERVICE_NAME` when given a `LockdownClient` and `RSD_SERVICE_NAME` when
given an RSD, so transport differences stay in one place. The connection opens on first use or on
entering `async with`.

## 3. Register a new command group

Adding commands to an existing group needs no extra wiring. For a new top-level module (for example
`pymobiledevice3/cli/example.py`, exposing a module-level `cli`), add it to `CLI_GROUPS` in
`pymobiledevice3/__main__.py`, mapping the command name to the module name:

```python
CLI_GROUPS = {
    ...
    "example": "example",
}
```

## 4. Use `async with` for service connections

Services hold sockets, so open them with `async with` in the handler. They are closed when the
command finishes, including on errors or Ctrl-C:

```python
@cli.command("watch")
@async_command
async def watch(service_provider: ServiceProviderDep) -> None:
    async with ExampleService(service_provider) as svc:
        print_json(await svc.get_data())
```

## 5. Test against a device with the `service_provider` fixture

Integration tests can use the `service_provider` fixture from `tests/conftest.py`. Tests run
under `asyncio_mode = auto`, so plain `async def` tests need no marker:

```python
from pymobiledevice3.services.example import ExampleService


async def test_example(service_provider) -> None:
    async with ExampleService(service_provider) as svc:
        data = await svc.get_data()
        assert "Status" in data
```

The fixture uses the first USB device by default; pass `--udid <UDID>`, `--rsd HOST PORT`, or
`--tunnel <UDID>` to `pytest` to target a specific device or transport.

## Related references

- CLI dependency wiring:
  [`pymobiledevice3/cli/cli_common.py`](https://github.com/doronz88/pymobiledevice3/blob/master/pymobiledevice3/cli/cli_common.py)
- Base service wrapper:
  [`pymobiledevice3/services/lockdown_service.py`](https://github.com/doronz88/pymobiledevice3/blob/master/pymobiledevice3/services/lockdown_service.py)
- Example CLI modules:
  [`pymobiledevice3/cli/apps.py`](https://github.com/doronz88/pymobiledevice3/blob/master/pymobiledevice3/cli/apps.py),
  [`pymobiledevice3/cli/developer/dvt/__init__.py`](https://github.com/doronz88/pymobiledevice3/blob/master/pymobiledevice3/cli/developer/dvt/__init__.py)
