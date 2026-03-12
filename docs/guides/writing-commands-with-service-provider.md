# Writing Commands with `service_provider`

This guide shows how to add project CLI commands that interact with a device through
`LockdownServiceProvider` (`service_provider` in command handlers).

## 1. Use the standard CLI command pattern

In CLI modules, use `ServiceProviderDep` and `@async_command`:

```python
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, async_command, print_json
from pymobiledevice3.services.installation_proxy import InstallationProxyService

cli = InjectingTyper(name="my-group", no_args_is_help=True)

@cli.command("my-command")
@async_command
async def my_command(service_provider: ServiceProviderDep) -> None:
    result = await InstallationProxyService(lockdown=service_provider).get_apps()
    print_json(result)
```

Why this pattern:

- `ServiceProviderDep` auto-resolves USB, `--rsd`, or `--tunnel` connection modes.
- `@async_command` keeps async handlers ergonomic for Typer commands.

## 2. Prefer service classes over command-local protocol logic

If a command talks to a protocol service, implement/reuse a class under `pymobiledevice3/services/` and call it from CLI.

Typical service wrapper shape:

```python
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.lockdown_service import LockdownService

class ExampleService(LockdownService):
    SERVICE_NAME = "com.apple.example"
    RSD_SERVICE_NAME = "com.apple.example.shim.remote"

    def __init__(self, lockdown: LockdownServiceProvider):
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME)

    async def get_data(self) -> dict:
        await self.service.send_plist({"Command": "GetData"})
        return await self.service.recv_plist()
```

This keeps transport/service-name differences in one place and keeps CLI handlers thin.

## 3. Add command group wiring

If you create a new top-level CLI module (for example `pymobiledevice3/cli/example.py`), add it to `CLI_GROUPS` in:

- `pymobiledevice3/__main__.py`

Example entry:

```python
CLI_GROUPS = {
    ...
    "example": "example",
}
```

If adding commands to an existing group, no `CLI_GROUPS` change is needed.

## 4. Handle long-lived services with context managers

For services that hold sockets/streams, use `async with` in commands:

```python
@cli.command("watch")
@async_command
async def watch(service_provider: ServiceProviderDep) -> None:
    async with ExampleService(service_provider) as svc:
        print_json(await svc.get_data())
```

## 5. Test command behavior with `service_provider` fixture

Integration tests can use the existing fixture from `tests/conftest.py`:

```python
async def test_example(service_provider) -> None:
    async with ExampleService(service_provider) as svc:
        data = await svc.get_data()
        assert "Status" in data
```

The fixture already supports USB, `--rsd`, and `--tunnel` test runs.

## Related references

- CLI dependency wiring:
  [`pymobiledevice3/cli/cli_common.py`](../../pymobiledevice3/cli/cli_common.py)
- Base service wrapper:
  [`pymobiledevice3/services/lockdown_service.py`](../../pymobiledevice3/services/lockdown_service.py)
- Example CLI modules:
  [`pymobiledevice3/cli/apps.py`](../../pymobiledevice3/cli/apps.py),
  [`pymobiledevice3/cli/developer/dvt/__init__.py`](../../pymobiledevice3/cli/developer/dvt/__init__.py)
