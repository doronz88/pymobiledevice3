"""MkDocs hook that generates a full CLI reference from the Typer command tree.

At build time the hook imports every CLI group registered in
``pymobiledevice3.__main__.CLI_GROUPS``, walks the resulting command tree, and emits one
generated page per group under ``cli/`` plus an index page. The pages are produced from the
same objects that power ``--help``, so the reference can never drift from the code.

The connection options injected into every device-facing command (``--rsd``, ``--tunnel``,
``--userspace``, ...) are documented once on the index page; each command lists which of them
it accepts instead of repeating the full descriptions.

The click command objects are introspected through their public attributes only
(``commands``, ``params``, ``get_help_record``, ...) — no ``click``/``typer._click`` import,
per the repository convention.
"""

from __future__ import annotations

import importlib
from typing import Any, Optional

from mkdocs.exceptions import PluginError
from mkdocs.structure.files import File

# Long-form flags of the options injected by cli_common's service-provider dependencies.
# They are shared by (nearly) every device-facing command, so their full descriptions live
# once on the index page and each command only lists which of them it accepts.
CONNECTION_FLAGS = ("--rsd", "--tunnel", "--userspace", "--mobdev2", "--usbmux", "--udid")

INDEX_URI = "cli/index.md"


def _escape_cell(text: str) -> str:
    """Make an arbitrary help string safe inside a one-line Markdown table cell."""
    return " ".join(text.split()).replace("|", "\\|")


def _connection_flag(param: Any) -> Optional[str]:
    """Return the connection flag this option represents, or None for regular params."""
    for opt in getattr(param, "opts", []):
        if opt in CONNECTION_FLAGS:
            return opt
    return None


def _help_records(cmd: Any, ctx: Any) -> tuple[list[tuple[str, str]], list[tuple[str, str]], list[str]]:
    """Split a command's params into (argument records, option records, connection flags)."""
    arguments: list[tuple[str, str]] = []
    options: list[tuple[str, str]] = []
    connection: list[str] = []
    for param in cmd.params:
        if getattr(param, "hidden", False):
            continue
        flag = _connection_flag(param)
        if flag is not None:
            connection.append(flag)
            continue
        record = param.get_help_record(ctx)
        if record is None:
            continue
        if param.param_type_name == "argument":
            arguments.append(record)
        else:
            options.append(record)
    return arguments, options, connection


def _records_table(title: str, records: list[tuple[str, str]]) -> list[str]:
    if not records:
        return []
    lines = [f"**{title}:**", "", f"| {title[:-1]} | Description |", "| --- | --- |"]
    for name, help_text in records:
        lines.append(f"| `{_escape_cell(name)}` | {_escape_cell(help_text)} |")
    lines.append("")
    return lines


def _usage_line(cmd: Any, ctx: Any) -> str:
    pieces = " ".join(cmd.collect_usage_pieces(ctx))
    return f"{ctx.command_path} {pieces}".rstrip()


def _walk(cmd: Any, ctx: Any, group_name: str, out: list[str]) -> None:
    """Emit the section for ``cmd`` and recurse into its subcommands."""
    # Heading: the command path relative to the group page's H1.
    relative = ctx.command_path.replace(f"pymobiledevice3 {group_name}", "").strip()
    if relative:
        deprecated = " *(deprecated)*" if getattr(cmd, "deprecated", False) else ""
        out.append(f"## `{relative}`{deprecated}")
        out.append("")

    help_text = (cmd.help or cmd.short_help or "").strip()
    if help_text:
        out.append(help_text)
        out.append("")

    subcommands = getattr(cmd, "commands", None)
    if subcommands is None:
        out.append("```text")
        out.append(_usage_line(cmd, ctx))
        out.append("```")
        out.append("")
        arguments, options, connection = _help_records(cmd, ctx)
        out.extend(_records_table("Arguments", arguments))
        out.extend(_records_table("Options", options))
        if connection:
            flags = ", ".join(f"`{f}`" for f in connection)
            out.append(f"Accepts the [connection options](index.md#connection-options): {flags}.")
            out.append("")
        return

    for sub in subcommands.values():
        if getattr(sub, "hidden", False):
            continue
        sub_ctx = sub.context_class(sub, info_name=sub.name, parent=ctx)
        _walk(sub, sub_ctx, group_name, out)


def _summary(cmd: Any) -> str:
    text = (cmd.short_help or cmd.help or "").strip()
    return text.splitlines()[0] if text else ""


def _load_group_commands() -> dict[str, Any]:
    import typer

    from pymobiledevice3.__main__ import CLI_GROUPS

    groups: dict[str, Any] = {}
    for name, module_name in CLI_GROUPS.items():
        mod = importlib.import_module(f"pymobiledevice3.cli.{module_name}")
        groups[name] = typer.main.get_command(mod.cli)
    return groups


def _connection_records(groups: dict[str, Any]) -> list[tuple[str, str]]:
    """Harvest one help record per connection flag from the first command carrying it."""
    records: dict[str, tuple[str, str]] = {}
    stack = list(groups.values())
    while stack and len(records) < len(CONNECTION_FLAGS):
        cmd = stack.pop()
        stack.extend(getattr(cmd, "commands", {}).values())
        ctx = cmd.context_class(cmd, info_name=cmd.name)
        for param in cmd.params:
            flag = _connection_flag(param)
            if flag is None or flag in records:
                continue
            record = param.get_help_record(ctx)
            if record is not None:
                records[flag] = record
    return [records[flag] for flag in CONNECTION_FLAGS if flag in records]


def _index_page(groups: dict[str, Any]) -> str:
    out = [
        "---",
        "search:",
        "  boost: 0.5",
        "---",
        "",
        "# CLI Reference",
        "",
        "Complete reference for every `pymobiledevice3` command, generated from the CLI itself",
        "at build time. For task-oriented examples see the",
        "[CLI recipes](../guides/cli-recipes.md).",
        "",
        "## Command groups",
        "",
        "| Group | Description |",
        "| --- | --- |",
    ]
    for name, cmd in groups.items():
        out.append(f"| [`{name}`]({name}.md) | {_escape_cell(_summary(cmd))} |")
    out += [
        "",
        "## Connection options",
        "",
        "Device-facing commands accept a shared set of options selecting the target device and",
        "transport. Each command's page lists which of them it accepts.",
        "",
        "| Option | Description |",
        "| --- | --- |",
    ]
    for name, help_text in _connection_records(groups):
        out.append(f"| `{_escape_cell(name)}` | {_escape_cell(help_text)} |")
    out += [
        "",
        "See [iOS 17+ tunnels](../guides/ios17-tunnels.md) for when a tunnel (`--rsd`/`--tunnel`/",
        "`--userspace`) is required and how the no-root userspace default works.",
        "",
    ]
    return "\n".join(out)


def _group_page(name: str, cmd: Any) -> str:
    out = [
        "---",
        "search:",
        "  boost: 0.5",
        "---",
        "",
        f"# `pymobiledevice3 {name}`",
        "",
    ]
    ctx = cmd.context_class(cmd, info_name=f"pymobiledevice3 {name}")
    _walk(cmd, ctx, name, out)
    return "\n".join(out)


def _nav_uris(nav: Any) -> set[str]:
    """Collect every page URI referenced by the (raw, pre-resolution) nav config."""
    uris: set[str] = set()
    items = list(nav or [])
    while items:
        item = items.pop()
        if isinstance(item, str):
            uris.add(item)
        elif isinstance(item, dict):
            items.extend(item.values())
        elif isinstance(item, list):
            items.extend(item)
    return uris


def on_files(files, config):
    groups = _load_group_commands()

    nav_uris = _nav_uris(config["nav"])
    missing = [name for name in groups if f"cli/{name}.md" not in nav_uris]
    if missing or INDEX_URI not in nav_uris:
        raise PluginError(
            "mkdocs.yml nav is missing CLI reference pages for: "
            f"{missing or [INDEX_URI]}. Update the 'CLI Reference' nav section to match "
            "CLI_GROUPS in pymobiledevice3/__main__.py."
        )

    files.append(File.generated(config, INDEX_URI, content=_index_page(groups)))
    for name, cmd in groups.items():
        files.append(File.generated(config, f"cli/{name}.md", content=_group_page(name, cmd)))
    return files
