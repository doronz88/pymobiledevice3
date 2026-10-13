import argparse
import asyncio
import os
import pathlib
import shutil
import sys
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Annotated, Any, Optional

import pytest
from prompt_toolkit.application import create_app_session
from prompt_toolkit.completion import CompleteEvent
from prompt_toolkit.document import Document
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput

from pymobiledevice3.interactive_shell import (
    Arg,
    CompletionContext,
    InteractiveShell,
    Pipeline,
    ShellCompleter,
    ShellSyntaxError,
    build_parser,
    parse_line,
    quote_word,
    shell_command,
)

UPPER = "import sys; sys.stdout.write(sys.stdin.read().upper())"
FIRST_LINE = "import sys; sys.stdout.write(sys.stdin.readline())"
SLEEP = "import time; time.sleep(60)"


def fruit_completer(context: CompletionContext) -> list[str]:
    return ["apple", "apricot", "banana", "blood orange", "dir/"]


Fruit = Annotated[str, Arg(completer=fruit_completer)]


def broken_completer(context: CompletionContext) -> list[str]:
    raise OSError("device went away")


async def async_fruit_completer(context: CompletionContext) -> list[str]:
    await asyncio.sleep(0)
    return [f"{context.prefix}-berry"]


def _out(capfd: pytest.CaptureFixture[str]) -> str:
    """Captured stdout, with the line endings Windows host processes write normalized."""
    return capfd.readouterr().out.replace("\r\n", "\n")


PYTHON = pathlib.Path(sys.executable).name


@pytest.fixture
def python_on_path(monkeypatch: pytest.MonkeyPatch) -> str:
    """Make the running interpreter findable by name, and return that name."""
    monkeypatch.setenv("PATH", str(pathlib.Path(sys.executable).parent), prepend=os.pathsep)
    return PYTHON


class DemoShell(InteractiveShell):
    def __init__(self, host_tools: Iterable[str] = ()) -> None:
        super().__init__(host_tools)
        # the tests spell command lines the POSIX way wherever they run
        self.escape = True
        self.calls: list[Any] = []
        self.register_host_command("py", sys.executable)
        self.register_host_command("missing", "/nonexistent/pymobiledevice3-tool")

    @shell_command(raw=True)
    def _do_raw(self, args: list[str]) -> None:
        print("raw:" + ",".join(args))

    @shell_command(raw=True, completer=fruit_completer)
    def _do_rawfruit(self, args: list[str]) -> None:
        pass

    @shell_command(raw=True, completer=broken_completer)
    def _do_fragile(self, args: list[str]) -> None:
        pass

    @shell_command
    def _do_echo(self, words: Annotated[list[str], Arg(nargs="*")]) -> None:
        """
        Print the given words.

        Separated by single spaces, whatever the original spacing was.

        :param words: The words to print
        """
        self.calls.append(words)
        print(" ".join(words))

    @shell_command
    def _do_boom(self) -> None:
        raise ValueError("kaboom")

    @shell_command
    def _do_flood(self) -> None:
        while True:
            print("line")

    @shell_command
    def _do_eat(self, fruit: Fruit) -> None:
        print(f"ate {fruit}")

    @shell_command
    def _do_eat_all(self, fruits: list[Fruit], *, loudly: bool = False) -> None:
        print(("ATE " if loudly else "ate ") + ", ".join(fruits))

    @shell_command
    def _do_copy(self, local: str, fruit: Fruit) -> None:
        print(f"{local} -> {fruit}")

    @shell_command
    async def _do_later(self, word: str) -> None:
        await asyncio.sleep(0)
        print(word)

    @shell_command
    async def _do_nap(self) -> None:
        await asyncio.sleep(60)

    @shell_command
    async def _do_pick(self, fruit: Annotated[str, Arg(completer=async_fruit_completer)]) -> None:
        pass


class ExtendedShell(DemoShell):
    HOST_COMMANDS = ("pymobiledevice3-no-such-tool", PYTHON)

    @shell_command
    def _do_two_words(self) -> None:
        print("derived name")

    @shell_command(name="renamed")
    def _do_something_else(self) -> None:
        print("explicit name")

    @shell_command
    def _do_boom(self) -> None:
        print("defused")

    def _do_unmarked(self) -> None:
        pass


async def test_decorated_methods_become_commands_in_definition_order(capfd: pytest.CaptureFixture[str]) -> None:
    assert DemoShell().command_names() == [
        "help",
        "exit",
        "raw",
        "rawfruit",
        "fragile",
        "echo",
        "boom",
        "flood",
        "eat",
        "eat-all",
        "copy",
        "later",
        "nap",
        "pick",
        "py",
        "missing",
    ]


async def test_subclass_adds_renames_and_overrides_commands(
    capfd: pytest.CaptureFixture[str], python_on_path: str
) -> None:
    shell = ExtendedShell()
    names = shell.command_names()
    assert "two-words" in names
    assert "renamed" in names
    assert "something-else" not in names
    assert "unmarked" not in names
    assert names.count("boom") == 1
    assert await shell.run_line("two-words && renamed && boom && echo inherited") == 0
    assert _out(capfd) == "derived name\nexplicit name\ndefused\ninherited\n"
    # only the host tools that exist are offered
    assert shell.get_command(python_on_path) == shutil.which(python_on_path)
    assert shell.get_command("pymobiledevice3-no-such-tool") is None


async def test_help_lists_every_command_with_its_summary(capfd: pytest.CaptureFixture[str]) -> None:
    shell = DemoShell()
    assert await shell.run_line("help") == 0
    out = _out(capfd)
    lines = out.splitlines()
    assert any(line.split() == ["echo", "Print", "the", "given", "words."] for line in lines)
    assert any(line.split()[:1] == ["help"] for line in lines)
    assert any(line.split()[:1] == ["exit"] for line in lines)
    # commands without a docstring are still listed
    assert any(line.split() == ["boom"] for line in lines)
    # host tools are listed apart from the shell's own commands, with how to use them
    heading = next(index for index, line in enumerate(lines) if line.startswith("Host tools"))
    assert "|" in lines[heading]
    assert lines[heading + 1].replace(",", " ").split() == ["missing", "py"]
    assert "help COMMAND" in out


async def test_help_for_one_command_shows_usage_and_parameters(capfd: pytest.CaptureFixture[str]) -> None:
    shell = DemoShell()
    assert await shell.run_line("help echo") == 0
    out = _out(capfd)
    assert "usage: echo" in out
    assert "Print the given words." in out
    assert "The words to print" in out
    assert await shell.run_line("echo -h") == 0
    assert _out(capfd) == out
    assert await shell.run_line("help eat-all") == 0
    assert "--loudly" in _out(capfd)


async def test_help_for_raw_host_and_unknown_commands(capfd: pytest.CaptureFixture[str]) -> None:
    shell = DemoShell()
    assert await shell.run_line("help py") == 0
    assert sys.executable in _out(capfd)
    assert await shell.run_line("help rawfruit") == 0
    assert "rawfruit" in _out(capfd)
    assert await shell.run_line("help nope") == 1
    assert "nope: command not found" in capfd.readouterr().err


async def test_unknown_command_suggests_a_close_match(capfd: pytest.CaptureFixture[str]) -> None:
    shell = DemoShell()
    assert await shell.run_line("ech hello") == 127
    err = capfd.readouterr().err
    assert "ech: command not found" in err
    assert "echo" in err
    assert await shell.run_line("zzzzzz") == 127
    assert "help" in capfd.readouterr().err


async def test_exit_stops_the_rest_of_the_line(capfd: pytest.CaptureFixture[str]) -> None:
    shell = DemoShell()
    with create_pipe_input() as pipe_input, create_app_session(input=pipe_input, output=DummyOutput()):
        pipe_input.send_text("echo one ; exit ; echo two\recho three\r")
        await asyncio.wait_for(shell.interact(), timeout=30)
    assert _out(capfd) == "one\n"


async def test_extra_host_tools_can_be_requested_by_name(
    capfd: pytest.CaptureFixture[str], python_on_path: str
) -> None:
    shell = DemoShell(host_tools=[python_on_path])
    assert shell.get_command(python_on_path) == shutil.which(python_on_path)
    assert await shell.run_line(f'echo hello | {python_on_path} -c "{UPPER}"') == 0
    assert _out(capfd) == "HELLO\n"
    with pytest.raises(ValueError, match="pymobiledevice3-no-such-tool"):
        DemoShell(host_tools=["pymobiledevice3-no-such-tool"])


async def test_bang_runs_any_host_command(capfd: pytest.CaptureFixture[str], python_on_path: str) -> None:
    shell = DemoShell()
    assert shell.get_command(python_on_path) is None
    assert await shell.run_line(f'echo hello | !{python_on_path} -c "{UPPER}"') == 0
    assert _out(capfd) == "HELLO\n"
    # also on its own, where it wins over a shell command of the same name
    assert await shell.run_line(f'!{python_on_path} -c "print(40 + 2)"') == 0
    assert _out(capfd) == "42\n"
    assert await shell.run_line("!pymobiledevice3-no-such-tool") == 127
    assert "pymobiledevice3-no-such-tool: command not found" in capfd.readouterr().err
    assert await shell.run_line("help") == 0
    assert "!TOOL" in _out(capfd)


async def test_register_command_adds_one_at_runtime(capfd: pytest.CaptureFixture[str]) -> None:
    shell = DemoShell()

    async def greet(name: str) -> None:
        print(f"hi {name}")

    shell.register_command("greet", greet)
    assert await shell.run_line("greet you") == 0
    assert _out(capfd) == "hi you\n"


def test_parse_line_splits_pipes_redirects_and_connectors() -> None:
    assert parse_line("cat a.txt | grep 'x y' | wc -l > out.txt") == [
        ("", Pipeline(stages=[["cat", "a.txt"], ["grep", "x y"], ["wc", "-l"]], redirect="out.txt", append=False))
    ]
    assert parse_line("a && b || c ; d >> log") == [
        ("", Pipeline(stages=[["a"]])),
        ("&&", Pipeline(stages=[["b"]])),
        ("||", Pipeline(stages=[["c"]])),
        (";", Pipeline(stages=[["d"]], redirect="log", append=True)),
    ]
    assert parse_line("   ") == []


def test_parse_line_keeps_operators_inside_quotes_literal() -> None:
    assert parse_line("echo \"a | b\" 'c > d'") == [("", Pipeline(stages=[["echo", "a | b", "c > d"]]))]


def test_parse_line_without_escape_keeps_backslashes() -> None:
    assert parse_line(r"pull a C:\Users\me", escape=False) == [("", Pipeline(stages=[["pull", "a", r"C:\Users\me"]]))]
    assert parse_line(r"cat my\ file") == [("", Pipeline(stages=[["cat", "my file"]]))]


@pytest.mark.parametrize("line", ["a |", "| a", "a > ", "a < b", "a & b", 'a "unterminated', "a && ", "a > b c"])
def test_parse_line_rejects_bad_syntax(line: str) -> None:
    with pytest.raises(ShellSyntaxError):
        parse_line(line)


def test_build_parser_maps_signature_to_arguments() -> None:
    def handler(
        remote: Fruit,
        local: str,
        files: list[Fruit],
        *,
        force: Annotated[bool, Arg("-f")] = False,
        dry_run: bool = False,
        match: Annotated[Optional[list[str]], Arg("-m")] = None,
        count: Annotated[int, Arg("-n")] = 1,
    ) -> None:
        """Do the thing.

        :param remote: ignored detail
        """

    parser = build_parser("thing", handler)
    assert isinstance(parser, argparse.ArgumentParser)
    assert parser.prog == "thing"
    assert parser.description == "Do the thing."
    assert vars(parser.parse_args(["r", "l", "x", "y", "-f", "-m", "a", "--match", "b", "-n", "3"])) == {
        "remote": "r",
        "local": "l",
        "files": ["x", "y"],
        "force": True,
        "dry_run": False,
        "match": ["a", "b"],
        "count": 3,
    }
    assert vars(parser.parse_args(["r", "l", "x", "--dry-run", "--count", "2"])) == {
        "remote": "r",
        "local": "l",
        "files": ["x"],
        "force": False,
        "dry_run": True,
        "match": None,
        "count": 2,
    }
    # a positional list needs at least one item
    with pytest.raises(SystemExit):
        parser.parse_args(["r", "l"])


def test_build_parser_positional_with_default_is_optional() -> None:
    def handler(path: Fruit = "/", *, mode: str = "fast") -> None:
        pass

    parser = build_parser("thing", handler)
    assert vars(parser.parse_args([])) == {"path": "/", "mode": "fast"}
    assert vars(parser.parse_args(["x", "--mode", "slow"])) == {"path": "x", "mode": "slow"}


def test_build_parser_keyword_only_without_default_is_required() -> None:
    def handler(*, target: str) -> None:
        pass

    parser = build_parser("thing", handler)
    assert vars(parser.parse_args(["--target", "x"])) == {"target": "x"}
    with pytest.raises(SystemExit):
        parser.parse_args([])


def test_build_parser_passes_extra_argparse_options_through() -> None:
    def handler(
        words: Annotated[list[str], Arg(nargs="*")], *, level: Annotated[str, Arg(choices=["a", "b"])] = "a"
    ) -> None:
        pass

    parser = build_parser("thing", handler)
    assert vars(parser.parse_args([])) == {"words": [], "level": "a"}
    with pytest.raises(SystemExit):
        parser.parse_args(["--level", "z"])


async def test_builtin_output_goes_to_stdout(capfd: pytest.CaptureFixture[str]) -> None:
    shell = DemoShell()
    assert await shell.run_line("echo hello 'big world'") == 0
    assert _out(capfd) == "hello big world\n"
    assert shell.calls == [["hello", "big world"]]


async def test_async_handlers_are_awaited(capfd: pytest.CaptureFixture[str]) -> None:
    shell = DemoShell()
    assert await shell.run_line(f'later hello | py -c "{UPPER}" && later done') == 0
    assert _out(capfd) == "HELLO\ndone\n"


async def test_interrupt_cancels_an_async_handler(capfd: pytest.CaptureFixture[str]) -> None:
    shell = DemoShell()
    task = asyncio.create_task(shell.run_line("nap ; echo unreachable"))
    await asyncio.sleep(0.2)
    shell.interrupt()
    assert await asyncio.wait_for(task, timeout=30) == 130
    assert shell.last_status == 130
    assert await shell.run_line("echo alive") == 0
    assert _out(capfd) == "alive\n"


async def test_cancelling_run_line_itself_propagates() -> None:
    shell = DemoShell()
    task = asyncio.create_task(shell.run_line("nap"))
    await asyncio.sleep(0.2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_list_and_keyword_only_parameters(capfd: pytest.CaptureFixture[str]) -> None:
    shell = DemoShell()
    assert await shell.run_line("eat-all apple banana --loudly && eat-all dir/") == 0
    assert _out(capfd) == "ATE apple, banana\nate dir/\n"


async def test_raw_command_receives_unparsed_args(capfd: pytest.CaptureFixture[str]) -> None:
    assert await DemoShell().run_line("raw -l x") == 0
    assert _out(capfd) == "raw:-l,x\n"


async def test_builtin_pipes_into_host_commands(capfd: pytest.CaptureFixture[str]) -> None:
    shell = DemoShell()
    assert await shell.run_line(f'echo hello | py -c "{UPPER}" | py -c "{UPPER}"') == 0
    assert _out(capfd) == "HELLO\n"


async def test_redirect_writes_and_appends_local_file(tmp_path: Path, capfd: pytest.CaptureFixture[str]) -> None:
    shell = DemoShell()
    out = tmp_path / "out file.txt"
    assert await shell.run_line(f"echo one > '{out}'") == 0
    assert await shell.run_line(f"echo two | py -c \"{UPPER}\" >> '{out}'") == 0
    assert out.read_text() == "one\nTWO\n"
    assert _out(capfd) == ""


async def test_exit_status_comes_from_last_stage(capfd: pytest.CaptureFixture[str]) -> None:
    shell = DemoShell()
    assert await shell.run_line('echo x | py -c "import sys; sys.exit(3)"') == 3
    assert shell.last_status == 3


async def test_connectors_short_circuit(capfd: pytest.CaptureFixture[str]) -> None:
    shell = DemoShell()
    assert await shell.run_line("boom && echo skipped ; boom || echo recovered ; echo a && echo b") == 0
    captured = capfd.readouterr()
    assert captured.out == "recovered\na\nb\n"
    assert captured.err.count("kaboom") == 2


async def test_handler_exception_is_reported_not_raised(capfd: pytest.CaptureFixture[str]) -> None:
    shell = DemoShell()
    assert await shell.run_line("boom") == 1
    assert "boom: kaboom" in capfd.readouterr().err


async def test_unknown_command_and_syntax_error(capfd: pytest.CaptureFixture[str]) -> None:
    shell = DemoShell()
    assert await shell.run_line("nope") == 127
    assert "nope: command not found" in capfd.readouterr().err
    assert await shell.run_line("echo a |") == 2
    assert "syntax error" in capfd.readouterr().err


async def test_bad_arguments_and_help_do_not_exit_the_shell(capfd: pytest.CaptureFixture[str]) -> None:
    shell = DemoShell()
    assert await shell.run_line("eat") == 2
    assert "usage: eat" in capfd.readouterr().err
    assert await shell.run_line("echo -h") == 0
    assert "Print the given words." in _out(capfd)
    assert await shell.run_line("eat-all a --bogus") == 2
    assert "usage: eat-all" in capfd.readouterr().err


async def test_shell_command_must_lead_the_pipeline(capfd: pytest.CaptureFixture[str]) -> None:
    shell = DemoShell()
    assert await shell.run_line("echo a | eat-all b") == 2
    assert "eat-all" in capfd.readouterr().err
    assert shell.calls == []


async def test_after_a_pipe_a_shell_command_name_means_the_host_tool(
    capfd: pytest.CaptureFixture[str], python_on_path: str
) -> None:
    shell = DemoShell()
    shell.register_command(python_on_path, lambda: print("the shell's own"))
    assert await shell.run_line(python_on_path) == 0
    assert _out(capfd) == "the shell's own\n"
    # a shell command cannot read a pipe, so there the name can only mean the host's
    assert await shell.run_line(f'echo hello | {python_on_path} -c "{UPPER}"') == 0
    assert _out(capfd) == "HELLO\n"


async def test_host_command_that_cannot_start_fails_the_pipeline(capfd: pytest.CaptureFixture[str]) -> None:
    shell = DemoShell()
    assert await shell.run_line(f'echo a | py -c "{UPPER}" | missing') == 126
    captured = capfd.readouterr()
    assert captured.err.startswith("missing: ")
    assert shell.calls == []
    assert await shell.run_line("echo still alive") == 0


async def test_interact_runs_lines_until_exit(capfd: pytest.CaptureFixture[str]) -> None:
    shell = DemoShell()
    with create_pipe_input() as pipe_input, create_app_session(input=pipe_input, output=DummyOutput()):
        pipe_input.send_text("echo one\r\rboom\recho two\rexit\recho unreachable\r")
        await asyncio.wait_for(shell.interact(), timeout=30)
    assert _out(capfd) == "one\ntwo\n"
    assert shell.calls == [["one"], ["two"]]


async def test_interact_ends_at_end_of_file() -> None:
    shell = DemoShell()
    with create_pipe_input() as pipe_input, create_app_session(input=pipe_input, output=DummyOutput()):
        pipe_input.send_text("\x04")
        await asyncio.wait_for(shell.interact(), timeout=30)


def test_prompt_shows_label_and_last_status() -> None:
    class Labelled(DemoShell):
        def _prompt_label(self) -> str:
            return "afc:/DCIM"

    shell = Labelled()
    assert "".join(fragment[1] for fragment in shell._prompt_message()) == "[afc:/DCIM]$ "
    assert ("bold ansigreen", "$") in shell._prompt_message()
    shell.last_status = 1
    assert ("bold ansired", "$") in shell._prompt_message()


async def test_reader_exiting_early_stops_the_writer(capfd: pytest.CaptureFixture[str]) -> None:
    shell = DemoShell()
    assert await asyncio.wait_for(shell.run_line(f'flood | py -c "{FIRST_LINE}"'), timeout=30) == 0
    assert _out(capfd) == "line\n"


async def test_interrupt_stops_a_running_host_command() -> None:
    shell = DemoShell()
    task = asyncio.create_task(shell.run_line(f'py -c "{SLEEP}"'))
    await asyncio.sleep(1)
    started = time.monotonic()
    shell.interrupt()
    assert await asyncio.wait_for(task, timeout=30) != 0
    assert time.monotonic() - started < 10


async def _complete(shell: InteractiveShell, text: str) -> list[tuple[str, int]]:
    completer = ShellCompleter(shell)
    return [(c.text, c.start_position) async for c in completer.get_completions_async(Document(text), CompleteEvent())]


async def test_completes_command_names() -> None:
    shell = DemoShell()
    assert await _complete(shell, "e") == [("eat", -1), ("eat-all", -1), ("echo", -1), ("exit", -1)]
    # only host executables can follow a pipe, so `pick` is not offered
    assert await _complete(shell, "p") == [("pick", -1), ("py", -1)]
    assert await _complete(shell, "echo x | p") == [("py", -1)]
    assert await _complete(shell, "boom && fl") == [("flood", -2)]
    assert await _complete(shell, "help ea") == [("eat", -2), ("eat-all", -2)]


async def test_completes_arguments_with_the_parameter_completer() -> None:
    shell = DemoShell()
    assert await _complete(shell, "eat ap") == [("apple", -2), ("apricot", -2)]
    assert await _complete(shell, "eat ") == [
        ("apple", 0),
        ("apricot", 0),
        ("banana", 0),
        ("blood\\ orange", 0),
        ("dir/", 0),
    ]
    # every item of a list parameter is completed, and options are skipped
    assert await _complete(shell, "eat-all apple --loudly b") == [("banana", -1), ("blood\\ orange", -1)]
    # the second positional of `copy` is the one with the completer
    assert await _complete(shell, "copy somewhere b") == [("banana", -1), ("blood\\ orange", -1)]


async def test_completion_understands_quoted_and_escaped_words() -> None:
    shell = DemoShell()
    assert await _complete(shell, "eat blood\\ o") == [("blood\\ orange", -8)]
    assert await _complete(shell, "eat 'blood o") == [("blood\\ orange", -8)]


async def test_completion_quotes_when_backslash_is_not_an_escape() -> None:
    shell = DemoShell()
    shell.escape = False
    assert await _complete(shell, "eat bl") == [('"blood orange"', -2)]
    assert await _complete(shell, 'eat "blood o') == [('"blood orange"', -8)]
    assert await _complete(shell, "eat ap") == [("apple", -2), ("apricot", -2)]


async def test_raw_commands_complete_with_their_own_completer() -> None:
    shell = DemoShell()
    assert await _complete(shell, "raw ba") == []
    assert await _complete(shell, "rawfruit -l ba") == [("banana", -2)]


async def test_async_completers_are_awaited() -> None:
    assert await _complete(DemoShell(), "pick blue") == [("blue-berry", -4)]


async def test_failing_completer_yields_nothing() -> None:
    assert await _complete(DemoShell(), "fragile ba") == []


async def test_parameters_without_completer_complete_local_paths(tmp_path: Path) -> None:
    (tmp_path / "local file.txt").write_text("")
    shell = DemoShell()
    # a Windows path only survives the command line when the backslash is literal
    shell.escape = os.name != "nt"
    prefix = str(tmp_path / "local")
    expected = [(quote_word(f"{prefix} file.txt", shell.escape), -len(prefix))]
    assert await _complete(shell, f"copy {prefix}") == expected
    # and so does the target of a redirection
    assert await _complete(shell, f"echo x > {prefix}") == expected
