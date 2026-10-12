"""
A small interactive command shell: line editing, completion, pipes into host tools, redirection.

:class:`InteractiveShell` is device-agnostic. Subclasses register commands, which are either
Python handlers or paths of host executables. A handler may start a pipeline whose remaining
stages are host executables (``cat file | grep foo > out.txt``), so handlers only ever write to
``sys.stdout``. Handlers run on the event loop: plain functions for quick local work, coroutine
functions for anything that waits.

A shell is a subclass whose commands are its methods marked with :func:`shell_command`::

    class Demo(InteractiveShell):
        HOST_COMMANDS = ("grep", "wc")

        @shell_command
        async def _do_greet(self, name: str, shout: Annotated[bool, Arg("--shout")] = False) -> None:
            '''Say hello.'''
            print(f"hello {name}".upper() if shout else f"hello {name}")

    await Demo().interact()
"""

import argparse
import asyncio
import contextlib
import difflib
import inspect
import io
import os
import re
import shutil
import signal
import subprocess
import sys
from collections.abc import AsyncGenerator, Awaitable, Generator, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from types import FrameType
from typing import (
    Annotated,
    Any,
    Callable,
    ClassVar,
    NamedTuple,
    Optional,
    TextIO,
    TypeVar,
    Union,
    cast,
    get_args,
    get_origin,
    get_type_hints,
    overload,
)

from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import CompleteEvent, Completer, Completion, PathCompleter
from prompt_toolkit.document import Document
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.history import FileHistory, InMemoryHistory

#: Returns candidate replacements for ``context.prefix``. May be a coroutine function.
ArgCompleter = Callable[["CompletionContext"], Union[Iterable[str], Awaitable[Iterable[str]]]]
_OPERATOR_CHARS = "|&;<>"
_CONNECTORS = (";", "&&", "||")
_SPECIAL_CHARS = re.compile(r"""([\s'"\\|&;<>])""")
_PARAM_DOC = re.compile(r"^\s*:param (\w+):\s*(.+)$", re.MULTILINE)


class ShellSyntaxError(Exception):
    """The command line could not be parsed."""


class Arg:
    """Refine how a handler parameter maps to a command-line argument.

    The signature alone already says most of it:

    - a positional parameter is a positional argument, optional when it has a default
    - a keyword-only parameter is an option named after it (``dry_run`` is ``--dry-run``)
    - ``bool`` options are flags, ``int`` and ``float`` are converted, ``list[...]`` collects several
      values (one or more words for a positional, a repeatable option otherwise)

    ``Annotated[..., Arg(...)]`` adds what a signature cannot express: a ``completer`` for the
    values, extra option names (``Arg("-n")``), and any other ``ArgumentParser.add_argument``
    keyword. An annotated type is reusable: ``RemotePath = Annotated[str, Arg(completer=...)]``.
    """

    def __init__(self, *flags: str, completer: Optional[ArgCompleter] = None, **kwargs: Any) -> None:
        self.flags = flags
        self.completer = completer
        self.kwargs = kwargs


@dataclass
class CompletionContext:
    """What an :data:`ArgCompleter` gets: the word being completed and the shell asking."""

    prefix: str
    shell: "InteractiveShell"


@dataclass
class Pipeline:
    """Commands connected with ``|``, optionally redirected into a local file."""

    stages: list[list[str]] = field(default_factory=list[list[str]])
    redirect: Optional[str] = None
    append: bool = False


class _Token(NamedTuple):
    text: str
    is_operator: bool
    start: int


def _tokenize(text: str, escape: bool, partial: bool = False) -> list[_Token]:
    """Split a command line into words and operators.

    :param escape: treat a backslash as an escape character (off on Windows, where it separates paths)
    :param partial: tolerate an unterminated quote or a trailing backslash (a line still being typed)
    """
    tokens: list[_Token] = []
    i = 0
    while i < len(text):
        if text[i].isspace():
            i += 1
            continue
        start = i
        if text[i] in _OPERATOR_CHARS:
            while i < len(text) and text[i] in _OPERATOR_CHARS:
                i += 1
            tokens.append(_Token(text[start:i], True, start))
            continue
        word: list[str] = []
        while i < len(text) and not text[i].isspace() and text[i] not in _OPERATOR_CHARS:
            char = text[i]
            if char == "\\" and escape:
                if i + 1 == len(text) and not partial:
                    raise ShellSyntaxError("trailing backslash")
                word.append(text[i + 1 : i + 2])
                i += 2
            elif char in "'\"":
                end = text.find(char, i + 1)
                if end == -1:
                    if not partial:
                        raise ShellSyntaxError("unterminated quote")
                    end = len(text)
                word.append(text[i + 1 : end])
                i = end + 1
            else:
                word.append(char)
                i += 1
        tokens.append(_Token("".join(word), False, start))
    return tokens


def parse_line(line: str, escape: bool = True) -> list[tuple[str, Pipeline]]:
    """Parse a command line into pipelines, each paired with the connector that precedes it.

    The connector is ``""`` for the first pipeline and one of ``;``, ``&&``, ``||`` for the rest.
    """
    result: list[tuple[str, Pipeline]] = []
    connector = ""
    pipeline = Pipeline()
    stage: list[str] = []
    tokens = iter(_tokenize(line, escape))
    for token in tokens:
        if not token.is_operator:
            if pipeline.redirect is not None:
                raise ShellSyntaxError(f"unexpected {token.text!r} after the redirection")
            stage.append(token.text)
            continue
        if not stage:
            raise ShellSyntaxError(f"unexpected {token.text!r}")
        if token.text == "|":
            if pipeline.redirect is not None:
                raise ShellSyntaxError("unexpected '|' after the redirection")
            pipeline.stages.append(stage)
            stage = []
        elif token.text in (">", ">>"):
            target = next(tokens, None)
            if target is None or target.is_operator or pipeline.redirect is not None:
                raise ShellSyntaxError(f"expected a file name after {token.text!r}")
            pipeline.redirect = target.text
            pipeline.append = token.text == ">>"
        elif token.text in _CONNECTORS:
            pipeline.stages.append(stage)
            result.append((connector, pipeline))
            connector, pipeline, stage = token.text, Pipeline(), []
        else:
            raise ShellSyntaxError(f"unsupported operator {token.text!r}")
    if stage:
        pipeline.stages.append(stage)
        result.append((connector, pipeline))
    elif connector not in ("", ";") or pipeline.stages:
        raise ShellSyntaxError("unexpected end of line")
    return result


def quote_word(word: str, escape: bool = True) -> str:
    """Quote ``word`` so that :func:`parse_line` reads it back as a single word."""
    if escape:
        return _SPECIAL_CHARS.sub(r"\\\1", word)
    return f'"{word}"' if _SPECIAL_CHARS.search(word) else word


class _Argument(NamedTuple):
    names: tuple[str, ...]
    kwargs: dict[str, Any]
    completer: Optional[ArgCompleter]
    positional: bool


def _unwrap(annotation: Any) -> tuple[Any, list[Arg]]:
    """Strip ``Annotated`` and ``Optional`` off a type hint, collecting the :class:`Arg` s met on the way."""
    args: list[Arg] = []
    while True:
        origin = get_origin(annotation)
        if origin is Annotated:
            annotation, *metadata = get_args(annotation)
            args.extend(item for item in metadata if isinstance(item, Arg))
        elif origin is Union:
            # Optional[X] (which Python <= 3.10 also adds around the hint of a parameter defaulting to None)
            members = [member for member in get_args(annotation) if member is not type(None)]
            if len(members) != 1:
                return annotation, args
            annotation = members[0]
        else:
            return annotation, args


def _arguments(func: Callable[..., Any]) -> Iterator[_Argument]:
    hints = get_type_hints(func, include_extras=True)
    docs = dict(_PARAM_DOC.findall(inspect.getdoc(func) or ""))
    for name, parameter in inspect.signature(func).parameters.items():
        annotation, args = _unwrap(hints.get(name, str))
        repeated = get_origin(annotation) is list
        if repeated:
            annotation, item_args = _unwrap(get_args(annotation)[0])
            args += item_args
        kwargs: dict[str, Any] = {}
        for arg in reversed(args):
            kwargs.update(arg.kwargs)
        completer = next((arg.completer for arg in args if arg.completer is not None), None)
        has_default = parameter.default is not inspect.Parameter.empty
        positional = parameter.kind is not inspect.Parameter.KEYWORD_ONLY

        if positional:
            names = (name,)
            if repeated:
                kwargs.setdefault("nargs", "*" if has_default else "+")
            elif has_default:
                kwargs.setdefault("nargs", "?")
        else:
            names = ("--" + name.replace("_", "-"), *(flag for arg in args for flag in arg.flags))
            kwargs["dest"] = name
            if repeated:
                kwargs.setdefault("action", "append")
            elif annotation is bool:
                kwargs.setdefault("action", "store_true")
            elif not has_default:
                kwargs.setdefault("required", True)
        if has_default:
            kwargs.setdefault("default", parameter.default)
        if annotation in (int, float):
            kwargs.setdefault("type", annotation)
        if name in docs:
            kwargs.setdefault("help", docs[name].replace("%", "%%"))
        yield _Argument(names, kwargs, completer, positional)


def _summary(func: Callable[..., Any]) -> str:
    """The first paragraph of a handler's docstring, on one line."""
    return " ".join((inspect.getdoc(func) or "").split("\n\n")[0].split())


def build_parser(name: str, func: Callable[..., Any]) -> argparse.ArgumentParser:
    """Build the argument parser of a handler from its signature and docstring.

    The first paragraph of the docstring describes the command and its ``:param name:`` lines
    describe the arguments.
    """
    parser = argparse.ArgumentParser(prog=name, description=_summary(func) or None)
    for argument in _arguments(func):
        parser.add_argument(*argument.names, **argument.kwargs)
    return parser


def local_path_completer(context: "CompletionContext") -> list[str]:
    """Complete a path on the host."""
    completions = PathCompleter(expanduser=True).get_completions(Document(context.prefix), CompleteEvent())
    return [context.prefix + completion.text for completion in completions]


class _CommandSpec(NamedTuple):
    name: str
    raw: bool
    completer: Optional[ArgCompleter]


_COMMAND_SPEC = "_shell_command_spec"
_F = TypeVar("_F", bound=Callable[..., Any])


@overload
def shell_command(func: _F) -> _F: ...


@overload
def shell_command(
    *, name: Optional[str] = None, raw: bool = False, completer: Optional[ArgCompleter] = None
) -> Callable[[_F], _F]: ...


def shell_command(
    func: Optional[_F] = None,
    *,
    name: Optional[str] = None,
    raw: bool = False,
    completer: Optional[ArgCompleter] = None,
) -> Union[_F, Callable[[_F], _F]]:
    """Mark a method of an :class:`InteractiveShell` subclass as a shell command.

    The command line is parsed into the method's parameters (see :class:`Arg`), and the first
    paragraph of its docstring is the command's help. The method may be a coroutine function.

    :param name: command name. Defaults to the method name without its ``_do_`` prefix and with
        dashes for underscores: ``_do_show_help`` is ``show-help``.
    :param raw: pass the arguments unparsed, as a single list of words
    :param completer: completes the arguments of a ``raw`` command
    """

    def decorate(target: _F) -> _F:
        derived = target.__name__.lstrip("_")
        derived = derived[3:] if derived.startswith("do_") else derived
        vars(target)[_COMMAND_SPEC] = _CommandSpec(name or derived.replace("_", "-"), raw, completer)
        return target

    return decorate if func is None else decorate(func)


class _Handler:
    """A command implemented in Python."""

    def __init__(self, spec: _CommandSpec, func: Callable[..., Any]) -> None:
        self.func = func
        self.spec = spec
        self.parser = None if spec.raw else build_parser(spec.name, func)
        self.positionals = [] if spec.raw else [argument for argument in _arguments(func) if argument.positional]

    def __call__(self, args: list[str]) -> Any:
        if self.parser is None:
            return self.func(args)
        return self.func(**vars(self.parser.parse_args(args)))

    @property
    def summary(self) -> str:
        return _summary(self.func)

    def format_help(self) -> str:
        if self.parser is None:
            return (inspect.getdoc(self.func) or self.spec.name) + "\n"
        return self.parser.format_help()

    def completer_at(self, index: int) -> Optional[ArgCompleter]:
        """The completer of the ``index``-th positional word, if that word can be completed."""
        if self.parser is None:
            return self.spec.completer
        if index >= len(self.positionals):
            if not self.positionals or self.positionals[-1].kwargs.get("nargs") not in ("*", "+"):
                return None
            index = -1
        return self.positionals[index].completer or local_path_completer


#: A command: a handler, or the path of a host executable.
ShellCommand = Union[str, _Handler]


def command_name_completer(context: "CompletionContext") -> list[str]:
    """Complete the name of a command of the shell."""
    return context.shell.command_names()


class ShellCompleter(Completer):
    """Complete command names, then each argument with the completer its parameter declares."""

    def __init__(self, shell: "InteractiveShell") -> None:
        self.shell = shell

    def get_completions(self, document: Document, complete_event: CompleteEvent) -> Iterator[Completion]:
        # completers may be coroutine functions: async only
        return iter(())

    async def get_completions_async(
        self, document: Document, complete_event: CompleteEvent
    ) -> AsyncGenerator[Completion, None]:
        text = document.text_before_cursor
        escape = self.shell.escape
        tokens = _tokenize(text, escape, partial=True)
        prefix, raw_length = "", 0
        if tokens and not tokens[-1].is_operator and not text[-1:].isspace():
            current = tokens.pop()
            prefix, raw_length = current.text, len(text) - current.start
        operators = [index for index, token in enumerate(tokens) if token.is_operator]
        words = [token.text for token in tokens[operators[-1] + 1 if operators else 0 :]]

        completer: Optional[ArgCompleter] = None
        candidates: list[str] = []
        if operators and tokens[operators[-1]].text in (">", ">>"):
            completer = local_path_completer
        elif not words:
            # only host executables can follow a pipe
            piped = bool(operators) and tokens[operators[-1]].text == "|"
            candidates = sorted(
                name
                for name in self.shell.command_names()
                if not piped or isinstance(self.shell.get_command(name), str)
            )
        else:
            command = self.shell.get_command(words[0])
            if isinstance(command, _Handler):
                completer = command.completer_at(sum(1 for word in words[1:] if not word.startswith("-")))

        if completer is not None:
            try:
                found = completer(CompletionContext(prefix, self.shell))
                if inspect.isawaitable(found):
                    found = await found
                candidates = list(cast(Iterable[str], found))
            except Exception:
                # a completer that cannot reach its data must not break the prompt
                return
        for candidate in candidates:
            if candidate.startswith(prefix):
                yield Completion(quote_word(candidate, escape), start_position=-raw_length, display=candidate)


class InteractiveShell:
    """Runs command lines and prompts for them. Subclass it and mark methods with :func:`shell_command`."""

    #: Host executables offered as commands, by name. The ones not installed are left out.
    HOST_COMMANDS: ClassVar[tuple[str, ...]] = ()

    def __init__(self, host_tools: Iterable[str] = ()) -> None:
        """
        :param host_tools: names of more host executables to offer as commands
        :raises ValueError: when one of ``host_tools`` is not installed
        """
        self._commands: dict[str, ShellCommand] = {}
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._running: Optional[asyncio.Future[int]] = None
        self._processes: list[subprocess.Popen[bytes]] = []
        self._interrupted = False
        self._exiting = False
        #: Exit status of the last command line.
        self.last_status = 0
        #: Whether a backslash escapes the next character. Off on Windows, where it separates paths.
        self.escape = os.name != "nt"

        for klass in reversed(type(self).__mro__):
            for attribute, value in vars(klass).items():
                spec = cast(Optional[_CommandSpec], getattr(value, _COMMAND_SPEC, None))
                if spec is not None:
                    self._commands[spec.name] = _Handler(spec, getattr(self, attribute))
        for name in self.HOST_COMMANDS:
            executable = shutil.which(name)
            if executable is not None:
                self.register_host_command(name, executable)
        for name in host_tools:
            executable = shutil.which(name)
            if executable is None:
                raise ValueError(f"{name}: no such host tool")
            self.register_host_command(name, executable)

    def register_command(self, name: str, handler: Callable[..., Any]) -> None:
        """Add a command at runtime. Prefer :func:`shell_command` for the commands a shell is born with."""
        self._commands[name] = _Handler(_CommandSpec(name, False, None), handler)

    def register_host_command(self, name: str, executable: str) -> None:
        """Offer the host executable at path ``executable`` as the command ``name``."""
        self._commands[name] = executable

    @shell_command
    def _do_help(self, command: Annotated[Optional[str], Arg(completer=command_name_completer)] = None) -> None:
        """
        List the commands, or describe one of them.

        :param command: The command to describe
        """
        if command is not None:
            described = self._commands.get(command)
            if described is None:
                raise ValueError(f"{command}: command not found")
            if isinstance(described, str):
                print(f"{command}: host tool at {described}")
            else:
                print(described.format_help(), end="")
            return

        handlers = {name: value for name, value in self._commands.items() if not isinstance(value, str)}
        width = max(map(len, handlers))
        print("Commands:")
        for name in sorted(handlers):
            print(f"  {name:<{width}}  {handlers[name].summary}".rstrip())
        host_tools = sorted(name for name, value in self._commands.items() if isinstance(value, str))
        if host_tools:
            print("\nHost tools, usable after a pipe (COMMAND | TOOL), with their usual arguments:")
            print("  " + ", ".join(host_tools))
        print("Any other host tool works with a `!` in front: COMMAND | !TOOL")
        print("\nType `help COMMAND` to describe one command. Output can go to a local file: COMMAND > FILE")

    @shell_command
    def _do_exit(self) -> None:
        """Leave the shell."""
        self._exiting = True

    def command_names(self) -> list[str]:
        return list(self._commands)

    def get_command(self, name: str) -> Optional[ShellCommand]:
        return self._commands.get(name)

    async def run_line(self, line: str) -> int:
        """Run a command line and return its exit status (130 when interrupted)."""
        self._loop = asyncio.get_running_loop()
        self._interrupted = False
        self._running = asyncio.ensure_future(self._run_line(line))
        try:
            self.last_status = await self._running
        except asyncio.CancelledError:
            if not self._interrupted:
                # we are the one being cancelled, not just the command
                raise
            self.last_status = 130
        finally:
            self._running = None
        return self.last_status

    def interrupt(self) -> None:
        """Stop the running command line. Safe to call from any thread."""
        self._interrupted = True
        for process in list(self._processes):
            with contextlib.suppress(OSError):
                process.kill()
        if self._running is not None and self._loop is not None:
            self._loop.call_soon_threadsafe(self._running.cancel)

    async def interact(self) -> None:
        """Prompt for command lines and run them until end-of-file or ``exit``."""
        self._exiting = False
        history_path = self._history_path()
        session: PromptSession[str] = PromptSession(
            history=InMemoryHistory() if history_path is None else FileHistory(str(history_path)),
            completer=ShellCompleter(self),
            complete_while_typing=False,
            auto_suggest=AutoSuggestFromHistory(),
        )
        while True:
            try:
                line = (await session.prompt_async(self._prompt_message)).strip()
            except KeyboardInterrupt:
                continue
            except EOFError:
                return
            if line:
                with self._interrupt_on_sigint():
                    await self.run_line(line)
            if self._exiting:
                return

    def _prompt_label(self) -> str:
        """Text shown between the brackets of the prompt."""
        return ""

    def _prompt_message(self) -> FormattedText:
        status_style = "bold ansigreen" if self.last_status == 0 else "bold ansired"
        return FormattedText([
            ("", "["),
            ("bold ansicyan", self._prompt_label()),
            ("", "]"),
            (status_style, "$"),
            ("", " "),
        ])

    def _history_path(self) -> Optional[Path]:
        """Where the prompt history is kept. In memory only when ``None``."""
        return None

    @contextlib.contextmanager
    def _interrupt_on_sigint(self) -> Generator[None, None, None]:
        """Make Ctrl-C stop the running command instead of the whole shell."""
        loop = asyncio.get_running_loop()

        def handler(signum: int, frame: Optional[FrameType]) -> None:
            loop.call_soon_threadsafe(self.interrupt)

        try:
            previous = signal.signal(signal.SIGINT, handler)
        except ValueError:
            # not the main thread: signals cannot be handled here
            yield
            return
        try:
            yield
        finally:
            signal.signal(signal.SIGINT, previous)

    async def _run_line(self, line: str) -> int:
        try:
            pipelines = parse_line(line, self.escape)
        except ShellSyntaxError as e:
            print(f"syntax error: {e}", file=sys.stderr)
            return 2
        status = 0
        for connector, pipeline in pipelines:
            if (connector == "&&" and status != 0) or (connector == "||" and status == 0):
                continue
            status = await self._run_pipeline(pipeline)
            if self._interrupted:
                return 130
            if self._exiting:
                break
        return status

    async def _run_pipeline(self, pipeline: Pipeline) -> int:
        commands: list[ShellCommand] = []
        for index, stage in enumerate(pipeline.stages):
            name = stage[0]
            if name.startswith("!"):
                # an explicit request for a host executable, whatever the shell itself offers
                name = name[1:]
                command = shutil.which(name)
                hint = "no such host tool"
            else:
                command = self._commands.get(name)
                close = difflib.get_close_matches(name, self._commands, n=1)
                hint = f"did you mean {close[0]}?" if close else "type help to list the commands"
            if command is None:
                print(f"{name}: command not found ({hint})", file=sys.stderr)
                return 127
            if index > 0 and not isinstance(command, str):
                # a shell command cannot read a pipe, so here its name can only mean the host's tool
                command = shutil.which(name) or command
            if index > 0 and not isinstance(command, str):
                print(f"{stage[0]}: only the first command of a pipeline can be a shell command", file=sys.stderr)
                return 2
            commands.append(command)

        with contextlib.ExitStack() as stack:
            sink: Optional[io.BufferedWriter] = None
            if pipeline.redirect is not None:
                try:
                    sink = stack.enter_context(open(pipeline.redirect, "ab" if pipeline.append else "wb"))
                except OSError as e:
                    print(f"{pipeline.redirect}: {e.strerror}", file=sys.stderr)
                    return 1

            leader = commands[0]
            hosted = list(zip(pipeline.stages, commands))[0 if isinstance(leader, str) else 1 :]
            processes = self._processes = []
            stack.callback(processes.clear)
            for stage, executable in hosted:
                # everything after the leader was verified above to be a host executable
                assert isinstance(executable, str)
                # the leader's output reaches the first host process through a pipe we write to
                first_stdin = None if isinstance(leader, str) else subprocess.PIPE
                stdin = processes[-1].stdout if processes else first_stdin
                stdout = sink if stage is pipeline.stages[-1] else subprocess.PIPE
                try:
                    process = subprocess.Popen([executable, *stage[1:]], stdin=stdin, stdout=stdout)
                except OSError as e:
                    print(f"{stage[0]}: {e.strerror}", file=sys.stderr)
                    for started in processes:
                        started.kill()
                    if processes and processes[0].stdin is not None:
                        processes[0].stdin.close()
                    return 126
                finally:
                    if processes and processes[-1].stdout is not None:
                        # the next process owns the read end now
                        processes[-1].stdout.close()
                processes.append(process)
                stack.callback(process.wait)

            status = 0
            try:
                if not isinstance(leader, str):
                    target: Optional[TextIO] = None
                    if processes:
                        assert processes[0].stdin is not None
                        target = io.TextIOWrapper(processes[0].stdin, encoding="utf-8", errors="replace")
                    elif sink is not None:
                        target = io.TextIOWrapper(sink, encoding="utf-8", errors="replace")
                    status = await self._run_handler(pipeline.stages[0], leader, target)
                for process in processes:
                    await asyncio.to_thread(process.wait)
            except asyncio.CancelledError:
                # nobody is left to wait for the host processes
                for process in processes:
                    with contextlib.suppress(OSError):
                        process.kill()
                raise
            if processes:
                status = processes[-1].returncode
            return status

    async def _run_handler(self, argv: list[str], handler: _Handler, target: Optional[TextIO]) -> int:
        """Run a handler with ``sys.stdout`` pointing at ``target`` (when given), which gets closed."""
        try:
            with contextlib.redirect_stdout(target) if target is not None else contextlib.nullcontext():
                result = handler(argv[1:])
                if inspect.isawaitable(result):
                    await result
                sys.stdout.flush()
        except BrokenPipeError:
            # the reading side of the pipe is gone (`walk / | head`): nothing left to say
            return 0
        except SystemExit as e:
            # argparse reports bad arguments and `--help` by exiting
            return e.code if isinstance(e.code, int) else int(e.code is not None)
        except Exception as e:
            print(f"{argv[0]}: {e}", file=sys.stderr)
            return 1
        finally:
            if target is not None:
                with contextlib.suppress(OSError, ValueError):
                    target.close()
        return 0
