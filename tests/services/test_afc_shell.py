import asyncio
import os
import shutil
import sys
from collections.abc import AsyncGenerator
from contextlib import suppress
from pathlib import Path

import pytest
import pytest_asyncio
from prompt_toolkit.application import create_app_session
from prompt_toolkit.completion import CompleteEvent
from prompt_toolkit.document import Document
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput

from pymobiledevice3.exceptions import AfcException
from pymobiledevice3.interactive_shell import ShellCompleter
from pymobiledevice3.lockdown import LockdownClient, create_using_usbmux
from pymobiledevice3.services.afc import AfcService, AfcShell
from pymobiledevice3.services.crash_reports import CrashReportsManager, CrashReportsShell
from pymobiledevice3.utils import get_asyncio_loop

TEST_DIR = "__pymobiledevice3_shell_tests"
ROOT = f"/{TEST_DIR}"
BINARY = bytes(range(256)) * 4
UPPER = "import sys; sys.stdout.write(sys.stdin.read().upper())"


@pytest_asyncio.fixture(scope="function")
async def afc(lockdown: LockdownClient) -> AsyncGenerator[AfcService, None]:
    async with AfcService(lockdown) as afc:
        with suppress(AfcException):
            await afc.rm(TEST_DIR)
        await afc.makedirs(f"{TEST_DIR}/sub dir/nested")
        await afc.set_file_contents(f"{TEST_DIR}/hello.txt", b"hello\nworld\n")
        await afc.set_file_contents(f"{TEST_DIR}/blob.bin", BINARY)
        await afc.set_file_contents(f"{TEST_DIR}/sub dir/inner.txt", b"inner\n")
        try:
            yield afc
        finally:
            await afc.rm(TEST_DIR)


@pytest.fixture
def shell(afc: AfcService) -> AfcShell:
    shell = AfcShell(afc, cwd=ROOT)
    shell.register_host_command("py", sys.executable)
    return shell


@pytest.mark.device
def test_create_runs_a_shell_until_exit(capfd: pytest.CaptureFixture[str]) -> None:
    """The blocking entry point: it builds the service itself and runs on the CLI event loop."""
    loop = get_asyncio_loop()
    lockdown = loop.run_until_complete(create_using_usbmux())
    try:
        with create_pipe_input() as pipe_input, create_app_session(input=pipe_input, output=DummyOutput()):
            pipe_input.send_text("pwd\rexit\r")
            AfcShell.create(lockdown, auto_cd="/DCIM")
    finally:
        loop.run_until_complete(lockdown.close())
    assert capfd.readouterr().out.endswith("/DCIM\n")


async def _complete(shell: AfcShell, text: str) -> list[str]:
    completer = ShellCompleter(shell)
    return [c.text async for c in completer.get_completions_async(Document(text), CompleteEvent())]


async def test_pwd_and_cd(shell: AfcShell, capfd: pytest.CaptureFixture[str]) -> None:
    assert await shell.run_line("pwd") == 0
    assert capfd.readouterr().out == f"{ROOT}\n"
    assert await shell.run_line("cd 'sub dir' && pwd && cd .. && pwd && cd / && pwd") == 0
    assert capfd.readouterr().out == f"{ROOT}/sub dir\n{ROOT}\n/\n"
    # like a regular shell, a bare cd goes home
    assert await shell.run_line(f"cd {ROOT} && cd && pwd") == 0
    assert capfd.readouterr().out == "/\n"


async def test_cd_to_missing_directory_fails_and_stays(shell: AfcShell, capfd: pytest.CaptureFixture[str]) -> None:
    assert await shell.run_line("cd nope") != 0
    assert "nope does not exist" in capfd.readouterr().err
    assert shell.cwd == ROOT


async def test_ls(shell: AfcShell, capfd: pytest.CaptureFixture[str]) -> None:
    assert await shell.run_line("ls") == 0
    assert capfd.readouterr().out.split("\n")[:-1] == ["blob.bin", "hello.txt", "sub dir"]
    assert await shell.run_line("ls -l 'sub dir'") == 0
    long_listing = capfd.readouterr().out
    assert "inner.txt" in long_listing
    assert "nested" in long_listing


async def test_cat_pipes_into_host_commands(shell: AfcShell, capfd: pytest.CaptureFixture[str]) -> None:
    assert await shell.run_line(f'cat hello.txt | py -c "{UPPER}"') == 0
    assert capfd.readouterr().out == "HELLO\nWORLD\n"


@pytest.mark.skipif(shutil.which("grep") is None or shutil.which("wc") is None, reason="needs grep and wc")
async def test_host_tools_are_available(shell: AfcShell, capfd: pytest.CaptureFixture[str]) -> None:
    assert await shell.run_line("cat hello.txt | grep wor") == 0
    assert capfd.readouterr().out == "world\n"
    assert await shell.run_line("walk . | grep -c inner | wc -l") == 0
    assert capfd.readouterr().out.strip() == "1"
    assert await shell.run_line("cat hello.txt | grep absent") == 1


async def test_cat_is_byte_exact(shell: AfcShell, tmp_path: Path, capfd: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "blob.bin"
    assert await shell.run_line(f"cat blob.bin > '{out}'") == 0
    assert out.read_bytes() == BINARY
    assert await shell.run_line("cat hello.txt") == 0
    assert capfd.readouterr().out == "hello\nworld\n"


async def test_cat_missing_file_reports_the_error(shell: AfcShell, capfd: pytest.CaptureFixture[str]) -> None:
    assert await shell.run_line("cat missing.txt") == 1
    assert capfd.readouterr().err.startswith("cat: ")
    assert await shell.run_line("pwd") == 0


async def test_mkdir_mv_stat_rm(shell: AfcShell, afc: AfcService, capfd: pytest.CaptureFixture[str]) -> None:
    assert await shell.run_line("mkdir made/deeper && mv hello.txt made/moved.txt && stat made/moved.txt") == 0
    assert "st_size: 12" in capfd.readouterr().out
    assert await afc.listdir(f"{TEST_DIR}/made") == ["deeper", "moved.txt"] or sorted(
        await afc.listdir(f"{TEST_DIR}/made")
    ) == ["deeper", "moved.txt"]
    assert await shell.run_line("rm made/moved.txt made/deeper") == 0
    assert await afc.listdir(f"{TEST_DIR}/made") == []


async def test_walk_head_hexdump_info(shell: AfcShell, capfd: pytest.CaptureFixture[str]) -> None:
    assert await shell.run_line("walk 'sub dir'") == 0
    walked = capfd.readouterr().out.splitlines()
    assert f"{ROOT}/sub dir/inner.txt" in walked
    assert f"{ROOT}/sub dir/nested" in walked
    assert await shell.run_line("head hello.txt") == 0
    assert capfd.readouterr().out == "hello\nworld\n"
    assert await shell.run_line("head -n 1 hello.txt && head --lines 0 hello.txt") == 0
    assert capfd.readouterr().out == "hello\n"
    assert await shell.run_line("hexdump hello.txt") == 0
    assert "68 65 6c 6c 6f" in capfd.readouterr().out.lower()
    assert await shell.run_line("info") == 0
    assert "FSTotalBytes" in capfd.readouterr().out


async def test_push_and_pull_round_trip(shell: AfcShell, tmp_path: Path, capfd: pytest.CaptureFixture[str]) -> None:
    source = tmp_path / "local source.bin"
    source.write_bytes(BINARY)
    pulled = tmp_path / "pulled"
    pulled.mkdir()
    assert await shell.run_line(f"push '{source}' 'sub dir/pushed.bin'") == 0
    assert await shell.run_line(f"pull 'sub dir/pushed.bin' '{pulled}'") == 0
    assert (pulled / "pushed.bin").read_bytes() == BINARY


async def test_help_describes_the_commands(shell: AfcShell, capfd: pytest.CaptureFixture[str]) -> None:
    assert await shell.run_line("help") == 0
    listing = capfd.readouterr().out
    for name in ("ls", "cd", "cat", "pull", "push", "walk", "rm", "help", "exit"):
        assert any(line.split()[:1] == [name] and len(line.split()) > 1 for line in listing.splitlines()), name
    assert await shell.run_line("help pull") == 0
    details = capfd.readouterr().out
    assert "usage: pull" in details
    assert "--ignore-errors" in details
    assert "Local destination path" in details
    assert await shell.run_line("help ls") == 0
    assert "List directory contents" in capfd.readouterr().out


async def test_extra_host_tools(
    afc: AfcService, capfd: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    python = Path(sys.executable).name
    monkeypatch.setenv("PATH", str(Path(sys.executable).parent), prepend=os.pathsep)
    shell = AfcShell(afc, cwd=ROOT, host_tools=[python])
    assert await shell.run_line(f'cat hello.txt | {python} -c "{UPPER}"') == 0
    assert capfd.readouterr().out == "HELLO\nWORLD\n"


async def test_completes_remote_paths(shell: AfcShell) -> None:
    assert await _complete(shell, "cat he") == ["hello.txt"]
    assert sorted(await _complete(shell, "cat ")) == ["blob.bin", "hello.txt", "sub\\ dir/"]
    assert sorted(await _complete(shell, "cat sub\\ dir/")) == ["sub\\ dir/inner.txt", "sub\\ dir/nested/"]
    assert await _complete(shell, f"cat {ROOT}/he") == [f"{ROOT}/hello.txt"]
    # completing a word that already names a file must not fail
    assert await _complete(shell, "cat hello.txt") == ["hello.txt"]


async def test_cd_completes_directories_only_and_ls_completes_remote_paths(shell: AfcShell) -> None:
    assert await _complete(shell, "cd ") == ["sub\\ dir/"]
    assert await _complete(shell, "ls su") == ["sub\\ dir/"]


async def test_completion_sees_changes_made_by_commands(shell: AfcShell) -> None:
    assert await _complete(shell, "cat ne") == []
    assert await shell.run_line("mkdir newdir") == 0
    assert await _complete(shell, "cat ne") == ["newdir/"]


async def test_interrupt_cancels_a_device_command_and_the_shell_keeps_working(
    shell: AfcShell, capfd: pytest.CaptureFixture[str]
) -> None:
    async def spin() -> None:
        while True:
            await shell.afc.listdir(ROOT)

    shell.register_command("spin", spin)
    task = asyncio.create_task(shell.run_line("spin"))
    await asyncio.sleep(0.3)
    assert not task.done()
    shell.interrupt()
    assert await asyncio.wait_for(task, timeout=30) == 130
    assert await shell.run_line("pwd") == 0
    assert await shell.run_line("cat hello.txt") == 0
    assert capfd.readouterr().out == f"{ROOT}\nhello\nworld\n"


async def test_crash_reports_shell_adds_its_commands(
    lockdown: LockdownClient, capfd: pytest.CaptureFixture[str]
) -> None:
    async with CrashReportsManager(lockdown) as manager:
        shell = CrashReportsShell(manager)
        for name in ("parse", "parse-latest", "clear", "ls", "cd"):
            assert shell.get_command(name) is not None
        assert await shell.run_line("pwd && ls") == 0
        assert capfd.readouterr().out.startswith("/\n")
        assert await shell.run_line("parse-latest --count 1 /") in (0, 1)
