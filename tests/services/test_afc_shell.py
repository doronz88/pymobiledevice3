from pathlib import Path
from unittest import mock

import pytest
from cmd2_ext_test import ExternalTestMixin
from cmd2 import CommandResult
import gnureadline

from pymobiledevice3.services.afc import AfcShell

SINGLE_PARAM_COMMANDS = ['edit', 'cd', 'walk', 'cat', 'rm', 'head', 'hexdump', 'stat']


class AfcShellTester(ExternalTestMixin, AfcShell):
    def __init__(self, *args, **kwargs):
        # gotta have this or neither the plugin or cmd2 will initialize
        super().__init__(*args, **kwargs)


@pytest.fixture(scope='function')
def afc_shell(lockdown):
    app = AfcShellTester(lockdown)
    try:
        yield app
    finally:
        app.afc.service.close()


def get_completions(line, part, app):
    def get_line():
        return line

    def get_begidx():
        return len(line) - len(part)

    def get_endidx():
        return len(line)

    with mock.patch.object(gnureadline, 'get_line_buffer', get_line):
        with mock.patch.object(gnureadline, 'get_begidx', get_begidx):
            with mock.patch.object(gnureadline, 'get_endidx', get_endidx):
                app.complete(part, 0)

    return app.completion_matches


@pytest.mark.parametrize('command', SINGLE_PARAM_COMMANDS)
def test_completion(command, afc_shell):
    filenames = get_completions(f'{command} D', 'D', afc_shell)
    assert 'DCIM' in filenames
    assert 'Downloads' in filenames
    assert 'Books' not in filenames


@pytest.mark.parametrize('command', SINGLE_PARAM_COMMANDS)
def test_completion_empty(command, afc_shell):
    filenames = get_completions(f'{command} ', '', afc_shell)
    assert 'DCIM' in filenames
    assert 'Downloads' in filenames
    assert 'Books' in filenames


@pytest.mark.parametrize('command', SINGLE_PARAM_COMMANDS)
def test_completion_with_space(command, afc_shell):
    afc_shell.afc.makedirs('aa bb cc/dd ee ff')
    try:
        assert ['"aa bb cc" '] == get_completions(f'{command} aa ', 'aa ', afc_shell)
        assert ['aa bb cc" '] == get_completions(f'{command} "aa ', 'aa ', afc_shell)
        assert ['"aa bb cc/dd ee ff" '] == get_completions(f'{command} aa bb cc/dd ee', 'aa bb cc/dd ee', afc_shell)
    finally:
        afc_shell.afc.rm('aa bb cc')


@pytest.mark.parametrize('command', SINGLE_PARAM_COMMANDS)
def test_in_folder_completion(command, afc_shell):
    afc_shell.afc.makedirs('temp1/temp2')
    afc_shell.afc.makedirs('temp1/temp4')
    try:
        assert ['temp1 '] == get_completions(f'{command} temp', 'temp', afc_shell)
        assert ['temp1/temp2', 'temp1/temp4'] == get_completions(f'{command} temp1/', 'temp1/', afc_shell)
        assert ['temp1/temp2', 'temp1/temp4'] == get_completions(f'{command} temp1/temp', 'temp1/temp', afc_shell)
    finally:
        afc_shell.afc.rm('temp1')


@pytest.mark.parametrize('command', SINGLE_PARAM_COMMANDS)
def test_completion_after_cd(command, afc_shell):
    afc_shell.afc.makedirs('temp1/temp2')
    afc_shell.afc.makedirs('temp1/temp4')
    afc_shell.app_cmd('cd temp1')
    completions = get_completions(f'{command} temp', 'temp', afc_shell)
    afc_shell.afc.rm('temp1')
    assert ['temp2', 'temp4'] == completions


@pytest.mark.parametrize('command', SINGLE_PARAM_COMMANDS)
def test_not_over_completing(command, afc_shell):
    assert not get_completions(f'{command} DCIM ', '', afc_shell)


def test_mv_completion(afc_shell):
    afc_shell.afc.makedirs('temp1')
    afc_shell.afc.set_file_contents('temp1/temp.txt', b'data')
    try:
        assert get_completions('mv temp1/t', 'temp1/t', afc_shell) == ['temp1/temp.txt ']
        assert get_completions('mv temp1/temp.txt tem', 'tem', afc_shell) == ['temp1 ']
    finally:
        afc_shell.afc.rm('temp1')


def test_push_completion(afc_shell, tmp_path: Path):
    (tmp_path / 'temp1.txt').write_text('hey1')
    (tmp_path / 'temp2.txt').write_text('hey2')
    assert get_completions(f'push {tmp_path}', str(tmp_path), afc_shell) == [f'{tmp_path} ']
    assert get_completions(f'push {tmp_path}/', f'{tmp_path}/', afc_shell) == [f'{tmp_path}/temp1.txt',
                                                                               f'{tmp_path}/temp2.txt']

    second_completion = get_completions(f'push {tmp_path} D', 'D', afc_shell)
    assert 'DCIM' in second_completion
    assert 'Downloads' in second_completion
    assert 'Books' not in second_completion


def test_pull_completion(afc_shell, tmp_path: Path):
    completions = get_completions('pull D', 'D', afc_shell)
    assert 'DCIM' in completions
    assert 'Downloads' in completions
    assert 'Books' not in completions

    (tmp_path / 'temp1.txt').write_text('hey1')
    (tmp_path / 'temp2.txt').write_text('hey2')
    assert get_completions(f'pull DCIM {tmp_path}', str(tmp_path), afc_shell) == [f'{tmp_path} ']
    assert get_completions(f'pull DCIM {tmp_path}/', f'{tmp_path}/', afc_shell) == [f'{tmp_path}/temp1.txt',
                                                                                    f'{tmp_path}/temp2.txt']


def test_ls(afc_shell):
    out = afc_shell.app_cmd('ls')
    assert isinstance(out, CommandResult)
    filenames = str(out.stdout).strip().splitlines()
    assert 'DCIM' in filenames
    assert 'Downloads' in filenames
    assert 'Books' in filenames


def test_pull_after_cd_single_file(afc_shell, tmp_path: Path):
    """
    source:
    temp1
    └── temp.txt

    cd temp1
    pull temp.txt target

    target
    └── temp.txt
    """
    file_name = 'temp.txt'
    file_data = b'data'
    afc_shell.afc.makedirs('temp1')
    afc_shell.afc.set_file_contents(f'temp1/{file_name}', file_data)
    out = afc_shell.app_cmd(f'pull {file_name} {tmp_path.absolute()}')
    try:
        assert 'AfcFileNotFoundError' in out.stderr
        afc_shell.app_cmd('cd temp1')
        out = afc_shell.app_cmd(f'pull {file_name} {tmp_path.absolute()}')
        assert not out.stderr
        assert (tmp_path / file_name).read_bytes() == file_data
    finally:
        afc_shell.afc.rm('temp1')


def test_pull_after_cd_single_file_with_prefix(afc_shell, tmp_path: Path):
    """
    source:
    temp1
    └── temp2
        └── temp3
            └── temp.txt

    cd temp1
    pull temp2/temp3/temp.txt target

    target
    └── temp.txt
    """
    file_name = 'temp.txt'
    file_data = b'data'
    afc_shell.afc.makedirs('temp1/temp2/temp3')
    afc_shell.afc.set_file_contents(f'temp1/temp2/temp3/{file_name}', file_data)
    try:
        afc_shell.app_cmd('cd temp1')
        out = afc_shell.app_cmd(f'pull temp2/temp3/{file_name} {tmp_path.absolute()}')
        assert not out.stderr
        assert (tmp_path / file_name).read_bytes() == file_data
    finally:
        afc_shell.afc.rm('temp1')


def test_pull_after_cd_single_file_with_rename(afc_shell, tmp_path: Path):
    """
    source:
    temp1
    └── temp.txt

    cd temp1
    pull temp.txt target/temp1.txt

    target
    └── temp1.txt
    """
    file_name = 'temp.txt'
    file_rename = 'temp1.txt'
    file_data = b'data'
    afc_shell.afc.makedirs('temp1')
    afc_shell.afc.set_file_contents(f'temp1/{file_name}', file_data)
    try:
        afc_shell.app_cmd('cd temp1')
        out = afc_shell.app_cmd(f'pull {file_name} {(tmp_path / file_rename).absolute()}')
        assert not out.stderr
        assert (tmp_path / file_rename).read_bytes() == file_data
    finally:
        afc_shell.afc.rm('temp1')


def test_pull_after_cd_recursive(afc_shell, tmp_path: Path):
    """
    source:
    temp1
    └── temp2
        └── temp3
            ├── temp4
            │   └── temp1.txt
            └── temp.txt

    cd temp1/temp2
    pull temp3 target

    target
    └── temp3
        ├── temp4
        │   └── temp1.txt
        └── temp.txt
    """
    file_name = 'temp.txt'
    file_name1 = 'temp.txt'
    file_data = b'data'
    file_data1 = b'data1'
    afc_shell.afc.makedirs('temp1/temp2/temp3/temp4')
    afc_shell.afc.set_file_contents(f'temp1/temp2/temp3/{file_name}', file_data)
    afc_shell.afc.set_file_contents(f'temp1/temp2/temp3/temp4/{file_name1}', file_data1)
    try:
        afc_shell.app_cmd('cd temp1/temp2')
        out = afc_shell.app_cmd(f'pull temp3 {tmp_path.absolute()}')
        assert not out.stderr
        assert (tmp_path / 'temp3' / file_name).read_bytes() == file_data
        assert len(list((tmp_path / 'temp3').iterdir())) == 2
        assert (tmp_path / 'temp3' / 'temp4' / file_name1).read_bytes() == file_data1
        assert len(list((tmp_path / 'temp3' / 'temp4').iterdir())) == 1
    finally:
        afc_shell.afc.rm('temp1')


def test_pull_after_cd_recursive_current(afc_shell, tmp_path: Path):
    """
    source:
    temp1
    └── temp2
        └── temp3
            ├── temp4
            │   └── temp1.txt
            └── temp.txt

    cd temp1/temp2/temp3
    pull . target

    target
    ├── temp4
    │   └── temp1.txt
    └── temp.txt
    """
    file_name = 'temp.txt'
    file_name1 = 'temp1.txt'
    file_data = b'data'
    file_data1 = b'data1'
    afc_shell.afc.makedirs('temp1/temp2/temp3/temp4')
    afc_shell.afc.set_file_contents(f'temp1/temp2/temp3/{file_name}', file_data)
    afc_shell.afc.set_file_contents(f'temp1/temp2/temp3/temp4/{file_name1}', file_data1)
    try:
        afc_shell.app_cmd('cd temp1/temp2/temp3')
        out = afc_shell.app_cmd(f'pull . {tmp_path.absolute()}')
        assert not out.stderr
        assert (tmp_path / file_name).read_bytes() == file_data
        assert len(list(tmp_path.iterdir())) == 2
        assert (tmp_path / 'temp4' / file_name1).read_bytes() == file_data1
        assert len(list((tmp_path / 'temp4').iterdir())) == 1
    finally:
        afc_shell.afc.rm('temp1')


def test_pull_after_cd_recursive_with_prefix(afc_shell, tmp_path: Path):
    """
    source:
    temp1
    └── temp2
        └── temp3
            ├── temp4
            │   └── temp1.txt
            └── temp.txt

    cd temp1
    pull temp2/temp3 target

    target
    └── temp3
        ├── temp4
        │   └── temp1.txt
        └── temp.txt
    """
    file_name = 'temp.txt'
    file_name1 = 'temp.txt'
    file_data = b'data'
    file_data1 = b'data1'
    afc_shell.afc.makedirs('temp1/temp2/temp3/temp4')
    afc_shell.afc.set_file_contents(f'temp1/temp2/temp3/{file_name}', file_data)
    afc_shell.afc.set_file_contents(f'temp1/temp2/temp3/temp4/{file_name1}', file_data1)
    try:
        afc_shell.app_cmd('cd temp1')
        out = afc_shell.app_cmd(f'pull temp2/temp3 {tmp_path.absolute()}')
        assert not out.stderr
        assert (tmp_path / 'temp3' / file_name).read_bytes() == file_data
        assert len(list((tmp_path / 'temp3').iterdir())) == 2
        assert (tmp_path / 'temp3' / 'temp4' / file_name1).read_bytes() == file_data1
        assert len(list((tmp_path / 'temp3' / 'temp4').iterdir())) == 1
    finally:
        afc_shell.afc.rm('temp1')


def test_push_after_cd_single_file_current(afc_shell, tmp_path: Path):
    """
    source:
    temp.txt

    cd target
    push source/temp.txt .

    target
    └── temp.txt
    """
    file_name = 'temp.txt'
    file_data = b'data'
    source_file = (tmp_path / file_name)
    source_file.write_bytes(file_data)
    afc_shell.afc.makedirs('temp1')
    afc_shell.app_cmd('cd temp1')
    try:
        out = afc_shell.app_cmd(f'push {source_file} .')
        assert not out.stderr
        assert afc_shell.afc.get_file_contents(f'temp1/{file_name}') == file_data
    finally:
        afc_shell.afc.rm('temp1')


def test_push_after_cd_single_file_with_prefix(afc_shell, tmp_path: Path):
    """
    source:
    temp.txt

    cd temp1/temp2
    push source/temp.txt temp3/temp.txt

    target
    temp1
    └── temp2
        └── temp3
            └── temp.txt
    """
    file_name = 'temp.txt'
    file_data = b'data'
    source_file = (tmp_path / file_name)
    source_file.write_bytes(file_data)
    afc_shell.afc.makedirs('temp1/temp2/temp3')
    afc_shell.app_cmd('cd temp1/temp2')
    try:
        out = afc_shell.app_cmd(f'push {source_file} temp3/{file_name}')
        assert not out.stderr
        assert afc_shell.afc.get_file_contents(f'temp1/temp2/temp3/{file_name}') == file_data
    finally:
        afc_shell.afc.rm('temp1')


def test_push_after_cd_single_file_with_rename(afc_shell, tmp_path: Path):
    """
    source:
    temp.txt

    cd temp1
    push source/temp.txt temp1.txt

    target
    temp1
    └── temp1.txt
    """
    file_name = 'temp.txt'
    file_rename = 'temp1.txt'
    file_data = b'data'
    source_file = (tmp_path / file_name)
    source_file.write_bytes(file_data)
    afc_shell.afc.makedirs('temp1')
    afc_shell.app_cmd('cd temp1')
    try:
        out = afc_shell.app_cmd(f'push {source_file} {file_rename}')
        assert not out.stderr
        assert afc_shell.afc.get_file_contents(f'temp1/{file_rename}') == file_data
    finally:
        afc_shell.afc.rm('temp1')


def test_push_after_cd_recursive_current(afc_shell, tmp_path: Path):
    """
    source:
    temp2
    └── temp3
        ├── temp4
        │   └── temp1.txt
        └── temp.txt

    mkdir temp1
    cd temp1
    push temp2 .

    temp1
    └── temp2
        └── temp3
            ├── temp4
            │   └── temp1.txt
            └── temp.txt
    """
    (tmp_path / 'temp2' / 'temp3' / 'temp4').mkdir(parents=True)
    (tmp_path / 'temp2' / 'temp3' / 'temp.txt').write_bytes(b'data')
    (tmp_path / 'temp2' / 'temp3' / 'temp4' / 'temp1.txt').write_bytes(b'data1')
    source_file = tmp_path / 'temp2'
    afc_shell.afc.makedirs('temp1')
    afc_shell.app_cmd('cd temp1')
    try:
        out = afc_shell.app_cmd(f'push {source_file} .')
        assert not out.stderr
        assert afc_shell.afc.get_file_contents('temp1/temp2/temp3/temp.txt') == b'data'
        assert afc_shell.afc.get_file_contents('temp1/temp2/temp3/temp4/temp1.txt') == b'data1'
    finally:
        afc_shell.afc.rm('temp1')


def test_push_after_cd_recursive_with_slash_current(afc_shell, tmp_path: Path):
    """
    source:
    temp2
    └── temp3
        ├── temp4
        │   └── temp1.txt
        └── temp.txt

    mkdir temp1
    cd temp1
    push temp2/ .

    temp1
    └── temp3
        ├── temp4
        │   └── temp1.txt
        └── temp.txt
    """
    (tmp_path / 'temp2' / 'temp3' / 'temp4').mkdir(parents=True)
    (tmp_path / 'temp2' / 'temp3' / 'temp.txt').write_bytes(b'data')
    (tmp_path / 'temp2' / 'temp3' / 'temp4' / 'temp1.txt').write_bytes(b'data1')
    source_file = tmp_path / 'temp2'
    afc_shell.afc.makedirs('temp1')
    afc_shell.app_cmd('cd temp1')
    try:
        out = afc_shell.app_cmd(f'push {source_file}/ .')
        assert not out.stderr
        assert afc_shell.afc.get_file_contents('temp1/temp3/temp.txt') == b'data'
        assert afc_shell.afc.get_file_contents('temp1/temp3/temp4/temp1.txt') == b'data1'
    finally:
        afc_shell.afc.rm('temp1')


def test_push_after_cd_recursive_with_prefix(afc_shell, tmp_path: Path):
    """
    source:
    temp2
    └── temp3
        ├── temp4
        │   └── temp1.txt
        └── temp.txt

    mkdir temp1/temp1a/temp1b
    cd temp1
    push temp2 temp1a/temp1b

    temp1
    └── temp1a
        └── temp1b
            └── temp2
                └── temp3
                    ├── temp4
                    │   └── temp1.txt
                    └── temp.txt
    """
    (tmp_path / 'temp2' / 'temp3' / 'temp4').mkdir(parents=True)
    (tmp_path / 'temp2' / 'temp3' / 'temp.txt').write_bytes(b'data')
    (tmp_path / 'temp2' / 'temp3' / 'temp4' / 'temp1.txt').write_bytes(b'data1')
    source_file = tmp_path / 'temp2'
    afc_shell.afc.makedirs('temp1/temp1a/temp1b')
    afc_shell.app_cmd('cd temp1')
    try:
        out = afc_shell.app_cmd(f'push {source_file} temp1a/temp1b')
        assert not out.stderr
        assert afc_shell.afc.get_file_contents('temp1/temp1a/temp1b/temp2/temp3/temp.txt') == b'data'
        assert afc_shell.afc.get_file_contents('temp1/temp1a/temp1b/temp2/temp3/temp4/temp1.txt') == b'data1'
    finally:
        afc_shell.afc.rm('temp1')
