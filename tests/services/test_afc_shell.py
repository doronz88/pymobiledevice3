import os
import pathlib
import sys
from pathlib import Path
from unittest import mock

import pytest
from cmd2 import CommandResult
from cmd2_ext_test import ExternalTestMixin

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


def get_completions(line: str, part: str, app: AfcShellTester) -> list[str]:
    if sys.platform in ['win32', 'cygwin']:
        import readline
    else:
        import gnureadline as readline

    with mock.patch.object(readline, 'get_line_buffer', lambda: line):
        with mock.patch.object(readline, 'get_begidx', lambda: len(line) - len(part)):
            with mock.patch.object(readline, 'get_endidx', lambda: len(line)):
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


def test_ls(afc_shell):
    out = afc_shell.app_cmd('ls')
    assert isinstance(out, CommandResult)
    filenames = str(out.stdout).strip().splitlines()
    assert 'DCIM' in filenames
    assert 'Downloads' in filenames
    assert 'Books' in filenames


class TestPull:
    FILE_NAME = 'temp.txt'
    FILE_NAME1 = 'temp1.txt'
    FILE_DATA = b'data'
    FILE_DATA1 = b'data1'
    TEMP1 = 'temp1'
    TEMP2 = 'temp2'
    TEMP3 = 'temp3'
    TEMP4 = 'temp4'

    @pytest.fixture()
    def make_temp_dirs_and_files(self, afc_shell):
        """
        source:
        temp1
        └── temp2
            └── temp3
                ├── temp.txt
                └── temp4
                    └── temp1.txt
        """
        full_path = f'{self.TEMP1}/{self.TEMP2}/{self.TEMP3}/{self.TEMP4}'
        afc_shell.afc.makedirs(full_path)
        afc_shell.afc.set_file_contents(f'{self.TEMP1}/{self.TEMP2}/{self.TEMP3}/{self.FILE_NAME}', self.FILE_DATA)
        afc_shell.afc.set_file_contents(f'{full_path}/{self.FILE_NAME1}', self.FILE_DATA1)
        yield
        afc_shell.afc.rm(self.TEMP1)

    def test_pull_completion(self, afc_shell, tmp_path: Path):
        completions = get_completions('pull D', 'D', afc_shell)
        assert 'DCIM' in completions
        assert 'Downloads' in completions
        assert 'Books' not in completions

        (tmp_path / 'temp1.txt').write_text('hey1')
        (tmp_path / 'temp2.txt').write_text('hey2')
        assert get_completions(f'pull DCIM {tmp_path}', str(tmp_path), afc_shell) == [f'{tmp_path} ']
        assert get_completions(f'pull DCIM {tmp_path}/', f'{tmp_path}{os.path.sep}', afc_shell) == \
               [f'{tmp_path}{os.path.sep}temp1.txt', f'{tmp_path}{os.path.sep}temp2.txt']

    def test_pull_afc_file_not_found_error(self, afc_shell, tmp_path: Path):
        """
        Raises: AfcFileNotFoundError
        """
        out = afc_shell.app_cmd(f'pull {self.FILE_NAME} {tmp_path.absolute()}')
        assert 'AfcFileNotFoundError' in out.stderr

    def test_pull_file_to_non_exists_folder(self, afc_shell, tmp_path: Path, make_temp_dirs_and_files):
        """
        Raises: NotADirectoryError
        """
        dst = f'{tmp_path}/temp1/'
        out = afc_shell.app_cmd(
            f'pull {self.TEMP1}/{self.TEMP2}/{self.TEMP3}/{self.FILE_NAME} {dst}')
        assert 'NotADirectoryError' in out.stderr
        assert f'pull: directory {pathlib.PurePosixPath(dst)} does not exist' in out.stderr

    def test_pull_file_to_folder_with_slash(self, afc_shell, tmp_path: Path, make_temp_dirs_and_files):
        """
        cd temp3
        pull temp.txt target/

        target
        └── temp.txt
        """
        afc_shell.app_cmd(f'cd {self.TEMP1}/{self.TEMP2}/{self.TEMP3}')
        out = afc_shell.app_cmd(f'pull {self.FILE_NAME} {tmp_path.absolute()}/')
        assert not out.stderr
        assert len(list(tmp_path.iterdir())) == 1
        assert (tmp_path / self.FILE_NAME).read_bytes() == self.FILE_DATA

    def test_pull_file_with_prefix_to_folder(self, afc_shell, tmp_path: Path, make_temp_dirs_and_files):
        """
        cd temp1
        pull temp2/temp3/temp.txt target

        target
        └── temp.txt
        """
        afc_shell.app_cmd(f'cd {self.TEMP1}')
        out = afc_shell.app_cmd(f'pull {self.TEMP2}/{self.TEMP3}/{self.FILE_NAME} {tmp_path.absolute()}')
        assert not out.stderr
        assert len(list(tmp_path.iterdir())) == 1
        assert (tmp_path / self.FILE_NAME).read_bytes() == self.FILE_DATA

    def test_pull_file_to_current_folder(self, afc_shell, tmp_path: Path, make_temp_dirs_and_files):
        """
        cd temp3
        pull temp.txt .

        target
        └── temp.txt
        """
        afc_shell.app_cmd(f'cd {self.TEMP1}/{self.TEMP2}/{self.TEMP3}')
        os.chdir(tmp_path)
        out = afc_shell.app_cmd(f'pull {self.FILE_NAME} .')
        assert not out.stderr
        assert len(list(tmp_path.iterdir())) == 1
        file = pathlib.Path(self.FILE_NAME)
        assert file.read_bytes() == self.FILE_DATA

    def test_pull_file_to_new_file_name(self, afc_shell, tmp_path: Path, make_temp_dirs_and_files):
        """
        cd temp3
        pull temp.txt temp1.txt

        target
        └── temp1.txt
        """
        afc_shell.app_cmd(f'cd {self.TEMP1}/{self.TEMP2}/{self.TEMP3}')
        os.chdir(tmp_path)
        out = afc_shell.app_cmd(f'pull {self.FILE_NAME} {self.FILE_NAME1}')
        assert not out.stderr
        assert len(list(tmp_path.iterdir())) == 1
        file = pathlib.Path(self.FILE_NAME1)
        assert file.read_bytes() == self.FILE_DATA

    def test_pull_file_to_new_file_name_in_folder(self, afc_shell, tmp_path: Path, make_temp_dirs_and_files):
        """
        cd temp3
        pull temp.txt target/temp1.txt

        target
        └── temp1.txt
        """
        new_file_path = tmp_path / self.FILE_NAME1
        afc_shell.app_cmd(f'cd {self.TEMP1}/{self.TEMP2}/{self.TEMP3}')
        out = afc_shell.app_cmd(f'pull {self.FILE_NAME} {new_file_path.absolute()}')
        assert not out.stderr
        assert len(list(tmp_path.iterdir())) == 1
        assert new_file_path.read_bytes() == self.FILE_DATA

    def test_pull_file_content_to_existing_file(self, afc_shell, tmp_path: Path, make_temp_dirs_and_files):
        """
        cd temp3
        pull temp.txt target/temp1.txt

        target
        └── temp1.txt
        """
        exist_file = tmp_path / self.FILE_NAME1
        exist_file.touch()
        afc_shell.app_cmd(f'cd {self.TEMP1}/{self.TEMP2}/{self.TEMP3}')
        out = afc_shell.app_cmd(f'pull {self.FILE_NAME} {exist_file.absolute()}')
        assert not out.stderr
        assert len(list(tmp_path.iterdir())) == 1
        assert exist_file.read_bytes() == self.FILE_DATA

    def test_pull_folder_to_existing_file(self, afc_shell, tmp_path, make_temp_dirs_and_files):
        """
        pull temp1 target/temp.txt

        Raises: IsADirectoryError
        """
        new_file_path = tmp_path / self.FILE_NAME
        new_file_path.touch()
        src = self.TEMP1
        out = afc_shell.app_cmd(f'pull {src} {new_file_path.absolute()}')
        assert 'IsADirectoryError' in out.stderr
        assert f'pull: {afc_shell.curdir}{src} is a directory (not copied).' in out.stderr

    def test_pull_folder_to_folder(self, afc_shell, tmp_path: Path, make_temp_dirs_and_files):
        """
        cd temp1/temp2
        pull temp3 target

        target
        └── temp3
            ├── temp.txt
            └── temp4
                └── temp1.txt
        """
        afc_shell.app_cmd(f'cd {self.TEMP1}/{self.TEMP2}')
        out = afc_shell.app_cmd(f'pull {self.TEMP3} {tmp_path.absolute()}')
        assert not out.stderr
        assert len(list(tmp_path.iterdir())) == 1

        temp3 = tmp_path / self.TEMP3
        assert len(list(temp3.iterdir())) == 2
        assert (temp3 / self.FILE_NAME).read_bytes() == self.FILE_DATA

        temp4 = temp3 / self.TEMP4
        assert len(list(temp4.iterdir())) == 1
        assert (temp4 / self.FILE_NAME1).read_bytes() == self.FILE_DATA1

    def test_pull_current_folder_to_folder(self, afc_shell, tmp_path: Path, make_temp_dirs_and_files):
        """
        cd temp1/temp2/temp3
        pull . target

        target
        └── temp3
            ├── temp.txt
            └── temp4
                └── temp1.txt
        """
        afc_shell.app_cmd(f'cd {self.TEMP1}/{self.TEMP2}/{self.TEMP3}')
        out = afc_shell.app_cmd(f'pull . {tmp_path.absolute()}')
        assert not out.stderr
        assert len(list(tmp_path.iterdir())) == 1

        temp3 = tmp_path / self.TEMP3
        assert len(list(temp3.iterdir())) == 2
        assert (temp3 / self.FILE_NAME).read_bytes() == self.FILE_DATA

        temp4 = temp3 / self.TEMP4
        assert len(list(temp4.iterdir())) == 1
        assert (temp4 / self.FILE_NAME1).read_bytes() == self.FILE_DATA1

    def test_pull_folder_with_prefix_to_folder(self, afc_shell, tmp_path: Path, make_temp_dirs_and_files):
        """
        cd temp1
        pull temp2/temp3 target

        target
        └── temp3
            ├── temp.txt
            └── temp4
                └── temp1.txt
        """
        afc_shell.app_cmd(f'cd {self.TEMP1}')
        out = afc_shell.app_cmd(f'pull {self.TEMP2}/{self.TEMP3} {tmp_path.absolute()}')
        assert not out.stderr
        assert len(list(tmp_path.iterdir())) == 1

        temp3 = tmp_path / self.TEMP3
        assert len(list(temp3.iterdir())) == 2
        assert (temp3 / self.FILE_NAME).read_bytes() == self.FILE_DATA

        temp4 = temp3 / self.TEMP4
        assert len(list(temp4.iterdir())) == 1
        assert (temp4 / self.FILE_NAME1).read_bytes() == self.FILE_DATA1

    def test_pull_folder_with_slash_to_non_exists_folder(self, afc_shell, tmp_path: Path, make_temp_dirs_and_files):
        """
        cd temp1/temp2
        pull temp3/ target

        target
        └── temp1
            ├── temp.txt
            └── temp4
                └── temp1.txt
        """
        afc_shell.app_cmd(f'cd {self.TEMP1}/{self.TEMP2}')
        os.chdir(tmp_path)
        out = afc_shell.app_cmd(f'pull {self.TEMP3}/ {self.TEMP1}')
        assert not out.stderr
        assert len(list(tmp_path.iterdir())) == 1

        temp1 = tmp_path / self.TEMP1
        assert len(list(temp1.iterdir())) == 2
        assert (temp1 / self.FILE_NAME).read_bytes() == self.FILE_DATA

        temp4 = temp1 / self.TEMP4
        assert len(list(temp4.iterdir())) == 1
        assert (temp4 / self.FILE_NAME1).read_bytes() == self.FILE_DATA1

    def test_pull_folder_with_slash_to_folder(self, afc_shell, tmp_path: Path, make_temp_dirs_and_files):
        """
        cd temp1/temp2
        pull temp3/ target

        target
        ├── temp.txt
        └── temp4
            └── temp1.txt
        """
        afc_shell.app_cmd(f'cd {self.TEMP1}/{self.TEMP2}')
        out = afc_shell.app_cmd(f'pull {self.TEMP3}/ {tmp_path.absolute()}')
        assert not out.stderr
        assert len(list(tmp_path.iterdir())) == 2
        assert (tmp_path / self.FILE_NAME).read_bytes() == self.FILE_DATA

        temp4 = tmp_path / self.TEMP4
        assert len(list(temp4.iterdir())) == 1
        assert (temp4 / self.FILE_NAME1).read_bytes() == self.FILE_DATA1

    def test_pull_folder_to_not_exists_path(self, afc_shell, tmp_path, make_temp_dirs_and_files):
        """
        Raises: FileNotFoundError
        """
        dst = f'{tmp_path}/temp1/temp2'
        out = afc_shell.app_cmd(f'pull {self.TEMP1} {dst}')
        assert 'FileNotFoundError' in out.stderr
        assert f'pull: {dst}: No such file or directory' in out.stderr


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
