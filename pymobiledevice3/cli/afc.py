import click
import sys
import os
import tempfile
import logging
import shlex
import hexdump
import posixpath
import pathlib
from click.exceptions import Exit
from cmd2 import Cmd, Cmd2ArgumentParser, with_argparser
from pygments import formatters, highlight, lexers
from pygnuutils.cli.ls import ls as ls_cli
from pygnuutils.ls import Ls, LsStub
from pymobiledevice3.utils import try_decode
from pymobiledevice3.services.afc import AfcService, LockdownClient, afc_link_type_t
from pymobiledevice3.cli.cli_common import Command
from pymobiledevice3.lockdown import LockdownClient

pwd_parser = Cmd2ArgumentParser(description='print working directory')

link_parser = Cmd2ArgumentParser(description='create a symlink')
link_parser.add_argument('target')
link_parser.add_argument('source')

edit_parser = Cmd2ArgumentParser(description='edit a given file on remote')
edit_parser.add_argument('filename')

cd_parser = Cmd2ArgumentParser(description='change working directory')
cd_parser.add_argument('directory')

walk_parser = Cmd2ArgumentParser(
    description='traverse all entries from given path recursively (by default, from current working directory)')
walk_parser.add_argument('directory', default='.', nargs='?')

cat_parser = Cmd2ArgumentParser(description='print given filename contents')
cat_parser.add_argument('filename')

rm_parser = Cmd2ArgumentParser(description='remove given entries')
rm_parser.add_argument('files', nargs='+')

pull_parser = Cmd2ArgumentParser(description='pull an entry from given path into a local existing directory')
pull_parser.add_argument('remote_path')
pull_parser.add_argument('local_path')

push_parser = Cmd2ArgumentParser(description='push an entry from a given local path into remote device at a given path')
push_parser.add_argument('local_path')
push_parser.add_argument('remote_path')

head_parser = Cmd2ArgumentParser(description='print first 32 characters of a given entry')
head_parser.add_argument('filename')

hexdump_parser = Cmd2ArgumentParser(description='print a full hexdump of a given entry')
hexdump_parser.add_argument('filename')

mkdir_parser = Cmd2ArgumentParser(description='create a directory at a given path')
mkdir_parser.add_argument('filename')

info_parser = Cmd2ArgumentParser(description='print device info')

mv_parser = Cmd2ArgumentParser(description='move a file from a given source to a given destination')
mv_parser.add_argument('source')
mv_parser.add_argument('dest')

stat_parser = Cmd2ArgumentParser(description='print information on a given file')
stat_parser.add_argument('filename')


class AfcLsStub(LsStub):
    def __init__(self, afc_shell):
        self.afc_shell = afc_shell

    @property
    def sep(self):
        return posixpath.sep

    def join(self, path, *paths):
        return posixpath.join(path, *paths)

    def abspath(self, path):
        return posixpath.normpath(path)

    def stat(self, path, dir_fd=None, follow_symlinks=True):
        if follow_symlinks:
            path = self.afc_shell.afc.resolve_path(path)
        return self.afc_shell.afc.os_stat(path)

    def readlink(self, path, dir_fd=None):
        return self.afc_shell.afc.resolve_path(path)

    def isabs(self, path):
        return posixpath.isabs(path)

    def dirname(self, path):
        return posixpath.dirname(path)

    def basename(self, path):
        return posixpath.basename(path)

    def getgroup(self, st_gid):
        return '-'

    def getuser(self, st_uid):
        return '-'

    def now(self):
        return self.afc_shell.lockdown.date

    def listdir(self, path='.'):
        return self.afc_shell.afc.listdir(path)

    def system(self):
        return 'Darwin'

    def getenv(self, key, default=None):
        return ''

    def print(self, *objects, sep=' ', end='\n', file=sys.stdout, flush=False):
        self.afc_shell.poutput(objects[0], end=end)


class AfcShell(Cmd):
    def __init__(self, lockdown: LockdownClient, service_name='com.apple.afc', completekey='tab', afc_service=None):
        # bugfix: prevent the Cmd instance from trying to parse click's arguments
        sys.argv = sys.argv[:1]

        Cmd.__init__(self,
                     completekey=completekey,
                     persistent_history_file=os.path.join(tempfile.gettempdir(), f'.{service_name}-history'))
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown
        self.service_name = service_name
        self.afc = afc_service or AfcService(self.lockdown, service_name=service_name)
        self.curdir = '/'
        self.complete_edit = self._complete_first_arg
        self.complete_cd = self._complete_first_arg
        self.complete_ls = self._complete
        self.complete_walk = self._complete_first_arg
        self.complete_cat = self._complete_first_arg
        self.complete_rm = self._complete_first_arg
        self.complete_pull = self._complete_pull_arg
        self.complete_push = self._complete_push_arg
        self.complete_head = self._complete_first_arg
        self.complete_hexdump = self._complete_first_arg
        self.complete_mv = self._complete
        self.complete_stat = self._complete_first_arg
        self.ls = Ls(AfcLsStub(self))
        self.aliases['ll'] = 'ls -lh'
        self.aliases['l'] = 'ls -lah'
        self._update_prompt()

    @with_argparser(pwd_parser)
    def do_pwd(self, args):
        self.poutput(self.curdir)

    @with_argparser(link_parser)
    def do_link(self, args):
        self.afc.link(self.relative_path(args.target), self.relative_path(args.source), afc_link_type_t.SYMLINK)

    @with_argparser(edit_parser)
    def do_edit(self, args) -> None:
        remote = self.relative_path(args.filename)
        with tempfile.NamedTemporaryFile('wb+') as local:
            if self.afc.exists(remote):
                local.write(self.afc.get_file_contents(remote))
                local.seek(0, os.SEEK_SET)

            self.run_editor(local.name)
            buf = open(local.name, 'rb').read()
            self.afc.set_file_contents(remote, buf)

    @with_argparser(cd_parser)
    def do_cd(self, args):
        directory = self.relative_path(args.directory)
        directory = posixpath.normpath(directory)
        if self.afc.exists(directory):
            self.curdir = directory
            self._update_prompt()
        else:
            self.poutput(f'[ERROR] {directory} does not exist')

    def help_ls(self):
        try:
            with ls_cli.make_context('ls', ['--help']):
                pass
        except Exit:
            pass

    def do_ls(self, args):
        try:
            with ls_cli.make_context('ls', shlex.split(args)) as ctx:
                files = list(map(self.relative_path, ctx.params.pop('files')))
                files = files if files else [self.curdir]
                self.ls(*files, **ctx.params)
        except Exit:
            pass

    @with_argparser(walk_parser)
    def do_walk(self, args):
        for root, dirs, files in self.afc.walk(self.relative_path(args.directory)):
            for name in files:
                self.poutput(posixpath.join(root, name))
            for name in dirs:
                self.poutput(posixpath.join(root, name))

    @with_argparser(cat_parser)
    def do_cat(self, args):
        data = self.afc.get_file_contents(self.relative_path(args.filename))
        self.ppaged(try_decode(data))

    @with_argparser(rm_parser)
    def do_rm(self, args):
        for filename in args.files:
            self.afc.rm(self.relative_path(filename))

    @with_argparser(pull_parser)
    def do_pull(self, args):
        def log(src, dst):
            self.poutput(f'{src} --> {dst}')

        self.afc.pull(args.remote_path, args.local_path, callback=log, src_dir=self.curdir)

    @with_argparser(push_parser)
    def do_push(self, args):
        def log(src, dst):
            self.poutput(f'{src} --> {dst}')

        self.afc.push(args.local_path, self.relative_path(args.remote_path), callback=log)

    @with_argparser(head_parser)
    def do_head(self, args):
        self.poutput(try_decode(self.afc.get_file_contents(self.relative_path(args.filename))[:32]))

    @with_argparser(hexdump_parser)
    def do_hexdump(self, args):
        self.poutput(hexdump.hexdump(self.afc.get_file_contents(self.relative_path(args.filename)), result='return'))

    @with_argparser(mkdir_parser)
    def do_mkdir(self, args):
        self.afc.makedirs(self.relative_path(args.filename))

    @with_argparser(info_parser)
    def do_info(self, args):
        for k, v in self.afc.get_device_info().items():
            self.poutput(f'{k}: {v}')

    @with_argparser(mv_parser)
    def do_mv(self, args):
        return self.afc.rename(self.relative_path(args.source), self.relative_path(args.dest))

    @with_argparser(stat_parser)
    def do_stat(self, args):
        for k, v in self.afc.stat(self.relative_path(args.filename)).items():
            self.poutput(f'{k}: {v}')

    def relative_path(self, filename):
        return posixpath.join(self.curdir, filename)

    def _update_prompt(self):
        self.prompt = highlight(f'[{self.service_name}:{self.curdir}]$ ', lexers.BashSessionLexer(),
                                formatters.TerminalTrueColorFormatter(style='solarized-dark')).strip()

    def _complete(self, text, line, begidx, endidx):
        curdir_diff = posixpath.dirname(text)
        dirname = posixpath.join(self.curdir, curdir_diff)
        prefix = posixpath.basename(text)
        return [
            str(posixpath.join(curdir_diff, filename)) for filename in self.afc.listdir(dirname)
            if filename.startswith(prefix)
        ]

    def _complete_first_arg(self, text, line, begidx, endidx):
        if self._count_completion_parts(line, begidx) > 1:
            return []
        return self._complete(text, line, begidx, endidx)

    def _complete_push_arg(self, text, line, begidx, endidx):
        count = self._count_completion_parts(line, begidx)
        if count == 1:
            return self._complete_local(text)
        elif count == 2:
            return self._complete(text, line, begidx, endidx)
        else:
            return []

    def _complete_pull_arg(self, text, line, begidx, endidx):
        count = self._count_completion_parts(line, begidx)
        if count == 1:
            return self._complete(text, line, begidx, endidx)
        elif count == 2:
            return self._complete_local(text)
        else:
            return []

    @staticmethod
    def _complete_local(text: str):
        path = pathlib.Path(text)
        path_iter = path.iterdir() if text.endswith(os.path.sep) else path.parent.iterdir()
        return [str(p) for p in path_iter if str(p).startswith(text)]

    @staticmethod
    def _count_completion_parts(line, begidx):
        # Strip the " for paths including spaces.
        return len(shlex.split(line[:begidx].rstrip('"')))


@click.group()
def cli():
    """ apps cli """
    pass


@cli.group()
def afc():
    """ FileSystem utils """
    pass


@afc.command('shell', cls=Command)
def afc_shell(lockdown: LockdownClient):
    """ open an AFC shell rooted at /var/mobile/Media """
    AfcShell(lockdown=lockdown, service_name='com.apple.afc').cmdloop()


@afc.command('pull', cls=Command)
@click.argument('remote_file', type=click.Path(exists=False))
@click.argument('local_file', type=click.File('wb'))
def afc_pull(lockdown: LockdownClient, remote_file, local_file):
    """ pull remote file from /var/mobile/Media """
    local_file.write(AfcService(lockdown=lockdown).get_file_contents(remote_file))


@afc.command('push', cls=Command)
@click.argument('local_file', type=click.File('rb'))
@click.argument('remote_file', type=click.Path(exists=False))
def afc_push(lockdown: LockdownClient, local_file, remote_file):
    """ push local file into /var/mobile/Media """
    AfcService(lockdown=lockdown).set_file_contents(remote_file, local_file.read())


@afc.command('ls', cls=Command)
@click.argument('remote_file', type=click.Path(exists=False))
@click.option('-r', '--recursive', is_flag=True)
def afc_ls(lockdown: LockdownClient, remote_file, recursive):
    """ perform a dirlist rooted at /var/mobile/Media """
    for path in AfcService(lockdown=lockdown).dirlist(remote_file, -1 if recursive else 1):
        print(path)


@afc.command('rm', cls=Command)
@click.argument('remote_file', type=click.Path(exists=False))
def afc_rm(lockdown: LockdownClient, remote_file):
    """ remove a file rooted at /var/mobile/Media """
    AfcService(lockdown=lockdown).rm(remote_file)
