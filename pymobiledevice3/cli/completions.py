import logging
from collections import namedtuple
from pathlib import Path

import click
from plumbum import CommandNotFound, local

logger = logging.getLogger(__name__)

ShellCompletion = namedtuple('ShellCompletion', ['source', 'rc', 'path'])

COMPLETIONS = [
    ShellCompletion('zsh_source', Path('~/.zshrc').expanduser(), Path('~/.pymobiledevice3.zsh').expanduser()),
    ShellCompletion('bash_source', Path('~/.bashrc').expanduser(), Path('~/.pymobiledevice3.bash').expanduser()),
    ShellCompletion('fish_source', None, Path('~/.config/fish/completions/pymobiledevice3.fish').expanduser()),
]


@click.group()
def cli() -> None:
    pass


@cli.command()
def install_completions() -> None:
    """
    Install shell completions for the pymobiledevice3 command

    If supplying an explicit shell script to write, install it there, otherwise install globally.
    """
    try:
        pymobiledevice3 = local['pymobiledevice3']
    except CommandNotFound:
        logger.error('pymobiledevice3 main binary could not be found in your path.')
        return

    for completion in COMPLETIONS:
        with local.env(_PYMOBILEDEVICE3_COMPLETE=completion.source):
            if not completion.path.parent.exists():
                # fish is not installed, skip
                continue
            logger.info(f'Writing shell completions to: {completion.path}')
            completion.path.write_text(pymobiledevice3())
            line = f'source {completion.path}'

            if not completion.rc.exists() or line in completion.rc.read_text():
                continue

            logger.info(f'Adding source line to {completion.rc}')
            completion.rc.write_text(f'{completion.rc.read_text()}\n{line}')
