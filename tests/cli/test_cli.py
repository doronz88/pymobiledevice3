import subprocess
import sys

import pytest
from click.testing import CliRunner

from pymobiledevice3 import __main__

pytestmark = [pytest.mark.cli]


def test_cli_main_interface():
    runner = CliRunner()
    r1 = runner.invoke(__main__.cli, ['--help'])
    assert r1.exit_code == 0

    r2 = runner.invoke(__main__.cli)
    assert r2.exit_code == 0


@pytest.mark.parametrize('keyword,suggestions', [
    ('kill', ['dvt kill', 'dvt pkill']),
    ('sysdi', ['crash sysdiagnose']),
    ('shell', ['accessibility shell', 'afc shell', 'crash shell', 'developer shell', 'dvt shell', 'restore shell',
               'springboard shell', 'webinspector js-shell', 'webinspector shell'])
])
def test_cli_suggestions(keyword, suggestions):
    output = subprocess.run([sys.executable, '-m', 'pymobiledevice3', keyword], capture_output=True, text=True)
    for suggestion in suggestions:
        assert suggestion in output.stderr


@pytest.mark.parametrize('group', __main__.CLI_GROUPS.keys())
def test_cli_groups(group):
    runner = CliRunner()
    group_help_result = runner.invoke(__main__.cli, [group, '--help'])
    assert group_help_result.exit_code == 0


@pytest.mark.parametrize('group', __main__.CLI_GROUPS.keys())
def test_cli_from_python_m_flag(group):
    subprocess.run([sys.executable, '-m', 'pymobiledevice3', group, '--help'], check=True)
