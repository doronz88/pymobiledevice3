import os
import subprocess
import sys


def test_the_cli_highlights_the_commands_its_messages_name() -> None:
    # In a subprocess: the log handler is installed on import, on the process's root logger
    code = (
        "import logging, pymobiledevice3.__main__\n"
        "logging.getLogger('pymobiledevice3.tests').info('run `pymobiledevice3 mounter auto-mount` first')\n"
    )
    env = {**os.environ, "FORCE_COLOR": "1"}
    env.pop("NO_COLOR", None)
    stderr = subprocess.run([sys.executable, "-c", code], check=True, capture_output=True, text=True, env=env).stderr

    assert "run \x1b[0m\x1b[1;36m`pymobiledevice3 mounter auto-mount`\x1b[0m first" in stderr


def test_plain_output_names_the_command_as_before() -> None:
    code = (
        "import logging, pymobiledevice3.__main__\n"
        "logging.getLogger('pymobiledevice3.tests').info('run `pymobiledevice3 mounter auto-mount` first')\n"
    )
    env = {**os.environ, "NO_COLOR": "1"}
    env.pop("FORCE_COLOR", None)
    stderr = subprocess.run([sys.executable, "-c", code], check=True, capture_output=True, text=True, env=env).stderr

    assert stderr.rstrip().endswith("INFO run `pymobiledevice3 mounter auto-mount` first")
