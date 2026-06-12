from typer.testing import CliRunner

from pymobiledevice3 import __main__


def test_file_relay_list_sources() -> None:
    runner = CliRunner()

    result = runner.invoke(__main__.app, ["file-relay", "list-sources"])

    assert result.exit_code == 0
    assert "CrashReporter" in result.output
    assert "UserDatabases" in result.output
    assert "WiFi" in result.output


def test_file_relay_request_help() -> None:
    runner = CliRunner()

    result = runner.invoke(__main__.app, ["file-relay", "request", "--help"])

    assert result.exit_code == 0
    assert "--source" in result.output
    assert "--timeout" in result.output
    assert "--force" in result.output
    assert "--allow-unsupported" in result.output
