import inspect

import pytest

from pymobiledevice3.cli.developer.dvt import core_profile_session


@pytest.mark.parametrize("command", ["parse_live_profile_session", "callstacks_live_profile_session"])
def test_live_commands_stream_endlessly_by_default(command: str) -> None:
    # The count is passed to itertools.islice, which rejects -1 as "no limit".
    count = inspect.signature(getattr(core_profile_session, command)).parameters["count"]
    assert count.default is None
