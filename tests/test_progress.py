import logging
import sys

import pytest

from pymobiledevice3 import progress
from pymobiledevice3.progress import BYTES_UNIT, ProgressBar, track, trange


def test_trange_yields_the_range() -> None:
    assert list(trange(0, 10, 3)) == [0, 3, 6, 9]
    assert list(trange(4)) == [0, 1, 2, 3]


def test_track_advances_once_per_item() -> None:
    seen = []
    for item in track("abc"):
        seen.append(item)
        assert progress._display._progress is not None
    assert seen == ["a", "b", "c"]
    assert progress._display._progress is None


def test_disabled_bar_never_starts_a_display() -> None:
    with ProgressBar(total=10, disable=True) as bar:
        bar.update(4)
        bar.n = 7
        assert bar.n == 7
        assert progress._display._progress is None
    assert list(track(range(3), disable=True)) == [0, 1, 2]


def test_concurrent_bars_share_one_display() -> None:
    with ProgressBar(total=100, desc="outer") as outer:
        display = progress._display._progress
        with ProgressBar(total=1024, desc="inner", unit=BYTES_UNIT) as inner:
            assert progress._display._progress is display
            inner.update(512)
            assert display is not None
            assert [task.completed for task in display.tasks] == [0, 512]
        outer.n = 50
        assert [task.completed for task in display.tasks] == [50]
        assert progress._display._progress is display
    assert progress._display._progress is None


def test_fixed_stream_log_handlers_print_above_the_bars(monkeypatch: pytest.MonkeyPatch) -> None:
    # Rich only redirects stdio for terminals.
    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.setenv("TTY_COMPATIBLE", "1")
    logger = logging.getLogger("pymobiledevice3.tests.progress")
    handler = logging.StreamHandler(sys.__stderr__)
    logger.addHandler(handler)
    try:
        with ProgressBar(total=1):
            assert sys.stderr is not sys.__stderr__
            assert handler.stream is sys.stderr
        assert handler.stream is sys.__stderr__
    finally:
        logger.removeHandler(handler)


def test_bars_finishing_under_a_running_bar_leave_the_live_display() -> None:
    with ProgressBar(total=100, desc="filesystem") as outer:
        display = progress._display._progress
        assert display is not None
        for name in ("iBEC", "BasebandData"):
            with ProgressBar(total=1, desc=name) as inner:
                inner.update()
        outer.update(10)
        assert [task.description for task in display.tasks] == ["filesystem"]


def test_rapid_updates_are_coalesced_and_flushed(monkeypatch: pytest.MonkeyPatch) -> None:
    now = [1000.0]
    monkeypatch.setattr(progress.time, "monotonic", lambda: now[0])
    with ProgressBar(total=100, desc="burst") as bar:
        display = progress._display._progress
        assert display is not None
        bar.update(1)
        bar.update(1)
        bar.update(1)
        # Only the first of a burst reaches rich; the rest wait for the next interval.
        assert [task.completed for task in display.tasks] == [1]
        now[0] += 2 * progress._MIN_UPDATE_INTERVAL
        bar.update(1)
        assert [task.completed for task in display.tasks] == [4]
        bar.update(1)
        (task,) = display.tasks
        bar.close()
        # Closing flushes the latest position.
        assert task.completed == 5


def test_reaching_total_is_pushed_immediately(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(progress.time, "monotonic", lambda: 1000.0)
    with ProgressBar(total=10, desc="done") as bar:
        display = progress._display._progress
        assert display is not None
        bar.update(1)
        bar.update(9)
        assert [task.completed for task in display.tasks] == [10]


def test_ansilogs_records_go_through_the_live_display(monkeypatch: pytest.MonkeyPatch) -> None:
    import io

    import ansilogs

    # Rich only redirects stdio for terminals.
    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.setenv("TTY_COMPATIBLE", "1")
    terminal = io.StringIO()
    monkeypatch.setattr(sys, "stderr", terminal)
    logger = logging.getLogger("pymobiledevice3.tests.progress.ansilogs")
    handler = ansilogs.StderrHandler()
    handler.setFormatter(ansilogs.ColoredFormatter(colors=False))
    logger.addHandler(handler)
    try:
        with ProgressBar(total=1, desc="bar"):
            proxy = sys.stderr
            assert proxy is not terminal
            logger.warning("above the bar")
        assert sys.stderr is terminal
    finally:
        logger.removeHandler(handler)
    assert "WARNING above the bar" in terminal.getvalue()
