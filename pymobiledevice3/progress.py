"""
tqdm-shaped progress bars rendered with rich.

Every bar is a task on one shared rich ``Progress`` display on stderr, so concurrent bars stack
instead of fighting over the terminal, and the whole CLI renders progress the same way. While
any bar is visible, log records and ``print()`` output are drawn above the bars instead of
tearing through them: rich redirects ``sys.stdout``/``sys.stderr`` (which the CLI's ansilogs
handler resolves on every record), and logging handlers bound to a fixed stdio stream are pointed at
those redirections until the last bar closes.
"""

import logging
import sys
import threading
import time
from collections.abc import Iterable, Iterator, Sized
from types import TracebackType
from typing import IO, Any, Optional, TypeVar, cast

from rich import filesize
from rich.console import Console
from rich.progress import (
    BarColumn,
    DownloadColumn,
    MofNCompleteColumn,
    Progress,
    ProgressColumn,
    Task,
    TaskID,
    TaskProgressColumn,
    TextColumn,
    TimeRemainingColumn,
)
from rich.text import Text

_T = TypeVar("_T")

BYTES_UNIT = "B"
_REFRESH_PER_SECOND = 10
# Like tqdm's ``mininterval``: rich's per-update bookkeeping (a lock plus a speed sample) is several
# times tqdm's, so per-chunk updates on a fast transfer would cost real CPU. Forwarding a bar's
# position at twice the redraw rate keeps every redraw at most half a frame stale.
_MIN_UPDATE_INTERVAL = 0.5 / _REFRESH_PER_SECOND
_BINARY_SUFFIXES = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"]


class _AmountColumn(ProgressColumn):
    """``1.2/3.4 MiB`` for byte bars, ``12/34`` for everything else."""

    def __init__(self) -> None:
        super().__init__()
        self._bytes = DownloadColumn(binary_units=True)
        self._count = MofNCompleteColumn()

    def render(self, task: Task) -> Any:
        return (self._bytes if task.fields.get("unit") == BYTES_UNIT else self._count).render(task)


class _RateColumn(ProgressColumn):
    """Binary-unit transfer rate for byte bars (it doubles as a transfer benchmark), nothing otherwise."""

    def render(self, task: Task) -> Text:
        speed = task.finished_speed or task.speed
        if task.fields.get("unit") != BYTES_UNIT or speed is None:
            return Text()
        unit, suffix = filesize.pick_unit_and_suffix(int(speed), _BINARY_SUFFIXES, 1024)
        return Text(f"{speed / unit:.1f} {suffix}/s", style="progress.data.speed")


class _SharedDisplay:
    """Reference-counted rich ``Progress`` that is live only while at least one bar is open."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._progress: Optional[Progress] = None
        self._users = 0
        self._retargeted: list[tuple[logging.StreamHandler[IO[str]], IO[str]]] = []

    def acquire(self) -> Progress:
        with self._lock:
            if self._progress is None:
                self._progress = Progress(
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TaskProgressColumn(),
                    _AmountColumn(),
                    _RateColumn(),
                    TimeRemainingColumn(elapsed_when_finished=True),
                    console=Console(stderr=True),
                    refresh_per_second=_REFRESH_PER_SECOND,
                )
                self._progress.start()
                self._retarget_log_handlers()
            self._users += 1
            return self._progress

    def release(self, task_id: TaskID) -> None:
        with self._lock:
            self._users -= 1
            if self._progress is None:
                return
            if self._users > 0:
                # Other bars are still running: freeze this one as a static line above the live
                # display (in order with the log output) so only running bars stay at the bottom.
                task = next(task for task in self._progress.tasks if task.id == task_id)
                self._progress.console.print(self._progress.make_tasks_table([task]))
                self._progress.remove_task(task_id)
                return
            self._restore_log_handlers()
            self._progress.stop()
            self._progress = None

    def _retarget_log_handlers(self) -> None:
        # rich swapped sys.stdout/sys.stderr for proxies that print above the live display (only
        # when stderr is a terminal); handlers that captured the real stream at creation time
        # (e.g. logging.basicConfig) would still write straight through the bars.
        redirections = {id(sys.__stdout__): sys.stdout, id(sys.__stderr__): sys.stderr}
        loggers: list[logging.Logger] = [logging.getLogger()]
        loggers.extend(
            logger for logger in logging.Logger.manager.loggerDict.values() if isinstance(logger, logging.Logger)
        )
        for logger in loggers:
            for handler in logger.handlers:
                if not isinstance(handler, logging.StreamHandler):
                    continue
                handler = cast("logging.StreamHandler[IO[str]]", handler)
                stream = handler.stream
                proxy = redirections.get(id(stream))
                if proxy is not None and proxy is not stream:
                    handler.setStream(proxy)
                    self._retargeted.append((handler, stream))

    def _restore_log_handlers(self) -> None:
        for handler, stream in self._retargeted:
            handler.setStream(stream)
        self._retargeted.clear()


_display = _SharedDisplay()


class ProgressBar:
    """
    Manually-advanced progress bar with tqdm's shape::

        with ProgressBar(total=size, desc="file.bin", unit="B") as bar:
            bar.update(len(chunk))

    ``unit="B"`` renders the amount and rate as binary byte sizes. A falsy ``total`` means the total
    is unknown. ``disable=True`` turns every method into a no-op, so call sites need no branching.
    """

    def __init__(self, total: Optional[float] = None, desc: str = "", unit: str = "it", disable: bool = False) -> None:
        self._progress: Optional[Progress] = None
        self._task: Optional[TaskID] = None
        self._n: float = 0
        self._total = total or None
        self._last_push = 0.0
        if disable:
            return
        self._progress = _display.acquire()
        self._task = self._progress.add_task(desc, total=self._total, unit=unit)

    @property
    def n(self) -> float:
        """Amount completed so far; assign to jump to an absolute position (e.g. a percentage)."""
        return self._n

    @n.setter
    def n(self, value: float) -> None:
        self._n = value
        self._maybe_push()

    def update(self, n: float = 1) -> None:
        # Hot path (called per chunk): avoid the property indirection.
        self._n += n
        self._maybe_push()

    def _maybe_push(self) -> None:
        if self._task is None:
            return
        now = time.monotonic()
        if now - self._last_push >= _MIN_UPDATE_INTERVAL or (self._total is not None and self._n >= self._total):
            self._last_push = now
            self._push()

    def _push(self) -> None:
        if self._progress is not None and self._task is not None:
            self._progress.update(self._task, completed=self._n)

    def close(self) -> None:
        if self._task is None:
            return
        self._push()
        task = self._task
        self._progress = None
        self._task = None
        _display.release(task)

    def __enter__(self) -> "ProgressBar":
        return self

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        self.close()


def track(
    iterable: Iterable[_T],
    total: Optional[float] = None,
    desc: str = "",
    unit: str = "it",
    disable: bool = False,
) -> Iterator[_T]:
    """Like ``tqdm(iterable)``: yield every item, advancing a bar by one each time."""
    if total is None and isinstance(iterable, Sized):
        total = len(iterable)
    with ProgressBar(total=total, desc=desc, unit=unit, disable=disable) as bar:
        for item in iterable:
            yield item
            bar.update()


def trange(
    start: int, stop: Optional[int] = None, step: int = 1, desc: str = "", disable: bool = False
) -> Iterator[int]:
    """Like ``tqdm.trange``: ``track(range(start, stop, step))``."""
    return track(range(start) if stop is None else range(start, stop, step), desc=desc, disable=disable)
