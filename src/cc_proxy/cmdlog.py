"""SR-013 command log: one JSON object per line for each uplink MAVLink command.

Every COMMAND_LONG / COMMAND_INT frame the proxy **forwards** to the FC is
logged with ``"action": "forward"``. Command frames the proxy **drops** after
recognising them as commands (MAV_CMD not in the allowlist, ``rate_limited``,
``unknown_peer``, send error) are logged too, with ``"action": "drop"`` and the
drop ``reason``. A frame is recognised as a command only once it has passed the
structure and checksum checks and the message allowlist
(``Decision.command`` is set); frames dropped before that are not logged, as
their fields cannot be trusted. Non-command messages are never logged.

Fields, in this order:

* ``ts``: UTC time the proxy handled the frame, ISO-8601 with microseconds and ``Z``;
* ``action``: ``"forward"`` or ``"drop"``; ``reason``: drops only;
* ``peer``: peer name from the policy peer map (``null`` for ``unknown_peer``);
* ``src``: packet source ``ip:port`` (``[ip]:port`` for IPv6);
* ``sysid``, ``compid``: MAVLink header source system / component;
* ``msg``: ``"COMMAND_LONG"`` or ``"COMMAND_INT"``;
* ``command``: ``{"name": "MAV_CMD_...", "number": n}`` (``name`` is ``null``
  for a number the common dialect does not define);
* ``target_system``, ``target_component``: from the payload;
* ``signed``: the frame carries a MAVLink 2 signature (not verified: the proxy
  holds no key).

Drop lines are capped so that a command flood cannot fill the disk: at most
``drop_lines_per_second`` (default :data:`DROP_LINES_PER_SECOND`) drop lines
are written per peer per one-second window (all ``unknown_peer`` sources share
the ``null`` peer's budget). Further drops in that window are only counted;
when the window ends (:meth:`CommandLog.tick`, called from the proxy loop) or
the log is closed, one summary line is written per peer that had any::

    {"ts": ..., "action": "drop_suppressed", "peer": ..., "since": ..., "suppressed": K}

``since`` is the window start (UTC). The windows are keyed by peer name only,
which the policy bounds, never by anything the sender controls. Forward lines
are not capped (forwarded commands are already held to the SR-012 rate), so the
cap never hides a forwarded command.

Suppressed drops lose their per-attempt detail: they appear only in the
``suppressed`` count, without ``src``, ``sysid``, ``compid``, ``command``,
targets or ``reason``. This cuts both ways: anyone sending disallowed commands
from inside a peer's AllowedIPs, or from any unknown IP (all share the ``null``
peer), can use up that peer's budget and hide other drops' details for that
second. The proxy counters (``dropped`` by msgid and reason, ``peer_dropped``
by peer and reason) still hold the exact totals. The summary has no per-source
or per-command breakdown because those values are chosen by the sender and,
with all unknown IPs sharing one budget, such a map could grow without limit
within one window.

Each line is written after the frame was sent and flushed at once. A write
error is not caught: it stops the proxy loop (``Proxy.error``), so at most the
one command whose line failed is forwarded without a log entry. A write error
in :meth:`CommandLog.close` (pending summaries, or the line that already failed
still buffered) is logged and kept in ``CommandLog.error`` instead of raised:
the proxy has stopped by then, and ``cc-proxy`` exits 1 when it is set. A
failed summary does not stop the others from being attempted, and its peer and
suppressed count go to the error log instead.

The log holds peer addresses and the full command history, so a new file is
created with mode ``0o600`` (owner read/write only, :data:`FILE_MODE`; POSIX).
An existing file is appended to and keeps its mode.
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pymavlink.dialects.v20 import common as _mavlink

from .classifier import INCOMPAT_SIGNED, MAGIC_V2, Decision

DEFAULT_PATH = "cc-commands.jsonl"
DROP_LINES_PER_SECOND = 10
FILE_MODE = 0o600
# O_BINARY (Windows only): no CRT newline translation, as with built-in open().
_OPEN_FLAGS = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0)
_DROP_WINDOW = 1.0  # seconds

log = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def format_timestamp(when: datetime) -> str:
    """``when`` (timezone-aware) as UTC ISO-8601 with microseconds and a ``Z`` suffix."""
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def format_source(addr: tuple) -> str:
    host, port = addr[0], addr[1]
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def command_entry(
    frame: bytes,
    src: tuple,
    peer: str | None,
    decision: Decision,
    when: datetime,
    reason: str | None = None,
) -> dict[str, Any]:
    """The log record for a command frame; ``reason`` set means it was dropped."""
    cmd = _mavlink.enums["MAV_CMD"].get(decision.command)
    entry: dict[str, Any] = {
        "ts": format_timestamp(when),
        "action": "forward" if reason is None else "drop",
    }
    if reason is not None:
        entry["reason"] = reason
    entry.update(
        peer=peer,
        src=format_source(src),
        sysid=decision.sysid,
        compid=decision.compid,
        msg=_mavlink.mavlink_map[decision.msgid].msgname,
        command={"name": cmd.name if cmd is not None else None, "number": decision.command},
        target_system=decision.target_system,
        target_component=decision.target_component,
        signed=frame[0] == MAGIC_V2 and bool(frame[2] & INCOMPAT_SIGNED),
    )
    return entry


@dataclass
class _DropWindow:
    start: float  # clock() at the window's first drop
    since: datetime
    logged: int = 0
    suppressed: int = 0


class CommandLog:
    """Append-only JSON-lines command log at ``path`` (see the module docstring).

    Called from the proxy thread only; :meth:`close` once the proxy has stopped.
    ``now`` gives the wall-clock timestamps, ``clock`` (monotonic) times the
    drop-line windows.
    """

    def __init__(
        self,
        path: str | Path,
        now: Callable[[], datetime] = _utcnow,
        clock: Callable[[], float] = time.monotonic,
        drop_lines_per_second: int = DROP_LINES_PER_SECOND,
    ):
        if drop_lines_per_second < 0:
            raise ValueError("drop_lines_per_second must be >= 0")
        self.path = Path(path)
        self._now = now
        self._clock = clock
        self._drop_limit = drop_lines_per_second
        self._drop_windows: dict[str | None, _DropWindow] = {}
        self.error: OSError | None = None  # write error in close()
        fd = os.open(self.path, _OPEN_FLAGS, FILE_MODE)
        try:
            self._file = os.fdopen(fd, "a", encoding="utf-8", newline="\n")
        except BaseException:
            os.close(fd)
            raise

    def forwarded(self, frame: bytes, src: tuple, peer: str | None, decision: Decision) -> None:
        if decision.command is None:
            return
        self._write(command_entry(frame, src, peer, decision, self._now()))

    def dropped(
        self, frame: bytes, src: tuple, peer: str | None, decision: Decision, reason: str
    ) -> None:
        if decision.command is None:
            return
        t = self._clock()
        window = self._drop_windows.get(peer)
        if window is not None and t - window.start >= _DROP_WINDOW:
            self._end_window(peer)
            window = None
        when = self._now()
        if window is None:
            window = self._drop_windows[peer] = _DropWindow(start=t, since=when)
        if window.logged >= self._drop_limit:
            window.suppressed += 1
            return
        window.logged += 1
        self._write(command_entry(frame, src, peer, decision, when, reason))

    def tick(self) -> None:
        """Close drop windows that have ended, writing their summary lines."""
        t = self._clock()
        for peer, window in list(self._drop_windows.items()):
            if t - window.start >= _DROP_WINDOW:
                self._end_window(peer)

    def _end_window(self, peer: str | None) -> None:
        window = self._drop_windows.pop(peer)
        if window.suppressed:
            self._write({
                "ts": format_timestamp(self._now()),
                "action": "drop_suppressed",
                "peer": peer,
                "since": format_timestamp(window.since),
                "suppressed": window.suppressed,
            })

    def _write(self, entry: dict[str, Any]) -> None:
        self._file.write(json.dumps(entry) + "\n")
        self._file.flush()

    def close(self) -> None:
        """Write the pending summary lines and close the file.

        Every pending summary is attempted and the file is closed even if a
        write fails. Each error is logged (with the peer's suppressed count if
        its summary could not be written), the first is stored in
        :attr:`error`, and none is raised (see the module docstring).
        """
        if self._file.closed:
            return
        try:
            for peer, window in list(self._drop_windows.items()):
                try:
                    self._end_window(peer)
                except OSError as exc:
                    self._close_error(exc)
                    log.error(
                        "cannot write command log %s on close: drop_suppressed line for"
                        " peer %r (%d suppressed since %s): %s",
                        self.path, peer, window.suppressed, format_timestamp(window.since), exc,
                    )
        finally:
            try:
                self._file.close()
            except OSError as exc:
                self._close_error(exc)
                log.error("cannot write command log %s on close: %s", self.path, exc)

    def _close_error(self, exc: OSError) -> None:
        if self.error is None:
            self.error = exc

    def __enter__(self) -> CommandLog:
        return self

    def __exit__(self, *exc) -> None:
        self.close()
