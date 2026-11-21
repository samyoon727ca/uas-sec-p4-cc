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

Each line is written after the frame was sent and flushed at once. A write
error is not caught: it stops the proxy loop (``Proxy.error``), so at most the
one command whose line failed is forwarded without a log entry.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pymavlink.dialects.v20 import common as _mavlink

from .classifier import INCOMPAT_SIGNED, MAGIC_V2, V1_HEADER_LEN, V2_HEADER_LEN, Decision

DEFAULT_PATH = "cc-commands.jsonl"

# COMMAND_LONG and COMMAND_INT both put uint8 target_system, target_component
# right after the uint16 command at payload offset 28.
_TARGET_OFFSET = 30


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def format_timestamp(when: datetime) -> str:
    """``when`` (timezone-aware) as UTC ISO-8601 with microseconds and a ``Z`` suffix."""
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def format_source(addr: tuple) -> str:
    host, port = addr[0], addr[1]
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def _targets(frame: bytes) -> tuple[int, int]:
    """target_system / target_component, restoring v2 trailing-zero truncation."""
    header_len = V2_HEADER_LEN if frame[0] == MAGIC_V2 else V1_HEADER_LEN
    payload = frame[header_len : header_len + frame[1]]
    field = payload[_TARGET_OFFSET : _TARGET_OFFSET + 2].ljust(2, b"\x00")
    return field[0], field[1]


def command_entry(
    frame: bytes,
    src: tuple,
    peer: str | None,
    decision: Decision,
    when: datetime,
    reason: str | None = None,
) -> dict[str, Any]:
    """The log record for a command frame; ``reason`` set means it was dropped."""
    frame = bytes(frame)
    target_system, target_component = _targets(frame)
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
        target_system=target_system,
        target_component=target_component,
        signed=frame[0] == MAGIC_V2 and bool(frame[2] & INCOMPAT_SIGNED),
    )
    return entry


class CommandLog:
    """Append-only JSON-lines command log at ``path`` (see the module docstring).

    Called from the proxy thread only; :meth:`close` once the proxy has stopped.
    """

    def __init__(self, path: str | Path, now: Callable[[], datetime] = _utcnow):
        self.path = Path(path)
        self._now = now
        self._file = open(self.path, "a", encoding="utf-8", newline="\n")

    def forwarded(self, frame: bytes, src: tuple, peer: str | None, decision: Decision) -> None:
        self._write(frame, src, peer, decision, None)

    def dropped(
        self, frame: bytes, src: tuple, peer: str | None, decision: Decision, reason: str
    ) -> None:
        self._write(frame, src, peer, decision, reason)

    def _write(self, frame, src, peer, decision, reason) -> None:
        if decision.command is None:
            return
        entry = command_entry(frame, src, peer, decision, self._now(), reason)
        self._file.write(json.dumps(entry) + "\n")
        self._file.flush()

    def close(self) -> None:
        self._file.close()

    def __enter__(self) -> CommandLog:
        return self

    def __exit__(self, *exc) -> None:
        self.close()
