"""SR-013: commands sent through the proxy to PX4 are written to the command log.

Through the proxy, the test sends MAV_CMD_REQUEST_MESSAGE (allowlisted, PX4
acks it) and MAV_CMD_REQUEST_PROTOCOL_VERSION (harmless, but not in the
policy.yaml allowlist). The session's command log (``command_log_path``, see
conftest.py) must gain exactly two command lines, both valid JSON with the
SR-013 fields: a ``forward`` for the first and a ``drop`` with the allowlist
reason for the second.
"""

import json
import time
from datetime import datetime, timezone

import pytest
from pymavlink.dialects.v20 import common as mav2

pytestmark = pytest.mark.sitl

ACK_TIMEOUT = 5.0
ACCOUNT_TIMEOUT = 2.0
DROP_WINDOW_WAIT = 1.1  # > the command log's 1 s drop-line window
ALLOWED = mav2.MAV_CMD_REQUEST_MESSAGE
DISALLOWED = mav2.MAV_CMD_REQUEST_PROTOCOL_VERSION
FIELDS = ["ts", "action", "peer", "src", "sysid", "compid", "msg", "command",
          "target_system", "target_component", "signed"]


def log_lines(path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines(keepends=True) if path.exists() else []


def command_entries(path, start: int) -> list[dict]:
    """Forward/drop entries in the complete lines from line ``start`` on.

    The log is shared by the session, so a ``drop_suppressed`` summary for an
    earlier test's drop window could also land in it; that is skipped.
    """
    entries = [json.loads(line) for line in log_lines(path)[start:] if line.endswith("\n")]
    return [e for e in entries if e["action"] in ("forward", "drop")]


def parse_ts(ts: str) -> datetime:
    assert ts.endswith("Z"), ts
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def test_proxied_commands_logged(via_proxy, proxy, command_log_path):
    assert proxy.policy.peer_for("127.0.0.1").name == "cc-local"
    assert DISALLOWED not in proxy.policy.allowed_commands
    lines_before = len(log_lines(command_log_path))
    reason = f"command {DISALLOWED} not in allowlist"
    drop_key = (mav2.MAVLINK_MSG_ID_COMMAND_LONG, reason)
    dropped_before = proxy.stats().dropped.get(drop_key, 0)
    start = datetime.now(timezone.utc)

    via_proxy.drain()
    via_proxy.mav.command_long_send(
        via_proxy.target_system, via_proxy.target_component, ALLOWED, 0,
        mav2.MAVLINK_MSG_ID_AUTOPILOT_VERSION, 0, 0, 0, 0, 0, 0,
    )
    acks = via_proxy.collect(
        lambda m: m.get_type() == "COMMAND_ACK" and m.command == ALLOWED, ACK_TIMEOUT
    )
    assert acks and acks[0].result == mav2.MAV_RESULT_ACCEPTED

    # Drop lines are capped at 10 per peer per 1-second window, and the log is
    # shared by the session. Let any cc-local drop window left by an earlier
    # test end, so the drop line below is always written whatever the test
    # order (command_entries skips the drop_suppressed summary this may cause).
    time.sleep(DROP_WINDOW_WAIT)
    via_proxy.mav.command_long_send(
        via_proxy.target_system, via_proxy.target_component, DISALLOWED, 0, 0, 0, 0, 0, 0, 0, 0,
    )
    deadline = time.monotonic() + ACCOUNT_TIMEOUT
    while (len(command_entries(command_log_path, lines_before)) < 2
           and time.monotonic() < deadline):
        time.sleep(0.05)
    end = datetime.now(timezone.utc)

    assert proxy.stats().dropped.get(drop_key, 0) == dropped_before + 1
    new = log_lines(command_log_path)[lines_before:]
    assert all(line.endswith("\n") for line in new)
    entries = command_entries(command_log_path, lines_before)
    assert len(entries) == 2, f"expected 2 new command log entries, got {new}"
    forward, drop = entries

    src = f"127.0.0.1:{via_proxy.conn.port.getsockname()[1]}"
    common = {
        "peer": "cc-local", "src": src, "sysid": 255, "compid": 190, "msg": "COMMAND_LONG",
        "target_system": via_proxy.target_system,
        "target_component": via_proxy.target_component, "signed": False,
    }
    assert list(forward) == FIELDS
    assert forward | common == forward
    assert forward["action"] == "forward"
    assert forward["command"] == {"name": "MAV_CMD_REQUEST_MESSAGE", "number": ALLOWED}

    assert list(drop) == FIELDS[:2] + ["reason"] + FIELDS[2:]
    assert drop | common == drop
    assert drop["action"] == "drop"
    assert drop["reason"] == reason
    assert drop["command"] == {"name": "MAV_CMD_REQUEST_PROTOCOL_VERSION", "number": DISALLOWED}

    stamps = [parse_ts(forward["ts"]), parse_ts(drop["ts"])]
    assert start <= stamps[0] <= stamps[1] <= end
