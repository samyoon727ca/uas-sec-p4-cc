"""SR-013 command log (cc_proxy.cmdlog), in-process through the proxy (no SITL)."""

import json
import socket
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml
from pymavlink.dialects.v20 import common as mav2

from cc_proxy.classifier import Action, Decision
from cc_proxy.cmdlog import CommandLog, command_entry, format_source, format_timestamp
from cc_proxy.policy import load_policy, parse_policy
from cc_proxy.proxy import RATE_LIMITED, UNKNOWN_PEER, Proxy

POLICY_PATH = Path(__file__).resolve().parents[1] / "policy.yaml"
RECV_TIMEOUT = 2.0
SILENCE_TIMEOUT = 0.3
FIXED_NOW = datetime(2026, 11, 21, 12, 34, 56, 789012, tzinfo=timezone.utc)
FIELDS = ["ts", "action", "peer", "src", "sysid", "compid", "msg", "command",
          "target_system", "target_component", "signed"]
DROP_FIELDS = FIELDS[:2] + ["reason"] + FIELDS[2:]

REQUEST_MESSAGE = mav2.MAV_CMD_REQUEST_MESSAGE
REBOOT = mav2.MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN  # not in the policy.yaml allowlist


def encoder(signed=False):
    mav = mav2.MAVLink(None, srcSystem=255, srcComponent=190)
    if signed:
        mav.signing.secret_key = bytes(range(32))
        mav.signing.link_id = 1
        mav.signing.timestamp = 1
        mav.signing.sign_outgoing = True
    return mav


def command_long(command=REQUEST_MESSAGE, target=(1, 1), signed=False):
    msg = mav2.MAVLink_command_long_message(*target, command, 0, 148, 0, 0, 0, 0, 0, 0)
    return bytes(msg.pack(encoder(signed)))


def command_int(command=REQUEST_MESSAGE, target=(7, 0)):
    msg = mav2.MAVLink_command_int_message(*target, 0, command, 0, 0, 148, 0, 0, 0, 0, 0, 0)
    return bytes(msg.pack(encoder()))


def heartbeat():
    return bytes(mav2.MAVLink_heartbeat_message(6, 8, 0, 0, 0, 3).pack(encoder()))


def udp_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(RECV_TIMEOUT)
    return sock


@contextmanager
def make_rig(log_path, policy=None, now=lambda: FIXED_NOW, **proxy_kwargs):
    fc, gcs = udp_socket(), udp_socket()
    with CommandLog(log_path, now=now) as command_log:
        proxy = Proxy(policy or load_policy(POLICY_PATH), ("127.0.0.1", 0), fc.getsockname(),
                      command_log=command_log, **proxy_kwargs)
        proxy.start()
        try:
            yield proxy, gcs, fc
        finally:
            proxy.stop()
            gcs.close()
            fc.close()
    assert proxy.error is None


def read_log(path, n, timeout=RECV_TIMEOUT):
    """The log's entries once it has at least ``n`` complete lines (read while still open)."""
    deadline = time.monotonic() + timeout
    while True:
        text = path.read_text(encoding="utf-8") if path.exists() else ""
        lines = text.splitlines(keepends=True)
        if len(lines) >= n or time.monotonic() > deadline:
            break
        time.sleep(0.02)
    assert all(line.endswith("\n") for line in lines), "every entry must be a complete line"
    return [json.loads(line) for line in lines]


def assert_silent(sock):
    sock.settimeout(SILENCE_TIMEOUT)
    with pytest.raises(socket.timeout):
        sock.recvfrom(65535)
    sock.settimeout(RECV_TIMEOUT)


def test_forwarded_command_line_schema(tmp_path):
    log_path = tmp_path / "cmd.jsonl"
    with make_rig(log_path) as (proxy, gcs, fc):
        frame = command_long()
        gcs_port = gcs.getsockname()[1]
        gcs.sendto(frame, proxy.listen_address)
        assert fc.recvfrom(65535)[0] == frame
        (entry,) = read_log(log_path, 1)  # flushed: read while the log is still open
    assert list(entry) == FIELDS
    assert entry == {
        "ts": "2026-11-21T12:34:56.789012Z",
        "action": "forward",
        "peer": "cc-local",
        "src": f"127.0.0.1:{gcs_port}",
        "sysid": 255,
        "compid": 190,
        "msg": "COMMAND_LONG",
        "command": {"name": "MAV_CMD_REQUEST_MESSAGE", "number": 512},
        "target_system": 1,
        "target_component": 1,
        "signed": False,
    }


def test_timestamp_is_utc_iso8601_with_z(tmp_path):
    log_path = tmp_path / "cmd.jsonl"
    with make_rig(log_path, now=lambda: datetime.now(timezone.utc)) as (proxy, gcs, fc):
        before = datetime.now(timezone.utc)
        gcs.sendto(command_long(), proxy.listen_address)
        fc.recvfrom(65535)
        (entry,) = read_log(log_path, 1)
        after = datetime.now(timezone.utc)
    assert entry["ts"].endswith("Z")
    ts = datetime.strptime(entry["ts"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    assert before <= ts <= after


def test_format_timestamp_converts_to_utc():
    plus_one = timezone(timedelta(hours=1))
    assert format_timestamp(datetime(2026, 1, 1, 1, 0, tzinfo=plus_one)) == (
        "2026-01-01T00:00:00.000000Z"
    )


def test_format_source_brackets_ipv6():
    assert format_source(("10.8.0.2", 14550)) == "10.8.0.2:14550"
    assert format_source(("::1", 14550, 0, 0)) == "[::1]:14550"


def test_peer_name_comes_from_peer_map(tmp_path):
    raw = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    raw["peers"] = [{"name": "ground-test", "allowed_ips": ["127.0.0.0/8"]}]
    del raw["local_peer"]
    log_path = tmp_path / "cmd.jsonl"
    with make_rig(log_path, parse_policy(raw)) as (proxy, gcs, fc):
        gcs.sendto(command_long(), proxy.listen_address)
        fc.recvfrom(65535)
        (entry,) = read_log(log_path, 1)
    assert entry["peer"] == "ground-test"


def test_unknown_peer_command_logged_as_drop_without_peer(tmp_path):
    raw = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    raw["peers"] = [{"name": "gcs-primary", "allowed_ips": ["10.8.0.2/32"]}]
    del raw["local_peer"]
    log_path = tmp_path / "cmd.jsonl"
    with make_rig(log_path, parse_policy(raw)) as (proxy, gcs, fc):
        gcs.sendto(command_long(), proxy.listen_address)
        (entry,) = read_log(log_path, 1)
        assert_silent(fc)
    assert entry["action"] == "drop"
    assert entry["reason"] == UNKNOWN_PEER
    assert entry["peer"] is None


def test_dropped_and_forwarded_commands_and_non_commands(tmp_path):
    log_path = tmp_path / "cmd.jsonl"
    with make_rig(log_path) as (proxy, gcs, fc):
        allowed = command_long()
        gcs.sendto(heartbeat(), proxy.listen_address)  # forwarded, not a command
        fc.recvfrom(65535)
        gcs.sendto(command_long(REBOOT), proxy.listen_address)
        gcs.sendto(allowed, proxy.listen_address)
        assert fc.recvfrom(65535)[0] == allowed
        assert_silent(fc)
        entries = read_log(log_path, 2)
    assert len(entries) == 2
    drop, forward = entries
    assert list(drop) == DROP_FIELDS
    assert drop["action"] == "drop"
    assert drop["reason"] == f"command {REBOOT} not in allowlist"
    assert drop["command"] == {"name": "MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN", "number": REBOOT}
    assert drop["peer"] == "cc-local"
    assert list(forward) == FIELDS
    assert forward["action"] == "forward"
    assert forward["command"]["number"] == REQUEST_MESSAGE


def test_rate_limited_command_logged_as_drop(tmp_path):
    policy = load_policy(POLICY_PATH)
    burst = policy.rate_for(mav2.MAVLINK_MSG_ID_COMMAND_LONG).burst
    log_path = tmp_path / "cmd.jsonl"
    # Frozen clock: the bucket never refills, so exactly `burst` commands pass.
    with make_rig(log_path, policy, clock=lambda: 0.0) as (proxy, gcs, fc):
        for _ in range(burst + 1):
            gcs.sendto(command_long(), proxy.listen_address)
        entries = read_log(log_path, burst + 1)
    assert [e["action"] for e in entries] == ["forward"] * burst + ["drop"]
    assert entries[-1]["reason"] == RATE_LIMITED


def test_signed_command_int_with_truncated_targets(tmp_path):
    log_path = tmp_path / "cmd.jsonl"
    with make_rig(log_path) as (proxy, gcs, fc):
        signed = command_long(signed=True)
        assert signed[2] & 0x01
        truncated = command_int(target=(7, 0))
        # MAVLink 2 strips trailing zero bytes: target_component (and after) are absent.
        assert truncated[1] <= 31
        gcs.sendto(signed, proxy.listen_address)
        gcs.sendto(truncated, proxy.listen_address)
        entries = read_log(log_path, 2)
    assert [(e["msg"], e["signed"]) for e in entries] == [
        ("COMMAND_LONG", True), ("COMMAND_INT", False)
    ]
    assert (entries[1]["target_system"], entries[1]["target_component"]) == (7, 0)


def test_unknown_command_number_has_null_name():
    frame = command_long(command=60000)
    decision = Decision(Action.DROP, "x", msgid=mav2.MAVLINK_MSG_ID_COMMAND_LONG,
                        command=60000, sysid=255, compid=190)
    entry = command_entry(frame, ("127.0.0.1", 1), "cc-local", decision, FIXED_NOW, "x")
    assert entry["command"] == {"name": None, "number": 60000}


def test_log_appends_to_existing_file(tmp_path):
    log_path = tmp_path / "cmd.jsonl"
    log_path.write_text('{"earlier": true}\n', encoding="utf-8")
    with make_rig(log_path) as (proxy, gcs, fc):
        gcs.sendto(command_long(), proxy.listen_address)
        entries = read_log(log_path, 2)
    assert entries[0] == {"earlier": True}
    assert entries[1]["action"] == "forward"
