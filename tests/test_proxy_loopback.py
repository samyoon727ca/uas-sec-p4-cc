"""In-process loopback tests for cc_proxy.proxy (no SITL)."""

import signal
import socket
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

import pytest
import yaml
from pymavlink.dialects.v20 import common as mav2

from cc_proxy.policy import load_policy, parse_policy
from cc_proxy.proxy import RATE_LIMITED, UNKNOWN_PEER, Proxy, split_frames

POLICY_PATH = Path(__file__).resolve().parents[1] / "policy.yaml"
RECV_TIMEOUT = 2.0
SILENCE_TIMEOUT = 0.3
SEND_DELAY = 0.3

HEARTBEAT_ID = mav2.MAVLINK_MSG_ID_HEARTBEAT
FTP_ID = mav2.MAVLINK_MSG_ID_FILE_TRANSFER_PROTOCOL


def link(signed=False):
    mav = mav2.MAVLink(None, srcSystem=255, srcComponent=190)
    if signed:
        mav.signing.secret_key = bytes(range(32))
        mav.signing.link_id = 1
        mav.signing.timestamp = 1
        mav.signing.sign_outgoing = True
    return mav


def heartbeat(signed=False):
    return bytes(mav2.MAVLink_heartbeat_message(6, 8, 0, 0, 0, 3).pack(link(signed)))


def ftp():
    return bytes(mav2.MAVLink_file_transfer_protocol_message(0, 1, 1, [0] * 251).pack(link()))


def udp_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(RECV_TIMEOUT)
    return sock


@contextmanager
def make_rig(policy=None, **proxy_kwargs):
    fc = udp_socket()
    gcs = udp_socket()
    policy = policy or load_policy(POLICY_PATH)
    proxy = Proxy(policy, ("127.0.0.1", 0), fc.getsockname(), **proxy_kwargs)
    proxy.start()
    try:
        yield proxy, gcs, fc
    finally:
        proxy.stop()
        gcs.close()
        fc.close()
    assert proxy.error is None


@pytest.fixture
def rig():
    with make_rig() as r:
        yield r


def send_up(proxy, gcs, data):
    gcs.sendto(data, proxy.listen_address)


def wait_until(predicate, timeout=RECV_TIMEOUT):
    """Poll until predicate() is true; the proxy thread updates state after send."""
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            pytest.fail("condition not met before timeout")
        time.sleep(0.01)


def assert_silent(sock):
    sock.settimeout(SILENCE_TIMEOUT)
    with pytest.raises(socket.timeout):
        sock.recvfrom(65535)
    sock.settimeout(RECV_TIMEOUT)


def test_allowed_frame_arrives_byte_identical(rig):
    proxy, gcs, fc = rig
    frame = heartbeat()
    send_up(proxy, gcs, frame)
    data, _ = fc.recvfrom(65535)
    assert data == frame
    wait_until(lambda: proxy.stats().forwarded == {HEARTBEAT_ID: 1})
    assert proxy.stats().dropped == {}


def test_excluded_frame_dropped_and_counted(rig):
    proxy, gcs, fc = rig
    send_up(proxy, gcs, ftp())
    assert_silent(fc)
    stats = proxy.stats()
    assert stats.forwarded == {}
    assert stats.dropped == {(FTP_ID, "excluded message FILE_TRANSFER_PROTOCOL (SR-011)"): 1}


def test_datagram_with_two_frames_forwards_only_allowed(rig):
    proxy, gcs, fc = rig
    allowed = heartbeat()
    send_up(proxy, gcs, ftp() + allowed)
    data, _ = fc.recvfrom(65535)
    assert data == allowed
    assert_silent(fc)
    stats = proxy.stats()
    assert stats.forwarded == {HEARTBEAT_ID: 1}
    assert sum(stats.dropped.values()) == 1
    assert (FTP_ID, "excluded message FILE_TRANSFER_PROTOCOL (SR-011)") in stats.dropped


def test_signed_frame_arrives_byte_identical(rig):
    proxy, gcs, fc = rig
    frame = heartbeat(signed=True)
    assert frame[2] & 0x01  # signed
    send_up(proxy, gcs, frame)
    data, _ = fc.recvfrom(65535)
    assert data == frame


def test_trailing_garbage_dropped_frame_before_it_forwarded(rig):
    proxy, gcs, fc = rig
    frame = heartbeat()
    send_up(proxy, gcs, frame + b"\x00garbage")
    data, _ = fc.recvfrom(65535)
    assert data == frame
    assert_silent(fc)
    stats = proxy.stats()
    assert stats.forwarded == {HEARTBEAT_ID: 1}
    assert stats.dropped == {(None, "unknown magic 0x00"): 1}


def test_fc_reply_reaches_gcs(rig):
    proxy, gcs, fc = rig
    send_up(proxy, gcs, heartbeat())
    _, proxy_fc_side = fc.recvfrom(65535)
    reply = bytes(mav2.MAVLink_heartbeat_message(2, 12, 0, 0, 4, 3).pack(
        mav2.MAVLink(None, srcSystem=1, srcComponent=1)))
    fc.sendto(reply, proxy_fc_side)
    data, src = gcs.recvfrom(65535)
    assert data == reply
    assert src[:2] == proxy.listen_address[:2]
    assert proxy.stats().downlink_relayed == 1


def test_downlink_counted_by_the_time_gcs_receives_it(monkeypatch):
    # The proxy thread can be descheduled right after its send to the GCS. A
    # GCS that has received the datagram must still see it counted (the SITL
    # control checks read downlink_relayed as soon as PX4's reply arrives).
    # Sleeping after each send makes that window long enough to hit every time.
    real_socket = socket.socket

    class SlowSendSocket(real_socket):
        def sendto(self, *args):
            sent = super().sendto(*args)
            time.sleep(SEND_DELAY)
            return sent

    with udp_socket() as fc, udp_socket() as gcs:
        proxy = Proxy(load_policy(POLICY_PATH), ("127.0.0.1", 0), fc.getsockname())
        sockets = iter([SlowSendSocket, real_socket])  # GCS side, then FC side
        monkeypatch.setattr(socket, "socket", lambda *a, **kw: next(sockets)(*a, **kw))
        proxy.start()
        monkeypatch.undo()
        try:
            send_up(proxy, gcs, heartbeat())
            _, proxy_fc_side = fc.recvfrom(65535)
            fc.sendto(heartbeat(), proxy_fc_side)
            gcs.recvfrom(65535)
            assert proxy.stats().downlink_relayed == 1
        finally:
            proxy.stop()
    assert proxy.error is None


def test_downlink_from_non_fc_source_filtered_by_kernel(rig):
    proxy, gcs, fc = rig
    send_up(proxy, gcs, heartbeat())
    _, proxy_fc_side = fc.recvfrom(65535)
    with udp_socket() as intruder:
        intruder.sendto(heartbeat(), proxy_fc_side)
    assert_silent(gcs)
    # The FC-side socket is connected to the FC, so the datagram never reaches
    # the proxy at all (not even as "ignored").
    assert proxy.stats().downlink_ignored == 0
    assert proxy.stats().downlink_relayed == 0


def test_downlink_not_sent_to_unknown_peer():
    raw = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    raw["peers"] = [{"name": "gcs-primary", "allowed_ips": ["10.8.0.2/32"]}]
    del raw["local_peer"]
    with make_rig(parse_policy(raw)) as (proxy, gcs, fc):
        send_up(proxy, gcs, heartbeat())
        assert_silent(fc)
        fc.sendto(heartbeat(), proxy._fc_sock.getsockname())
        assert_silent(gcs)
        stats = proxy.stats()
    assert stats.downlink_relayed == 0
    assert stats.downlink_ignored == 1


def test_downlink_counted_as_send_failed_when_no_gcs_send_succeeds(rig):
    proxy, gcs, fc = rig
    send_up(proxy, gcs, heartbeat())
    _, proxy_fc_side = fc.recvfrom(65535)
    # Wait until the proxy has finished handling the uplink, so it cannot
    # re-add the real GCS address after the peer list is replaced below.
    gcs_addr = gcs.getsockname()
    wait_until(lambda: gcs_addr in proxy._gcs_peers)
    # An IPv6 address cannot be sent to from the IPv4 GCS socket, so every
    # send to the GCS fails.
    with proxy._lock:
        proxy._gcs_peers.clear()
        proxy._gcs_peers[("::1", 9)] = None
    fc.sendto(heartbeat(), proxy_fc_side)
    assert_silent(gcs)
    stats = proxy.stats()
    assert stats.downlink_relayed == 0
    assert stats.downlink_send_failed == 1
    assert "send failed: 1" in stats.format()


def test_start_closes_gcs_socket_when_fc_socket_creation_fails(monkeypatch):
    created = []
    real_socket = socket.socket

    def fake_socket(*args, **kwargs):
        if created:
            raise OSError("address family not supported")
        sock = real_socket(*args, **kwargs)
        created.append(sock)
        return sock

    proxy = Proxy(load_policy(POLICY_PATH), ("127.0.0.1", 0), ("127.0.0.1", 9))
    monkeypatch.setattr(socket, "socket", fake_socket)
    with pytest.raises(OSError, match="address family"):
        proxy.start()
    assert len(created) == 1
    assert created[0].fileno() == -1  # closed


@pytest.mark.parametrize("error", [ConnectionRefusedError, ConnectionResetError])
@pytest.mark.parametrize("refusals, forwarded", [(1, True), (2, False)])
def test_fc_send_retried_once_after_icmp_refusal(monkeypatch, refusals, forwarded, error):
    # A connected UDP socket fails the send after an ICMP port-unreachable (FC
    # not up yet): ConnectionRefusedError on Linux, ConnectionResetError
    # (WSAECONNRESET) on Windows. Simulated here, since loopback does not
    # report it the same way on every OS.
    real_socket = socket.socket

    class RefusingSocket(real_socket):
        remaining = refusals

        def send(self, data, *args):
            if RefusingSocket.remaining:
                RefusingSocket.remaining -= 1
                raise error("connection refused")
            return super().send(data, *args)

    with udp_socket() as fc, udp_socket() as gcs:
        proxy = Proxy(load_policy(POLICY_PATH), ("127.0.0.1", 0), fc.getsockname())
        sockets = iter([real_socket, RefusingSocket])
        monkeypatch.setattr(socket, "socket", lambda *a, **kw: next(sockets)(*a, **kw))
        proxy.start()
        monkeypatch.undo()
        try:
            frame = heartbeat()
            send_up(proxy, gcs, frame)
            if forwarded:
                data, _ = fc.recvfrom(65535)
                assert data == frame
                wait_until(lambda: proxy.stats().forwarded == {HEARTBEAT_ID: 1})
                assert proxy.stats().dropped == {}
            else:
                wait_until(lambda: proxy.stats().dropped == {(HEARTBEAT_ID, "send error"): 1})
                assert_silent(fc)
                assert proxy.stats().forwarded == {}
        finally:
            proxy.stop()
    assert proxy.error is None


def test_allowed_frame_counted_for_local_peer(rig):
    proxy, gcs, fc = rig
    send_up(proxy, gcs, heartbeat())
    fc.recvfrom(65535)
    send_up(proxy, gcs, ftp())
    assert_silent(fc)
    stats = proxy.stats()
    assert stats.peer_forwarded == {"cc-local": 1}
    assert stats.peer_dropped == {
        ("cc-local", "excluded message FILE_TRANSFER_PROTOCOL (SR-011)"): 1
    }
    assert stats.local_peer == "cc-local"
    assert "cc-local (CC-originated): forwarded 1" in stats.format()


def test_unknown_peer_dropped():
    raw = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    raw["peers"] = [{"name": "gcs-primary", "allowed_ips": ["10.8.0.2/32"]}]
    del raw["local_peer"]
    with make_rig(parse_policy(raw)) as (proxy, gcs, fc):
        send_up(proxy, gcs, heartbeat() + ftp())
        assert_silent(fc)
        stats = proxy.stats()
    assert stats.forwarded == {}
    assert stats.dropped == {(HEARTBEAT_ID, UNKNOWN_PEER): 1, (FTP_ID, UNKNOWN_PEER): 1}
    assert stats.peer_forwarded == {}
    assert stats.peer_dropped == {}


def test_over_rate_frames_dropped_as_rate_limited():
    policy = load_policy(POLICY_PATH)
    burst = policy.rate_for(HEARTBEAT_ID).burst
    extra = 3
    # Frozen clock: the bucket never refills, so exactly `burst` frames pass.
    with make_rig(policy, clock=lambda: 0.0) as (proxy, gcs, fc):
        frame = heartbeat()
        for _ in range(burst + extra):
            send_up(proxy, gcs, frame)
        for _ in range(burst):
            data, _ = fc.recvfrom(65535)
            assert data == frame
        assert_silent(fc)
        stats = proxy.stats()
    assert stats.forwarded == {HEARTBEAT_ID: burst}
    assert stats.dropped == {(HEARTBEAT_ID, RATE_LIMITED): extra}
    assert stats.peer_forwarded == {"cc-local": burst}
    assert stats.peer_dropped == {("cc-local", RATE_LIMITED): extra}


def test_split_frames_returns_views_of_datagram():
    a, b = heartbeat(), heartbeat(signed=True)
    data = a + b + b"\xfd\x09"
    frames = split_frames(data)
    assert [bytes(f) for f in frames] == [a, b, b"\xfd\x09"]
    assert all(f.obj is data for f in frames)


def test_cli_starts_and_stops_on_interrupt(tmp_path):
    command_log = tmp_path / "commands.jsonl"
    kwargs = {}
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    proc = subprocess.Popen(
        [sys.executable, "-m", "cc_proxy.proxy", "--policy", str(POLICY_PATH),
         "--listen", "127.0.0.1:0", "--fc", "127.0.0.1:9", "--command-log", str(command_log)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **kwargs,
    )
    try:
        for line in proc.stderr:
            if "listening on" in line:
                break
        else:
            pytest.fail(f"proxy did not start: {proc.communicate()}")
        proc.send_signal(signal.CTRL_BREAK_EVENT if sys.platform == "win32" else signal.SIGINT)
        out, _ = proc.communicate(timeout=10)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    assert proc.returncode == 0
    assert "uplink forwarded:" in out
    assert "uplink dropped:" in out
    assert command_log.is_file()
