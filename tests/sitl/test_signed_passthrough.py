"""VE-02 through the proxy: MAVLink 2 signed frames pass byte-for-byte and PX4 accepts them.

Signing is set up as in the P3 repo (samyoon727ca/uas-sec-p3-pki,
scripts/mss_provision.py and harness/signing.py): SETUP_SIGNING with a fresh
32-byte key and the current signing timestamp, sent to PX4 while disarmed, then
the key counts as installed once PX4's own frames verify against it. The key is
installed **directly** on PX4's GCS link: SETUP_SIGNING is an SR-011 exclusion,
so the proxy drops it (checked below). PX4 v1.18.0-rc2 keeps one key for all
its links (mavlink_main.cpp: after SETUP_SIGNING every other instance reloads
the key file), so the offboard link behind the proxy enforces it too.

With the key installed (``signing`` fixture):

1. A signed COMMAND_LONG MAV_CMD_REQUEST_MESSAGE through the proxy is acked
   ACCEPTED, the ACK is signed with the key, and the one COMMAND_LONG the proxy
   sent to PX4 (``forward_tap``) equals the frame the client sent. The tap is
   the proxy's ``on_forward`` hook; that it equals what arrives on the FC
   socket is shown in loopback by
   ``tests/test_cmdlog.py::test_signed_command_on_wire_equals_sent_and_forward_hook``.
2. The same command unsigned, and signed with a wrong key, is also forwarded
   unchanged (the proxy holds no key and does not judge signatures), but PX4
   does not ack it: PX4 accepts only HEARTBEAT and RADIO_STATUS unsigned once
   a key is set (mavlink_sign_control.cpp, ``unsigned_messages``). A signed
   control afterwards is acked within the same window, so the silence is PX4's
   rejection, not a dead link.
3. SETUP_SIGNING with another key through the proxy is dropped (counter, and
   no such frame reaches PX4); PX4 still signs with the installed key.

The fixture removes the key at the end (signed SETUP_SIGNING with a blank key
and zero timestamp, accepted by PX4 only when signed with the current key) and
turns client signing off again, so the session's other tests keep running
unsigned. If a run is interrupted before that, the key stays in the SITL
working directory (``mavlink/mavlink-signing-key.bin``); start the next run
with a fresh one, as CI does.
"""

from __future__ import annotations

import hashlib
import os
import time

import pytest
from pymavlink.dialects.v20 import common as mav2

pytestmark = pytest.mark.sitl

KEY_LEN = 32
MAVLINK_EPOCH = 1420070400  # 2015-01-01T00:00:00Z
DIRECT_LINK_ID = 11  # signing link IDs of our two connections (distinct signing streams)
PROXY_LINK_ID = 12
WRONG_KEY_LINK_ID = 13
CONFIRM_TIMEOUT = 5.0
SETUP_ATTEMPTS = 3
WINDOW = 5.0  # ACK wait, for the negative cases and the controls alike
ACCOUNT_TIMEOUT = 2.0

COMMAND = mav2.MAV_CMD_REQUEST_MESSAGE
COMMAND_LONG_ID = mav2.MAVLINK_MSG_ID_COMMAND_LONG
SETUP_SIGNING_ID = mav2.MAVLINK_MSG_ID_SETUP_SIGNING
SETUP_SIGNING_DROP = "excluded message SETUP_SIGNING (SR-011)"


def signing_timestamp() -> int:
    """Current MAVLink signing timestamp (10 us units since 2015-01-01)."""
    return int((time.time() - MAVLINK_EPOCH) * 100_000)


def is_signed(buf: bytes) -> bool:
    return len(buf) > 10 and buf[0] == 0xFD and bool(buf[2] & 0x01)


def signed_with(buf: bytes, key: bytes) -> bool:
    """``buf`` is a signed MAVLink 2 frame whose signature verifies against ``key``."""
    buf = bytes(buf)
    return (is_signed(buf) and len(buf) == 10 + buf[1] + 2 + 13
            and hashlib.sha256(key + buf[:-6]).digest()[:6] == buf[-6:])


def msgid(frame: bytes) -> int:
    return int.from_bytes(frame[7:10], "little") if frame[0] == 0xFD else frame[5]


def accept_all(mav, msg_id) -> bool:
    """pymavlink unsigned callback: hand every frame to the test, which checks it itself."""
    return True


def from_autopilot(link, msg) -> bool:
    return msg.get_srcSystem() == link.target_system and msg.get_srcComponent() == 1


def wait_frame(link, check, timeout: float = CONFIRM_TIMEOUT) -> bool:
    """True once an autopilot frame whose raw bytes satisfy ``check`` arrives on ``link``."""
    link.drain()
    found = link.collect(
        lambda m: from_autopilot(link, m) and check(bytes(m.get_msgbuf())), timeout
    )
    return bool(found)


def request_message(enc, link):
    return enc.command_long_encode(
        link.target_system, link.target_component, COMMAND, 0,
        mav2.MAVLINK_MSG_ID_AUTOPILOT_VERSION, 0, 0, 0, 0, 0, 0,
    )


def is_ack(m) -> bool:
    return m.get_type() == "COMMAND_ACK" and m.command == COMMAND


def forwarded_commands(tap, mark) -> list[bytes]:
    return [f for f in tap.since(mark) if msgid(f) == COMMAND_LONG_ID]


@pytest.fixture(scope="module")
def signing(direct, via_proxy):
    """Install a fresh key on PX4 (directly), sign on both connections; undo it afterwards."""
    key = os.urandom(KEY_LEN)
    installed = False
    try:
        for _ in range(SETUP_ATTEMPTS):  # UDP: resend if PX4 shows no sign of the key
            direct.mav.setup_signing_send(direct.target_system, direct.target_component,
                                          list(key), signing_timestamp())
            if wait_frame(direct, lambda b: signed_with(b, key)):
                installed = True
                break
        if not installed:
            pytest.fail(f"PX4 did not sign with the key after {SETUP_ATTEMPTS} direct "
                        f"SETUP_SIGNING attempts", pytrace=False)
        direct.conn.setup_signing(key, sign_outgoing=True, allow_unsigned_callback=accept_all,
                                  link_id=DIRECT_LINK_ID)
        via_proxy.conn.setup_signing(key, sign_outgoing=True, allow_unsigned_callback=accept_all,
                                     link_id=PROXY_LINK_ID)
        # The offboard link reloads the key on its own thread.
        if not wait_frame(via_proxy, lambda b: signed_with(b, key)):
            pytest.fail("PX4's offboard link (behind the proxy) did not start signing",
                        pytrace=False)
        yield key
    finally:
        try:
            if installed:
                for _ in range(SETUP_ATTEMPTS):
                    direct.mav.setup_signing_send(direct.target_system, direct.target_component,
                                                  [0] * KEY_LEN, 0)
                    if wait_frame(direct, lambda b: not is_signed(b)):
                        break
                else:
                    pytest.fail("could not remove the signing key from PX4; later SITL tests "
                                "in this PX4 session would see signing", pytrace=False)
                assert wait_frame(via_proxy, lambda b: not is_signed(b)), (
                    "PX4's offboard link still signs after the key was removed"
                )
        finally:
            direct.conn.disable_signing()
            via_proxy.conn.disable_signing()


def test_signed_command_through_proxy_acked_byte_for_byte(signing, via_proxy, proxy,
                                                         forward_tap):
    key = signing
    forwarded_before = proxy.stats().forwarded.get(COMMAND_LONG_ID, 0)
    mark = forward_tap.mark()
    via_proxy.drain()
    msg = request_message(via_proxy.mav, via_proxy)
    via_proxy.mav.send(msg)
    sent = bytes(msg.get_msgbuf())
    assert signed_with(sent, key), "the client's COMMAND_LONG is not signed with the key"

    acks = via_proxy.collect(is_ack, WINDOW)
    assert acks, f"no COMMAND_ACK for the signed MAV_CMD_REQUEST_MESSAGE within {WINDOW}s"
    assert acks[0].result == mav2.MAV_RESULT_ACCEPTED
    assert signed_with(acks[0].get_msgbuf(), key), "PX4's COMMAND_ACK is not signed with the key"

    assert forwarded_commands(forward_tap, mark) == [sent], (
        "the COMMAND_LONG the proxy sent to PX4 differs from the one the client sent"
    )
    assert proxy.stats().forwarded.get(COMMAND_LONG_ID, 0) == forwarded_before + 1


@pytest.mark.parametrize("client", ["unsigned", "wrong_key"])
def test_unsigned_or_wrong_key_command_not_accepted(client, signing, via_proxy, forward_tap):
    key = signing
    # Own encoder (same identity) on the same socket, so the proxy sees the same
    # source; the connection's signing state is untouched.
    enc = mav2.MAVLink(via_proxy.conn, srcSystem=via_proxy.mav.srcSystem,
                       srcComponent=via_proxy.mav.srcComponent)
    if client == "wrong_key":
        wrong = os.urandom(KEY_LEN)
        enc.signing.secret_key = wrong
        enc.signing.link_id = WRONG_KEY_LINK_ID
        enc.signing.timestamp = signing_timestamp()
        enc.signing.sign_outgoing = True

    mark = forward_tap.mark()
    via_proxy.drain()
    msg = request_message(enc, via_proxy)
    enc.send(msg)
    sent = bytes(msg.get_msgbuf())
    if client == "wrong_key":
        assert signed_with(sent, wrong) and not signed_with(sent, key)
    else:
        assert not is_signed(sent)
    assert via_proxy.collect(is_ack, WINDOW) == [], f"PX4 acked a {client} command"
    assert forwarded_commands(forward_tap, mark) == [sent], (
        "the proxy should forward the command unchanged; PX4 is what rejects it"
    )

    # Control: the signed client, same command, same window, is acked.
    via_proxy.mav.send(request_message(via_proxy.mav, via_proxy))
    acks = via_proxy.collect(is_ack, WINDOW)
    assert acks and acks[0].result == mav2.MAV_RESULT_ACCEPTED, (
        f"control failed: signed command not acked within {WINDOW}s, so the {client} "
        f"silence above proves nothing"
    )


def test_setup_signing_through_proxy_dropped(signing, via_proxy, proxy, forward_tap):
    key = signing
    other = os.urandom(KEY_LEN)
    stats = proxy.stats()
    dropped_before = stats.dropped.get((SETUP_SIGNING_ID, SETUP_SIGNING_DROP), 0)
    forwarded_before = stats.forwarded.get(SETUP_SIGNING_ID, 0)
    mark = forward_tap.mark()

    # Signed with the installed key, so PX4 would apply it if it got through.
    via_proxy.mav.setup_signing_send(via_proxy.target_system, via_proxy.target_component,
                                     list(other), signing_timestamp())
    deadline = time.monotonic() + ACCOUNT_TIMEOUT
    while (proxy.stats().dropped.get((SETUP_SIGNING_ID, SETUP_SIGNING_DROP), 0) == dropped_before
           and time.monotonic() < deadline):
        time.sleep(0.05)

    stats = proxy.stats()
    assert stats.dropped.get((SETUP_SIGNING_ID, SETUP_SIGNING_DROP), 0) == dropped_before + 1
    assert stats.forwarded.get(SETUP_SIGNING_ID, 0) == forwarded_before
    assert not [f for f in forward_tap.since(mark) if msgid(f) == SETUP_SIGNING_ID]

    # PX4 still signs with the installed key, not the one sent through the proxy.
    assert wait_frame(via_proxy, lambda b: signed_with(b, key))
    assert not wait_frame(via_proxy, lambda b: signed_with(b, other), timeout=2.0)
