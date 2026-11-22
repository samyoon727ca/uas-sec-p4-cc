"""VE-10: the SR-011 exclusions other than FILE_TRANSFER_PROTOCOL never reach PX4.

FILE_TRANSFER_PROTOCOL has its own test (test_differential_ftp.py). This module
covers the other five, each with the strongest oracle PX4 SITL (v1.18.0-rc2,
SIH, the links of conftest.py) allows. The oracle type is stated per type in
``CASES`` and in docs/evidence/VE-10.md.

**Differential** (PX4 reacts in a way the client can see):

* SERIAL_CONTROL: a MAVLink shell (pxh) line with SERIAL_CONTROL_FLAG_RESPOND.
  PX4 starts a shell on the receiving link and answers with SERIAL_CONTROL
  replies (the echoed characters and the command output). The shell is closed
  again afterwards (a SERIAL_CONTROL with no RESPOND flag, as QGroundControl
  does when its console closes).
* SETUP_SIGNING: a fresh 32-byte key, sent unsigned while PX4 has no key (the
  THR-057 first-key case). PX4 installs it on all links and from then on signs
  its own frames with it. The key is removed again afterwards (signed blank-key
  SETUP_SIGNING, as in test_signed_passthrough.py), so every test starts and
  ends with PX4 unsigned.
* ADSB_VEHICLE: a traffic report with a random ICAO address and no valid
  coordinates (so traffic avoidance has nothing to act on). PX4 publishes it as
  a transponder report and re-sends it in its own ADSB_VEHICLE stream on every
  link, with PX4 as the source system. That shows the report entered PX4's
  traffic pipeline, the input THR-050 is about.

For each: the direct baseline (GCS link, no proxy) shows the reaction; via the
proxy there is none within the same window, the proxy counts exactly one SR-011
drop and forwards none of that type; and the control, the same frame sent
straight to the proxy's FC-side target (PX4's offboard link) and answered back
through the proxy, shows that link would have reacted (same pattern as the FTP
test).

**Egress-only** (no reaction PX4 SITL can show):

* RADIO_STATUS: PX4 records it and only throttles its streams on a link started
  with software throttling (``mavlink start -s``); none of the SITL links is.
  PX4 has no RADIO_STATUS stream that would echo it.
* COLLISION: PX4 v1.18.0-rc2 has no receive handler for it.

For these only the proxy's egress is checked: the frame is counted as one SR-011
drop and is not among the frames the proxy sent to PX4 (``forward_tap``). An
allowlisted PING sent right after it is in the tap, which shows the tap sees
the proxy's egress; the proxy handles uplink datagrams in order on one thread,
so by then the excluded frame has been handled too. Nothing here shows what
PX4 would do with these frames.
"""

from __future__ import annotations

import hashlib
import os
import random
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass

import pytest
from pymavlink.dialects.v20 import common as mav2

pytestmark = pytest.mark.sitl

DIFFERENTIAL = "differential"
EGRESS_ONLY = "egress-only"

REPLY_TIMEOUT = 5.0  # reaction wait, also the silence window for the proxied frame
SEND_ATTEMPTS = 3  # UDP: resend a frame that should get a reaction
ACCOUNT_TIMEOUT = 2.0
AUTOPILOT_COMPONENT = 1

KEY_LEN = 32
MAVLINK_EPOCH = 1420070400  # 2015-01-01T00:00:00Z
CLEANUP_LINK_ID = 21  # signing link ID for the key removal (distinct signing stream)

SHELL_LINE = b"ver git\n"
SERIAL_CONTROL_DATA_LEN = 70


def msgid(frame: bytes) -> int:
    return int.from_bytes(frame[7:10], "little") if frame[0] == 0xFD else frame[5]


def from_autopilot(link, msg) -> bool:
    return (msg.get_srcSystem() == link.target_system
            and msg.get_srcComponent() == AUTOPILOT_COMPONENT)


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


def wait_frame(link, check, timeout: float = REPLY_TIMEOUT) -> bool:
    """True once an autopilot frame whose raw bytes satisfy ``check`` arrives on ``link``."""
    link.drain()
    found = link.collect(
        lambda m: from_autopilot(link, m) and check(bytes(m.get_msgbuf())), timeout
    )
    return bool(found)


def accept_all(mav, msg_id) -> bool:
    """pymavlink unsigned callback: hand every frame to the test."""
    return True


@dataclass
class Route:
    """Where a frame is sent (``send``) and where PX4's reaction is read (``link``)."""

    link: object
    send: Callable[[bytes], object]


class Case:
    """One SR-011 excluded type: how to build it and, if differential, see PX4 react."""

    name: str
    oracle: str

    @property
    def msgid(self) -> int:
        return getattr(mav2, f"MAVLINK_MSG_ID_{self.name}")

    @property
    def drop_reason(self) -> str:
        return f"excluded message {self.name} (SR-011)"

    def token(self):
        """Fresh per-test value that ties a reaction to the frame that caused it."""
        return None

    def message(self, link, token):
        raise NotImplementedError

    def frame(self, link, token) -> bytes:
        return bytes(self.message(link, token).pack(link.mav))

    # Differential cases only.
    def prepare(self, direct, via_proxy) -> None:
        """Check the PX4 state the test relies on."""

    def reacted(self, link, token, timeout: float) -> bool:
        raise NotImplementedError

    def cleanup(self, route: Route, direct, via_proxy, token) -> None:
        """Undo whatever the frame changed on PX4, whether or not it got through."""


class SerialControl(Case):
    name = "SERIAL_CONTROL"
    oracle = DIFFERENTIAL

    @staticmethod
    def _shell(flags: int, data: bytes):
        return mav2.MAVLink_serial_control_message(
            mav2.SERIAL_CONTROL_DEV_SHELL, flags, 0, 0, len(data),
            list(data + bytes(SERIAL_CONTROL_DATA_LEN - len(data))),
        )

    def message(self, link, token):
        flags = mav2.SERIAL_CONTROL_FLAG_RESPOND | mav2.SERIAL_CONTROL_FLAG_EXCLUSIVE
        return self._shell(flags, SHELL_LINE)

    def reacted(self, link, token, timeout: float) -> bool:
        def is_shell_reply(m) -> bool:
            return (m.get_type() == "SERIAL_CONTROL" and from_autopilot(link, m)
                    and bool(m.flags & mav2.SERIAL_CONTROL_FLAG_REPLY)
                    and m.device == mav2.SERIAL_CONTROL_DEV_SHELL)

        return bool(link.collect(is_shell_reply, timeout))

    def cleanup(self, route: Route, direct, via_proxy, token) -> None:
        # No RESPOND flag: PX4 closes the shell of the link it arrives on.
        route.send(bytes(self._shell(0, b"").pack(route.link.mav)))


class SetupSigning(Case):
    name = "SETUP_SIGNING"
    oracle = DIFFERENTIAL

    def token(self) -> bytes:
        return os.urandom(KEY_LEN)

    def message(self, link, key):
        return mav2.MAVLink_setup_signing_message(
            link.target_system, link.target_component, list(key), signing_timestamp()
        )

    def prepare(self, direct, via_proxy) -> None:
        for link in (direct, via_proxy):
            assert wait_frame(link, lambda b: not is_signed(b)), (
                "PX4 already signs its frames; this test needs PX4 without a key"
            )

    def reacted(self, link, key, timeout: float) -> bool:
        return wait_frame(link, lambda b: signed_with(b, key), timeout)

    def cleanup(self, route: Route, direct, via_proxy, key) -> None:
        """Remove ``key`` from PX4 (a no-op if PX4 has no key) and check both links."""
        direct.conn.setup_signing(key, sign_outgoing=True, allow_unsigned_callback=accept_all,
                                  link_id=CLEANUP_LINK_ID)
        try:
            # Both links are checked inside the loop: a key installed on the
            # offboard link reaches the GCS link by a reload on its own thread, so
            # a blank key that arrives first is a no-op and has to be resent.
            for _ in range(SEND_ATTEMPTS):
                direct.mav.setup_signing_send(direct.target_system, direct.target_component,
                                              [0] * KEY_LEN, 0)
                if (wait_frame(direct, lambda b: not is_signed(b))
                        and wait_frame(via_proxy, lambda b: not is_signed(b))):
                    break
            else:
                pytest.fail("could not remove the signing key from PX4; later SITL tests "
                            "in this PX4 session would see signing", pytrace=False)
        finally:
            direct.conn.disable_signing()


class AdsbVehicle(Case):
    name = "ADSB_VEHICLE"
    oracle = DIFFERENTIAL

    def token(self) -> int:
        return random.randrange(0x100000, 0xFFFFFF)  # ICAO address

    def message(self, link, icao: int):
        return mav2.MAVLink_adsb_vehicle_message(
            icao, 0, 0, mav2.ADSB_ALTITUDE_TYPE_GEOMETRIC, 0, 0, 0, 0, b"CCPROBE",
            mav2.ADSB_EMITTER_TYPE_NO_INFO, 1, mav2.ADSB_FLAGS_VALID_CALLSIGN, 0,
        )

    def reacted(self, link, icao: int, timeout: float) -> bool:
        def is_reemitted(m) -> bool:
            return (m.get_type() == "ADSB_VEHICLE" and from_autopilot(link, m)
                    and m.ICAO_address == icao)

        return bool(link.collect(is_reemitted, timeout))


class RadioStatus(Case):
    name = "RADIO_STATUS"
    oracle = EGRESS_ONLY

    def message(self, link, token):
        # txbuf 0: the "radio buffer nearly full" report THR-051 is about.
        return mav2.MAVLink_radio_status_message(0, 0, 0, 0, 0, 0, 0)


class Collision(Case):
    name = "COLLISION"
    oracle = EGRESS_ONLY

    def message(self, link, token):
        return mav2.MAVLink_collision_message(
            mav2.MAV_COLLISION_SRC_ADSB, random.randrange(0x100000, 0xFFFFFF),
            mav2.MAV_COLLISION_ACTION_RTL, mav2.MAV_COLLISION_THREAT_LEVEL_HIGH, 1.0, 0.0, 0.0,
        )


CASES = [SerialControl(), SetupSigning(), RadioStatus(), AdsbVehicle(), Collision()]
DIFFERENTIAL_CASES = [c for c in CASES if c.oracle == DIFFERENTIAL]


def case_id(case: Case) -> str:
    return f"{case.name}-{case.oracle}"


def counts(stats, case: Case) -> tuple[int, int, int]:
    """(forwarded, dropped as SR-011, dropped for any reason) for the case's message ID."""
    dropped_all = sum(n for (mid, _), n in stats.dropped.items() if mid == case.msgid)
    return (stats.forwarded.get(case.msgid, 0),
            stats.dropped.get((case.msgid, case.drop_reason), 0), dropped_all)


def wait_for(condition: Callable[[], bool], timeout: float = ACCOUNT_TIMEOUT) -> bool:
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)
    return True


def expect_reaction(case: Case, route: Route, token) -> bool:
    frame = case.frame(route.link, token)
    for _ in range(SEND_ATTEMPTS):
        route.link.drain()
        route.send(frame)
        if case.reacted(route.link, token, REPLY_TIMEOUT):
            return True
    return False


@pytest.mark.parametrize("case", DIFFERENTIAL_CASES, ids=case_id)
def test_direct_baseline_reacts(case, direct, via_proxy):
    case.prepare(direct, via_proxy)
    token = case.token()
    route = Route(direct, direct.conn.write)
    try:
        assert expect_reaction(case, route, token), (
            f"no PX4 reaction to {case.name} within {REPLY_TIMEOUT}s x {SEND_ATTEMPTS} "
            f"on the direct link, so the differential has no baseline"
        )
    finally:
        case.cleanup(route, direct, via_proxy, token)


@pytest.mark.parametrize("case", CASES, ids=case_id)
def test_proxied_excluded_type_dropped(case, direct, via_proxy, proxy, forward_tap, fc_address):
    if case.oracle == DIFFERENTIAL:
        case.prepare(direct, via_proxy)
    token = case.token()
    forwarded, sr011, dropped_all = counts(proxy.stats(), case)
    mark = forward_tap.mark()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as bypass:
        control = Route(via_proxy, lambda frame: bypass.sendto(frame, fc_address))
        try:
            via_proxy.drain()
            via_proxy.conn.write(case.frame(via_proxy, token))

            if case.oracle == DIFFERENTIAL:
                assert not case.reacted(via_proxy, token, REPLY_TIMEOUT), (
                    f"PX4 reacted to a {case.name} sent through the proxy"
                )
            else:
                # Egress oracle: a later allowlisted frame reaching the tap means
                # the proxy has handled the excluded one.
                via_proxy.mav.ping_send(int(time.time() * 1e6), 0, 0, 0)
                assert wait_for(lambda: any(msgid(f) == mav2.MAVLINK_MSG_ID_PING
                                            for f in forward_tap.since(mark))), (
                    f"the PING sent after the {case.name} did not reach the proxy's "
                    f"egress within {ACCOUNT_TIMEOUT}s, so the tap shows nothing"
                )

            assert wait_for(lambda: counts(proxy.stats(), case)[1] > sr011)
            assert counts(proxy.stats(), case) == (forwarded, sr011 + 1, dropped_all + 1)
            assert not [f for f in forward_tap.since(mark) if msgid(f) == case.msgid], (
                f"the proxy sent a {case.name} frame to PX4"
            )

            if case.oracle == DIFFERENTIAL:
                # Control: same type, same link, same receiving connection, proxy bypassed.
                relayed_before = proxy.stats().downlink_relayed
                assert expect_reaction(case, control, token), (
                    f"control failed: no PX4 reaction to {case.name} sent straight to "
                    f"{fc_address}, so the proxied silence above proves nothing"
                )
                assert proxy.stats().downlink_relayed > relayed_before
                assert counts(proxy.stats(), case) == (forwarded, sr011 + 1, dropped_all + 1)
        finally:
            if case.oracle == DIFFERENTIAL:
                case.cleanup(control, direct, via_proxy, token)
