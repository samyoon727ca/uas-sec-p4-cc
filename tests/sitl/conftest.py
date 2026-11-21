"""Fixtures for the differential PX4 SITL tests (``pytest -m sitl``).

PX4 SITL (started outside pytest, see .github/workflows/sitl.yml) runs two
MAVLink UDP links that matter here (ROMFS init.d-posix/px4-rc.mavlink, both
started with ``-x``, i.e. MAVLink FTP enabled):

* GCS link: listens on 18570, sends to 127.0.0.1:14550. The ``direct``
  connection listens on 14550 and talks to PX4 with nothing in between.
* Offboard link: listens on 14580, sends to 127.0.0.1:14540 until it receives
  its first datagram. The in-process :class:`~cc_proxy.proxy.Proxy` is pointed
  at 14580 and the ``via_proxy`` connection talks to the proxy.

A PX4 UDP link pairs with the source address of the first datagram it receives
and sends everything to that address. It accepts and handles datagrams from
any source, but once its partner has been silent for 3 s (PX4 v1.18.0-rc2,
``Mavlink::CLIENT_SOURCE_TIMEOUT``) the next other source takes the link over.
The two paths therefore use different links (each pairs with its own client),
the proxy is started once per session, and the ``via_proxy`` connection sends a
GCS HEARTBEAT at 1 Hz (through the proxy, which allows it) while it waits for
messages, so the proxy stays PX4's partner on the offboard link.

The proxy writes its SR-013 command log to ``command_log_path`` (a session temp
file) and hands every frame it sends to PX4 to ``forward_tap``, so tests can
compare it with the frame the client sent.

If no PX4 HEARTBEAT arrives on the GCS link, the SITL tests are skipped, so
``pytest`` works without PX4. Set ``CC_SITL_REQUIRED=1`` (CI does) to make that
a failure instead, so a SITL that did not start cannot pass as skipped tests.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import pytest

# MAVLink 2 from the first frame on (pymavlink would otherwise start in MAVLink 1
# and only switch if the first bytes it receives are MAVLink 2).
os.environ["MAVLINK20"] = "1"

from pymavlink import mavutil  # noqa: E402

from cc_proxy.cmdlog import CommandLog  # noqa: E402
from cc_proxy.policy import load_policy  # noqa: E402
from cc_proxy.proxy import Proxy  # noqa: E402

POLICY_PATH = Path(__file__).resolve().parents[2] / "policy.yaml"

SITL_HOST = "127.0.0.1"
GCS_LINK_REMOTE_PORT = 14550  # where PX4's GCS link sends; the direct connection listens here
OFFBOARD_LINK_PORT = 14580  # PX4's offboard link listens here; the proxy forwards to it
AUTOPILOT_COMPONENT = 1  # MAV_COMP_ID_AUTOPILOT1
CLIENT_SYSTEM = 255
CLIENT_COMPONENT = 190  # MAV_COMP_ID_MISSIONPLANNER

REQUIRED = os.environ.get("CC_SITL_REQUIRED", "") not in ("", "0")
# Without CC_SITL_REQUIRED only probe briefly: PX4 sends HEARTBEAT at 1 Hz.
HEARTBEAT_TIMEOUT = 120.0 if REQUIRED else 3.0
PAIR_TIMEOUT = 15.0
KEEPALIVE_PERIOD = 1.0  # well inside PX4's 3 s partner timeout


def _unavailable(reason: str):
    if REQUIRED:
        pytest.fail(f"PX4 SITL required (CC_SITL_REQUIRED) but {reason}", pytrace=False)
    pytest.skip(f"PX4 SITL not reachable: {reason}")


def _is_px4_heartbeat(msg) -> bool:
    return (
        msg.get_type() == "HEARTBEAT"
        and msg.get_srcComponent() == AUTOPILOT_COMPONENT
        and msg.type != mavutil.mavlink.MAV_TYPE_GCS
    )


@dataclass
class Link:
    """A pymavlink connection plus the PX4 system/component it talks to."""

    conn: object
    target_system: int
    target_component: int
    keepalive: bool = False  # send a GCS HEARTBEAT every KEEPALIVE_PERIOD in collect()
    _last_heartbeat: float = field(default=float("-inf"), repr=False)

    @property
    def mav(self):
        return self.conn.mav

    def heartbeat(self) -> None:
        self.mav.heartbeat_send(mavutil.mavlink.MAV_TYPE_GCS,
                                mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0)
        self._last_heartbeat = time.monotonic()

    def drain(self) -> None:
        while self.conn.recv_match(blocking=False) is not None:
            pass

    def collect(self, predicate: Callable, timeout: float) -> list:
        """The first message matching ``predicate`` within ``timeout`` seconds, as a list.

        Empty if none arrived, so ``collect(...) == []`` asserts silence.
        """
        deadline = time.monotonic() + timeout
        while (remaining := deadline - time.monotonic()) > 0:
            if self.keepalive and time.monotonic() - self._last_heartbeat >= KEEPALIVE_PERIOD:
                self.heartbeat()
            msg = self.conn.recv_match(blocking=True, timeout=min(remaining, 0.5))
            if msg is not None and msg.get_type() != "BAD_DATA" and predicate(msg):
                return [msg]
        return []


@pytest.fixture(scope="session")
def direct():
    """Connection on PX4's GCS link, no proxy in between; waits for PX4's HEARTBEAT."""
    try:
        conn = mavutil.mavlink_connection(
            f"udpin:0.0.0.0:{GCS_LINK_REMOTE_PORT}", dialect="common",
            source_system=CLIENT_SYSTEM, source_component=CLIENT_COMPONENT,
        )
    except OSError as exc:
        _unavailable(f"cannot listen on UDP {GCS_LINK_REMOTE_PORT}: {exc}")
    try:
        link = Link(conn, 0, AUTOPILOT_COMPONENT)
        hb = link.collect(_is_px4_heartbeat, HEARTBEAT_TIMEOUT)
        if not hb:
            _unavailable(f"no PX4 HEARTBEAT on UDP {GCS_LINK_REMOTE_PORT} "
                         f"within {HEARTBEAT_TIMEOUT:.0f}s")
        link.target_system = hb[0].get_srcSystem()
        yield link
    finally:
        conn.close()


@pytest.fixture(scope="session")
def fc_address():
    """PX4 address the proxy forwards to (the offboard link)."""
    return SITL_HOST, OFFBOARD_LINK_PORT


class ForwardTap:
    """Collects every frame the proxy sends to the FC (``Proxy(on_forward=...)``).

    Unbounded: a test session forwards a few hundred frames.
    """

    def __init__(self):
        self._frames: list[bytes] = []

    def __call__(self, frame: bytes) -> None:  # proxy thread; list.append is atomic
        self._frames.append(frame)

    def mark(self) -> int:
        """Number of frames seen so far; pass it to :meth:`since`."""
        return len(self._frames)

    def since(self, mark: int) -> list[bytes]:
        return self._frames[mark:]


@pytest.fixture(scope="session")
def command_log_path(tmp_path_factory) -> Path:
    """Path of the proxy's SR-013 command log for this session."""
    return tmp_path_factory.mktemp("cmdlog") / "cc-commands.jsonl"


@pytest.fixture(scope="session")
def forward_tap() -> ForwardTap:
    return ForwardTap()


@pytest.fixture(scope="session")
def proxy(direct, fc_address, command_log_path, forward_tap):
    """In-process proxy on an ephemeral local port, forwarding to PX4's offboard link."""
    with CommandLog(command_log_path) as command_log:
        p = Proxy(load_policy(POLICY_PATH), (SITL_HOST, 0), fc_address,
                  command_log=command_log, on_forward=forward_tap)
        p.start()
        try:
            yield p
        finally:
            p.stop()
    assert p.error is None, f"proxy loop failed: {p.error!r}"


@pytest.fixture(scope="session")
def via_proxy(direct, proxy):
    """Connection to the proxy; returns once PX4's HEARTBEAT comes back through it.

    Our HEARTBEAT (allowed by policy.yaml) is what pairs PX4's offboard link with
    the proxy's FC-side socket and registers this connection as a proxy GCS peer;
    the keepalive repeats it so the pairing holds (see the module docstring).
    """
    host, port = proxy.listen_address[:2]
    conn = mavutil.mavlink_connection(
        f"udpout:{host}:{port}", dialect="common",
        source_system=CLIENT_SYSTEM, source_component=CLIENT_COMPONENT,
    )
    try:
        link = Link(conn, direct.target_system, AUTOPILOT_COMPONENT, keepalive=True)
        if not link.collect(_is_px4_heartbeat, PAIR_TIMEOUT):
            pytest.fail(
                f"no PX4 HEARTBEAT through the proxy (offboard link, UDP "
                f"{OFFBOARD_LINK_PORT}) within {PAIR_TIMEOUT:.0f}s", pytrace=False,
            )
        yield link
    finally:
        conn.close()
