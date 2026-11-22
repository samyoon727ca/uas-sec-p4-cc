"""Minimal UDP MAVLink proxy between the GCS link and the flight controller.

Uplink (GCS -> FC) is filtered: the datagram's source IP is mapped to a peer
(``Policy.peer_for``, see ``peers`` in policy.yaml), every received datagram is
split into MAVLink frames (one datagram may carry several), each frame is
passed to :func:`cc_proxy.classifier.classify`, frames the classifier allows
are checked against the SR-012 token bucket for ``(peer, msgid)``, and only
frames that pass both are sent to the FC, one datagram per frame. All frames
from a source no peer covers are dropped with reason ``"unknown_peer"``; frames
over their rate are dropped with reason ``"rate_limited"``. What is sent is a
``memoryview`` slice of the received datagram, never a re-encoded message, so
MAVLink 2 signatures and every other byte survive unchanged.

Downlink (FC -> GCS) is **not filtered** in this slice: datagrams arriving from
the FC address are relayed unchanged to the most recent GCS addresses that had
at least one frame forwarded. Only sources the peer map covers can have a
frame forwarded, so only they receive downlink. The FC-side socket is
connected to the FC address, so the kernel discards datagrams from any other
source; any that still arrive are ignored. A connected socket also reports an
ICMP port-unreachable from an earlier send (FC not up yet) on a later send;
that send is retried once before the frame counts as a send error. A datagram
counts as relayed when at least one GCS send succeeded, otherwise as
``downlink_send_failed``.

Every uplink frame ends up in exactly one counter: ``forwarded[msgid]`` or
``dropped[(msgid, reason)]`` (``msgid`` is ``None`` when the header could not
be parsed; a send error is counted as a drop with reason ``"send error"``).
Frames from a known peer are also counted per peer: ``peer_forwarded[peer]``
and ``peer_dropped[(peer, reason)]``. The ``local_peer`` from the policy is
labelled CC-originated.

COMMAND_LONG / COMMAND_INT frames are also written to the SR-013 command log
(:class:`cc_proxy.cmdlog.CommandLog`), forwarded and dropped alike (drop
lines are capped per peer; the proxy loop calls ``tick`` to write the
suppressed-drop summaries).
"""

from __future__ import annotations

import argparse
import logging
import selectors
import signal
import socket
import sys
import threading
import time
from collections import Counter, OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field

from pymavlink.dialects.v20 import common as _mavlink

from .classifier import (
    CHECKSUM_LEN,
    INCOMPAT_SIGNED,
    MAGIC_V1,
    MAGIC_V2,
    SIGNATURE_LEN,
    V1_HEADER_LEN,
    V2_HEADER_LEN,
    Action,
    Decision,
    classify,
)
from .cmdlog import DEFAULT_PATH as DEFAULT_COMMAND_LOG
from .cmdlog import CommandLog
from .policy import Policy, PolicyError, load_policy
from .ratelimit import Clock, RateLimiter

log = logging.getLogger(__name__)

Address = tuple[str, int]

MAX_DATAGRAM = 65535
MAX_GCS_PEERS = 8  # downlink fan-out bound; oldest GCS address is evicted first
_SELECT_TIMEOUT = 0.1

UNKNOWN_PEER = "unknown_peer"
RATE_LIMITED = "rate_limited"


@dataclass(frozen=True)
class ProxyStats:
    """Snapshot of the proxy counters."""

    forwarded: dict[int, int] = field(default_factory=dict)
    dropped: dict[tuple[int | None, str], int] = field(default_factory=dict)
    downlink_relayed: int = 0
    downlink_ignored: int = 0
    downlink_send_failed: int = 0
    peer_forwarded: dict[str, int] = field(default_factory=dict)
    peer_dropped: dict[tuple[str, str], int] = field(default_factory=dict)
    local_peer: str | None = None

    def format(self) -> str:
        lines = ["uplink forwarded:"]
        for msgid, n in sorted(self.forwarded.items()):
            lines.append(f"  {_msg_name(msgid)} ({msgid}): {n}")
        lines.append("uplink dropped:")
        for (msgid, reason), n in sorted(
            self.dropped.items(), key=lambda kv: (kv[0][0] is None, kv[0][0] or 0, kv[0][1])
        ):
            lines.append(f"  {_msg_name(msgid)} ({msgid}) [{reason}]: {n}")
        lines.append("uplink per peer:")
        names = sorted(set(self.peer_forwarded) | {name for name, _ in self.peer_dropped})
        for name in names:
            label = f"{name} (CC-originated)" if name == self.local_peer else name
            lines.append(f"  {label}: forwarded {self.peer_forwarded.get(name, 0)}")
            for (peer, reason), n in sorted(self.peer_dropped.items()):
                if peer == name:
                    lines.append(f"    dropped [{reason}]: {n}")
        lines.append(
            f"downlink relayed: {self.downlink_relayed} datagrams, "
            f"ignored: {self.downlink_ignored}, "
            f"send failed: {self.downlink_send_failed}"
        )
        return "\n".join(lines)


def _msg_name(msgid: int | None) -> str:
    cls = _mavlink.mavlink_map.get(msgid) if msgid is not None else None
    return cls.msgname if cls is not None else "?"


def frame_length(buf: memoryview, offset: int) -> int | None:
    """Declared length of the frame starting at ``buf[offset]``.

    Returns ``None`` if the magic byte is unknown or the header is incomplete.
    The length is only used to delimit the slice; :func:`classify` validates it.
    """
    remaining = len(buf) - offset
    magic = buf[offset]
    if magic == MAGIC_V2 and remaining >= V2_HEADER_LEN:
        signature_len = SIGNATURE_LEN if buf[offset + 2] & INCOMPAT_SIGNED else 0
        return V2_HEADER_LEN + buf[offset + 1] + CHECKSUM_LEN + signature_len
    if magic == MAGIC_V1 and remaining >= V1_HEADER_LEN:
        return V1_HEADER_LEN + buf[offset + 1] + CHECKSUM_LEN
    return None


def split_frames(data: bytes) -> list[memoryview]:
    """Split a datagram into frame slices (views into ``data``, no copies).

    If a frame cannot be delimited (unknown magic, short header, or a declared
    length past the end of the datagram), the whole remainder is returned as one
    final slice; :func:`classify` always drops such a slice.
    """
    view = memoryview(data)
    frames = []
    offset = 0
    while offset < len(view):
        n = frame_length(view, offset)
        if n is None or offset + n > len(view):
            n = len(view) - offset
        frames.append(view[offset : offset + n])
        offset += n
    return frames


def _resolve(addr: Address) -> tuple[int, tuple]:
    host, port = addr
    family, _, _, _, sockaddr = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)[0]
    return family, sockaddr


class Proxy:
    """UDP MAVLink proxy; run it with :meth:`start` / :meth:`stop`.

    ``command_log`` receives every command frame (see :mod:`cc_proxy.cmdlog`);
    the caller owns it and closes it after :meth:`stop`. ``on_forward``, if
    given, is called from the proxy thread with a copy of each frame exactly as
    it was sent to the FC (tests use it to check frames pass byte-for-byte).
    An exception raised by ``on_forward`` is not caught: like a command-log
    write error it stops the proxy loop (fail closed, see :attr:`error`).
    """

    def __init__(
        self,
        policy: Policy,
        listen_addr: Address,
        fc_addr: Address,
        clock: Clock = time.monotonic,
        command_log: CommandLog | None = None,
        on_forward: Callable[[bytes], None] | None = None,
    ):
        self.policy = policy
        self._command_log = command_log
        self._on_forward = on_forward
        self._limiter = RateLimiter(policy.rate_for, clock)
        self._listen_addr = listen_addr
        self._fc_addr = fc_addr
        self._fc_sockaddr: tuple | None = None
        self._gcs_sock: socket.socket | None = None
        self._fc_sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._forwarded: Counter[int] = Counter()
        self._dropped: Counter[tuple[int | None, str]] = Counter()
        self._peer_forwarded: Counter[str] = Counter()
        self._peer_dropped: Counter[tuple[str, str]] = Counter()
        self._downlink_relayed = 0
        self._downlink_ignored = 0
        self._downlink_send_failed = 0
        self._gcs_peers: OrderedDict[tuple, None] = OrderedDict()
        self.error: BaseException | None = None

    @property
    def listen_address(self) -> tuple:
        """Bound GCS-side address (useful when listening on port 0)."""
        if self._gcs_sock is None:
            raise RuntimeError("proxy not started")
        return self._gcs_sock.getsockname()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("proxy already started")
        listen_family, listen_sockaddr = _resolve(self._listen_addr)
        fc_family, self._fc_sockaddr = _resolve(self._fc_addr)
        gcs_sock = socket.socket(listen_family, socket.SOCK_DGRAM)
        fc_sock = None
        try:
            fc_sock = socket.socket(fc_family, socket.SOCK_DGRAM)
            gcs_sock.bind(listen_sockaddr)
            # Connected: the kernel picks the local address that routes to the
            # FC and discards datagrams from any other source.
            fc_sock.connect(self._fc_sockaddr)
            gcs_sock.setblocking(False)
            fc_sock.setblocking(False)
        except OSError:
            gcs_sock.close()
            if fc_sock is not None:
                fc_sock.close()
            raise
        self._gcs_sock, self._fc_sock = gcs_sock, fc_sock
        self._thread = threading.Thread(target=self._run, name="cc-proxy", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join()
        for sock in (self._gcs_sock, self._fc_sock):
            if sock is not None:
                sock.close()

    def stats(self) -> ProxyStats:
        with self._lock:
            return ProxyStats(
                forwarded=dict(self._forwarded),
                dropped=dict(self._dropped),
                downlink_relayed=self._downlink_relayed,
                downlink_ignored=self._downlink_ignored,
                downlink_send_failed=self._downlink_send_failed,
                peer_forwarded=dict(self._peer_forwarded),
                peer_dropped=dict(self._peer_dropped),
                local_peer=next((p.name for p in self.policy.peers if p.local), None),
            )

    def _run(self) -> None:
        sel = selectors.DefaultSelector()
        sel.register(self._gcs_sock, selectors.EVENT_READ, self._on_uplink)
        sel.register(self._fc_sock, selectors.EVENT_READ, self._on_downlink)
        try:
            while not self._stop_event.is_set():
                for key, _ in sel.select(timeout=_SELECT_TIMEOUT):
                    key.data()
                if self._command_log is not None:
                    self._command_log.tick()
        except BaseException as exc:
            self.error = exc
            log.exception("proxy loop failed")
        finally:
            sel.close()

    @staticmethod
    def _recv(sock: socket.socket) -> tuple[bytes, tuple] | None:
        try:
            return sock.recvfrom(MAX_DATAGRAM)
        except OSError as exc:
            # Includes BlockingIOError and, on Windows, ConnectionResetError
            # caused by an ICMP port-unreachable for an earlier sendto.
            log.debug("recvfrom failed: %s", exc)
            return None

    def _on_uplink(self) -> None:
        received = self._recv(self._gcs_sock)
        if received is None:
            return
        data, src = received
        peer = self.policy.peer_for(src[0])
        peer_name = peer.name if peer is not None else None
        any_forwarded = False
        for frame in split_frames(data):
            decision = classify(frame, self.policy)
            if peer is None:
                # Classified only to count the drop under its message ID.
                log.debug("drop from %s: msgid=%s %s", src, decision.msgid, UNKNOWN_PEER)
                self._drop(frame, src, decision, UNKNOWN_PEER)
                continue
            if decision.action is not Action.FORWARD:
                log.debug("drop from %s (%s): msgid=%s %s",
                          src, peer_name, decision.msgid, decision.reason)
                self._drop(frame, src, decision, decision.reason, peer_name)
                continue
            if not self._limiter.allow(peer_name, decision.msgid):
                log.debug("drop from %s (%s): msgid=%s %s",
                          src, peer_name, decision.msgid, RATE_LIMITED)
                self._drop(frame, src, decision, RATE_LIMITED, peer_name)
                continue
            try:
                self._send_to_fc(frame)
            except OSError as exc:
                log.warning("send to FC failed: %s", exc)
                self._drop(frame, src, decision, "send error", peer_name)
                continue
            with self._lock:
                self._forwarded[decision.msgid] += 1
                self._peer_forwarded[peer_name] += 1
            any_forwarded = True
            if self._command_log is not None:
                self._command_log.forwarded(frame, src, peer_name, decision)
            if self._on_forward is not None:
                self._on_forward(bytes(frame))
        if any_forwarded:
            with self._lock:
                self._gcs_peers[src] = None
                self._gcs_peers.move_to_end(src)
                while len(self._gcs_peers) > MAX_GCS_PEERS:
                    self._gcs_peers.popitem(last=False)

    def _send_to_fc(self, frame: memoryview) -> None:
        try:
            self._fc_sock.send(frame)
        except ConnectionRefusedError as exc:
            # A connected UDP socket reports an ICMP port-unreachable from an
            # earlier send (FC not up yet, or restarting) on the next send,
            # which then fails although this frame was never sent. The error
            # is cleared once reported, so send this frame once more.
            log.debug("send to FC refused (earlier ICMP error), retrying: %s", exc)
            self._fc_sock.send(frame)

    def _on_downlink(self) -> None:
        received = self._recv(self._fc_sock)
        if received is None:
            return
        data, src = received
        with self._lock:
            peers = list(self._gcs_peers)
            if src[:2] != self._fc_sockaddr[:2] or not peers:
                self._downlink_ignored += 1
                return
        sent = False
        for peer in peers:
            try:
                self._gcs_sock.sendto(data, peer)
            except OSError as exc:
                log.debug("send to GCS %s failed: %s", peer, exc)
            else:
                sent = True
        with self._lock:
            if sent:
                self._downlink_relayed += 1
            else:
                self._downlink_send_failed += 1

    def _drop(
        self, frame: memoryview, src: tuple, decision: Decision, reason: str,
        peer: str | None = None,
    ) -> None:
        with self._lock:
            self._dropped[(decision.msgid, reason)] += 1
            if peer is not None:
                self._peer_dropped[(peer, reason)] += 1
        if self._command_log is not None:
            self._command_log.dropped(frame, src, peer, decision, reason)


def parse_address(value: str) -> Address:
    """Parse ``host:port`` (IPv6 as ``[addr]:port``)."""
    host, sep, port = value.rpartition(":")
    if not sep or not host:
        raise argparse.ArgumentTypeError(f"expected HOST:PORT, got {value!r}")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        port_num = int(port)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid port in {value!r}") from None
    if not 0 <= port_num <= 65535:
        raise argparse.ArgumentTypeError(f"port out of range in {value!r}")
    return host, port_num


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cc-proxy", description="Inline MAVLink allowlist proxy (GCS -> FC uplink)."
    )
    parser.add_argument("--policy", required=True, help="path to policy.yaml")
    parser.add_argument(
        "--listen", required=True, type=parse_address, help="GCS-side HOST:PORT to bind"
    )
    parser.add_argument("--fc", required=True, type=parse_address, help="FC HOST:PORT")
    parser.add_argument(
        "--command-log", default=DEFAULT_COMMAND_LOG,
        help=f"JSON-lines command log to append to (default: {DEFAULT_COMMAND_LOG})",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="log every drop")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        policy = load_policy(args.policy)
    except (PolicyError, OSError) as exc:
        print(f"cc-proxy: {exc}", file=sys.stderr)
        return 2

    stop = threading.Event()

    def _request_stop(signum, _frame):
        stop.set()

    # Installed before start() so Ctrl-C at any point leads to a clean stop.
    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), _request_stop)

    try:
        command_log = CommandLog(args.command_log)
    except OSError as exc:
        print(f"cc-proxy: cannot open command log: {exc}", file=sys.stderr)
        return 1
    with command_log:
        proxy = Proxy(policy, args.listen, args.fc, command_log=command_log)
        try:
            proxy.start()
        except OSError as exc:
            print(f"cc-proxy: cannot open sockets: {exc}", file=sys.stderr)
            return 1

        listen = proxy.listen_address
        log.info(
            "listening on %s:%s, forwarding to %s:%s (policy status: %s, command log: %s)",
            listen[0], listen[1], args.fc[0], args.fc[1], policy.status, command_log.path,
        )
        try:
            while proxy.running and not stop.wait(0.5):
                pass
        finally:
            proxy.stop()
            print(proxy.stats().format(), flush=True)
    return 1 if proxy.error is not None or command_log.error is not None else 0


if __name__ == "__main__":
    sys.exit(main())
