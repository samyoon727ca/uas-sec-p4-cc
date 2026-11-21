"""Pure-Python MAVLink frame classifier (SR-011 allowlist).

:func:`classify` takes exactly one raw MAVLink frame and decides whether the
proxy should forward it or drop it. Header fields are parsed directly from the
bytes; the frame is never decoded into a pymavlink message, re-encoded or
mutated, so whatever is forwarded is byte-for-byte what was received.

Checks, in order (first failure drops the frame):

1. Structure: known magic (v1 ``0xFE`` / v2 ``0xFD``), complete header, no
   unsupported v2 incompat flags, and the buffer length equals exactly the
   declared frame length (a trailing second frame could otherwise be smuggled
   past the classifier).
2. Message ID is known to the common dialect and the X.25 CRC (with CRC_EXTRA)
   matches, i.e. the flight controller would parse the frame as the same
   message we classified.
3. SR-011 exclusions (always win), then the message allowlist.
4. For COMMAND_LONG / COMMAND_INT, the MAV_CMD allowlist.

MAVLink 2 signatures are accounted for (13-byte trailer) but not verified here;
the proxy holds no signing key.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import Enum

from pymavlink.dialects.v20 import common as _mavlink
from pymavlink.generator.mavcrc import x25crc

from .policy import Policy

MAGIC_V1 = 0xFE
MAGIC_V2 = 0xFD

V1_HEADER_LEN = 6  # magic, len, seq, sysid, compid, msgid
V2_HEADER_LEN = 10  # magic, len, incompat, compat, seq, sysid, compid, msgid[3]
CHECKSUM_LEN = 2
SIGNATURE_LEN = 13
INCOMPAT_SIGNED = 0x01

MSG_ID_COMMAND_INT = 75
MSG_ID_COMMAND_LONG = 76

# Byte offset of the uint16 ``command`` field in the wire payload. Both messages
# put 28 bytes of 4-byte fields before it (see test_command_offsets_match_pymavlink).
_COMMAND_OFFSET = {MSG_ID_COMMAND_INT: 28, MSG_ID_COMMAND_LONG: 28}
# Both then put uint8 target_system, target_component right after ``command``.
_TARGETS_DELTA = 2


class Action(str, Enum):
    FORWARD = "forward"
    DROP = "drop"


@dataclass(frozen=True)
class Decision:
    action: Action
    reason: str
    msgid: int | None = None
    command: int | None = None
    sysid: int | None = None
    compid: int | None = None
    # Payload target_system / target_component; set whenever ``command`` is.
    target_system: int | None = None
    target_component: int | None = None


@dataclass(frozen=True)
class _Header:
    header_len: int
    payload_len: int
    frame_len: int
    sysid: int
    compid: int
    msgid: int


def classify(frame: bytes, policy: Policy) -> Decision:
    """Classify a single raw MAVLink frame against ``policy``.

    ``frame`` must contain exactly one MAVLink v1 or v2 frame (including the
    signature trailer if the v2 signed flag is set). The input is only read.
    """
    frame = bytes(frame)  # immutable snapshot; never written to
    header = _parse_header(frame)
    if isinstance(header, Decision):
        return header

    def decide(
        action: Action, reason: str, command: int | None = None,
        targets: tuple[int | None, int | None] = (None, None),
    ) -> Decision:
        return Decision(
            action=action,
            reason=reason,
            msgid=header.msgid,
            command=command,
            sysid=header.sysid,
            compid=header.compid,
            target_system=targets[0],
            target_component=targets[1],
        )

    msg_cls = _mavlink.mavlink_map.get(header.msgid)
    if msg_cls is None:
        return decide(Action.DROP, "unknown message id")

    crc_end = header.header_len + header.payload_len
    crc = x25crc(frame[1:crc_end])
    crc.accumulate(bytes([msg_cls.crc_extra]))
    (received_crc,) = struct.unpack_from("<H", frame, crc_end)
    if crc.crc != received_crc:
        return decide(Action.DROP, "bad checksum")

    if header.msgid in policy.excluded_messages:
        return decide(Action.DROP, f"excluded message {msg_cls.msgname} (SR-011)")
    if header.msgid not in policy.allowed_messages:
        return decide(Action.DROP, f"message {msg_cls.msgname} not in allowlist")

    offset = _COMMAND_OFFSET.get(header.msgid)
    if offset is None:
        return decide(Action.FORWARD, f"message {msg_cls.msgname} allowed")

    command = int.from_bytes(_read_payload(frame, header, offset, 2), "little")
    targets = tuple(_read_payload(frame, header, offset + _TARGETS_DELTA, 2))
    if command not in policy.allowed_commands:
        return decide(Action.DROP, f"command {command} not in allowlist", command, targets)
    return decide(Action.FORWARD, f"command {command} allowed", command, targets)


def _parse_header(frame: bytes) -> _Header | Decision:
    if not frame:
        return Decision(Action.DROP, "empty frame")
    magic = frame[0]
    if magic == MAGIC_V2:
        if len(frame) < V2_HEADER_LEN:
            return Decision(Action.DROP, "truncated header")
        payload_len = frame[1]
        incompat = frame[2]
        if incompat & ~INCOMPAT_SIGNED:
            return Decision(
                Action.DROP,
                f"unsupported incompat flags 0x{incompat:02x}",
                sysid=frame[5],
                compid=frame[6],
                msgid=int.from_bytes(frame[7:10], "little"),
            )
        signature_len = SIGNATURE_LEN if incompat & INCOMPAT_SIGNED else 0
        header = _Header(
            header_len=V2_HEADER_LEN,
            payload_len=payload_len,
            frame_len=V2_HEADER_LEN + payload_len + CHECKSUM_LEN + signature_len,
            sysid=frame[5],
            compid=frame[6],
            msgid=int.from_bytes(frame[7:10], "little"),
        )
    elif magic == MAGIC_V1:
        if len(frame) < V1_HEADER_LEN:
            return Decision(Action.DROP, "truncated header")
        payload_len = frame[1]
        header = _Header(
            header_len=V1_HEADER_LEN,
            payload_len=payload_len,
            frame_len=V1_HEADER_LEN + payload_len + CHECKSUM_LEN,
            sysid=frame[3],
            compid=frame[4],
            msgid=frame[5],
        )
    else:
        return Decision(Action.DROP, f"unknown magic 0x{magic:02x}")

    if len(frame) != header.frame_len:
        reason = "truncated frame" if len(frame) < header.frame_len else "trailing bytes"
        return Decision(
            Action.DROP,
            f"{reason} (got {len(frame)} bytes, expected {header.frame_len})",
            msgid=header.msgid,
            sysid=header.sysid,
            compid=header.compid,
        )
    return header


def _read_payload(frame: bytes, header: _Header, offset: int, size: int) -> bytes:
    """``size`` payload bytes at ``offset``, restoring v2 trailing-zero truncation.

    MAVLink 2 senders strip trailing zero bytes from the payload, so a field
    may be partly or wholly absent; missing bytes are zero.
    """
    payload = frame[header.header_len : header.header_len + header.payload_len]
    return payload[offset : offset + size].ljust(size, b"\x00")
