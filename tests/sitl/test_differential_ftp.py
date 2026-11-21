"""VE-10 differential test: FILE_TRANSFER_PROTOCOL (SR-011 exclusion) never reaches PX4.

The FC cannot be observed from inside, so the block is shown by its absence of
effect. The request is MAVLink FTP ListDirectory of "/"; PX4 answers it with an
FTP ACK or NAK (``req_opcode`` 3) whatever the directory holds.

1. Direct (GCS link, no proxy): PX4 replies.
2. Via the proxy (offboard link): no reply within the same timeout, and the
   proxy counts exactly one FILE_TRANSFER_PROTOCOL drop and no forward.
   Control: the same request sent straight to the proxy's FC-side target
   (PX4's offboard link), bypassing the proxy, is answered and the reply comes
   back through the proxy to the same connection. So that link answers FTP and
   relays replies; the silence in step 2 is the proxy's drop.
"""

import random
import socket
import struct

import pytest
from pymavlink.dialects.v20 import common as mav2

pytestmark = pytest.mark.sitl

FTP_ID = mav2.MAVLINK_MSG_ID_FILE_TRANSFER_PROTOCOL
FTP_LIST_DIRECTORY = 3
FTP_RSP_ACK = 128
FTP_RSP_NAK = 129
FTP_PAYLOAD_LEN = 251
REPLY_TIMEOUT = 5.0  # also the silence window for the proxied request


def list_directory(link, path: str = "/") -> mav2.MAVLink_file_transfer_protocol_message:
    """FTP ListDirectory request addressed to the link's PX4, with a fresh sequence number."""
    data = path.encode("ascii")
    # seq_number, session, opcode, size, req_opcode, burst_complete, padding, offset
    header = struct.pack("<HBBBBBBI", random.randrange(1, 0xFFFF), 0, FTP_LIST_DIRECTORY,
                         len(data), 0, 0, 0, 0)
    payload = header + data
    return mav2.MAVLink_file_transfer_protocol_message(
        0, link.target_system, link.target_component,
        list(payload + bytes(FTP_PAYLOAD_LEN - len(payload))),
    )


def is_list_directory_reply(msg) -> bool:
    if msg.get_type() != "FILE_TRANSFER_PROTOCOL":
        return False
    opcode, req_opcode = msg.payload[3], msg.payload[5]
    return opcode in (FTP_RSP_ACK, FTP_RSP_NAK) and req_opcode == FTP_LIST_DIRECTORY


def ftp_counts(stats) -> tuple[int, dict[str, int]]:
    forwarded = stats.forwarded.get(FTP_ID, 0)
    dropped = {reason: n for (msgid, reason), n in stats.dropped.items() if msgid == FTP_ID}
    return forwarded, dropped


def test_direct_ftp_list_directory_gets_reply(direct):
    direct.drain()
    direct.mav.send(list_directory(direct))
    replies = direct.collect(is_list_directory_reply, REPLY_TIMEOUT)
    assert replies, f"no FTP ACK/NAK from PX4 within {REPLY_TIMEOUT}s on the direct link"


def test_proxied_ftp_list_directory_dropped(via_proxy, proxy, fc_address):
    forwarded_before, dropped_before = ftp_counts(proxy.stats())
    via_proxy.drain()
    via_proxy.mav.send(list_directory(via_proxy))
    replies = via_proxy.collect(is_list_directory_reply, REPLY_TIMEOUT)
    assert replies == [], "PX4 answered an FTP request sent through the proxy"

    forwarded_after, dropped_after = ftp_counts(proxy.stats())
    assert forwarded_after == forwarded_before
    reason = "excluded message FILE_TRANSFER_PROTOCOL (SR-011)"
    assert dropped_after.get(reason, 0) == dropped_before.get(reason, 0) + 1
    assert sum(dropped_after.values()) == sum(dropped_before.values()) + 1

    # Control: same request, same link, same receiving connection, proxy bypassed.
    relayed_before = proxy.stats().downlink_relayed
    frame = bytes(list_directory(via_proxy).pack(via_proxy.mav))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as bypass:
        bypass.sendto(frame, fc_address)
        replies = via_proxy.collect(is_list_directory_reply, REPLY_TIMEOUT)
    assert replies, (
        f"control failed: no FTP ACK/NAK within {REPLY_TIMEOUT}s for the request sent "
        f"straight to {fc_address}, so the proxied silence above proves nothing"
    )
    assert proxy.stats().downlink_relayed > relayed_before
    assert ftp_counts(proxy.stats()) == (forwarded_after, dropped_after)
