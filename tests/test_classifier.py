import struct
from dataclasses import replace
from pathlib import Path

import pytest
from pymavlink.dialects.v10 import common as mav1
from pymavlink.dialects.v20 import common as mav2

from cc_proxy.classifier import _COMMAND_OFFSET, _TARGETS_DELTA, Action, classify
from cc_proxy.policy import load_policy

POLICY_PATH = Path(__file__).resolve().parents[1] / "policy.yaml"


@pytest.fixture(scope="module")
def policy():
    return load_policy(POLICY_PATH)


def v2_link(signed=False):
    link = mav2.MAVLink(None, srcSystem=255, srcComponent=190)
    if signed:
        link.signing.secret_key = bytes(range(32))
        link.signing.link_id = 1
        link.signing.timestamp = 1
        link.signing.sign_outgoing = True
    return link


def pack(msg, link=None):
    return bytes(msg.pack(link or v2_link()))


def command_long(cmd, **kw):
    return mav2.MAVLink_command_long_message(
        kw.get("target_system", 1), kw.get("target_component", 1), cmd, 0, *([0.0] * 7)
    )


def command_int(cmd, **kw):
    return mav2.MAVLink_command_int_message(
        kw.get("target_system", 1), kw.get("target_component", 1), 0, cmd, 0, 0,
        0.0, 0.0, 0.0, 0.0, 0, 0, 0.0,
    )


def classify_checked(frame, policy):
    """Classify and assert the input buffer was not modified."""
    buf = bytearray(frame)
    before = bytes(buf)
    decision = classify(buf, policy)
    assert bytes(buf) == before
    return decision


EXCLUDED = {
    "SERIAL_CONTROL": mav2.MAVLink_serial_control_message(0, 0, 0, 0, 0, [0] * 70),
    "FILE_TRANSFER_PROTOCOL": mav2.MAVLink_file_transfer_protocol_message(0, 1, 1, [0] * 251),
    "SETUP_SIGNING": mav2.MAVLink_setup_signing_message(1, 1, [0] * 32, 0),
    "RADIO_STATUS": mav2.MAVLink_radio_status_message(0, 0, 0, 0, 0, 0, 0),
    "ADSB_VEHICLE": mav2.MAVLink_adsb_vehicle_message(
        1, 0, 0, 0, 0, 0, 0, 0, b"CALL", 0, 0, 0, 0
    ),
    "COLLISION": mav2.MAVLink_collision_message(0, 1, 0, 0, 0, 0, 0),
}


@pytest.mark.parametrize("name", sorted(EXCLUDED))
def test_excluded_messages_dropped(policy, name):
    frame = pack(EXCLUDED[name])
    d = classify_checked(frame, policy)
    assert d.action is Action.DROP
    assert d.msgid == getattr(mav2, f"MAVLINK_MSG_ID_{name}")
    assert "SR-011" in d.reason


def test_allowed_message_forwarded(policy):
    msg = mav2.MAVLink_heartbeat_message(6, 8, 0, 0, 0, 3)
    d = classify_checked(pack(msg), policy)
    assert d.action is Action.FORWARD
    hb = mav2.MAVLINK_MSG_ID_HEARTBEAT
    assert (d.msgid, d.command, d.sysid, d.compid) == (hb, None, 255, 190)


def test_message_not_in_allowlist_dropped(policy):
    msg = mav2.MAVLink_gps_inject_data_message(1, 1, 0, [0] * 110)
    d = classify_checked(pack(msg), policy)
    assert d.action is Action.DROP
    assert "not in allowlist" in d.reason


def test_excluded_wins_over_allowlist(policy):
    rid = mav2.MAVLINK_MSG_ID_RADIO_STATUS
    both = replace(policy, allowed_messages=policy.allowed_messages | {rid})
    assert rid in both.allowed_messages and rid in both.excluded_messages
    d = classify_checked(pack(EXCLUDED["RADIO_STATUS"]), both)
    assert d.action is Action.DROP
    assert "SR-011" in d.reason


@pytest.mark.parametrize("builder", [command_long, command_int], ids=["long", "int"])
class TestCommands:
    def test_request_message_forwarded(self, policy, builder):
        d = classify_checked(pack(builder(mav2.MAV_CMD_REQUEST_MESSAGE)), policy)
        assert d.action is Action.FORWARD
        assert d.command == mav2.MAV_CMD_REQUEST_MESSAGE

    def test_disallowed_command_dropped(self, policy, builder):
        d = classify_checked(pack(builder(mav2.MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN)), policy)
        assert d.action is Action.DROP
        assert d.command == mav2.MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN

    def test_zero_truncated_payload(self, policy, builder):
        # Command < 256 with zero targets/params: v2 strips the command's high
        # byte and everything after it, so the payload ends mid-field.
        for cmd, action in [
            (mav2.MAV_CMD_NAV_RETURN_TO_LAUNCH, Action.FORWARD),
            (mav2.MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN, Action.DROP),
        ]:
            frame = pack(builder(cmd, target_system=0, target_component=0))
            assert frame[1] == _COMMAND_OFFSET[frame[7]] + 1  # payload truncated
            d = classify_checked(frame, policy)
            assert (d.action, d.command) == (action, cmd)

    def test_signed_frame(self, policy, builder):
        for cmd, action in [
            (mav2.MAV_CMD_REQUEST_MESSAGE, Action.FORWARD),
            (mav2.MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN, Action.DROP),
        ]:
            frame = pack(builder(cmd), v2_link(signed=True))
            assert frame[2] & 0x01
            d = classify_checked(frame, policy)
            assert (d.action, d.command, d.sysid, d.compid) == (action, cmd, 255, 190)

    def test_targets(self, policy, builder):
        for cmd in (mav2.MAV_CMD_REQUEST_MESSAGE, mav2.MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN):
            d = classify_checked(pack(builder(cmd, target_system=7, target_component=42)), policy)
            assert (d.target_system, d.target_component) == (7, 42)
        # v2 strips the zero target_component (and everything after it).
        frame = pack(builder(mav2.MAV_CMD_REQUEST_MESSAGE, target_system=7, target_component=0))
        assert frame[1] == _COMMAND_OFFSET[frame[7]] + _TARGETS_DELTA + 1
        d = classify_checked(frame, policy)
        assert (d.target_system, d.target_component) == (7, 0)


def test_non_command_has_no_targets(policy):
    d = classify_checked(pack(mav2.MAVLink_heartbeat_message(6, 8, 0, 0, 0, 3)), policy)
    assert d.action is Action.FORWARD
    assert (d.command, d.target_system, d.target_component) == (None, None, None)


def test_signed_allowed_message_forwarded(policy):
    frame = pack(mav2.MAVLink_heartbeat_message(6, 8, 0, 0, 0, 3), v2_link(signed=True))
    assert frame[2] & 0x01
    assert classify_checked(frame, policy).action is Action.FORWARD
    # Stripping the signature trailer must not be accepted as a valid frame.
    assert classify_checked(frame[:-13], policy).action is Action.DROP


def test_mavlink_v1_frames(policy):
    link = mav1.MAVLink(None, srcSystem=255, srcComponent=190)
    ok = bytes(mav1.MAVLink_command_long_message(1, 1, mav1.MAV_CMD_REQUEST_MESSAGE, 0,
                                                  *([0.0] * 7)).pack(link))
    bad = bytes(mav1.MAVLink_command_long_message(1, 1, mav1.MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN, 0,
                                                   *([0.0] * 7)).pack(link))
    assert ok[0] == 0xFE
    d = classify_checked(ok, policy)
    assert (d.action, d.command, d.sysid, d.compid) == (Action.FORWARD, 512, 255, 190)
    assert classify_checked(bad, policy).action is Action.DROP
    assert classify_checked(pack(EXCLUDED["RADIO_STATUS"], link), policy).action is Action.DROP


@pytest.mark.parametrize("cut", [1, 2, 5, 9, 12])
def test_truncated_frame_dropped(policy, cut):
    frame = pack(command_long(mav2.MAV_CMD_REQUEST_MESSAGE))
    d = classify_checked(frame[: len(frame) - cut], policy)
    assert d.action is Action.DROP


@pytest.mark.parametrize(
    "frame, reason",
    [
        (b"", "empty"),
        (b"\xfd\x09\x00", "truncated header"),
        (b"\xfe\x09", "truncated header"),
        (b"\x55" + bytes(20), "unknown magic"),
    ],
)
def test_malformed_frames_dropped(policy, frame, reason):
    d = classify_checked(frame, policy)
    assert d.action is Action.DROP
    assert reason in d.reason


def test_trailing_bytes_dropped(policy):
    # An allowed frame must not carry a second (excluded) frame past the classifier.
    frame = pack(mav2.MAVLink_heartbeat_message(6, 8, 0, 0, 0, 3)) + pack(EXCLUDED["SETUP_SIGNING"])
    d = classify_checked(frame, policy)
    assert d.action is Action.DROP
    assert "trailing bytes" in d.reason


def test_bad_checksum_dropped(policy):
    frame = bytearray(pack(command_long(mav2.MAV_CMD_REQUEST_MESSAGE)))
    frame[10 + 28] = 0xF6  # rewrite command low byte -> 0x2F6, CRC no longer matches
    d = classify_checked(bytes(frame), policy)
    assert d.action is Action.DROP
    assert "checksum" in d.reason


def test_unsupported_incompat_flag_dropped(policy):
    frame = bytearray(pack(mav2.MAVLink_heartbeat_message(6, 8, 0, 0, 0, 3)))
    frame[2] = 0x02
    d = classify_checked(bytes(frame), policy)
    assert d.action is Action.DROP
    assert "incompat" in d.reason


def test_unknown_msgid_dropped(policy):
    frame = bytearray(pack(mav2.MAVLink_heartbeat_message(6, 8, 0, 0, 0, 3)))
    frame[7:10] = (0xFFFFFE).to_bytes(3, "little")
    d = classify_checked(bytes(frame), policy)
    assert d.action is Action.DROP
    assert d.msgid == 0xFFFFFE


def test_classify_accepts_bytes_and_returns_same_frame_untouched(policy):
    frame = pack(command_int(mav2.MAV_CMD_COMPONENT_ARM_DISARM))
    snapshot = bytes(frame)
    d = classify(frame, policy)
    assert d.action is Action.FORWARD
    assert frame == snapshot


@pytest.mark.parametrize("msgid", sorted(_COMMAND_OFFSET))
def test_command_offsets_match_pymavlink(msgid):
    cls = mav2.mavlink_map[msgid]
    fmt = cls.unpacker.format
    idx = cls.ordered_fieldnames.index("command")
    assert struct.calcsize("<" + fmt[1 : 1 + idx]) == _COMMAND_OFFSET[msgid]
    targets = cls.ordered_fieldnames.index("target_system")
    assert cls.ordered_fieldnames[targets + 1] == "target_component"
    assert struct.calcsize("<" + fmt[1 : 1 + targets]) == (
        _COMMAND_OFFSET[msgid] + _TARGETS_DELTA
    )
