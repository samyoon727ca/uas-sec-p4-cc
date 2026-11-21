"""An allowlisted command passes the proxy: MAV_CMD_REQUEST_MESSAGE is acked ACCEPTED."""

import pytest
from pymavlink.dialects.v20 import common as mav2

pytestmark = pytest.mark.sitl

ACK_TIMEOUT = 5.0


def test_proxied_request_message_acked(via_proxy, proxy):
    command = mav2.MAV_CMD_REQUEST_MESSAGE
    forwarded_before = proxy.stats().forwarded.get(mav2.MAVLINK_MSG_ID_COMMAND_LONG, 0)
    via_proxy.drain()
    via_proxy.mav.command_long_send(
        via_proxy.target_system, via_proxy.target_component, command, 0,
        mav2.MAVLINK_MSG_ID_AUTOPILOT_VERSION, 0, 0, 0, 0, 0, 0,
    )
    acks = via_proxy.collect(
        lambda m: m.get_type() == "COMMAND_ACK" and m.command == command, ACK_TIMEOUT
    )
    assert acks, f"no COMMAND_ACK for MAV_CMD_REQUEST_MESSAGE within {ACK_TIMEOUT}s"
    assert acks[0].result == mav2.MAV_RESULT_ACCEPTED
    assert proxy.stats().forwarded.get(mav2.MAVLINK_MSG_ID_COMMAND_LONG, 0) == forwarded_before + 1
