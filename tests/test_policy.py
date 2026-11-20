from pathlib import Path

import pytest
import yaml
from pymavlink.dialects.v20 import common as mav2

from cc_proxy.policy import PolicyError, Rate, load_policy, parse_policy

POLICY_PATH = Path(__file__).resolve().parents[1] / "policy.yaml"

SR011_EXCLUSIONS = {
    "SERIAL_CONTROL",
    "FILE_TRANSFER_PROTOCOL",
    "SETUP_SIGNING",
    "RADIO_STATUS",
    "ADSB_VEHICLE",
    "COLLISION",
}


@pytest.fixture
def raw():
    return yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))


def test_repo_policy_loads_and_is_proposed():
    policy = load_policy(POLICY_PATH)
    assert policy.status == "proposed"
    assert policy.excluded_messages == {
        getattr(mav2, f"MAVLINK_MSG_ID_{name}") for name in SR011_EXCLUSIONS
    }
    assert mav2.MAV_CMD_REQUEST_MESSAGE in policy.allowed_commands
    assert mav2.MAV_CMD_COMPONENT_ARM_DISARM in policy.allowed_commands
    assert mav2.MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN not in policy.allowed_commands
    assert policy.rate_for(mav2.MAVLINK_MSG_ID_HEARTBEAT) == Rate(rate=2.0, burst=4)
    assert policy.rate_for(mav2.MAVLINK_MSG_ID_PING) == policy.default_rate


@pytest.mark.parametrize(
    "field, value",
    [
        ("allowed_messages", ["HEARTBEAT", "NOT_A_MESSAGE"]),
        ("excluded_messages", ["SERIAL_CONTROLL"]),
        ("allowed_commands", ["MAV_CMD_DOES_NOT_EXIST"]),
    ],
)
def test_unknown_names_rejected(raw, field, value):
    raw[field] = value
    with pytest.raises(PolicyError, match="unknown name"):
        parse_policy(raw)


def test_unknown_rate_name_rejected(raw):
    raw["rates"]["NOPE"] = {"rate": 1, "burst": 1}
    with pytest.raises(PolicyError, match="unknown name 'NOPE'"):
        parse_policy(raw)


def test_unknown_top_level_key_rejected(raw):
    raw["allowed_message"] = ["PING"]
    with pytest.raises(PolicyError, match="unknown policy keys"):
        parse_policy(raw)


def test_missing_default_rate_rejected(raw):
    del raw["rates"]["default"]
    with pytest.raises(PolicyError, match="default"):
        parse_policy(raw)


@pytest.mark.parametrize(
    "spec",
    [{"rate": 0, "burst": 1}, {"rate": 1, "burst": 0}, {"rate": "x", "burst": 1}, {"rate": 1}],
)
def test_invalid_rate_rejected(raw, spec):
    raw["rates"]["HEARTBEAT"] = spec
    with pytest.raises(PolicyError):
        parse_policy(raw)
