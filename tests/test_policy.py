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


def test_repo_peer_map():
    policy = load_policy(POLICY_PATH)
    assert policy.peer_for("10.8.0.2").name == "gcs-primary"
    assert not policy.peer_for("10.8.0.2").local
    local = policy.peer_for("127.0.0.1")
    assert local.name == "cc-local"
    assert local.local
    assert policy.peer_for("::1") is local
    assert policy.peer_for("::ffff:127.0.0.1") is local  # IPv4-mapped (dual-stack socket)
    assert policy.peer_for("10.8.0.3") is None
    assert policy.peer_for("127.0.0.2") is None


@pytest.fixture
def peers(raw):
    raw["peers"] = [
        {"name": "gcs-primary", "allowed_ips": ["10.8.0.2/32"]},
        {"name": "gcs-net", "allowed_ips": ["10.8.0.0/24", "fd00:8::/64"]},
    ]
    raw.pop("local_peer", None)
    return raw


@pytest.mark.parametrize(
    "host, peer",
    [
        ("10.8.0.2", "gcs-primary"),  # longest prefix wins, as in WireGuard
        ("10.8.0.1", "gcs-net"),
        ("10.8.0.255", "gcs-net"),
        ("10.8.1.0", None),
        ("10.7.255.255", None),
        ("fd00:8::1234", "gcs-net"),
        ("fd00:9::1", None),
        ("not-an-ip", None),
    ],
)
def test_cidr_matching(peers, host, peer):
    found = parse_policy(peers).peer_for(host)
    assert (found.name if found else None) == peer


def test_local_peer_optional(peers):
    policy = parse_policy(peers)
    assert not any(p.local for p in policy.peers)


@pytest.mark.parametrize(
    "peer_list, match",
    [
        ([], "non-empty list"),
        ([{"name": "a"}], "exactly keys"),
        ([{"name": "a", "allowed_ips": []}], "non-empty list of CIDRs"),
        ([{"name": "a", "allowed_ips": ["10.8.0.2"], "extra": 1}], "exactly keys"),
        ([{"name": "", "allowed_ips": ["10.8.0.2/32"]}], "non-empty string"),
        ([{"name": "a", "allowed_ips": ["10.8.0.300/32"]}], "invalid CIDR"),
        ([{"name": "a", "allowed_ips": ["10.8.0.2/24"]}], "invalid CIDR"),  # host bits set
        ([{"name": "a", "allowed_ips": [42]}], "expected a CIDR"),
        (
            [{"name": "a", "allowed_ips": ["10.8.0.2/32"]},
             {"name": "a", "allowed_ips": ["10.8.0.3/32"]}],
            "duplicate peer name",
        ),
        (
            [{"name": "a", "allowed_ips": ["10.8.0.2/32"]},
             {"name": "b", "allowed_ips": ["10.8.0.2/32"]}],
            "already belongs to peer 'a'",
        ),
    ],
)
def test_invalid_peers_rejected(peers, peer_list, match):
    peers["peers"] = peer_list
    with pytest.raises(PolicyError, match=match):
        parse_policy(peers)


def test_missing_peers_rejected(raw):
    del raw["peers"]
    with pytest.raises(PolicyError, match="missing policy keys"):
        parse_policy(raw)


def test_unknown_local_peer_rejected(raw):
    raw["local_peer"] = "nobody"
    with pytest.raises(PolicyError, match="no peer named 'nobody'"):
        parse_policy(raw)
