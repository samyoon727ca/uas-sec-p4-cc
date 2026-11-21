"""Load and validate ``policy.yaml`` (SR-011 allowlist, SR-012 rates, peer map).

Message and command names are resolved to numeric IDs against pymavlink's
MAVLink ``common`` dialect. Any unknown name, unknown key or malformed value is
a :class:`PolicyError`; nothing is silently ignored.

Peers are identified by packet source IP through ``peers[].allowed_ips``, which
mirrors WireGuard AllowedIPs (cryptokey routing binds an inner source IP to one
peer key). A source is mapped to the peer with the longest matching prefix, as
WireGuard does; the same prefix listed under two peers is a load error.
"""

from __future__ import annotations

import ipaddress
import math
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pymavlink.dialects.v20 import common as _mavlink

MESSAGE_IDS: dict[str, int] = {cls.msgname: msgid for msgid, cls in _mavlink.mavlink_map.items()}
COMMAND_IDS: dict[str, int] = {
    entry.name: value
    for value, entry in _mavlink.enums["MAV_CMD"].items()
    if not entry.name.endswith("_ENUM_END")
}

_TOP_LEVEL_KEYS = {
    "status",
    "excluded_messages",
    "allowed_messages",
    "allowed_commands",
    "rates",
    "peers",
}
_OPTIONAL_KEYS = {"local_peer"}
_RATE_KEYS = {"rate", "burst"}
_PEER_KEYS = {"name", "allowed_ips"}

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class PolicyError(ValueError):
    """Raised when a policy file is missing fields or contains invalid values."""


@dataclass(frozen=True)
class Rate:
    """Token-bucket limit: ``rate`` msgs/s refill, ``burst`` msgs bucket size."""

    rate: float
    burst: int


@dataclass(frozen=True)
class Peer:
    """A peer and the source networks attributed to it (WireGuard AllowedIPs).

    ``local`` marks the peer named by ``local_peer``: traffic originated on the
    companion computer itself rather than received from a remote peer.
    """

    name: str
    allowed_ips: tuple[IPNetwork, ...]
    local: bool = False


@dataclass(frozen=True)
class Policy:
    status: str
    excluded_messages: frozenset[int]
    allowed_messages: frozenset[int]
    allowed_commands: frozenset[int]
    default_rate: Rate
    rates: Mapping[int, Rate]
    peers: tuple[Peer, ...]

    def rate_for(self, msgid: int) -> Rate:
        return self.rates.get(msgid, self.default_rate)

    def peer_for(self, host: str) -> Peer | None:
        """The peer owning source address ``host`` (longest prefix), or ``None``."""
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            return None
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped  # dual-stack socket: ::ffff:a.b.c.d is a.b.c.d
        best: Peer | None = None
        best_len = -1
        for peer in self.peers:
            for net in peer.allowed_ips:
                if net.version == addr.version and addr in net and net.prefixlen > best_len:
                    best, best_len = peer, net.prefixlen
        return best


def load_policy(path: str | Path) -> Policy:
    """Read a YAML policy file and return a validated :class:`Policy`."""
    path = Path(path)
    try:
        with path.open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise PolicyError(f"{path}: invalid YAML: {exc}") from exc
    try:
        return parse_policy(data)
    except PolicyError as exc:
        raise PolicyError(f"{path}: {exc}") from exc


def parse_policy(data: Any) -> Policy:
    """Validate an already-parsed policy mapping and resolve names to IDs."""
    if not isinstance(data, dict):
        raise PolicyError("policy must be a mapping")
    unknown = set(data) - _TOP_LEVEL_KEYS - _OPTIONAL_KEYS
    if unknown:
        raise PolicyError(f"unknown policy keys: {sorted(map(str, unknown))}")
    missing = _TOP_LEVEL_KEYS - set(data)
    if missing:
        raise PolicyError(f"missing policy keys: {sorted(missing)}")

    status = data["status"]
    if not isinstance(status, str) or not status:
        raise PolicyError("'status' must be a non-empty string")

    excluded = _resolve_names(data["excluded_messages"], MESSAGE_IDS, "excluded_messages")
    allowed = _resolve_names(data["allowed_messages"], MESSAGE_IDS, "allowed_messages")
    commands = _resolve_names(data["allowed_commands"], COMMAND_IDS, "allowed_commands")
    default_rate, rates = _parse_rates(data["rates"])
    peers = _parse_peers(data["peers"], data.get("local_peer"))

    return Policy(
        status=status,
        excluded_messages=excluded,
        allowed_messages=allowed,
        allowed_commands=commands,
        default_rate=default_rate,
        rates=rates,
        peers=peers,
    )


def _resolve_names(value: Any, table: Mapping[str, int], field: str) -> frozenset[int]:
    if value is None:
        return frozenset()
    if not isinstance(value, list):
        raise PolicyError(f"'{field}' must be a list of names")
    ids = set()
    for name in value:
        ids.add(_resolve_name(name, table, field))
    return frozenset(ids)


def _resolve_name(name: Any, table: Mapping[str, int], field: str) -> int:
    if not isinstance(name, str):
        raise PolicyError(f"'{field}': expected a name, got {name!r}")
    try:
        return table[name]
    except KeyError:
        raise PolicyError(
            f"'{field}': unknown name {name!r} (not in pymavlink common dialect)"
        ) from None


def _parse_rates(value: Any) -> tuple[Rate, dict[int, Rate]]:
    if not isinstance(value, dict):
        raise PolicyError("'rates' must be a mapping")
    if "default" not in value:
        raise PolicyError("'rates' must contain a 'default' entry")
    default = _parse_rate(value["default"], "rates.default")
    rates: dict[int, Rate] = {}
    for name, spec in value.items():
        if name == "default":
            continue
        msgid = _resolve_name(name, MESSAGE_IDS, "rates")
        rates[msgid] = _parse_rate(spec, f"rates.{name}")
    return default, rates


def _parse_rate(spec: Any, where: str) -> Rate:
    if not isinstance(spec, dict) or set(spec) != _RATE_KEYS:
        raise PolicyError(f"'{where}' must be a mapping with exactly keys {sorted(_RATE_KEYS)}")
    rate, burst = spec["rate"], spec["burst"]
    if (
        isinstance(rate, bool)
        or not isinstance(rate, (int, float))
        or not math.isfinite(rate)
        or rate <= 0
    ):
        raise PolicyError(f"'{where}.rate' must be a positive number, got {rate!r}")
    if isinstance(burst, bool) or not isinstance(burst, int) or burst < 1:
        raise PolicyError(f"'{where}.burst' must be an integer >= 1, got {burst!r}")
    return Rate(rate=float(rate), burst=burst)


def _parse_peers(value: Any, local_peer: Any) -> tuple[Peer, ...]:
    if not isinstance(value, list) or not value:
        raise PolicyError("'peers' must be a non-empty list")
    if local_peer is not None and (not isinstance(local_peer, str) or not local_peer):
        raise PolicyError(f"'local_peer' must be a peer name, got {local_peer!r}")
    peers: list[Peer] = []
    owner: dict[IPNetwork, str] = {}
    for i, spec in enumerate(value):
        where = f"peers[{i}]"
        if not isinstance(spec, dict) or set(spec) != _PEER_KEYS:
            raise PolicyError(f"'{where}' must be a mapping with exactly keys {sorted(_PEER_KEYS)}")
        name, cidrs = spec["name"], spec["allowed_ips"]
        if not isinstance(name, str) or not name:
            raise PolicyError(f"'{where}.name' must be a non-empty string")
        if any(p.name == name for p in peers):
            raise PolicyError(f"'{where}': duplicate peer name {name!r}")
        if not isinstance(cidrs, list) or not cidrs:
            raise PolicyError(f"'{where}.allowed_ips' must be a non-empty list of CIDRs")
        nets = []
        for cidr in cidrs:
            if not isinstance(cidr, str):
                raise PolicyError(f"'{where}.allowed_ips': expected a CIDR, got {cidr!r}")
            try:
                net = ipaddress.ip_network(cidr, strict=True)
            except ValueError as exc:
                raise PolicyError(f"'{where}.allowed_ips': invalid CIDR {cidr!r}: {exc}") from None
            if net in owner:
                raise PolicyError(
                    f"'{where}.allowed_ips': {net} already belongs to peer {owner[net]!r}"
                )
            owner[net] = name
            nets.append(net)
        peers.append(Peer(name=name, allowed_ips=tuple(nets), local=name == local_peer))
    if local_peer is not None and not any(p.local for p in peers):
        raise PolicyError(f"'local_peer': no peer named {local_peer!r}")
    return tuple(peers)
