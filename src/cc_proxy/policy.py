"""Load and validate ``policy.yaml`` (SR-011 allowlist, SR-012 rates).

Message and command names are resolved to numeric IDs against pymavlink's
MAVLink ``common`` dialect. Any unknown name, unknown key or malformed value is
a :class:`PolicyError`; nothing is silently ignored.
"""

from __future__ import annotations

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
}
_RATE_KEYS = {"rate", "burst"}


class PolicyError(ValueError):
    """Raised when a policy file is missing fields or contains invalid values."""


@dataclass(frozen=True)
class Rate:
    """Token-bucket limit: ``rate`` msgs/s refill, ``burst`` msgs bucket size."""

    rate: float
    burst: int


@dataclass(frozen=True)
class Policy:
    status: str
    excluded_messages: frozenset[int]
    allowed_messages: frozenset[int]
    allowed_commands: frozenset[int]
    default_rate: Rate
    rates: Mapping[int, Rate]

    def rate_for(self, msgid: int) -> Rate:
        return self.rates.get(msgid, self.default_rate)


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
    unknown = set(data) - _TOP_LEVEL_KEYS
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

    return Policy(
        status=status,
        excluded_messages=excluded,
        allowed_messages=allowed,
        allowed_commands=commands,
        default_rate=default_rate,
        rates=rates,
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
