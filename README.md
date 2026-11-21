# uas-sec-p4-cc

VE-10 first slice: inline MAVLink allowlist/rate-limit/log proxy for the CC, with differential SITL tests.

## Purpose

`cc_proxy` is an inline MAVLink proxy that runs on the UAS companion computer (CC)
between the GCS link and the flight controller (FC). It enforces the P1
requirements from `Yoon-SSE/uas-sec-p1-architecture` (`docs/07-requirements.md`,
verified per `docs/08-verification-plan.md`):

- **SR-011** message allowlist, including six message types that are always dropped
  (`SERIAL_CONTROL`, `FILE_TRANSFER_PROTOCOL`, `SETUP_SIGNING`, `RADIO_STATUS`,
  `ADSB_VEHICLE`, `COLLISION`);
- **SR-012** per-message rate limits;
- **SR-013** command log.

## Scope

This repo is the P4 companion-computer work package, covering VE-09 to VE-11. It
starts with **VE-10**. The current state is the scaffold, the policy file, a
pure-Python frame classifier (`cc_proxy.classifier.classify`) and a minimal UDP
proxy (`cc_proxy.proxy`). Rate limiting, logging, peer identity and SITL tests
come in later PRs.

## Baseline

The baseline is **mavlink-router's per-endpoint message-ID filters**. Those can
already allow or block message IDs per endpoint. `cc_proxy` goes further with:

- **command-ID filtering**: `MAV_CMD` allowlist inside `COMMAND_LONG` / `COMMAND_INT`;
- **per-peer rate limits**;
- **per-peer command log**.

## Policy

`policy.yaml` holds the exclusions, the message and command allowlists and the
rates. Only the six SR-011 exclusions come from P1. The **allowlists and rates are
proposed values for the owner to approve** (`status: proposed`), because P1 leaves
them open. Names are resolved against pymavlink's `common` dialect, and an unknown
name is a load error.

## Running the proxy

```sh
cc-proxy --policy policy.yaml --listen 0.0.0.0:14550 --fc 127.0.0.1:14580
```

- **Uplink (GCS -> FC) is filtered.** Each datagram is split into MAVLink frames,
  each frame is classified, and allowed frames are sent to the FC one per datagram
  as slices of the received bytes. Nothing is re-encoded, so MAVLink 2 signatures
  survive.
- **Downlink (FC -> GCS) is not filtered in this slice.** Datagrams from the FC
  address are relayed unchanged to the most recent GCS addresses (up to 8) that
  had a frame forwarded. Datagrams from any other source are ignored.
- Counters (`forwarded[msgid]`, `dropped[(msgid, reason)]`) are available from
  `Proxy.stats()` and printed when the proxy stops (Ctrl-C / SIGTERM).

## Development

```sh
pip install -e .[dev]
ruff check .
pytest -m "not sitl"
```
