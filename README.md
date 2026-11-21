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
pure-Python frame classifier (`cc_proxy.classifier.classify`), per-peer token
bucket rate limiting (`cc_proxy.ratelimit`) and a minimal UDP proxy
(`cc_proxy.proxy`), with PX4 SITL tests (FTP blocked, `MAV_CMD_REQUEST_MESSAGE`
acked, a flood held to its rate). The command log and the other SITL tests come
in later PRs.

## Baseline

The baseline is **mavlink-router's per-endpoint message-ID filters**. Those can
already allow or block message IDs per endpoint. `cc_proxy` goes further with:

- **command-ID filtering**: `MAV_CMD` allowlist inside `COMMAND_LONG` / `COMMAND_INT`;
- **per-peer rate limits**;
- **per-peer command log**.

## Policy

`policy.yaml` holds the exclusions, the message and command allowlists, the
rates and the peer map. Only the six SR-011 exclusions come from P1. The
**allowlists, rates and peer map are proposed values for the owner to approve**
(`status: proposed`), because P1 leaves them open. Names are resolved against
pymavlink's `common` dialect, and an unknown name is a load error.

### Peers: source IP to peer (assumption)

SR-012 limits each peer, so the proxy has to know which peer sent a frame. In this
slice **the peer is taken from the packet's source IP**, looked up in `peers`:
each peer lists `allowed_ips` CIDRs, and the peer with the longest matching prefix
wins. A source no peer covers is dropped with reason `unknown_peer`.

This mirrors **WireGuard AllowedIPs**. In the intended deployment each peer
reaches the CC over a WireGuard tunnel, and WireGuard's cryptokey routing only
accepts a decrypted packet if its inner source IP is inside the sending peer's
AllowedIPs. The inner source IP is therefore bound to that peer's key, so the
`peers` map can copy the tunnel's AllowedIPs. **Real tunnels are out of scope
here, so this binding is assumed, not enforced**: without WireGuard in front of
the proxy a source IP can be spoofed.

`local_peer` names the peer for traffic originated on the CC itself (`cc-local`,
loopback); its counters are labelled CC-originated. The tests send from
loopback, so they run as `cc-local`.

### Rate limits

Each `(peer, message type)` pair has its own token bucket with the `rate` and
`burst` from `rates` (`default` if the type has no entry). A bucket starts full
and refills at `rate` per second up to `burst`; a frame that finds it empty is
dropped with reason `rate_limited`. So over `t` seconds at most `rate * t + burst`
frames of one type from one peer reach the FC. Only frames the allowlist accepted
use a bucket.

## Running the proxy

```sh
cc-proxy --policy policy.yaml --listen 0.0.0.0:14550 --fc 127.0.0.1:14580
```

- **Uplink (GCS -> FC) is filtered.** Each datagram's source IP is mapped to a
  peer, the datagram is split into MAVLink frames, each frame is classified and
  then rate-limited, and frames that pass are sent to the FC one per datagram
  as slices of the received bytes. Nothing is re-encoded, so MAVLink 2 signatures
  survive.
- **Downlink (FC -> GCS) is not filtered in this slice.** Datagrams from the FC
  address are relayed unchanged to the most recent GCS addresses (up to 8) that
  had a frame forwarded. Datagrams from any other source are ignored.
- Counters (`forwarded[msgid]`, `dropped[(msgid, reason)]`, and per known peer
  `peer_forwarded[peer]`, `peer_dropped[(peer, reason)]`) are available from
  `Proxy.stats()` and printed when the proxy stops (Ctrl-C / SIGTERM).

## Development

```sh
pip install -e .[dev]
ruff check .
pytest -m "not sitl"
```

### SITL tests

`tests/sitl` runs against a PX4 SITL started outside pytest (CI:
`.github/workflows/sitl.yml`, PX4 `v1.18.0-rc2` as pinned by the P3 repo,
SIH model, headless). Each block is shown differentially, because what reaches
the FC cannot be observed inside SITL: a request sent straight to PX4 gets a
reaction, the same request through the proxy gets none and is counted as a drop.

- The `direct` connection listens on UDP 14550, where PX4's GCS link sends.
- The in-process proxy forwards to PX4's offboard link (UDP 14580). PX4 sends
  that link's traffic to its current partner and lets another sender take over
  after 3 s of silence, so the proxied connection sends a 1 Hz GCS HEARTBEAT
  through the proxy while it waits for replies.
- Without a PX4 HEARTBEAT within a few seconds the SITL tests are skipped, so
  plain `pytest` works without PX4. `CC_SITL_REQUIRED=1` (set in CI) turns that
  into a failure.
- `test_flood.py` sends `PARAM_REQUEST_READ` through the proxy at 5x its rate for
  4 s. It checks that every frame is forwarded or counted `rate_limited`, that the
  forwarded count is within `rate * t + burst` (with a 0.5 s timing allowance) and
  that PX4 answers the forwarded requests.

```sh
pytest -m sitl
```
