"""SR-012 flood test: PARAM_REQUEST_READ sent well above its rate through the proxy.

The connection sends PARAM_REQUEST_READ (by index) at ``FLOOD_RATE`` for
``FLOOD_SECONDS`` through the proxy to PX4. PARAM_REQUEST_READ has no entry of
its own in policy.yaml ``rates``, so the ``default`` rate and burst apply; the
test reads them from the loaded policy rather than hard-coding them.

* Every frame sent is either forwarded or dropped as ``rate_limited``, and the
  drops are also counted for the sending peer (``cc-local``: the test runs on
  loopback).
* Over the ``t`` seconds the flood lasted, the forwarded count is at most
  ``rate * t + burst``, and at least ``rate * t`` less a small allowance, so
  the limiter neither leaks nor over-drops. ``TIMING_SLACK`` covers the
  difference between the test's clock and the proxy's (scheduling jitter,
  frames still queued when the test stops its timer).
* PX4 answers the forwarded requests with PARAM_VALUE, so the flood did not
  stop forwarded traffic from working.

PARAM_REQUEST_READ is used because no other SITL test sends it, so its bucket
for this peer starts full and the other tests' counters are not affected.
"""

import time

import pytest
from pymavlink.dialects.v20 import common as mav2

from cc_proxy.proxy import RATE_LIMITED

pytestmark = pytest.mark.sitl

MSG_ID = mav2.MAVLINK_MSG_ID_PARAM_REQUEST_READ
FLOOD_RATE = 50.0  # msgs/s, 5x the proposed default rate
FLOOD_SECONDS = 4.0
INDEX_SPACE = 100  # requested param indices cycle through 0..99, all present in PX4 SITL
TIMING_SLACK = 0.5  # s, see the module docstring
ACCOUNT_TIMEOUT = 2.0  # for the proxy to finish counting every flood frame
REPLY_TIMEOUT = 3.0  # for PX4's last PARAM_VALUE replies after the flood
MIN_ANSWERED = 0.8  # fraction of forwarded requests that must be answered (UDP may drop)


def counts(stats, peer):
    return (
        stats.forwarded.get(MSG_ID, 0),
        stats.dropped.get((MSG_ID, RATE_LIMITED), 0),
        stats.peer_dropped.get((peer, RATE_LIMITED), 0),
    )


def test_flood_is_rate_limited_and_forwarded_requests_answered(via_proxy, proxy):
    rate = proxy.policy.rate_for(MSG_ID)
    assert FLOOD_RATE >= 4 * rate.rate, "flood must be well above the policy rate"
    peer = proxy.policy.peer_for("127.0.0.1")
    assert peer is not None and peer.local, "policy.yaml must map loopback to the local peer"

    answered = 0

    def record_reply(msg) -> bool:
        nonlocal answered
        if (
            msg.get_type() == "PARAM_VALUE"
            and msg.get_srcSystem() == via_proxy.target_system
            and 0 <= msg.param_index < INDEX_SPACE
        ):
            answered += 1
        return False  # keep collecting until the timeout

    fwd_before, lim_before, peer_lim_before = counts(proxy.stats(), peer.name)
    via_proxy.drain()

    total = int(FLOOD_RATE * FLOOD_SECONDS)
    start = time.monotonic()
    for i in range(total):
        wait = start + i / FLOOD_RATE - time.monotonic()
        if wait > 0:
            # Also sends the keepalive HEARTBEAT, and counts replies meanwhile.
            via_proxy.collect(record_reply, wait)
        via_proxy.mav.param_request_read_send(
            via_proxy.target_system, via_proxy.target_component, b"", i % INDEX_SPACE
        )
    elapsed = time.monotonic() - start

    deadline = time.monotonic() + ACCOUNT_TIMEOUT
    while True:
        fwd, lim, peer_lim = counts(proxy.stats(), peer.name)
        forwarded, limited = fwd - fwd_before, lim - lim_before
        if forwarded + limited >= total or time.monotonic() > deadline:
            break
        time.sleep(0.05)
    via_proxy.collect(record_reply, REPLY_TIMEOUT)

    assert forwarded + limited == total, (
        f"{total} sent, but {forwarded} forwarded + {limited} rate_limited"
    )
    assert peer_lim - peer_lim_before == limited
    upper = rate.rate * (elapsed + TIMING_SLACK) + rate.burst
    lower = rate.rate * (elapsed - TIMING_SLACK)
    assert lower <= forwarded <= upper, (
        f"{forwarded} forwarded in {elapsed:.2f}s at rate {rate.rate}/s, burst {rate.burst}; "
        f"expected {lower:.1f}..{upper:.1f}"
    )
    assert limited > 0
    assert answered >= MIN_ANSWERED * forwarded, (
        f"PX4 answered {answered} of {forwarded} forwarded PARAM_REQUEST_READ"
    )
