"""SR-012 token-bucket maths with a fake clock."""

from pathlib import Path

import pytest
from pymavlink.dialects.v20 import common as mav2

from cc_proxy.policy import Rate, load_policy
from cc_proxy.ratelimit import RateLimiter, TokenBucket

POLICY_PATH = Path(__file__).resolve().parents[1] / "policy.yaml"

HEARTBEAT_ID = mav2.MAVLINK_MSG_ID_HEARTBEAT
PING_ID = mav2.MAVLINK_MSG_ID_PING


class FakeClock:
    def __init__(self, now: float = 100.0):
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def takes(attempt, n):
    """How many of ``n`` immediate attempts succeed."""
    return sum(bool(attempt()) for _ in range(n))


def test_bucket_starts_full_then_empties():
    bucket = TokenBucket(Rate(rate=2.0, burst=4), now=0.0)
    assert takes(lambda: bucket.take(0.0), 10) == 4


def test_bucket_refills_at_rate():
    bucket = TokenBucket(Rate(rate=2.0, burst=4), now=0.0)
    assert takes(lambda: bucket.take(0.0), 4) == 4
    assert not bucket.take(0.25)  # 0.5 token
    assert bucket.take(0.5)  # 1.0 token
    assert not bucket.take(0.5)
    assert takes(lambda: bucket.take(1.5), 10) == 2


def test_bucket_refill_capped_at_burst():
    bucket = TokenBucket(Rate(rate=2.0, burst=4), now=0.0)
    assert takes(lambda: bucket.take(0.0), 4) == 4
    assert takes(lambda: bucket.take(1000.0), 10) == 4


def test_fractional_rate():
    bucket = TokenBucket(Rate(rate=0.2, burst=1), now=0.0)
    assert bucket.take(0.0)
    assert not bucket.take(4.0)
    assert bucket.take(5.0)
    assert not bucket.take(5.0)


def test_clock_going_backwards_adds_no_tokens():
    bucket = TokenBucket(Rate(rate=2.0, burst=4), now=10.0)
    assert takes(lambda: bucket.take(10.0), 4) == 4
    assert not bucket.take(5.0)
    assert not bucket.take(10.0)
    assert bucket.take(10.5)


@pytest.mark.parametrize("duration", [1.0, 3.0, 10.0])
def test_sustained_flood_bounded_by_rate_times_t_plus_burst(duration):
    rate = Rate(rate=5.0, burst=10)
    bucket = TokenBucket(rate, now=0.0)
    attempts_per_s = 64  # 1/64 s steps are exact in binary floating point
    times = [i / attempts_per_s for i in range(int(duration * attempts_per_s) + 1)]
    allowed = sum(bucket.take(t) for t in times)
    assert allowed == int(rate.rate * duration) + rate.burst


def test_limiter_uses_policy_rates_and_default():
    policy = load_policy(POLICY_PATH)
    clock = FakeClock()
    limiter = RateLimiter(policy.rate_for, clock)
    hb = policy.rate_for(HEARTBEAT_ID)
    assert hb != policy.default_rate  # HEARTBEAT has its own entry
    assert takes(lambda: limiter.allow("cc-local", HEARTBEAT_ID), 100) == hb.burst
    assert takes(lambda: limiter.allow("cc-local", PING_ID), 100) == policy.default_rate.burst


def test_peers_have_independent_buckets():
    clock = FakeClock()
    limiter = RateLimiter(lambda msgid: Rate(rate=1.0, burst=3), clock)
    assert takes(lambda: limiter.allow("gcs-primary", HEARTBEAT_ID), 10) == 3
    assert takes(lambda: limiter.allow("cc-local", HEARTBEAT_ID), 10) == 3
    clock.advance(1.0)
    assert takes(lambda: limiter.allow("gcs-primary", HEARTBEAT_ID), 10) == 1
    assert takes(lambda: limiter.allow("cc-local", HEARTBEAT_ID), 10) == 1


def test_message_types_have_independent_buckets():
    clock = FakeClock()
    limiter = RateLimiter(lambda msgid: Rate(rate=1.0, burst=2), clock)
    assert takes(lambda: limiter.allow("gcs-primary", HEARTBEAT_ID), 10) == 2
    assert takes(lambda: limiter.allow("gcs-primary", PING_ID), 10) == 2
