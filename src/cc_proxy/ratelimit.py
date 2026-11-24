"""SR-012 per-peer, per-message token buckets.

Each ``(peer, msgid)`` pair gets its own bucket with the ``rate`` and ``burst``
that the policy gives for ``msgid`` (``rates.default`` if it has no entry). A
bucket starts full with ``burst`` tokens and refills continuously at ``rate``
tokens/s up to ``burst``; a frame takes one token, and a frame that finds less
than one token is over the limit. So over any interval of ``t`` seconds at
most ``rate * t + burst`` frames of one type from one peer get through.

The key does not include the ``MAV_CMD`` of a ``COMMAND_LONG`` / ``COMMAND_INT``,
so all commands from one peer share that message type's bucket, and a flood of
one allowed command can starve the peer's others (known limitation, see the
README "Rate limits" section).

Buckets are only created for frames the classifier already allowed, so their
number is bounded by peers x allowed message types. Not thread-safe: the proxy
calls it from its single loop thread.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from .policy import Rate

Clock = Callable[[], float]


class TokenBucket:
    """A single token bucket; ``now`` values come from a monotonic clock."""

    def __init__(self, rate: Rate, now: float):
        self.rate = rate
        self._tokens = float(rate.burst)
        self._last = now

    def take(self, now: float) -> bool:
        """Take one token at time ``now``; ``False`` if the bucket is empty."""
        if now > self._last:
            self._tokens = min(
                float(self.rate.burst), self._tokens + (now - self._last) * self.rate.rate
            )
            self._last = now
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False


class RateLimiter:
    """Token buckets keyed by ``(peer, msgid)``.

    ``rate_for`` maps a message ID to its :class:`Rate` (normally
    :meth:`Policy.rate_for`); ``clock`` is injectable for tests.
    """

    def __init__(self, rate_for: Callable[[int], Rate], clock: Clock = time.monotonic):
        self._rate_for = rate_for
        self._clock = clock
        self._buckets: dict[tuple[str, int], TokenBucket] = {}

    def allow(self, peer: str, msgid: int) -> bool:
        """Whether one more ``msgid`` frame from ``peer`` is within its rate."""
        now = self._clock()
        bucket = self._buckets.get((peer, msgid))
        if bucket is None:
            bucket = self._buckets[(peer, msgid)] = TokenBucket(self._rate_for(msgid), now)
        return bucket.take(now)
