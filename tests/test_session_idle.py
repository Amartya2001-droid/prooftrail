"""Idle sessions: half an hour without a request ends the session,
even inside the 24-hour absolute window. Activity refreshes the idle
clock; the absolute expiry still wins over activity."""

import unittest

from prooftrail.auth import SessionStore


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class TestIdleTimeout(unittest.TestCase):
    def test_idle_session_expires(self):
        clock = FakeClock()
        store = SessionStore(time_fn=clock)
        token = store.create("designer")
        clock.now += 31 * 60
        self.assertIsNone(store.lookup(token))

    def test_activity_refreshes_the_idle_clock(self):
        clock = FakeClock()
        store = SessionStore(time_fn=clock)
        token = store.create("designer")
        clock.now += 29 * 60
        self.assertEqual(store.lookup(token), "designer")
        clock.now += 29 * 60
        self.assertEqual(store.lookup(token), "designer")
        clock.now += 31 * 60
        self.assertIsNone(store.lookup(token))

    def test_absolute_expiry_still_wins_over_activity(self):
        clock = FakeClock()
        store = SessionStore(time_fn=clock)
        token = store.create("designer")
        # Stay active every 20 minutes, inside the idle window.
        for _ in range(71):  # 71 x 20 minutes = 23h40m
            clock.now += 20 * 60
            self.assertEqual(store.lookup(token), "designer")
        # Cross the 24-hour absolute expiry with only 21 idle minutes:
        # the session dies on the absolute limit, not the idle one.
        clock.now += 21 * 60
        self.assertIsNone(store.lookup(token))

    def test_idle_check_does_not_revive_a_dead_session(self):
        clock = FakeClock()
        store = SessionStore(time_fn=clock)
        token = store.create("designer")
        clock.now += 60 * 60
        self.assertIsNone(store.lookup(token))
        self.assertIsNone(store.lookup(token))


if __name__ == "__main__":
    unittest.main()
