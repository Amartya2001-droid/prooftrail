"""Supabase state store, tested against a fake HTTP layer: no live
project or credentials exist, so no test here touches the network."""

import json
import os
import unittest
from unittest import mock

from prooftrail.server import ProofTrailApp
from prooftrail.supabase_store import SupabaseStore


class FakeSupabase:
    """In-memory stand-in for the PostgREST table."""

    def __init__(self):
        self.rows = {}
        self.calls = []

    def request(self, method, url, data, headers):
        self.calls.append((method, url, data, headers))
        if method == "GET":
            row = self.rows.get("main")
            body = json.dumps([{"state": row}] if row else []).encode()
            return 200, body
        if method == "POST":
            payload = json.loads(data)
            self.rows[payload[0]["id"]] = payload[0]["state"]
            return 201, b"[]"
        raise AssertionError(f"unexpected method {method}")


class TestSupabaseStore(unittest.TestCase):
    def test_from_env_returns_none_when_unconfigured(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(SupabaseStore.from_env())

    def test_load_returns_none_when_no_row_exists(self):
        fake = FakeSupabase()
        store = SupabaseStore("https://example.supabase.co", "key",
                              request_fn=fake.request)
        self.assertIsNone(store.load())

    def test_save_then_load_round_trips(self):
        fake = FakeSupabase()
        store = SupabaseStore("https://example.supabase.co", "key",
                              request_fn=fake.request)
        state = {"users": {"designer": {"name": "Designer"}},
                 "projects": {}}
        store.save(state)
        self.assertEqual(store.load(), state)
        posts = [c for c in fake.calls if c[0] == "POST"]
        self.assertEqual(len(posts), 1)
        method, url, _, headers = posts[0]
        self.assertEqual(method, "POST")
        self.assertIn("/rest/v1/prooftrail_state?on_conflict=id", url)
        self.assertEqual(headers["apikey"], "key")
        self.assertEqual(headers["Authorization"], "Bearer key")
        self.assertEqual(headers["Prefer"], "resolution=merge-duplicates")

    def test_http_error_becomes_value_error(self):
        def failing(method, url, data, headers):
            return 500, b"{}"

        store = SupabaseStore("https://example.supabase.co", "key",
                              request_fn=failing)
        with self.assertRaises(ValueError):
            store.load()
        with self.assertRaises(ValueError):
            store.save({"users": {}, "projects": {}})


class TestSupabaseServerWiring(unittest.TestCase):
    def test_server_round_trips_through_the_fake(self):
        fake = FakeSupabase()
        env = {
            "PROOFTRAIL_STATE_BACKEND": "supabase",
            "SUPABASE_URL": "https://example.supabase.co",
            "SUPABASE_KEY": "test-key",
        }
        with mock.patch.dict(os.environ, env):
            with mock.patch.object(
                    SupabaseStore, "_default_request",
                    lambda self, m, u, d, h: fake.request(m, u, d, h)):
                app = ProofTrailApp()
                app.register("designer", "Designer", "sunset-river-42")
                app2 = ProofTrailApp()
                self.assertIn("designer", app2.users)
                app2.login("designer", "sunset-river-42")

    def test_missing_credentials_raise_at_startup(self):
        env = {"PROOFTRAIL_STATE_BACKEND": "supabase"}
        with mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaises(ValueError):
                ProofTrailApp()


if __name__ == "__main__":
    unittest.main()
