"""Optional Supabase-backed state store (standard library only).

The JSON file store stays the default. When the environment selects
it (``PROOFTRAIL_STATE_BACKEND=supabase``) and ``SUPABASE_URL`` plus
``SUPABASE_KEY`` (or ``SUPABASE_SERVICE_KEY``) are set, the server
persists the same ``{users, projects}`` state document to a single
row (``id = "main"``) in a ``prooftrail_state`` table through the
Supabase REST API (PostgREST) with ``urllib``. No other dependency
is involved, and no live connection is attempted without those
variables.

The table must already exist in the Supabase project — this code
creates nothing server-side. A minimal shape is ``id text primary
key, state jsonb``. Use the service key only on the server: it
bypasses row-level security, so it must never ship to a client.

Unlike the file store there is no local ``.bak`` fallback here;
durability comes from Postgres itself. The state document holds the
same data the file does (password verifiers, public keys, blobs,
ledger events — never signing secrets), so the same transport
caution applies: Supabase REST runs over HTTPS.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

TABLE = "prooftrail_state"
ROW_ID = "main"


class SupabaseStore:
    """One state document in one Supabase table row.

    ``request_fn`` is the injectable HTTP layer: it takes
    (method, url, data, headers) and returns (status, body_bytes).
    Production uses a ``urllib`` implementation; tests pass a fake.
    """

    def __init__(self, base_url: str, api_key: str,
                 table: str = TABLE, request_fn=None) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.table = table
        self._request = request_fn or self._default_request

    @classmethod
    def from_env(cls) -> "SupabaseStore | None":
        """Build from the environment, or None when unconfigured."""
        url = os.environ.get("SUPABASE_URL")
        key = (os.environ.get("SUPABASE_SERVICE_KEY")
               or os.environ.get("SUPABASE_KEY"))
        if not url or not key:
            return None
        return cls(url, key)

    def _headers(self) -> dict:
        return {
            "apikey": self.api_key,
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def _default_request(self, method: str, url: str, data: bytes | None,
                         headers: dict) -> tuple[int, bytes]:
        request = urllib.request.Request(url, data=data, headers=headers,
                                         method=method)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            raise ValueError(
                f"supabase request failed: {method} {url} "
                f"-> HTTP {exc.code}") from exc

    def load(self) -> dict | None:
        """The stored state document, or None when no row exists."""
        url = (f"{self.base_url}/rest/v1/{self.table}"
               f"?id=eq.{ROW_ID}&select=state")
        status, body = self._request("GET", url, None, self._headers())
        if status != 200:
            raise ValueError(f"supabase load failed: HTTP {status}")
        rows = json.loads(body or b"[]")
        if not rows:
            return None
        return rows[0]["state"]

    def save(self, state: dict) -> None:
        """Upsert the state document as the single row."""
        url = (f"{self.base_url}/rest/v1/{self.table}"
               f"?on_conflict=id")
        headers = dict(self._headers())
        headers["Prefer"] = "resolution=merge-duplicates"
        body = json.dumps([{"id": ROW_ID, "state": state}]).encode()
        status, _ = self._request("POST", url, body, headers)
        if status not in (200, 201):
            raise ValueError(f"supabase save failed: HTTP {status}")
