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

Transient failures are retried: a 429, a 5xx response, or a network
error retries up to three attempts with exponential backoff, because
a single dropped request must not lose a save. Other HTTP errors
fail immediately, and a state document that fails to load or save
after the retries raises instead of being silently served or dropped.

Unlike the file store there is no local ``.bak`` fallback here;
durability comes from Postgres itself. The state document holds the
same data the file does (password verifiers, public keys, blobs,
ledger events — never signing secrets), so the same transport
caution applies: Supabase REST runs over HTTPS.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

TABLE = "prooftrail_state"
ROW_ID = "main"
MAX_ATTEMPTS = 3
RETRY_DELAY_SECONDS = 0.5
_RETRYABLE_STATUS = (429, 500, 502, 503, 504)


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
        """One request, retried on transient failures only.

        A 429, a 5xx response, or a network error retries with
        exponential backoff; anything else fails on the first attempt.
        Saves are upserts and loads are reads, so retrying them cannot
        duplicate an effect. After the last attempt the error is
        raised as ValueError, never swallowed.
        """
        for attempt in range(1, MAX_ATTEMPTS + 1):
            request = urllib.request.Request(url, data=data, headers=headers,
                                             method=method)
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    return response.status, response.read()
            except urllib.error.HTTPError as exc:
                retryable = exc.code in _RETRYABLE_STATUS
                if not retryable or attempt == MAX_ATTEMPTS:
                    raise ValueError(
                        f"supabase request failed: {method} {url} "
                        f"-> HTTP {exc.code}") from exc
            except urllib.error.URLError as exc:
                if attempt == MAX_ATTEMPTS:
                    raise ValueError(
                        f"supabase request failed: {method} {url} "
                        f"-> {exc.reason}") from exc
            time.sleep(RETRY_DELAY_SECONDS * (2 ** (attempt - 1)))
        raise AssertionError("unreachable: retry loop always returns or raises")

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
