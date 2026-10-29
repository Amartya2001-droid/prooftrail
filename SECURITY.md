# Security model

ProofTrail's week-1 server is a provenance system: its whole value is
that history cannot be rewritten. This page states what is protected,
how, and what is deliberately *not* covered.

## Protected

- **Ledger forgery.** Every event is Ed25519-signed and hash-chained.
  Rewriting, dropping or reordering an event breaks `verify()`. Signing
  keys are derived from the user's password (PBKDF2-HMAC-SHA256, 200,000
  iterations, separate salts for the login verifier and the key) and are
  never stored on disk; the state file holds salts, verifiers and public
  keys only.
- **Tampered state files.** A data file is fully re-verified on load —
  ledger chain, signatures, version linkage and blob presence — and
  refused outright if anything fails, so doctored history can never be
  served as if it were valid.
- **Swapped content.** Verification also re-hashes every stored blob
  against its version's content_id: the chain vouches for ids, so
  without this check, replacing a version's bytes in the data file
  would pass verification unnoticed.
- **One bad file cannot destroy history.** Every save keeps the
  previous good state as `<path>.bak`; if the main file is corrupt or
  fails verification, load falls back to that backup, and refuses only
  if both are unusable.
- **Inviting is creator-only.** Previously any collaborator could add
  new collaborators; now only the project creator can, so a reviewer
  added for one version cannot invite anyone else into the project.
- **Credential theft from disk.** The state file is written atomically
  (temp file + rename) with mode `0600`, so a crash cannot half-write it
  and other local users cannot read it.
- **Brute force.** After 5 failed logins in 10 minutes, the username is
  locked for 15 minutes. Login failures return the same message for
  unknown users and wrong passwords, so accounts cannot be enumerated.
  Separately, 20 failed logins in 10 minutes from one address locks
  that address out, so spraying many accounts from one place stops
  even though no single account hits its own lockout.
- **Login timing oracle.** Rejecting an unknown username runs the
  same PBKDF2 work as rejecting a wrong password for a real user, so
  the response time cannot enumerate accounts either: without this,
  unknown users were rejected immediately while known users paid for
  200,000 iterations first.
- **Weak passwords.** Registration rejects passwords from a
  common-password denylist (breach-list entries such as `password123`)
  and rejects the username itself as the password, on top of the
  existing 8-character minimum. The policy is enforced at the
  registration boundary, so existing accounts are unaffected.
- **Registration abuse.** Registrations are capped at 30 per hour per
  client address (429 beyond that), so an open deployment cannot be
  flooded with junk accounts from one address.
- **Session theft window.** Tokens are 256-bit random values, expire
  after 24 hours, live in memory only, and can be revoked via
  `POST /api/sessions/revoke`.
- **Idle sessions.** Thirty minutes without a request ends a session
  even inside the 24-hour absolute window, so a token left on a
  shared or stolen machine has a short life; activity refreshes the
  idle clock, but never extends the absolute expiry.
- **Authentication audit trail.** Registrations, logins, failed
  logins, lockouts, logouts and revoke-all actions are recorded in a
  capped in-memory log (last 1,000 events). Each user sees only their
  own events via `GET /api/sessions/audit` — the trail answers "was
  that login me?" without exposing other accounts.
- **Individual session control.** `GET /api/sessions` lists your own
  sessions with device labels and a current-session flag, and
  `POST /api/sessions/revoke-one` ends one session without logging
  out everywhere. Listings never contain tokens: the session id is
  the revocation handle, and it is useless on its own.
- **Unfamiliar-address logins are flagged.** The first successful
  login from an address an account has never used returns
  `new_ip: true` and is noted in the audit trail, so a login with a
  stolen password from a new place stands out. Familiarity is kept
  in memory like sessions: after a restart, the next login from any
  address is flagged once — fail-visible, not fail-open.
- **Collaborator removal.** The project creator can remove a
  collaborator with immediate effect: the next request from the
  removed account fails the collaborator check. Past history still
  verifies, because the ledger keeps the removed actor's key — removal
  ends access, never the record of what they signed.
- **Password change without breaking history.** `POST
  /api/users/password` requires the old password, revokes every other
  session, and keeps the calling session working with the new derived
  secret. Because the signing key is derived from the password, the
  ledger keeps a history of each actor's keys: events signed before
  the change still verify, new events use the new key, and the key
  history persists across restarts — including keys of removed
  collaborators, whose past events must stay verifiable.
- **Session binding.** A session created over HTTP is bound to the
  client address and user agent it came from: presenting the token
  from a different address or agent revokes the token outright, so a
  stolen token cannot be retried from the thief's machine.
- **Timestamp forgery.** Upload and approval timestamps are always
  server-assigned; client-supplied timestamps are ignored.
- **Memory exhaustion.** Request bodies over 10 MiB are rejected on
  headers alone, before the body is read. JSON and base64 inputs are
  validated; wrong content types get 415.
- **Empty uploads.** A zero-byte upload is rejected: it carries no
  content to prove, so it must never enter the ledger as a version.
- **Lookalike usernames.** Usernames are case-insensitive at
  registration, login and collaborator invite, so "Designer" cannot
  exist alongside "designer" and sign ledger events under a
  lookalike name. Display names keep their original case.
- **Self-approvals are flagged.** The verification page lists
  approvals where the approver is the version's own uploader: they
  are not rejected (a solo creator legitimately approves their own
  work), but they are named explicitly as weaker evidence than an
  independent approval.
- **General API throttle.** Beyond the registration and login
  limits, every request counts toward 300 per minute per client
  address, so one address cannot flood the API.
- **Information leakage.** 500 responses are a generic "internal error"
  (details go to server stderr only). The verification page exposes
  hashes, never document content. Responses carry `nosniff` and
  `no-store` headers.
- **Concurrency corruption.** All mutations run under one lock, so
  concurrent uploads, registrations and saves cannot interleave.
- **Signature malleability.** Non-canonically encoded Ed25519 points are
  rejected at verification.

## Deliberately not covered (yet)

- **Transport security.** The server binds `127.0.0.1` by default and
  speaks plain HTTP. In production it must sit behind a TLS reverse
  proxy — tokens and passwords cross the wire otherwise.
- **Key recovery.** Losing a password loses the signing key by design.
  There is no backdoor and no recovery flow yet (a week-3 concern).
- **Multi-server sessions.** Sessions live in one process's memory; a
  multi-instance deployment needs shared session storage.
- **Malicious collaborators.** Anyone added as a collaborator can upload
  and approve. That is the product's permission model, not a bypass —
  but a compromised collaborator account can append (never rewrite)
  history.

## Reporting

This is a portfolio project, not a production service. If you spot a
hole, the end-to-end suite in `tests/test_e2e_security.py` is the place
to prove it: add a failing test first.
