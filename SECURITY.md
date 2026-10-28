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
- **Credential theft from disk.** The state file is written atomically
  (temp file + rename) with mode `0600`, so a crash cannot half-write it
  and other local users cannot read it.
- **Brute force.** After 5 failed logins in 10 minutes, the username is
  locked for 15 minutes. Login failures return the same message for
  unknown users and wrong passwords, so accounts cannot be enumerated.
- **Registration abuse.** Registrations are capped at 30 per hour per
  client address (429 beyond that), so an open deployment cannot be
  flooded with junk accounts from one address.
- **Session theft window.** Tokens are 256-bit random values, expire
  after 24 hours, live in memory only, and can be revoked via
  `POST /api/sessions/revoke`.
- **Timestamp forgery.** Upload and approval timestamps are always
  server-assigned; client-supplied timestamps are ignored.
- **Memory exhaustion.** Request bodies over 10 MiB are rejected on
  headers alone, before the body is read. JSON and base64 inputs are
  validated; wrong content types get 415.
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
