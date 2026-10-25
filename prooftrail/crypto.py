"""Trust primitives for ProofTrail.

Content addressing uses SHA-256. Signatures use Ed25519 (RFC 8032),
implemented here in pure Python so the package has zero third-party
dependencies. The implementation follows the standard reference formulas
(base point, clamped scalar, SHA-512 hashing) and is verified against the
RFC 8032 test vectors in the test suite.
"""

from __future__ import annotations

import hashlib
import secrets

# --- Curve constants (Ed25519) ------------------------------------------------
_Q = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, _Q - 2, _Q) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


_BY = (4 * pow(5, _Q - 2, _Q)) % _Q
_BX = _xrecover(_BY)
_B = (_BX % _Q, _BY % _Q)


def _edwards(p: tuple[int, int], q: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = p
    x2, y2 = q
    denom = pow(1 + _D * x1 * x2 * y1 * y2, _Q - 2, _Q)
    x3 = (x1 * y2 + x2 * y1) * denom % _Q
    denom2 = pow(1 - _D * x1 * x2 * y1 * y2, _Q - 2, _Q)
    y3 = (y1 * y2 + x1 * x2) * denom2 % _Q
    return x3, y3


def _scalarmult(p: tuple[int, int], e: int) -> tuple[int, int]:
    if e == 0:
        return (0, 1)
    q = _scalarmult(p, e // 2)
    q = _edwards(q, q)
    if e & 1:
        q = _edwards(q, p)
    return q


def _encodeint(y: int) -> bytes:
    bits = [(y >> i) & 1 for i in range(256)]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(32))


def _encodepoint(p: tuple[int, int]) -> bytes:
    x, y = p
    bits = [(y >> i) & 1 for i in range(255)] + [x & 1]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(32))


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _decodeint(s: bytes) -> int:
    return sum(2 ** i * _bit(s, i) for i in range(256))


def _decodepoint(s: bytes) -> tuple[int, int]:
    y = sum(2 ** i * _bit(s, i) for i in range(255))
    x = _xrecover(y)
    if x & 1 != _bit(s, 255):
        x = _Q - x
    return x, y


def _hint(m: bytes) -> int:
    h = _sha512(m)
    return sum(2 ** i * _bit(h, i) for i in range(512))


# --- Public API ---------------------------------------------------------------

def sha256_hex(data: bytes) -> str:
    """SHA-256 content fingerprint, hex-encoded."""
    return hashlib.sha256(data).hexdigest()


def content_id(data: bytes) -> str:
    """Content address for a blob: ``sha256:<hex>``."""
    return "sha256:" + sha256_hex(data)


def generate_keypair() -> tuple[bytes, bytes]:
    """Return a fresh (secret_key, public_key) pair, 32 bytes each."""
    secret = secrets.token_bytes(32)
    return secret, public_key_from_secret(secret)


def public_key_from_secret(secret: bytes) -> bytes:
    """Derive the Ed25519 public key for a 32-byte secret."""
    if len(secret) != 32:
        raise ValueError("secret key must be 32 bytes")
    h = _sha512(secret)
    a = 2 ** 254 + sum(2 ** i * _bit(h, i) for i in range(3, 254))
    return _encodepoint(_scalarmult(_B, a))


def sign(secret: bytes, public: bytes, message: bytes) -> bytes:
    """Sign a message; returns a 64-byte signature."""
    if len(secret) != 32 or len(public) != 32:
        raise ValueError("keys must be 32 bytes")
    h = _sha512(secret)
    a = 2 ** 254 + sum(2 ** i * _bit(h, i) for i in range(3, 254))
    r = _hint(h[32:] + message)
    r_point = _scalarmult(_B, r)
    r_enc = _encodepoint(r_point)
    s = (r + _hint(r_enc + public + message) * a) % _L
    return r_enc + _encodeint(s)


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """Return True iff the signature is valid for the message and key."""
    if len(public) != 32 or len(signature) != 64:
        return False
    try:
        r_point = _decodepoint(signature[:32])
        a_point = _decodepoint(public)
        s = _decodeint(signature[32:])
    except Exception:
        return False
    if s >= _L:
        return False
    h = _hint(signature[:32] + public + message)
    left = _scalarmult(_B, s)
    right = _edwards(r_point, _scalarmult(a_point, h))
    return left == right
