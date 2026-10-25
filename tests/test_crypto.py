import unittest

from prooftrail.crypto import (
    content_id,
    generate_keypair,
    public_key_from_secret,
    sha256_hex,
    sign,
    verify,
)


class TestContentAddressing(unittest.TestCase):
    def test_sha256_matches_stdlib(self):
        import hashlib

        self.assertEqual(sha256_hex(b"hello"), hashlib.sha256(b"hello").hexdigest())

    def test_content_id_changes_with_content(self):
        self.assertNotEqual(content_id(b"v1"), content_id(b"v2"))
        self.assertEqual(content_id(b"same"), content_id(b"same"))


class TestEd25519(unittest.TestCase):
    def test_rfc8032_vector_empty_message(self):
        # RFC 8032 test vector 1.
        secret = bytes.fromhex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        )
        expected_pk = bytes.fromhex(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        )
        expected_sig = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        self.assertEqual(public_key_from_secret(secret), expected_pk)
        self.assertEqual(sign(secret, expected_pk, b""), expected_sig)
        self.assertTrue(verify(expected_pk, b"", expected_sig))

    def test_roundtrip_and_tamper(self):
        secret, public = generate_keypair()
        message = b"ProofTrail version 3"
        sig = sign(secret, public, message)
        self.assertTrue(verify(public, message, sig))
        self.assertFalse(verify(public, b"ProofTrail version 4", sig))
        tampered = bytearray(sig)
        tampered[10] ^= 1
        self.assertFalse(verify(public, message, bytes(tampered)))
        other_secret, other_public = generate_keypair()
        self.assertFalse(verify(other_public, message, sig))
        self.assertFalse(verify(public, message, b"x" * 64))


if __name__ == "__main__":
    unittest.main()
