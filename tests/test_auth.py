import unittest

from prooftrail.auth import SessionStore, authenticate, create_user
from prooftrail.crypto import public_key_from_secret, sign, verify


class TestAuth(unittest.TestCase):
    def test_login_derives_same_signing_key(self):
        user = create_user("designer", "Freelance Designer", "correct horse")
        secret = authenticate(user, "correct horse")
        self.assertIsNotNone(secret)
        assert secret is not None
        self.assertEqual(public_key_from_secret(secret), user.public_key)
        # The derived key actually signs, and the ledger can verify it.
        sig = sign(secret, user.public_key, b"hello")
        self.assertTrue(verify(user.public_key, b"hello", sig))

    def test_wrong_password_fails(self):
        user = create_user("designer", "Freelance Designer", "correct horse")
        self.assertIsNone(authenticate(user, "wrong horse"))

    def test_roundtrip_serialisation(self):
        from prooftrail.auth import UserRecord

        user = create_user("designer", "Freelance Designer", "pw")
        restored = UserRecord.from_dict(user.to_dict())
        self.assertEqual(restored.public_key, user.public_key)
        self.assertIsNotNone(authenticate(restored, "pw"))

    def test_sessions(self):
        store = SessionStore()
        token = store.create("designer")
        self.assertEqual(store.lookup(token), "designer")
        self.assertIsNone(store.lookup("bogus"))
        store.revoke(token)
        self.assertIsNone(store.lookup(token))


if __name__ == "__main__":
    unittest.main()
