import unittest
import os
import sys
import json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from jwtl import decode_token, verify_hs256, b64url_encode, b64url_decode


class TestDecode(unittest.TestCase):
    def test_valid(self):
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = decode_token(token)
        self.assertIsNotNone(result)
        header, payload, sig = result
        self.assertEqual(header["alg"], "HS256")
        self.assertEqual(payload["sub"], "1234567890")
        self.assertEqual(payload["name"], "John Doe")

    def test_invalid(self):
        self.assertIsNone(decode_token("not.a.jwt"))
        self.assertIsNone(decode_token("abc"))
        self.assertIsNone(decode_token(""))


class TestVerify(unittest.TestCase):
    def test_valid_signature(self):
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        self.assertTrue(verify_hs256(token, "your-256-bit-secret"))

    def test_invalid_signature(self):
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        self.assertFalse(verify_hs256(token, "wrong-secret"))


class TestB64(unittest.TestCase):
    def test_roundtrip(self):
        data = b"hello world"
        enc = b64url_encode(data)
        dec = b64url_decode(enc)
        self.assertEqual(dec, data)


if __name__ == "__main__":
    unittest.main()
