#!/usr/bin/env python3
import argparse
import base64
import hashlib
import hmac
import json
import sys
from datetime import datetime, timezone

def b64url_decode(s):
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def b64url_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def decode_token(token):
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except Exception:
        return None
    return header, payload, parts[2]

def verify_hs256(token, secret):
    parts = token.split(".")
    if len(parts) != 3:
        return False
    signing_input = (parts[0] + "." + parts[1]).encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    expected = b64url_encode(sig)
    return hmac.compare_digest(expected, parts[2])

def format_time(ts):
    if not isinstance(ts, (int, float)):
        return str(ts)
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def cmd_decode(args):
    result = decode_token(args.token)
    if not result:
        print("invalid token", file=sys.stderr)
        sys.exit(1)
    header, payload, sig = result
    if args.json:
        print(json.dumps({"header": header, "payload": payload, "signature": sig}, indent=2))
        return
    print("Header:")
    for k, v in header.items():
        print(f"  {k}: {v}")
    print("Payload:")
    for k, v in payload.items():
        if k in ("iat", "exp", "nbf"):
            print(f"  {k}: {v} ({format_time(v)})")
        else:
            print(f"  {k}: {v}")
    print(f"Signature: {sig}")

def cmd_verify(args):
    result = decode_token(args.token)
    if not result:
        print("invalid token", file=sys.stderr)
        sys.exit(1)
    if args.secret:
        ok = verify_hs256(args.token, args.secret)
        print("valid" if ok else "invalid signature")
        sys.exit(0 if ok else 1)
    else:
        print("provide --secret to verify", file=sys.stderr)
        sys.exit(1)

def cmd_generate(args):
    header = {"alg": args.alg, "typ": "JWT"}
    payload = {}
    if args.payload:
        try:
            payload = json.loads(args.payload)
        except json.JSONDecodeError:
            print("invalid JSON payload", file=sys.stderr)
            sys.exit(1)
    if args.exp:
        import time
        payload["exp"] = int(time.time()) + args.exp
    if args.sub:
        payload["sub"] = args.sub
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    if args.secret:
        sig = hmac.new(args.secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
        s = b64url_encode(sig)
    else:
        s = ""
    token = f"{h}.{p}.{s}"
    print(token)

def cmd_check(args):
    result = decode_token(args.token)
    if not result:
        print("invalid token", file=sys.stderr)
        sys.exit(1)
    _, payload, _ = result
    now = datetime.now(tz=timezone.utc).timestamp()
    if "exp" in payload:
        exp = payload["exp"]
        if now > exp:
            print(f"EXPIRED (expired {format_time(exp)})")
            sys.exit(1)
        else:
            remaining = int(exp - now)
            print(f"valid (expires in {remaining}s, at {format_time(exp)})")
    else:
        print("no exp claim (token does not expire)")

def main():
    parser = argparse.ArgumentParser(prog="jwtl", description="Work with JWT tokens. Zero dependencies.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_decode = sub.add_parser("decode", help="decode a JWT token")
    p_decode.add_argument("token", help="JWT token")
    p_decode.add_argument("--json", action="store_true", help="JSON output")
    p_decode.set_defaults(func=cmd_decode)

    p_verify = sub.add_parser("verify", help="verify a JWT signature")
    p_verify.add_argument("token", help="JWT token")
    p_verify.add_argument("--secret", required=True, help="HMAC secret")
    p_verify.set_defaults(func=cmd_verify)

    p_gen = sub.add_parser("generate", help="generate a JWT token")
    p_gen.add_argument("--alg", default="HS256", help="algorithm")
    p_gen.add_argument("--secret", default="", help="HMAC secret")
    p_gen.add_argument("--payload", default=None, help="JSON payload")
    p_gen.add_argument("--sub", default=None, help="subject claim")
    p_gen.add_argument("--exp", type=int, default=None, help="expiry in seconds from now")
    p_gen.set_defaults(func=cmd_generate)

    p_check = sub.add_parser("check", help="check if a JWT is expired")
    p_check.add_argument("token", help="JWT token")
    p_check.set_defaults(func=cmd_check)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
