"""Token / session-cookie auth helpers."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import socket
import time

from dash.config import SESSION_MAX_AGE, TOKEN_FILE


def load_token() -> str | None:
    if TOKEN_FILE.exists():
        token = TOKEN_FILE.read_text().strip()
        if token:
            return token
    return None


def make_session_cookie(token: str) -> str:
    ts = str(int(time.time()))
    sig = hmac.new(token.encode(), ts.encode(), hashlib.sha256).hexdigest()
    return f"{ts}.{sig}"


def verify_session_cookie(cookie_val: str, token: str) -> bool:
    parts = cookie_val.split(".", 1)
    if len(parts) != 2:
        return False
    ts_str, sig = parts
    try:
        ts = int(ts_str)
    except ValueError:
        return False
    if time.time() - ts > SESSION_MAX_AGE:
        return False
    expected = hmac.new(token.encode(), ts_str.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expected)


def get_local_ips() -> list[str]:
    ips = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addr = info[4][0]
            if not ipaddress.ip_address(addr).is_loopback:
                ips.append(addr)
    except Exception:
        pass
    if not ips:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("10.255.255.255", 1))
            ips.append(s.getsockname()[0])
            s.close()
        except Exception:
            pass
    return sorted(set(ips))
