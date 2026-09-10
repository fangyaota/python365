"""
厂商侧发证工具：用私钥签发许可证。

    python3 vendor/issue.py DATA,BASIC        # 签发给指定版本，默认 1 年有效
    python3 vendor/issue.py ENTERPRISE 3650   # 自定义有效天数

产出的许可证可以：
    PYTHON365_KEY='PYTHON365.xxx.yyy' python3 你的程序.py

客户端只有公钥，所以**改不了、伪造不了** —— 想白嫖只能真的拿到厂商签发的串。
"""
import base64
import hashlib
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
KEY_DIR = os.environ.get(
    "PYTHON365_VENDOR_DIR", os.path.join(os.path.expanduser("~"), ".python365-vendor"))


def load_private_key() -> tuple[int, int, int]:
    with open(os.path.join(KEY_DIR, "private_key.json")) as fh:
        k = json.load(fh)
    return k["n"], k["e"], k["d"]


def issue(tiers: str, days: int = 365) -> str:
    n, _e, d = load_private_key()
    expiry = time.strftime("%Y%m%d", time.localtime(time.time() + days * 86400))
    payload = f"{tiers.upper()}|{expiry}".encode()
    digest = int.from_bytes(hashlib.sha256(payload).digest()[:12], "big") % n
    signature = pow(digest, d, n)                       # 私钥签名
    b64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")   # noqa: E731
    return f"PYTHON365.{b64(payload)}.{b64(signature.to_bytes(128, 'big'))}"


def issue_topup(calls: int, seconds: float, days: int = 365) -> str:
    """
    签发「加油包」令牌：客户端用它调用 python365.apply_topup(token) 续费。

    客户端只有公钥 ⇒ 造不出额度（第三轮 R3-6 的修法）。
    """
    n, _e, d = load_private_key()
    expiry = time.strftime("%Y%m%d", time.localtime(time.time() + days * 86400))
    payload = f"TOPUP|{int(calls)}|{float(seconds)}|{expiry}".encode()
    digest = int.from_bytes(hashlib.sha256(payload).digest()[:12], "big") % n
    signature = pow(digest, d, n)
    b64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")   # noqa: E731
    return f"PYTHON365.{b64(payload)}.{b64(signature.to_bytes(128, 'big'))}"


if __name__ == "__main__":
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        sys.exit(1)
    if args[0] == "--topup":                       # python3 issue.py --topup 50000 3.0
        print(issue_topup(int(args[1]), float(args[2]),
                          int(args[3]) if len(args) > 3 else 365))
    else:
        print(issue(args[0], int(args[1]) if len(args) > 1 else 365))
