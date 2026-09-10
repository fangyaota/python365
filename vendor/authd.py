"""
厂商授权服务端（本地演示）

设计要点 —— 针对审计里"客户端拿得住的都不算凭据"的三条残留：

  ① 私钥只在本进程内存里。客户端进程、客户端机器都不需要它 ——
     所以"客户端被完全攻破"不再等于"私钥泄露"（R4-06）。
     （本地演示时它和客户端同机，真实部署应在另一台主机 / 独立 uid / HSM；
       密钥可以用 PYTHON365_VENDOR_KEY 直接注入，不落盘。）
  ② 设备绑定：一次激活把一个许可证绑到一个机器指纹；换机器续签一律拒绝。
  ③ 吊销：revoke 之后续签立即失败，客户端在"租约到期 + 宽限期"内停机。

租约载荷：LEASE|<lic_id>|<指纹>|<到期 unix>|<授权档>，用厂商私钥签名。
客户端只验签、不签 —— 它造不出租约。

    python3 vendor/authd.py 8787            # 启动
    curl -s localhost:8787/state            # 看设备/吊销状态
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
KEY_DIR = os.environ.get(
    "PYTHON365_VENDOR_DIR", os.path.join(os.path.expanduser("~"), ".python365-vendor"))
STATE = os.environ.get("PYTHON365_AUTHD_STATE", os.path.join(KEY_DIR, "authd_state.json"))

sys.path.insert(0, HERE)
from issue import load_private_key  # noqa: E402  同一份密钥加载逻辑

LEASE_TTL = int(os.environ.get("PYTHON365_LEASE_TTL", "8"))     # 演示用：8 秒租约


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _sign(payload: bytes) -> str:
    n, _e, d = load_private_key()
    digest = int.from_bytes(hashlib.sha256(payload).digest()[:12], "big") % n
    return _b64(pow(digest, d, n).to_bytes(128, "big"))


def lic_id(license_token: str) -> str:
    return hashlib.sha256(license_token.strip().encode()).hexdigest()[:16]


def license_tiers(license_token: str) -> list[str] | None:
    """
    服务端自己验一遍许可证 —— 客户端说什么都不算。

    （客户端也能验签，但"谁说了算"这件事必须落在服务端：
      客户端报上来的授权档只是请求，服务端返回的租约才是凭据。）
    """
    try:
        head, payload_b64, sig_b64 = license_token.strip().split(".")
        if head != "PYTHON365":
            return None
        payload = base64.urlsafe_b64decode(payload_b64 + "==")
        sig = base64.urlsafe_b64decode(sig_b64 + "==")
    except Exception:                                        # noqa: BLE001
        return None
    n, e, _d = load_private_key()
    digest = int.from_bytes(hashlib.sha256(payload).digest()[:12], "big") % n
    if pow(int.from_bytes(sig, "big"), e, n) != digest:
        return None
    try:
        tier_field, expiry = payload.decode().split("|")
    except Exception:                                        # noqa: BLE001
        return None
    if expiry < time.strftime("%Y%m%d"):
        return None
    tiers = [t.strip().upper() for t in tier_field.split(",") if t.strip()]
    return tiers or None


class Store:
    def __init__(self, path: str):
        self.path = path
        self.data = {"devices": {}, "revoked": []}
        try:
            with open(path) as fh:
                self.data.update(json.load(fh))
        except (OSError, ValueError):
            pass

    def save(self) -> None:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w") as fh:
            json.dump(self.data, fh, indent=1)

    def bind(self, lid: str, fp: str, license_token: str) -> None:
        self.data["devices"][lid] = {"fp": fp, "license": license_token}
        self.data["revoked"] = [r for r in self.data["revoked"] if r != lid]
        self.save()

    def device(self, lid: str):
        return self.data["devices"].get(lid)

    def revoke(self, lid: str) -> None:
        if lid not in self.data["revoked"]:
            self.data["revoked"].append(lid)
        self.save()

    def is_revoked(self, lid: str) -> bool:
        return lid in self.data["revoked"]


STORE: Store


def make_lease(lid: str, fp: str, tiers: list[str]) -> str:
    exp = int(time.time()) + LEASE_TTL
    payload = f"LEASE|{lid}|{fp}|{exp}|{','.join(tiers)}".encode()
    return f"{_b64(payload)}.{_sign(payload)}"


def _lease_fields(token: str) -> dict | None:
    try:
        payload_b64, _sig = token.split(".")
        fields = base64.urlsafe_b64decode(payload_b64 + "==").decode().split("|")
        if fields[0] != "LEASE":
            return None
        return {"lid": fields[1], "fp": fields[2], "exp": int(fields[3]),
                "tiers": [t for t in fields[4].split(",") if t]}
    except Exception:                                        # noqa: BLE001
        return None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):        # 别把演示日志刷满
        pass

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return {}

    def _reply(self, obj: dict, code: int = 200) -> None:
        raw = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/state":
            self._reply({"devices": {k: v["fp"] for k, v in STORE.data["devices"].items()},
                         "revoked": STORE.data["revoked"], "lease_ttl": LEASE_TTL})
        else:
            self._reply({"error": "not found"}, 404)

    def do_POST(self):
        body = self._body()
        if self.path == "/activate":
            license_token, fp = body.get("license", ""), body.get("fp", "")
            tiers = license_tiers(license_token)
            if not tiers:
                return self._reply({"error": "许可证无效或已过期"}, 403)
            lid = lic_id(license_token)
            bound = STORE.device(lid)
            if bound and bound["fp"] != fp:
                return self._reply({"error": f"该许可证已绑定其他设备（{bound['fp'][:8]}…）"}, 409)
            STORE.bind(lid, fp, license_token)
            return self._reply({"lease": make_lease(lid, fp, tiers), "lic_id": lid})

        if self.path == "/renew":
            fields = _lease_fields(body.get("lease", ""))
            if not fields:
                return self._reply({"error": "租约格式错误"}, 400)
            lid, fp = fields["lid"], fields["fp"]
            if body.get("fp") != fp:
                return self._reply({"error": "设备指纹不匹配"}, 409)
            if STORE.is_revoked(lid):
                return self._reply({"error": "许可证已被吊销"}, 403)
            bound = STORE.device(lid)
            if not bound:
                return self._reply({"error": "该租约没有对应的激活记录"}, 403)
            if bound["fp"] != fp:
                return self._reply({"error": "设备绑定不匹配"}, 409)
            tiers = license_tiers(bound["license"])
            if not tiers:
                return self._reply({"error": "许可证已过期"}, 403)
            return self._reply({"lease": make_lease(lid, fp, tiers)})

        if self.path == "/revoke":
            lid = body.get("lic_id") or lic_id(body.get("license", ""))
            STORE.revoke(lid)
            return self._reply({"revoked": lid, "list": STORE.data["revoked"]})

        self._reply({"error": "not found"}, 404)


def main() -> None:
    global STORE
    STORE = Store(STATE)
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8787
    print(f"厂商授权服务端已启动 :{port}  租约 {LEASE_TTL}s  状态文件 {STATE}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
