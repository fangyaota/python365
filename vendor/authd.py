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
import secrets
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
LEASE_GRACE = float(os.environ.get("PYTHON365_LEASE_GRACE", "4"))  # 宽限期：签进租约载荷


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _sign(payload: bytes) -> str:
    n, _e, d = load_private_key()
    digest = int.from_bytes(hashlib.sha256(payload).digest()[:12], "big") % n
    return _b64(pow(digest, d, n).to_bytes(128, "big"))


def lic_id(license_token: str) -> str:
    return hashlib.sha256(license_token.strip().encode()).hexdigest()[:16]


def license_info(license_token: str) -> tuple[list[str], str] | None:
    """验签 + 返回 (授权档, 到期日)。客户端说什么都不算 —— 服务端自己验。"""
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
    return (tiers, expiry) if tiers else None


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

    def bind(self, lid: str, fp: str, tiers: list[str], expiry: str, ip: str = "") -> str:
        """
        只存**派生信息**，不存许可证原文（第五轮 R5-06），并且**绝不碰吊销列表**。

        第六轮 R6-03：原来这里是"重新激活顺手清掉旧吊销"的写法 ——
        而 `/activate` 对任何持有效许可证的人都放行，客户端每次重启又会自动调它
        （`install()` 里 `if not keeper.valid(): keeper.activate()`）：
        **被吊销的客户只要重启一次程序就复活。**

        要解除吊销必须走显式的运维动作（`/unrevoke` + 管理令牌），
        不能是"重新激活"的副作用。

        返回一个**一次性刷新令牌**（R6-05）：租约在明文通道上走，
        抓到一张不该等于"无限续期"。
        """
        refresh = secrets.token_urlsafe(16)
        self.data["devices"][lid] = {"fp": fp, "tiers": tiers, "expiry": expiry,
                                     "refresh": refresh, "ip": ip}
        self.save()
        return refresh

    def rotate_refresh(self, lid: str) -> str | None:
        """换一张新的刷新令牌（旧的立刻作废）"""
        dev = self.data["devices"].get(lid)
        if not dev:
            return None
        dev["refresh"] = secrets.token_urlsafe(16)
        self.save()
        return dev["refresh"]

    def unrevoke(self, lid: str) -> None:
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
    """
    把**宽限期也签进载荷**（第七轮 R7-06）。

    原来宽限期来自客户端环境变量 `PYTHON365_LEASE_GRACE` —— 那是"到期就停机"这条
    fail-closed 规则的一个输入，摆在攻击者手里：`GRACE=999999999999` 一个环境变量，
    短周期租约就形同虚设。凡是要用来做安全判定的参数，都不能由被判定方声明。
    """
    exp = int(time.time()) + LEASE_TTL
    payload = f"LEASE|{lid}|{fp}|{exp}|{','.join(tiers)}|{LEASE_GRACE}".encode()
    return f"{_b64(payload)}.{_sign(payload)}"


def _lease_fields(token: str) -> dict | None:
    """只解析，不验签 —— 内部用，**绝不能**拿它的结果当凭据"""
    try:
        payload_b64, _sig = token.split(".")
        fields = base64.urlsafe_b64decode(payload_b64 + "==").decode().split("|")
        if fields[0] != "LEASE":
            return None
        return {"lid": fields[1], "fp": fields[2], "exp": int(fields[3]),
                "tiers": [t for t in fields[4].split(",") if t],
                "grace": float(fields[5]) if len(fields) > 5 else LEASE_GRACE}
    except Exception:                                        # noqa: BLE001
        return None


def verify_lease(token: str) -> dict | None:
    """
    **验签**之后才返回载荷。

    第五轮 R5-05/R5-09：`/renew` 原来只做 base64 解码 + 按 `|` 切分就当成可信输入，
    于是任何人只要知道 (lic_id, fp)（`/state` 或状态文件里都有）就能换到一张
    **服务端签名的**合法租约 —— 不需要许可证、不需要私钥。
    服务端把"客户端报上来的东西"直接变成了"服务端签发的凭据"，这是信任边界搞错了。
    """
    try:
        payload_b64, sig_b64 = token.split(".")
        payload = base64.urlsafe_b64decode(payload_b64 + "==")
        sig = base64.urlsafe_b64decode(sig_b64 + "==")
    except Exception:                                        # noqa: BLE001
        return None
    n, e, _d = load_private_key()
    digest = int.from_bytes(hashlib.sha256(payload).digest()[:12], "big") % n
    if pow(int.from_bytes(sig, "big"), e, n) != digest:
        return None
    return _lease_fields(token)


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

    def _admin_ok(self) -> bool:
        """
        /state 是**管理接口**，必须认证。

        第五轮 R5-05/R5-09：它原来是裸的，攻击者不用猜 `lic_id`，
        `GET /state` 直接把所有设备的 (lic_id, 指纹) 列出来，配合不验签的 /renew
        就是一条"零凭据拿企业版租约"的链。默认关闭（没配 token 就一律拒绝）。
        """
        want = os.environ.get("PYTHON365_ADMIN_TOKEN")
        return bool(want) and self.headers.get("X-Admin-Token") == want

    def do_GET(self):
        if self.path == "/state":
            if not self._admin_ok():
                return self._reply({"error": "管理接口需要 X-Admin-Token"}, 403)
            self._reply({"devices": {k: v["fp"] for k, v in STORE.data["devices"].items()},
                         "revoked": STORE.data["revoked"], "lease_ttl": LEASE_TTL})
        else:
            self._reply({"error": "not found"}, 404)

    def do_POST(self):
        body = self._body()
        if self.path == "/activate":
            license_token, fp = body.get("license", ""), body.get("fp", "")
            info = license_info(license_token)
            if not info:
                return self._reply({"error": "许可证无效或已过期"}, 403)
            tiers, expiry = info
            lid = lic_id(license_token)
            # 第七轮 R7-05：`bind()` 不再清吊销之后，这里必须自己看吊销名单 ——
            # 否则被吊销的客户每次重启都能靠 /activate 拿回一个完整租约周期。
            if STORE.is_revoked(lid):
                return self._reply({"error": "该许可证已被吊销"}, 403)
            bound = STORE.device(lid)
            if bound and bound["fp"] != fp:
                return self._reply({"error": f"该许可证已绑定其他设备（{bound['fp'][:8]}…）"}, 409)
            # 记下**连接**的来源地址（客户端自己报什么都不算）——
            # 第七轮 R7-04：租约与刷新令牌在明文 HTTP 上走，链路观察者抓到一次
            # 就能靠"谁先用谁赢"劫持会话。绑定来源地址是一条弱启发式，
            # 真正的修法是 TLS / token binding（见 README 的"仍然修不掉的"）。
            refresh = STORE.bind(lid, fp, tiers, expiry,
                                 self.client_address[0])   # 只存派生信息，不碰吊销列表
            return self._reply({"lease": make_lease(lid, fp, tiers), "lic_id": lid,
                                "refresh": refresh})

        if self.path == "/renew":
            # ⚠️ 先**验签**：客户端交上来的东西在验签之前一文不值
            fields = verify_lease(body.get("lease", ""))
            if not fields:
                return self._reply({"error": "租约签名无效"}, 403)
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
            if bound.get("ip") and bound["ip"] != self.client_address[0]:
                # 弱启发式：来源地址变了就拒（第七轮 R7-04 的缓解；真修法是 TLS）
                return self._reply({"error": "续签来源与激活来源不一致"}, 409)
            if bound.get("expiry", "0") < time.strftime("%Y%m%d"):
                return self._reply({"error": "许可证已过期"}, 403)
            # 一次性刷新令牌：抓到一张租约 ≠ 无限续期（R6-05）
            if not bound.get("refresh") or body.get("refresh") != bound["refresh"]:
                return self._reply({"error": "刷新令牌无效（可能已用过）"}, 403)
            # 只发"服务端自己记着的那份授权档"，不看客户端报了什么
            return self._reply({"lease": make_lease(lid, fp, bound["tiers"]),
                                "refresh": STORE.rotate_refresh(lid)})

        if self.path == "/revoke":
            lid = body.get("lic_id") or lic_id(body.get("license", ""))
            STORE.revoke(lid)
            return self._reply({"revoked": lid, "list": STORE.data["revoked"]})

        if self.path == "/unrevoke":
            # 解除吊销是**运维动作**，必须有管理凭据 —— 不能是重新激活的副作用
            if not self._admin_ok():
                return self._reply({"error": "管理接口需要 X-Admin-Token"}, 403)
            # 和 /revoke 保持一致：两种写法都认（只给 lic_id 时用它，给许可证时算出来）
            lid = body.get("lic_id") or lic_id(body.get("license", ""))
            STORE.unrevoke(lid)
            return self._reply({"unrevoked": lid, "list": STORE.data["revoked"]})

        self._reply({"error": "not found"}, 404)


def main() -> None:
    global STORE
    STORE = Store(STATE)
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8787
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    cert, key = os.environ.get("PYTHON365_TLS_CERT"), os.environ.get("PYTHON365_TLS_KEY")
    if cert and key:
        # TLS：租约与刷新令牌是 bearer 凭据，明文通道上"抓到一次 = 劫持"
        # （第七/八轮 R7-04 / R8-03）。加密之后同出口的观察者只剩"盲目转发"。
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "TLS"
    else:
        scheme = "明文 —— 仅演示用，生产必须 TLS"
    print(f"厂商授权服务端已启动 :{port}（{scheme}）  租约 {LEASE_TTL}s  状态文件 {STATE}",
          flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
