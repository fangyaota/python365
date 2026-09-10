"""
租约客户端 —— 短周期令牌 + 机器指纹 + 在线续签。

对付审计里那三条"客户端拿得住的都不算凭据"的残留：

  · 私钥不在客户端：这里只需要公钥（`_license.PUBLIC_KEY`）来**验签**，
    签名能力只在厂商服务端。客户端被完全攻破也签不出租约（R4-06）。
  · 设备绑定：租约载荷里带机器指纹，换机器续签一律被拒（无绑定问题）。
  · 可吊销：服务端 revoke 之后续签立即失败 → 本进程在"租约到期 + 宽限期"内停机。

诚实边界：
  · 完全控制本地进程的攻击者仍可 patch 掉"租约过期就停机"的判断，
    但**最多**只能在"租约 TTL + 宽限期"这个窗口里离线运行 —— 从"无限期绕过"
    变成"有上限的离线窗口"。要彻底消灭这个窗口，就得让每个特权动作都联网判定
    （代价是可用性）。
  · 本地演示时服务端与客户端同机同 uid，所以"私钥隔离"目前只是**架构上**成立；
    真实部署需要独立主机 / 独立 uid / HSM。
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import threading
import time

LEASE_FILE = os.environ.get("PYTHON365_LEASE_FILE", "/tmp/.python365_lease")

# ⚠️ 宽限期**不再从环境变量读**（第七轮 R7-06）。
# 它来自服务端签名的租约载荷，客户端只能照做 —— 否则
# `PYTHON365_LEASE_GRACE=999999999999` 一个环境变量就能让"到期停机"永不触发。
# 这条规则的教训：**凡是要用来做安全判定的参数，都不能由被判定方声明。**
_DEFAULT_GRACE = 6.0


def fingerprint() -> str:
    """
    机器指纹：主机名 + uid + machine-id（换机器就变）。

    ⚠️ **这是客户端自报的**，所以只挡得住"老实拷贝"，挡不住"伪造指纹"——
    完整的"机器绑定"需要可信计算（TPM/安全飞地）或服务端侧信号。
    演示用 PYTHON365_FP_OVERRIDE 可以模拟这两种情况。
    """
    override = os.environ.get("PYTHON365_FP_OVERRIDE")
    if override:
        return override
    parts = [platform.node(), str(os.getuid())]
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            with open(path) as fh:
                parts.append(fh.read().strip())
            break
        except OSError:
            continue
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def _http_error():
    import urllib.error
    return urllib.error.HTTPError


def _error_of(exc) -> str:
    """把服务端返回的 {"error": "..."} 读出来，别只报一个 HTTPError"""
    try:
        import json
        return json.loads(exc.read().decode()).get("error", str(exc))
    except Exception:                                        # noqa: BLE001
        return str(exc)


def _post(url: str, payload: dict, timeout: float = 4.0) -> dict:
    import urllib.request                       # 本模块被监控豁免，可以白嫖自己的"网络版"
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def parse_lease(token: str) -> dict | None:
    """本地验签 + 解析。只认签名，不认客户端自己说的任何东西。"""
    from ._license import PUBLIC_KEY, rsa_verify
    try:
        payload_b64, sig_b64 = token.strip().split(".")
        payload = base64.urlsafe_b64decode(payload_b64 + "==")
        sig = base64.urlsafe_b64decode(sig_b64 + "==")
    except Exception:                                        # noqa: BLE001
        return None
    if not rsa_verify(payload, sig):
        return None
    try:
        fields = payload.decode().split("|")
        if fields[0] != "LEASE":
            return None
        return {"lic_id": fields[1], "fp": fields[2], "exp": int(fields[3]),
                "tiers": [t for t in fields[4].split(",") if t],
                "grace": float(fields[5]) if len(fields) > 5 else _DEFAULT_GRACE}
    except Exception:                                        # noqa: BLE001
        return None


def _trusted_now() -> float:
    """
    用**可信时间**判定到期（第七轮 R7-06）。

    裸 `time.time()` 只是一个可 patch 的模块属性 —— "到期永不触发"只需要一行。
    这里复用许可证那套：网络时间 / 高水位 / 本地时钟**取最大**。

    ⚠️ 第八轮 R8-02：这个函数**不在运行期从模块字典里找** ——
    `LeaseKeeper.__init__` 用默认参数把它绑进实例（`self._clock`），
    所以 `python365._lease._trusted_now = lambda: 0.0` 打不穿它。

    而且**绝不退化成 `time.time()`**：可信时间拿不到就返回 `inf`（一律当已过期，
    fail-closed）。退化成"可被 patch 的时间"等于把 fail-closed 的选择权让出去。
    """
    try:
        from ._license import best_known_now
        return best_known_now()[0]
    except Exception:                                        # noqa: BLE001
        return float("inf")


class LeaseKeeper:
    """持有当前租约、后台续签、对外提供两个只读判断（都很便宜）"""

    def __init__(self, server: str, license_token: str | None = None,
                 interval: float | None = None, clock=_trusted_now):
        self.server = server.rstrip("/")
        self._clock = clock           # 启动期绑定：patch 模块级的 _trusted_now 影响不到它
        self.fp = fingerprint()
        self.license_token = license_token
        # 续签间隔：按宽限期推（用**服务端签进租约**的那个值，不是本地常量）
        self.interval = interval or max(1.0, (_DEFAULT_GRACE + 8) / 4)
        self._lock = threading.Lock()
        self._lease: str | None = None
        self._refresh: str | None = None      # 一次性刷新令牌（R6-05）：抓到租约 ≠ 能续期
        self._state = {"ok": False, "why": "未激活", "tiers": []}
        self._load()

    # ── 本地存储 ─────────────────────────────────────────────────────
    def _load(self) -> None:
        try:
            with open(LEASE_FILE) as fh:
                saved = json.load(fh)
            self._lease = saved.get("lease")
            self._refresh = saved.get("refresh")
        except (OSError, ValueError):
            self._lease = None
        self._refresh_state()

    def _save(self) -> None:
        try:
            with open(LEASE_FILE, "w") as fh:
                json.dump({"lease": self._lease, "fp": self.fp, "server": self.server,
                           "refresh": self._refresh}, fh)
        except OSError:
            pass

    def _refresh_state(self) -> None:
        fields = parse_lease(self._lease) if self._lease else None
        if not fields:
            self._state = {"ok": False, "why": "没有有效租约", "tiers": []}
        elif fields["fp"] != self.fp:
            self._state = {"ok": False, "why": f"租约绑定的是别的设备（{fields['fp'][:8]}…）",
                           "tiers": []}
        elif fields["exp"] + fields["grace"] < self._clock():
            self._state = {"ok": False, "why": "租约已过期且超出宽限期", "tiers": []}
        else:
            self._state = {"ok": True, "why": "有效", "tiers": fields["tiers"]}

    # ── 对外 ─────────────────────────────────────────────────────────
    def valid(self) -> bool:
        """每个计费事件都会调 —— 只读缓存，不做 I/O"""
        return self._state["ok"]

    def why(self) -> str:
        return self._state["why"]

    def tiers(self) -> list[str]:
        return list(self._state["tiers"])

    def license_id(self) -> str | None:
        fields = parse_lease(self._lease) if self._lease else None
        return fields["lic_id"] if fields else None

    def activate(self) -> bool:
        if not self.license_token:
            self._state = {"ok": False, "why": "没有许可证可激活", "tiers": []}
            return False
        try:
            got = _post(f"{self.server}/activate",
                        {"license": self.license_token, "fp": self.fp})
        except _http_error() as exc:                         # 服务端明确拒绝
            self._state = {"ok": False, "why": f"激活被拒：{_error_of(exc)}", "tiers": []}
            return False
        except Exception as exc:                             # noqa: BLE001
            self._state = {"ok": False, "why": f"激活失败：{type(exc).__name__}", "tiers": []}
            return False
        if "lease" not in got:
            self._state = {"ok": False, "why": f"激活被拒：{got.get('error', '?')}", "tiers": []}
            return False
        with self._lock:
            self._lease = got["lease"]
            self._refresh = got.get("refresh")
            self._save()
            self._refresh_state()
        return self._state["ok"]

    def renew_once(self) -> bool:
        with self._lock:
            lease = self._lease
        if not lease:
            return False
        try:
            got = _post(f"{self.server}/renew",
                        {"lease": lease, "fp": self.fp, "refresh": self._refresh})
        except _http_error() as exc:                         # 服务端明确拒绝（吊销/换机）
            with self._lock:
                self._state = {"ok": False, "why": f"续签被拒：{_error_of(exc)}", "tiers": []}
            return False
        except Exception as exc:                             # noqa: BLE001
            self._state["why"] = f"续签失败（离线）：{type(exc).__name__}"
            self._refresh_state()            # 本地租约没过期就还能撑到宽限期结束
            return False
        if "lease" not in got:
            with self._lock:
                self._state = {"ok": False, "why": f"续签被拒：{got.get('error', '?')}",
                               "tiers": []}
            return False
        with self._lock:
            self._lease = got["lease"]
            self._refresh = got.get("refresh", self._refresh)   # 令牌轮换：旧的作废
            self._save()
            self._refresh_state()
        return True

    def start(self) -> None:
        """后台续签线程"""
        def loop() -> None:
            while True:
                time.sleep(self.interval)
                self.renew_once()

        threading.Thread(target=loop, name="python365-lease", daemon=True).start()

    def guard(self, on_fail, interval: float = 0.5) -> None:
        """
        租约闸门线程：租约失效就执行 on_fail（默认 fail-closed）。

        ⚠️ 这条**必须独立于计费钩子**：早先把检查放在全局 `<start>` 钩子里，
        而那个钩子只在免费版注册 —— 于是"已付费"的进程反而不受租约约束，
        吊销之后照跑（实测 15 秒没停）。租约是对**进程授权**的约束，
        跟"按调用计费"是两件事，不该绑在一起。
        """
        def loop() -> None:
            while True:
                time.sleep(interval)
                if not self.valid():
                    on_fail()
                    return

        threading.Thread(target=loop, name="python365-lease-guard", daemon=True).start()
