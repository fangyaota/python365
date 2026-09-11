"""
授权 —— RSA 签名许可证。

客户端只内嵌**公钥**；伪造签名需要私钥，而私钥默认在 ~/.python365-vendor/（客户端目录树之外），
真实部署应放独立主机 / 独立 uid / HSM，或干脆只在服务端签名（见 _lease.py 与 vendor/authd.py）。
漏洞版本是 sum(ord(c)) % 10000 校验和 —— 读一眼源码就能算出企业版码。
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
import time

from ._tiers import TIERS

# ══════════════════════════════════════════════════════════════════════
#  可信时间 —— 让"拨回系统时钟"失效
# ══════════════════════════════════════════════════════════════════════
# 实测：明文 NTP 可以被伪造（测试里把时间拨走 617 天，
# 天真客户端照单全收），所以这里**只走 HTTPS 的 Date 响应头** —— 要伪造它
# 得先骗过 CA 体系，而不是伪造一个 UDP 包。
#
# 但单靠网络时间还不够：攻击者可以"取到合法时间后立刻断网"。所以再叠一层
# **高水位**：记下见过的最大时间，本地时钟一旦倒退就判定回拨。这层离线也有效，
# 是整个方案里性价比最高的部分。
#
# 三级来源取**最大值**：网络时间 / 高水位 / 本地时钟。取最大意味着"回拨无效" ——
# 攻击者把时钟拨回 2025，我们算出来的仍然是 2026。
_LOCAL_TIME = time.time          # 启动期缓存引用：防进程内 monkeypatch
_CLOCK_STAMP = "/tmp/.python365_clock"
_CLOCK_TOLERANCE = 300           # 容忍 5 分钟时钟漂移
_net_time: float | None = None
_net_source = "未取到"
_refresh_lock = threading.Lock()


def _high_water() -> float:
    try:
        with open(_CLOCK_STAMP) as fh:
            return float(json.load(fh)["seen"])
    except (OSError, ValueError, KeyError, TypeError):
        return 0.0


def _write_high_water(ts: float, source: str) -> None:
    try:
        with open(_CLOCK_STAMP, "w") as fh:
            json.dump({"seen": ts, "source": source, "at": _LOCAL_TIME()}, fh)
    except OSError:
        pass


def fetch_network_time(timeout: float = 5.0) -> tuple[float, str] | None:
    """
    只走 HTTPS。注意这里的 import 是"借用"了用户要花 ¥199/月 才能用的模块 ——
    本模块被监控豁免，所以厂商的校时代码可以白嫖自己的收费项。
    """
    try:
        import email.utils
        import urllib.request
        req = urllib.request.Request("https://example.com", method="HEAD")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            date = resp.headers.get("Date")
        if not date:
            return None
        return email.utils.parsedate_to_datetime(date).timestamp(), "HTTPS Date 头"
    except Exception:                                        # noqa: BLE001
        return None


def best_known_now() -> tuple[float, str]:
    """能给的最可信时间：网络时间 / 高水位 / 本地时钟，取最大"""
    local = _LOCAL_TIME()
    trust = max([t for t in (_net_time, _high_water()) if t] or [0.0])
    if trust and local + _CLOCK_TOLERANCE < trust:
        return trust, (f"检测到时钟回拨（本地 {time.strftime('%Y-%m-%d', time.gmtime(local))} "
                       f"< 可信 {time.strftime('%Y-%m-%d', time.gmtime(trust))}）")
    return max(local, trust), _net_source


def today() -> str:
    """给许可证到期日比较用（用可信时间，不是系统时钟）"""
    return time.strftime("%Y%m%d", time.gmtime(best_known_now()[0]))


def start_clock_watchdog(interval: float = 6 * 3600) -> None:
    """
    后台定期刷新网络时间 + 抬高水位。

    刻意**不在启动路径上联网**：那样每次启动都要等 DNS + TLS，没网就卡住。
    启动只用本地时钟 + 高水位（零延迟），心跳负责把水位慢慢抬上去。
    """
    def loop() -> None:
        global _net_time, _net_source
        while True:
            got = fetch_network_time()
            if got:
                with _refresh_lock:
                    _net_time, _net_source = got
                    _write_high_water(got[0], got[1])
            time.sleep(interval)

    threading.Thread(target=loop, name="python365-clock", daemon=True).start()

PUBLIC_KEY = (
    142941474762712786843892996419096218211714282571831346760677518336272116627156352088799937430545174289486324846523863179326485773510745922024700455257212453031325149402269393094513629679170934351429476456652260888046902592159936692461778873332553879829542426630233910309758763118190301952150864292860521530841,
    65537,
)

_owned: set[str] = set()
_shadow_owned: frozenset[str] = frozenset()     # 只由 set_owned 更新，运行期不再被读


def rsa_verify(payload: bytes, signature: bytes) -> bool:
    n, e = PUBLIC_KEY
    digest = int.from_bytes(hashlib.sha256(payload).digest()[:12], "big") % n
    return pow(int.from_bytes(signature, "big"), e, n) == digest


def parse_license(raw: str) -> tuple[set[str], list[str]]:
    """
    格式：PYTHON365.<b64(payload)>.<b64(signature)>，payload = "DATA,BASIC|20261010"

    三重校验：签名对不对（伪造不了）+ 许可证有没有过期 + 版本号是否已知。
    """
    owned: set[str] = set()
    invalid: list[str] = []
    for token in [t.strip() for t in (raw or "").split(",") if t.strip()]:
        try:
            head, payload_b64, sig_b64 = token.split(".")
            if head != "PYTHON365":
                raise ValueError("前缀不对")
            payload = base64.urlsafe_b64decode(payload_b64 + "==")
            signature = base64.urlsafe_b64decode(sig_b64 + "==")
        except Exception:                                # noqa: BLE001
            invalid.append(token[:24] + "…（格式错误）")
            continue
        if not rsa_verify(payload, signature):
            invalid.append(token[:24] + "…（签名无效）")
            continue
        try:
            tier_field, expiry = payload.decode().split("|")
        except Exception:                                # noqa: BLE001
            invalid.append(token[:24] + "…（载荷损坏）")
            continue
        # 到期判定用**可信时间**（网络时间 / 高水位 / 本地取最大）——
        # 拨回系统时钟不会让它复活
        if expiry < today():
            invalid.append(token[:24] + f"…（已于 {expiry} 过期）")
            continue
        codes = [c.strip().upper() for c in tier_field.split(",") if c.strip()]
        unknown = [c for c in codes if c not in TIERS]
        if unknown:
            invalid.append(token[:24] + f"…（未知版本 {unknown[0]}）")
            continue
        if "ENTERPRISE" in codes:
            owned |= set(TIERS)
        else:
            owned |= set(codes)
    return owned, invalid


def verify_topup(token: str) -> tuple[int, float] | None:
    """
    加油包令牌：`TOPUP|<次数>|<CPU 秒>|<到期日>`，和许可证同一把私钥签名。

    **客户端造不出来** —— 这才是"续费"该有的样子：凭据来自厂商。
    （第三轮 R3-6：早先 `python365.set_quota(free=10**9)` 就能自助充值，
      因为那是我为了演示加的脚手架，却挂在客户端公开 API 上。）
    """
    try:
        head, payload_b64, sig_b64 = token.strip().split(".")
        if head != "PYTHON365":
            return None
        payload = base64.urlsafe_b64decode(payload_b64 + "==")
        signature = base64.urlsafe_b64decode(sig_b64 + "==")
    except Exception:                                        # noqa: BLE001
        return None
    if not rsa_verify(payload, signature):
        return None
    try:
        kind, calls, seconds, expiry = payload.decode().split("|")
    except Exception:                                        # noqa: BLE001
        return None
    if kind != "TOPUP" or expiry < today():
        return None
    return int(calls), float(seconds)


def set_owned(codes: set[str]) -> None:
    global _owned, _shadow_owned
    _owned = set(codes)
    _shadow_owned = frozenset(codes)


def owns(code: str) -> bool:
    return code in _owned


def owned_tiers() -> set[str]:
    return set(_owned)


def owned_intact() -> bool:
    """
    授权表有没有被就地改过（`_owned.add("CORE")`）或被重新绑定。

    修掉审计缺口 A 的关键**不是**这个检查，而是把执法路径上的 `owns()` 全部提前到启动期：
      · 墙：启动期装好，改授权表拆不掉
      · import 闸门：启动期固化成一张只读表（_gate.freeze_blocked）
      · CORE 语法闸门：启动期固化成一个 bool（_meter.set_syntax_gate）
    于是运行期改 `_owned` **结构上无效** —— 它只影响横幅显示。
    这个检查是纵深防御：抓到有人在戳它，直接终止。
    """
    return _owned == _shadow_owned
