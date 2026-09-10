"""
从网络取时间的正确姿势 —— 以及它救不了什么。

实测结论：
  ① 明文 NTP：完全可伪造（见 exploits/x16_fake_ntp.py，617 天的差说改就改）
  ② HTTPS 的 Date 响应头：要伪造得先骗过 CA 体系（装本地根证书 / 劫持 TLS），成本高得多
  ③ 但只取时间仍然不够 —— 攻击者可以"取到合法时间后立刻断网"，之后用本地时钟慢慢干活
     → 所以还要加「高水位」：记住见过的最大时间，本地时钟一旦倒退就判定回拨
  ④ 最终形态不是问"现在几点"，而是问服务器"我的授权还有效吗"
     —— 要的是**服务器签名的授权状态**，那样连时间都不用信

注意：本脚本用 urllib（属于「网络版」¥199/月），所以在免费版下得原生跑。
     —— 产品内部做联网校时，代码必须放在被豁免的模块里（如 _license.py）。
"""
from __future__ import annotations

import email.utils
import json
import os
import time
import urllib.request

STAMP = "/tmp/.python365_clock"          # 高水位记录
TOLERANCE = 300                          # 容忍 5 分钟的时钟漂移/夏令时误差


def net_time_http(url: str = "https://example.com", timeout: float = 5.0):
    """从 HTTPS 响应头取时间。走 TLS ⇒ 伪造需要攻破 CA 体系，而不是伪造一个 UDP 包。"""
    req = urllib.request.Request(url, method="HEAD")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        date = resp.headers.get("Date")
    return email.utils.parsedate_to_datetime(date).timestamp(), f"HTTPS Date 头（{url}）"


def read_high_water() -> float:
    try:
        with open(STAMP) as fh:
            return float(json.load(fh)["seen"])
    except (OSError, ValueError, KeyError):
        return 0.0


def check_rollback(now: float, source: str) -> tuple[bool, str]:
    """本地时间一旦倒退到低于"见过的最大值"，就判定回拨 —— 离线也有效"""
    seen = read_high_water()
    if now + TOLERANCE < seen:
        return False, (f"检测到时钟回拨：当前 {time.strftime('%Y-%m-%d', time.gmtime(now))} "
                       f"< 高水位 {time.strftime('%Y-%m-%d', time.gmtime(seen))}")
    try:
        with open(STAMP, "w") as fh:
            json.dump({"seen": max(seen, now), "source": source, "at": time.time()}, fh)
    except OSError:
        pass
    return True, f"高水位已更新（来源：{source}）"


def main() -> None:
    local = time.time()
    print(f"① 本地时钟      : {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(local))} UTC")

    try:
        net, src = net_time_http()
        print(f"② 网络时间      : {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(net))} UTC "
              f"（{src}）")
        print(f"   本地与网络偏差: {local - net:+.1f} 秒")
    except Exception as exc:                                  # noqa: BLE001
        net, src = local, "本地时钟（网络不可达）"
        print(f"② 网络时间      : 取不到（{type(exc).__name__}）→ 回落本地时钟")

    print()
    print("③ 高水位防回拨（离线也能用）：")
    ok, why = check_rollback(net, src)
    print(f"   正常校验 → {'通过' if ok else '拒绝'} | {why}")

    fake = time.mktime(time.strptime("2025-01-01", "%Y-%m-%d"))   # 假装时钟被拨回 2025
    ok2, why2 = check_rollback(fake, "本地时钟")
    print(f"   本地时钟被拨到 2025 → {'通过' if ok2 else '拒绝'} | {why2}")

    print()
    print("④ 最终形态（不在本脚本里，需要厂商服务端）：")
    print("   别问'现在几点'，问'我的授权还有效吗' —— 拿服务器签名的授权状态，")
    print("   有效期由服务器给（比如 7 天），本地怎么改时钟都没用：签名伪造不了。")
    os.remove(STAMP) if os.path.exists(STAMP) else None


if __name__ == "__main__":
    main()
