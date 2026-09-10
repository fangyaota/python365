"""
双层计费与断供。

  ① 函数调用次数：dowhen 全局 <start> 事件，每调用记一笔
  ② CPU 时间    ：后台心跳线程采样（三源取最大，见 process_cpu）

断供点是 <start> 和 <return> 两个全局事件 —— 超支后在下一个 Python 边界抛异常。

⚠️ 第三轮审计的教训（R3-3/R3-4/R3-5）：**额度、用量、动作如果都是模块级全局，
  就等于把锁芯交给对手** —— `_state["calls"] = -10**9`、`_syntax_gate = False`、
  `on_tamper = noop` 三行就能让整套计费失效。

  所以真实状态与执法动作全部装进 make_account() 造出来的**闭包**里；
  模块级只留人类可见的只读视图（usage/quota），改它们影响不到执法。
  执法动作（paywall/quota_wall/cpu_wall）另外用**默认参数**绑进各个闭包，
  换掉模块级的同名函数也没用。
"""
from __future__ import annotations

import email.utils  # noqa: F401  （下面的话术里要用到时间格式，保持导入一致性）
import os
import sys
import threading
import time
from types import SimpleNamespace

from . import _license, _ui
from ._tiers import TIERS, key_for

# ── 免费版策略（初始值；运行期的真实额度在账户闭包里）─────────────────
FREE_QUOTA = 50000          # 第 1 层：每月 5 万次函数调用
CPU_QUOTA = 3.0             # 第 2 层：每月 3.0 秒 CPU 时间（抓 C 层运算）
AD_RATIO = 10               # 广告频率：每用掉 1/10 额度插一条
TRIAL_DAYS = 30
CPU_SAMPLE_INTERVAL = 0.02  # 心跳 50Hz（实测 100Hz 的线程唤醒开销约 0.8%，
#                             而唤醒开销也会被 time.process_time() 记到用户账上）

TOOL_ID = 4                 # dowhen 占用的 sys.monitoring 工具位
TRIPWIRE_ID = 3             # 我们自己的冗余监控器（0/1/2/5 是 CPython 预留）

# 第 2 层为什么必须靠外部采样：sum(range(10**8)) 是一次 C 调用，1678ms CPU、
# 0 个函数事件、0 个行事件，任何"事件驱动"的计量都看不见它。
_PROCESS_TIME = time.process_time          # 启动期缓存：防进程内 monkeypatch
_CLOCK_GETTIME = time.clock_gettime
_CLOCK_CPUTIME = time.CLOCK_PROCESS_CPUTIME_ID
_EXIT = os._exit                           # 同理：os._exit = noop 不该能吃掉终止动作
import tempfile as _tempfile               # noqa: E402  导入期取好（避免运行时撞 ¥79 的闸门）
_GETTEMP = _tempfile.gettempdir

_ADS = (
    "Python 365 全模块年付版低至 6 折 —— 一次买断 52 个标准库",
    "加购「数据版」，让 json.dumps 重新属于你",
    "企业版专享：标准库不限量，附赠 GIL 独享权",
    "检测到您正在手写 CSV 解析器，考虑加购数据版",
    "免费版不提供 try/except 退款服务",
)


class SubscriptionRequired(Exception):
    """付费墙异常 —— 未订阅的模块/语法被调用时抛出。"""


# ══════════════════════════════════════════════════════════════════════
#  CPU 电表（三源）
# ══════════════════════════════════════════════════════════════════════
def process_cpu() -> float:
    """
    三源取 CPU 时间，取较大者 —— 打桩其中一个源没有意义。

      · os.times()：四个字段，含**子进程**的 CPU（fork 出去烧的也算父进程账上）
      · clock_gettime(CLOCK_PROCESS_CPUTIME_ID)：独立于 time.process_time 的 API
      · time.process_time：交叉校验的第三方
    """
    t = os.times()
    from_os = t.user + t.system + t.children_user + t.children_system
    try:
        from_clock = _CLOCK_GETTIME(_CLOCK_CPUTIME)
    except Exception:                                    # noqa: BLE001
        from_clock = 0.0
    return max(from_os, from_clock, _PROCESS_TIME())


# ══════════════════════════════════════════════════════════════════════
#  断供话术（执法动作，会被默认参数绑进闭包）
# ══════════════════════════════════════════════════════════════════════
def paywall(feature: str, code: str, detail: str) -> None:
    name, price, blurb, _ = TIERS[code]
    _ui.box(f"⛔ 需要订阅：{feature}",
            [f"该功能属于「{name} {code}」¥{price}/月 —— {blurb}",
             detail,
             f"{_ui.GOLD}加购：{key_for(code)}{_ui.R}   ← 签名许可证，伪造需要厂商私钥"])
    raise SubscriptionRequired(feature)


def quota_wall(limit: int, used: int) -> None:
    _ui.box(f"⛔ 免费版额度已用完：{limit} 次函数调用/月",
            [f"本周期已调用 {used} 次，超出 {used - limit} 次",
             "解除方式：任意付费版本（最低「基础版 BASIC」¥19/月）",
             f"{_ui.GOLD}加购：{key_for('BASIC')}{_ui.R}"])
    raise SubscriptionRequired(f"函数调用额度（{limit} 次/月）")


def cpu_wall(limit: float, used: float) -> None:
    over = (used / limit - 1) * 100
    _ui.box("⛔ 需要订阅：CPU 时间额度",
            [f"免费版每月 {limit:.1f} 秒 CPU 时间，已用 {used:.3f} 秒（超支 {over:.0f}%）",
             "提示：把计算塞进 C 层内置操作可以绕过「调用次数」计费，",
             "　　　但绕不过时间计量 —— 这是第二层存在的意义",
             f"{_ui.GOLD}加购：{key_for('BASIC')}{_ui.R}"])
    raise SubscriptionRequired(f"CPU 时间额度（{limit:.1f} 秒/月）")


# ══════════════════════════════════════════════════════════════════════
#  计费账户 —— 状态与执法动作都住在闭包里
# ══════════════════════════════════════════════════════════════════════
def make_account(*, free_quota: int, cpu_quota: float, syntax_gate: bool, trust,
                 tamper=None, verify_topup=None, owned_intact=None,
                 lease_check=None, lease_fail=None,
                 paywall=paywall, quota_wall=quota_wall, cpu_wall=cpu_wall,
                 ads=_ADS, ad_ratio: int = AD_RATIO,
                 interval: float = CPU_SAMPLE_INTERVAL,
                 exit_fn=_EXIT, cpu_clock=process_cpu):
    """
    造一个计费账户。返回的命名空间里有：

      · hook_call / hook_return  —— 注册给 dowhen 的两个全局回调
      · usage / quota / shadow_ok / set_quota / topup —— 只读视图与官方续费口
      · start_meter / rearm_after_fork —— 心跳线程
      · state —— 仅供 _guard 的 fork 处理器与横幅读取（改它不影响执法）

    关键点（第四轮 R4-03 之后）：
      · 额度与用量在这一层，模块级的 FREE_QUOTA 只是初始值（改它没人读）
      · `busy` 标志、用量单调高水位都在闭包里
      · 话术函数、身份判定（trust）、验签函数、退出函数全部用**默认参数**绑定
      · **不再导出 `state` / `busy_state` / `bind_checker`** —— 早先它们把内部状态
        整份交了出去：`acct.state["free"] = acct.state["shadow_free"] = 10**9` 双写即可
        让影子值自洽；`busy_state["busy"] = True` 还能卡死整个计量。
      · 续费只在**这里**做：`apply_topup(token)` 内部验签，`renew` 不外露。
    """
    def _tamper(extra=None):
        if tamper is not None:
            tamper(extra=extra)

    def _owned_ok() -> bool:
        return owned_intact() if owned_intact else True

    st = {"free": float(free_quota), "cpu_quota": float(cpu_quota),
          "shadow_free": float(free_quota), "shadow_cpu": float(cpu_quota),
          "calls": 0, "cpu": 0.0, "exceeded": None, "forks": 0}
    inner = {"busy": False, "seen_calls": 0, "seen_cpu": 0.0}

    # ── 只读视图与官方口子 ────────────────────────────────────────────
    def quota() -> int:
        return int(st["free"])

    def shadow_ok() -> bool:
        return st["free"] == st["shadow_free"] and st["cpu_quota"] == st["shadow_cpu"]

    def usage() -> dict:
        return {"calls": st["calls"], "cpu": st["cpu"],
                "free_quota": int(st["free"]), "cpu_quota": st["cpu_quota"],
                "calls_left": max(0, int(st["free"]) - st["calls"]),
                "cpu_left": max(0.0, st["cpu_quota"] - st["cpu"]),
                "exceeded": st["exceeded"]}

    def set_quota(free: int | None = None, cpu: float | None = None) -> None:
        if free is not None:
            st["free"] = float(free)
            st["shadow_free"] = float(free)
        if cpu is not None:
            st["cpu_quota"] = float(cpu)
            st["shadow_cpu"] = float(cpu)

    def apply_topup(token: str) -> bool:
        """
        续费：**验过厂商签名令牌**才改额度。令牌由 `vendor/issue.py --topup` 签发，
        客户端只有公钥 ⇒ 造不出额度（第三轮 R3-6 / 第四轮 R4-07）。

        新额度设成「当前用量 + 新增」：否则用量仍高于额度，下一次心跳采样会立刻
        把 exceeded 又置上 —— 用户刚充完值就再次断供。
        """
        got = verify_topup(token) if verify_topup else None
        if not got:
            return False
        calls, seconds = got
        set_quota(free=st["calls"] + calls, cpu=st["cpu"] + seconds)
        st["exceeded"] = None
        return True

    # ── 电表 ─────────────────────────────────────────────────────────
    def meter_loop() -> None:
        last = cpu_clock()          # 三源时钟，启动期已绑
        while True:
            time.sleep(interval)
            now = cpu_clock()
            st["cpu"] += now - last
            last = now
            if st["exceeded"] is None and st["cpu"] > st["cpu_quota"]:
                st["exceeded"] = "cpu"

    def start_meter() -> None:
        threading.Thread(target=meter_loop, name="python365-meter",
                         daemon=True).start()

    def rearm_after_fork() -> None:
        used = st["cpu"]
        st["exceeded"] = None
        st["cpu"] = 0.0
        st["forks"] += 1
        if st["forks"] > 3:
            exit_fn(1)              # 启动期缓存的 os._exit（防 os._exit = noop）
        try:
            import resource
            remaining = max(1, int(st["cpu_quota"] - used))
            resource.setrlimit(resource.RLIMIT_CPU, (remaining, remaining))
        except Exception:                                   # noqa: BLE001
            pass
        start_meter()

    # ── 两个全局回调（判定与依赖全在闭包里）──────────────────────────
    # 身份判定用 trust（闭包命名空间），不走 _trust 的模块字典
    def hook_call() -> None:
        if inner["busy"]:
            return
        inner["busy"] = True
        try:
            if not shadow_ok() or not _owned_ok():
                _tamper()
            # 租约模式：授权档由服务端决定，租约失效即停机（fail-closed，
            # 和反篡改一个待遇）。lease_check 只读缓存，不做 I/O。
            if lease_check is not None and not lease_check():
                lease_fail()
            if st["calls"] < inner["seen_calls"] or st["cpu"] < inner["seen_cpu"]:
                _tamper(extra="用量计数器被回退")
            inner["seen_calls"] = st["calls"]
            inner["seen_cpu"] = st["cpu"]

            f = trust.user_frame()
            if f is None or trust.is_internal_frame(f):
                return
            code = f.f_code
            level = trust.trust_level(f)
            if level == 1:
                return
            if level == 2 and not trust.chain_has_user(f):
                return
            if st["exceeded"] == "cpu":
                cpu_wall(st["cpu_quota"], st["cpu"])
            if syntax_gate and level == 0:       # ← 启动期定的 bool，不在模块字典里
                if code.co_name == "<lambda>":
                    paywall("λ 匿名函数", "CORE", "语言特性按版本收费")
                if code.co_flags & (0x20 | 0x200):   # CO_GENERATOR | CO_ASYNC_GENERATOR
                    paywall("生成器 yield / async", "CORE", "语言特性按版本收费")

            st["calls"] += 1
            n = st["calls"]
            every = max(1, int(st["free"]) // ad_ratio)
            if n % every == 0:
                _ui.ad(ads[(n // every - 1) % len(ads)])
            if n > st["free"]:
                quota_wall(int(st["free"]), n)
        finally:
            inner["busy"] = False

    def hook_return() -> None:
        if st["exceeded"] is None:
            return
        f = trust.user_frame()
        if f is None or trust.is_internal_frame(f):
            return
        level = trust.trust_level(f)
        if level == 0 or (level == 2 and trust.chain_has_user(f)):
            cpu_wall(st["cpu_quota"], st["cpu"])

    # 只导出函数：没有 state / busy_state / renew / bind_checker 可供就地改写
    return SimpleNamespace(
        hook_call=hook_call, hook_return=hook_return,
        quota=quota, shadow_ok=shadow_ok, usage=usage,
        apply_topup=apply_topup,
        start_meter=start_meter, rearm_after_fork=rearm_after_fork,
        cpu_quota=lambda: st["cpu_quota"],
    )


# ══════════════════════════════════════════════════════════════════════
#  模块级只读视图（给演示脚本、横幅、_guard 用；改它们不影响执法）
# ══════════════════════════════════════════════════════════════════════
ACCOUNT = None          # 由 install() 装配


def usage() -> dict:
    return ACCOUNT.usage() if ACCOUNT else {}


def quota() -> int:
    return ACCOUNT.quota() if ACCOUNT else FREE_QUOTA


def apply_topup(token: str) -> bool:
    """续费入口（内部验签，客户端造不出额度）"""
    return ACCOUNT.apply_topup(token) if ACCOUNT else False


def start_watchdog() -> None:
    if ACCOUNT:
        ACCOUNT.start_meter()


def trial_days_left() -> int:
    """
    试用期倒计时（时间戳存在 /tmp，删掉即可"重置试用期"）。

    ⚠️ tempfile 在模块导入期就取好 —— 早先在函数里 `import tempfile`，
    而 `tempfile` 属于「系统版 ¥79」，闸门开启时会撞客户自己的墙，
    site 把 sitecustomize 的异常一吞，横幅和统计静默丢失（第四轮 R4-08）。
    """
    stamp = os.path.join(_GETTEMP(), ".python365_install")
    try:
        with open(stamp) as fh:
            first = float(fh.read().strip())
    except (OSError, ValueError):
        first = time.time()
        try:
            with open(stamp, "w") as fh:
                fh.write(str(first))
        except OSError:
            pass
    return TRIAL_DAYS - int((time.time() - first) // 86400)
