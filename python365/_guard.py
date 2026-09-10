"""
反篡改 —— 把计量做成"改不动"的，以及改不动时"至少知道"。

第三轮审计的教训：**判定链本身是可替换的模块全局，就等于锁芯在对手手里。**
所以这里所有判定函数都由 make_* 工厂在**启动期**构造，依赖全部作为参数绑进闭包；
运行期的模块字典里不再留下可替换的名字（`_guard.integrity_check = noop` 这种招式失效）。

机制清单：
  ① 冗余监控器（3 号工具位）：dowhen 用 4 号，拆掉 4 号时 3 号仍能同步报警
  ② 探针自测：调一次普通函数，看 tripwire 回调有没有响 —— 不依赖 monitoring API，
     所以那份 API 可以彻底删掉
  ③ 蜜罐：原位放一个假 sys.monitoring —— 直球调 API 的当场被抓
  ④ 句柄指纹：装墙时对 dowhen 内部注册表做快照，clear_all() 这种"清 dict 不设标志"
     的招数也能被发现
  ⑤ 内核兜底 RLIMIT_CPU：零事件的纯 C 运算只能靠内核杀

诚实声明：进程内反篡改只是**抬高门槛**，不是形成证明。对手把 3/4 号工具位一起拆、
再用 ctypes 抹掉闭包里的 cell，照样能绕。
"""
from __future__ import annotations

import hashlib
import os
import sys
import threading
import time

from . import _license, _meter, _ui

_MON = sys.monitoring
_MON_EVENTS = sys.monitoring.events
_MON_DISABLE = sys.monitoring.DISABLE      # 蜜罐要替真身伺候 dowhen 的运行时读取
_MON_MISSING = sys.monitoring.MISSING

TRIPWIRE_ID = 3
handlers: list = []                        # 所有注册过的 EventHandler（墙 + 计量钩子）
_EXIT = os._exit                           # 启动期缓存：`os._exit = noop` 不该能吃掉终止动作


def registry_snapshot() -> str:
    """
    监控注册表的**结构指纹**：每个 code object 下每个事件类型挂了哪些 handler 对象。

    ⚠️ R3-7 的指纹只记 `len(Instrumenter().handlers)`，也就是"有多少个 code object 被挂钩子"。
    但 `handlers[code]` 里面的列表是可以**原地清空**的 —— 键还在、长度不变、
    7117 道墙静默消失（第 21 号攻击）。只数个数等于没看。

    这里细到"每个 code 的每个 kind 的**对象 id**"：改列表内容会让 id 集合变化，
    而 id 偷换不了（活对象的 id 唯一）。
    """
    try:
        from dowhen.instrumenter import Instrumenter
        table = Instrumenter().handlers
    except Exception:                                        # noqa: BLE001
        return ""
    parts = []
    for code, kinds in table.items():
        cid = id(code)
        if not isinstance(kinds, dict):
            parts.append(f"{cid}:{type(kinds).__name__}")
            continue
        for kind, val in kinds.items():
            if isinstance(val, list):
                parts.append(f"{cid}.{kind}:" + ",".join(str(id(x)) for x in val))
            elif isinstance(val, dict):                      # line 事件：{行号: [handler]}
                inner = ",".join(f"{k}={len(v) if hasattr(v, '__len__') else 1}"
                                 for k, v in val.items())
                parts.append(f"{cid}.{kind}:{inner}")
            else:
                parts.append(f"{cid}.{kind}:{type(val).__name__}")
    return hashlib.sha1("|".join(sorted(parts)).encode()).hexdigest()


def _dowhen_registry_size() -> int:
    """dowhen 内部注册表里还有多少条记录 —— clear_all() 会把它清空"""
    try:
        from dowhen.instrumenter import Instrumenter
        return len(Instrumenter().handlers)
    except Exception:                                        # noqa: BLE001
        return -1


# ══════════════════════════════════════════════════════════════════════
#  判定器工厂：启动期把依赖焊进闭包
# ══════════════════════════════════════════════════════════════════════
def make_checker(*, shadow_ok, owned_intact, handlers_list, expected_registry, high_water,
                 registry_size=_dowhen_registry_size, high_water_of=None, net_time_of=None,
                 alarm=_ui.box, terminate=_EXIT,
                 expected_snapshot=None, snapshot_of=registry_snapshot):
    """
    造一个"完整性判定器"。**所有依赖都是参数** —— 运行期改 `_guard.xxx` 改不到它。

    第四轮 R4-05 的教训：闭包里还漏了 `os` / `_ui` / `_dowhen_registry_size` 三个模块全局，
    于是 `g.os = FakeOS()` 就能把"终止服务"吃掉 —— 检测响了 8 次，进程照样活着。
    现在退出函数、报警函数、指纹函数、时间水位全部从参数来。

    deep=False：额度影子值 + 授权表（便宜，50ms 一次）
    deep=True ：另外全量复查句柄列表 + dowhen 注册表指纹 + 时间高水位（贵，2 秒一次）
    """
    def check(deep: bool = False, extra: str | None = None) -> None:
        problems = [extra] if extra else []
        if not shadow_ok():
            problems.append("额度常量被篡改")
        if not owned_intact():
            problems.append("授权表被篡改")
        if deep:
            for handler in handlers_list:
                if getattr(handler, "removed", False) or getattr(handler, "disabled", False):
                    problems.append("付费墙钩子被摘除")
                    break
            # clear_all() 直接清 dowhen 内部 dict、**不设任何标志** —— 只查标志会漏
            current = registry_size()
            if current != -1 and current < expected_registry:
                problems.append(f"监控注册表被清空（{expected_registry} → {current}）")
            if expected_snapshot is not None:
                # 只比个数是不够的：原地清空 handlers[code]["start"] 时个数一点没变
                if snapshot_of() != expected_snapshot:
                    problems.append("监控注册表结构被改动（有墙被静默摘除）")
            if high_water_of is not None:
                seen = high_water_of()
                if seen < high_water[0] - 1:
                    problems.append("时间高水位被篡改（回拨检测被绕过）")
                high_water[0] = max(high_water[0], seen,
                                    (net_time_of() if net_time_of else 0.0) or 0.0)
        if problems:
            alarm("🚨 检测到篡改，Python 365 已终止服务",
                  [" · ".join(problems),
                   "请勿修改计量组件，或升级到企业版获取可审计的运行时"])
            terminate(1)
    return check


def make_probe(*, check, marker):
    """
    造一个"监控是否还活着"的探针。

    调一次普通过滤函数，看 tripwire 回调有没有把 marker 加一。
    **不碰 sys.monitoring API** —— 这是能把那份 API 彻底删掉的前提。
    """
    counter = {"seen": 0}

    def target() -> None:
        return None

    def hit(code=None, offset=None) -> None:
        counter["seen"] += 1
        marker[0] += 1
        check()

    def probe() -> bool:
        before = counter["seen"]
        target()
        return counter["seen"] > before

    return probe, hit, target


def make_import_wall_hook(on_import):
    """
    惰性铺墙的入口钩子：模块被**真正加载**的那一刻补墙。

    ⚠️ 挂的是 `_find_and_load(name, import_)`，**不是 `_gcd_import`** ——
    实测（CPython 3.12）：单个 `_gcd_import` 钩子对 `import xml.dom.minidom` **0 命中**，
    而 `_find_and_load` 10 次、`_call_with_frames_removed` 22 次。
    `_gcd_import` 只在 `importlib.import_module` 那条路上被调用；语句式 `import`
    走的是 C 里的 `__import__` → `_find_and_load`。

    （这条也是我第三轮埋下的死代码：那次"闸门三层"里的 `_gcd_import` 层从未生效，
    真正拦住 `import math` 的是另外两层 —— 我当时只验证了结果，没验证每一层。）
    """
    def hook(name=None, import_=None):
        on_import(name)
    return hook


def start_watchdog(check, probe) -> None:
    """快循环用探针自测事件是否还在；慢循环（2s）全量复查"""
    def loop() -> None:
        tick = 0
        while True:
            time.sleep(0.05)
            tick += 1
            if tick % 40 == 0:
                check(deep=True)
            if not probe():
                check(extra="监控事件被静默关闭（探针自测失败）")

    threading.Thread(target=loop, name="python365-guard", daemon=True).start()


def arm_tripwire(hit) -> str:
    """占用 3 号工具位，给监控体系加一条冗余命脉"""
    try:
        _MON.use_tool_id(TRIPWIRE_ID, "python365-tripwire")
        _MON.register_callback(TRIPWIRE_ID, _MON_EVENTS.PY_START, hit)
        _MON.set_events(TRIPWIRE_ID, _MON_EVENTS.PY_START)
        return "冗余监控器（3 号工具位）已启用"
    except Exception as exc:                                # noqa: BLE001
        return f"冗余监控器不可用：{type(exc).__name__}"


# ══════════════════════════════════════════════════════════════════════
#  蜜罐与拆武器
# ══════════════════════════════════════════════════════════════════════
def make_honeypot(check):
    """
    顶替真 sys.monitoring 的位置：读操作给"一切正常"的假象，写操作当场判定篡改。

    ⚠️ dowhen 的 _process_handlers 每次回调都要读 DISABLE，蜜罐必须先伺候好它。
    """
    class _Honeypot:
        _WRITE = ("set_events", "set_local_events", "use_tool_id", "free_tool_id",
                  "register_callback", "restart_events")

        def __getattr__(self, attr):
            if attr == "DISABLE":
                return _MON_DISABLE
            if attr == "MISSING":
                return _MON_MISSING
            if attr in self._WRITE:
                def trap(*_a, **_kw):
                    check(extra=f"有人调用 sys.monitoring.{attr}（踩到蜜罐）")
                return trap
            if attr == "get_events":
                return lambda tool_id: 5
            if attr == "get_tool":
                return lambda tool_id: "dowhen instrumenter"
            if attr == "events":
                return _MON_EVENTS
            raise AttributeError(attr)

    return _Honeypot()


def disarm_attack_surface(check) -> str:
    """
    拆掉对手用来关掉我们的那些 API。实测：
      · sys.monitoring **不在 sys.modules 里** → del 之后不可重新 import
      · 但只要还有引用活着，gc.get_objects() 就翻得出来 → 所以改用探针自测，
        从此不持有 monitoring API 的引用（删完自检，gc 里无残留）
      · 对比：del os.urandom 会连带炸掉 import random（手术刀误伤标准库）
      · 只能在**所有装配完成之后**调用：dowhen 每装一道墙都要读 get_local_events
    """
    global _MON
    # ⚠️ 顺序很要命：蜜罐必须**先造好**。
    #    `del sys.monitoring` 之后、重新赋值之前，任何一次 Python 函数调用都会让
    #    dowhen 的回调炸掉 —— 它在 _process_handlers 里**每次都要读**
    #    sys.monitoring.DISABLE。（早先版本能跑，是因为蜜罐是个无 __init__ 的类，
    #    实例化不产生 Python 栈帧；改工厂函数之后 `make_honeypot(check)` 是实打实的
    #    函数调用，于是启动直接 fatal。）
    honeypot = make_honeypot(check)
    _MON = None
    try:
        del sys.monitoring
        removed = "sys.monitoring 已删除（不在 sys.modules 里，无法重新 import）"
    except AttributeError:
        removed = "sys.monitoring 已不存在"
    sys.monitoring = honeypot          # 纯赋值：不产生任何函数调用，安全
    import gc
    gc.collect()
    left = sum(1 for o in gc.get_objects()
               if getattr(o, "__name__", "") == "sys.monitoring")
    tail = (f"（gc 里仍有 {left} 个残留引用 —— 绑定方法各自抱着 __self__）"
            if left else "（gc 里已无残留引用）")
    return f"{removed} · 原位留了蜜罐 · {tail}"


# ══════════════════════════════════════════════════════════════════════
#  内核兜底与 fork
# ══════════════════════════════════════════════════════════════════════
def arm_kernel_limit(cpu_quota: float) -> str:
    """
    RLIMIT_CPU。soft == hard，进程自己**无法**再把它抬高
    （抬高需要硬上限有余量）；子进程也继承这份限制。
    第三轮被独立验证过：容器里即便 root 也丢了 CAP_SYS_RESOURCE，抬高直接报
    `ValueError: not allowed to raise maximum limit`。
    """
    try:
        import resource
        limit = int(cpu_quota) + 3
        resource.setrlimit(resource.RLIMIT_CPU, (limit, limit))
        return f"内核 RLIMIT_CPU = {limit}s（soft==hard，进程内抬不起来）"
    except Exception as exc:                                # noqa: BLE001
        return f"内核兜底不可用：{type(exc).__name__}"


def register_fork_guard(handler) -> None:
    """
    fork 不复制线程，子进程里的电表是死的 —— 所以子进程里要重挂。

    实际动作由计费账户提供（`account.rearm_after_fork`）：额度、用量、内核限额
    都在那个闭包里，这里只负责挂上去。
    """
    os.register_at_fork(after_in_child=handler)


def registry_size() -> int:
    """给装配流程做指纹快照用"""
    return _dowhen_registry_size()
