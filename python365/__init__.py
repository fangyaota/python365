"""
Python 365 —— 把 CPython 爆改成分级订阅制运行时
================================================

纯娱乐/教学实现。用 dowhen 在解释器启动时把付费墙挂到语言和标准库上：
不改 Python 源码，不改你的程序，一个字节都不动。

用法
----
    # 免费版（任何程序一启动就上锁）
    PYTHONPATH=/workspace/python365 python3 你的程序.py

    # 加购（许可证由 vendor/issue.py 用私钥签发，客户端只有公钥，伪造不了）
    PYTHON365_KEY='PYTHON365.xxx.yyy' PYTHONPATH=/workspace/python365 python3 你的程序.py

模块地图
--------
    _tiers    定价表（唯一的事实来源）
    _trust    身份验真（"这一帧到底是谁"）—— 整套系统的地基
    _meter    双层计费（调用次数 + CPU 时间）、断供话术、广告
    _walls    付费墙本体（dowhen 模块墙 / C 包装层 / 随机数降级）
    _guard    反篡改（冗余监控器 / 探针自测 / 蜜罐 / 内核兜底 / fork）
    _gate     import 闸门（三层，默认关闭）
    _license  RSA 签名许可证
    _ui       终端输出

装配顺序踩过的坑（改 install() 前必读）
--------------------------------------
    1. dowhen 每装一道墙都要读 sys.monitoring.get_local_events
       → 拆 API（disarm）必须放在**所有装配完成之后**
    2. 全局事件一开，CPython 要为进程里所有 code object 做插桩（实测 0.26s CPU）
       → 心跳线程要在装配完成后才启动，否则启动开销会算到用户头上
    3. 蜜罐必须先伺候好 sys.monitoring.DISABLE，否则 dowhen 每次回调都会炸
"""
from __future__ import annotations

from . import _license
from ._license import owned_tiers, parse_license
from ._meter import (CPU_QUOTA, FREE_QUOTA, SubscriptionRequired, quota,
                     trial_days_left, usage)
from ._tiers import TIERS
from . import _gate, _guard, _meter, _walls

__version__ = "3.0"

_installed = False
_notes: dict[str, str] = {}


def installed() -> bool:
    """这个进程里付费墙装配好了吗（演示脚本用它区分"原生跑"和"被计费跑"）"""
    return _installed


def stats() -> dict:
    """装配统计（演示脚本用）"""
    return {**_walls.stats(), "notes": dict(_notes), "installed": _installed,
            "owned": sorted(owned_tiers())}


def install() -> None:
    """
    装配整套订阅制运行时。幂等。

    这一版的中心思想（第三轮审计后）：**执法决策不进模块字典** ——
    身份判定只认代码对象身份，额度/用量/动作住在计费账户闭包里，
    判定器与探针由工厂在启动期构造、依赖全部参数化。
    于是 `__name__ = "python365.fake"`、`_syntax_gate = False`、
    `on_tamper = noop`、`_state["calls"] = -10**9` 这些招式在结构上失效。
    """
    global _installed
    if _installed:
        return
    _installed = True

    import os
    from dowhen import when
    from . import _trust, _ui
    from ._license import owns, set_owned

    # ⓪ 授权
    owned, invalid = parse_license(os.environ.get("PYTHON365_KEY", ""))
    set_owned(owned)
    for bad in invalid:
        print(f"{_ui.RED}⚠️  激活码无效：{bad}（已忽略）{_ui.R}")
    free_tier = not owned

    # ① 身份判定：holder 装代码对象 id，build 出来的判定器全部闭包持有它。
    #
    # ⚠️ 收集之前必须把**我们自己的所有子模块**都导入一遍。
    # 它们是懒加载的（比如 `_lease` 只在租约模式才 import），而集合是启动期快照 ——
    # 之后才被导入的子模块，其栈帧不会被认作"自己人"，于是它在模块级碰任何标准库
    # 都会被当成用户代码收税（实测：`os.environ.get` 撞上「基础版 · collections.abc」）。
    # 这是第三轮 `dowhen.handler` 那个坑的同一族问题：**清单必须覆盖所有自己人。**
    import importlib as _importlib
    for _sub in ("_tiers", "_trust", "_license", "_ui", "_meter", "_walls",
                 "_guard", "_gate", "_lease"):
        _importlib.import_module(f"{__name__}.{_sub}")

    id_holder = _trust.new_holder()
    id_holder.update(_trust.collect_internal_objects())
    trust = _trust.build(id_holder)

    # ② 租约模式（PYTHON365_LEASE_SERVER 打开）：授权档改由**服务端**决定
    keeper = None
    lease_server = os.environ.get("PYTHON365_LEASE_SERVER")
    if lease_server:
        from . import _lease
        keeper = _lease.LeaseKeeper(lease_server,
                                    license_token=os.environ.get("PYTHON365_KEY"))
        # ⚠️ 关键：租约模式下**静态许可证不发授权档**。
        #    许可证只是"激活凭据"，授权档一律以服务端返回的租约为准 ——
        #    否则不启动服务端 / 掐掉网络就能拿回全部权益，在线仲裁形同虚设。
        #    （这正是"客户端自己说了算"的老毛病：本地能验的东西就不算凭据。）
        owned = set()
        if keeper.tiers():
            owned = {t for t in keeper.tiers() if t in TIERS}
            if "ENTERPRISE" in keeper.tiers():
                owned = set(TIERS)
        set_owned(owned)
        if not keeper.valid():
            keeper.activate()                    # 拿许可证去服务端激活
            if keeper.tiers():
                owned = {t for t in keeper.tiers() if t in TIERS}
                if "ENTERPRISE" in keeper.tiers():
                    owned = set(TIERS)
                set_owned(owned)
        if owned:
            keeper.start()                       # 后台续签
        free_tier = not owned
        _notes["lease"] = (f"租约模式：{lease_server} · 指纹 {keeper.fp} · "
                           f"{'有效' if keeper.valid() else '无效（' + keeper.why() + '）'}")

    # ②' 有许可证才需要校时（免费版没有到期日，省掉线程与网络）
    if owned:
        _license.start_clock_watchdog()

    # ③ 计费账户：额度、用量、身份判定、验签、退出函数全部注入
    holder: dict = {}                       # 只在 install 局部存在，放判定器

    def tamper(extra=None):
        fn = holder.get("check")
        if fn is not None:
            fn(extra=extra)

    def lease_fail():
        """租约失效 → fail-closed（跟反篡改一个待遇，但话术不同）"""
        _ui.box("⛔ 授权租约失效，服务已停机",
                [f"原因：{keeper.why()}" if keeper else "原因：未知",
                 "请检查设备绑定 / 许可证是否被吊销 / 网络是否可达",
                 "续签成功即可恢复（本进程需重启）"])
        _guard._EXIT(1)

    # 租约闸门：独立于计费钩子 —— 付费模式不注册计费钩子，
    # 但租约必须照样管（否则"已付费"进程反而不受吊销约束）
    if keeper is not None:
        keeper.guard(lease_fail)

    account = _meter.make_account(free_quota=_meter.FREE_QUOTA,
                                  cpu_quota=_meter.CPU_QUOTA,
                                  syntax_gate=not _license.owns("CORE"),
                                  trust=trust, tamper=tamper,
                                  verify_topup=_license.verify_topup,
                                  owned_intact=_license.owned_intact,
                                  lease_check=(keeper.valid if keeper else None),
                                  lease_fail=lease_fail)
    _meter.ACCOUNT = account

    # ④ 付费墙 + C 包装层（身份判定同样注入）
    _walls.install_walls(trust)
    _walls.install_c_shims(trust)

    # ⑤ 装完墙了，dowhen 的懒加载子模块（handler 等）都进了 sys.modules → 更新集合。
    #    漏掉这一步会让走栈在第一帧就"撞回监控机制"而放行所有墙（第三轮踩过）。
    id_holder.update(_trust.collect_internal_objects())

    # ⑥ 反篡改判定器与探针：工厂构造，依赖作为参数绑进闭包
    checker = _guard.make_checker(shadow_ok=account.shadow_ok,
                                  owned_intact=_license.owned_intact,
                                  handlers_list=_guard.handlers,
                                  expected_registry=_guard.registry_size(),
                                  high_water=[0.0],
                                  high_water_of=_license._high_water,
                                  net_time_of=lambda: _license._net_time)
    holder["check"] = checker
    probe, tripwire_hit, _ = _guard.make_probe(check=checker, marker=[0])

    # ⑦ 惰性补墙：模块被 import 的那一刻铺墙（装配期快照必然漏子模块，第四轮 R4-07）
    if any(not owns(code) for code in TIERS if code != "CORE"):
        from importlib import _bootstrap as _bootstrap
        # 挂 _find_and_load（语句式 import 真正会调用的那个），不是 _gcd_import
        _guard.handlers.append(
            when(_bootstrap._find_and_load, "<start>")
            .do(_guard.make_import_wall_hook(_walls.make_lazy_installer(trust))))

    # ⑧ 计量与加固（免费版专属）
    if free_tier:
        # 实测 CPU 分解：装墙 0.35s + 启用全局事件 0.26s（CPython 要为进程里所有
        # code object 做插桩，跟回调写得多快无关）。这笔账记在用户头上。
        _guard.handlers.append(when(None, "<start>").do(account.hook_call))
        _guard.handlers.append(when(None, "<return>").do(account.hook_return))
        account.start_meter()
        _guard.start_watchdog(checker, probe)
        _notes["tripwire"] = _guard.arm_tripwire(tripwire_hit)
        _guard.register_fork_guard(account.rearm_after_fork)
        _notes["kernel"] = _guard.arm_kernel_limit(account.cpu_quota())

    # ⑨ 随机数降级（在所有装配完成之前）
    _walls.install_random_walls(trust)

    # ⑩ import 闸门（默认关闭）
    _notes["gate"] = (_gate.install_import_gate(trust) if _gate_enabled()
                      else "未启用（PYTHON365_IMPORT_GATE=1 打开）")

    # ⑪ 拆掉对手的武器 —— 必须最后（dowhen 每装一道墙都要读 monitoring API）
    if free_tier:
        _notes["disarm"] = _guard.disarm_attack_surface(checker)
    else:
        _notes["disarm"] = "企业版：API 保持原样（不做反篡改）"

    _banner(free_tier)


def _gate_enabled() -> bool:
    import os
    return os.environ.get("PYTHON365_IMPORT_GATE") == "1"


def _banner(free_tier: bool) -> None:
    from . import _ui
    total = len(TIERS)
    owned = owned_tiers()
    if owned:
        names = " + ".join(TIERS[c][0] for c in TIERS if c in owned)
        head = f"{_ui.GOLD}● Python 365 已激活{_ui.R}  {_ui.DIM}{names}{_ui.R}"
        meter = (f"函数调用 ∞ 次 · CPU 时间 ∞ 秒 · "
                 f"已解锁 {len(owned)}/{total} 个版本")
        boot = ""
    else:
        u = _meter.usage()
        head = (f"{_ui.RED}○ Python 365 免费版{_ui.R}  "
                f"{_ui.DIM}试用期还剩 {trial_days_left()} 天{_ui.R}")
        meter = (f"①函数调用 {u.get('calls', 0)}/{u.get('free_quota', 0)} 次 · "
                 f"②CPU 时间 {u.get('cpu', 0.0):.3f}/{u.get('cpu_quota', 0.0):.3f} 秒")
        boot = (f"{_ui.DIM}（其中 {u.get('cpu', 0.0):.3f} 秒是启动与监控开销 —— "
                f"按行规计入您的账单）{_ui.R}")
    walls = _walls.stats()
    lines = [
        f"{_ui.B}{head}",
        f"{_ui.DIM}Python {__import__('sys').version.split()[0]} · 席位 1/1 · {meter}",
        f"{_ui.DIM}已装载 {walls['walls']} 道付费墙 + {walls['shims']} 个 C 包装层"
        f" · 仍锁定 {max(0, total - len(owned))}/{total} 个版本",
    ]
    if boot:
        lines.append(boot)
    if free_tier:
        lines.append(f"{_ui.DIM}🛡 {_notes.get('kernel', '')}")
        lines.append(f"{_ui.DIM}🔒 {_notes.get('disarm', '')}")
    if _notes.get("lease"):
        lines.append(f"{_ui.DIM}📜 {_notes['lease']}")
    lines.append(f"{_ui.DIM}🚧 import 闸门：{_notes.get('gate', '')}")
    _ui.banner_box(lines)
    if walls["skipped"]:
        print(f"{_ui.GREY}   （跳过 {walls['skipped']} 个纯 C 类型/无方法的类 —— "
              f"dowhen 挂不上，属于定价体系漏洞）{_ui.R}", flush=True)
    if walls["failed"]:
        print(f"{_ui.RED}   （挂载失败：{', '.join(walls['failed'])}）{_ui.R}", flush=True)


def apply_topup(token: str) -> bool:
    """
    应用一张**厂商签名的**加油包令牌（`python3 vendor/issue.py --topup 50000 3.0`）。

    客户端无法凭空造出额度 —— 这在结构上堵住了「官方 API 自助充值」
    （第三轮 R3-6：早先 `python365.set_quota(free=10**9)` 就能白拿 10 亿次额度）。
    这也正是"控制数据"那根支柱的小型示范：**凭据必须来自服务端/厂商**。
    """
    return _meter.apply_topup(token)      # 验签与改额度都在计费账户闭包里


def __getattr__(name: str):
    """
    PEP 562：让 `python365.FREE_QUOTA` / `CPU_QUOTA` 读到**活值**。

    注意这两条只是给人看的视图：真正的额度住在计费账户闭包里，
    给本模块或 `_meter` 的模块全局赋值都影响不到执法（第三轮 R3-3 的修法）。
    """
    if name == "FREE_QUOTA":
        return _meter.quota()
    if name == "CPU_QUOTA":
        return _meter.ACCOUNT.cpu_quota() if _meter.ACCOUNT else _meter.CPU_QUOTA
    raise AttributeError(name)


__all__ = [
    # 客户端公开面：只读视图 + 验签入口。**没有** set_quota / topup ——
    # 额度只能靠厂商签名的令牌变更（第三轮 R3-6）。
    "install", "installed", "stats", "usage", "quota", "trial_days_left",
    "owned_tiers", "parse_license", "apply_topup", "TIERS",
    "SubscriptionRequired", "__version__",
]
