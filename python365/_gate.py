"""
import 闸门 —— 三层设卡。默认关闭（PYTHON365_IMPORT_GATE=1 打开）。

实测结论：
  ① `importlib._bootstrap` 是**冻结模块**（没有源码文件），但 dowhen 的 `<start>` 事件
     照样能挂上去 —— 因为 `<start>` 不需要 inspect.getsourcelines。实测 `import json`
     会让这个钩子触发 99 次。
  ② `builtins.__import__` 是 C 内建函数 → dowhen 挂不上，只能用 Python 包装层换掉。
  ③ `sys.meta_path` 插一个 Finder → 最上游的正统做法。

真正的价值：C 模块（math / datetime / hashlib / sqlite3 …）dowhen 一个钩子都挂不上，
一直是"免费版白送"的越狱通道 —— 现在可以在**导入那一刻**设卡，
于是有了「原生扩展包 NATIVE」这一档。挂不上钩子 ≠ 拦不住。

边界：闸门管的是"导入这个动作"，管不住"已经在进程里"的模块 ——
只要 math 被任何组件导入过，sys.modules["math"].sqrt 照样能用。
"""
from __future__ import annotations

import sys

from . import _walls
from ._license import owns
from ._meter import paywall

_blocked: dict[str, str] = {}


def freeze_blocked() -> int:
    """
    把"哪些模块该拦"在**启动期**算成一张只读表。

    这样运行期就不再读授权表 —— 改 `_owned` 结构上失效（审计缺口 A）。
    注意这也让闸门是"启动期快照"：启动后新买的许可证要重启进程才生效，
    真实订阅制本来也是这样（重开会话）。
    """
    global _blocked
    _blocked = {name: tier for name, tier in _walls.walled_modules().items()
                if not owns(tier)}
    return len(_blocked)


def blocked_tier(name: str) -> str | None:
    """这个模块名属于未订阅的版本吗？（只查启动期快照）"""
    if not name:
        return None
    return _blocked.get(name.split(".")[0])


def make_gate_callback(trust, paywall=paywall):
    """挂在 importlib._bootstrap._find_and_load 上（name 从它的局部变量取值）"""
    def gate(name=None, import_=None) -> None:
        tier = blocked_tier(name)
        if tier and trust.wall_should_fire(allow_importlib=True):
            paywall(f"import {name}", tier, "标准库按模块单独售卖")
    return gate


def install_import_gate(trust) -> str:
    """装上三层闸门，返回一句话说明。`trust` 与 `paywall` 都走注入，不读模块字典。"""
    freeze_blocked()          # 先固化快照，运行期不再看授权表
    notes = []
    try:                                    # ① dowhen 挂冻结的 _find_and_load
        # ⚠️ 不是 _gcd_import —— 那个在语句式 import 的路径上根本不被调用（实测 0 命中）；
        # `importlib.import_module` 走 _gcd_import，语句式 import 走 _find_and_load。
        # 已经缓存的模块两者都不经过，由 ②③ 两层兜住。
        from dowhen import when
        from importlib import _bootstrap as bootstrap
        from . import _guard
        _guard.handlers.append(when(bootstrap._find_and_load, "<start>")
                               .do(make_gate_callback(trust)))
        notes.append("_find_and_load(dowhen)")
    except Exception as exc:                                # noqa: BLE001
        notes.append(f"_gcd_import 失败:{type(exc).__name__}")
    try:                                    # ② 换掉 builtins.__import__
        import builtins
        real_import = builtins.__import__

        def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
            tier = blocked_tier(name)
            if tier and trust.wall_should_fire(allow_importlib=True):
                paywall(f"import {name}", tier, "标准库按模块单独售卖")
            return real_import(name, globals, locals, fromlist, level)
        # ⚠️ 原函数只进闭包 cell —— 不挂 `__python365_shim__`（备用钥匙不在锁上）

        builtins.__import__ = guarded_import
        notes.append("__import__(包装层)")
    except Exception as exc:                                # noqa: BLE001
        notes.append(f"__import__ 失败:{type(exc).__name__}")
    try:                                    # ③ meta_path Finder（最上游）
        class _WalledFinder:
            def find_spec(self, fullname, path=None, target=None):
                tier = blocked_tier(fullname)
                if tier and trust.wall_should_fire(allow_importlib=True):
                    paywall(f"import {fullname}", tier, "模块单独售卖")
                return None             # 不接管加载，只设卡

        sys.meta_path.insert(0, _WalledFinder())
        notes.append("meta_path Finder")
    except Exception as exc:                                # noqa: BLE001
        notes.append(f"meta_path 失败:{type(exc).__name__}")
    return " · ".join(notes)
