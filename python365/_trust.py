"""
身份验真 —— 判断"这一帧到底是谁"。

这是整套系统的地基，也被攻破过两轮：
  · 第一轮：相信 `frame.f_code.co_filename`（**自报字段**）→ 伪造成标准库路径即可白嫖
  · 第三轮：改看 `__name__` 字符串 → 一行 `__name__ = "python365.fake"` 即白嫖
  · 第四轮：改看代码对象 id，但把 id 集合留在**模块全局**里 → 换成万能 `__contains__` 对象即白嫖

所以这一版把整套判定**装进闭包**：`build(codes)` 返回的每个函数都持有那份集合，
模块字典里不再留可替换的名字（第四轮 R4-04）。

⚠️ 本文件的函数都跑在**监控回调的关键路径**上，任何一层额外的包装函数
   都会让 sys._getframe(N) 的偏移错位。改动前先读 user_frame 的注释。
"""
from __future__ import annotations

import os
import sys
import types
from types import SimpleNamespace

_STDLIB = os.path.dirname(os.__file__)
_EXCLUDE = tuple({sys.base_prefix, sys.prefix, _STDLIB} | {
    p for p in sys.path if p.endswith(("site-packages", "dist-packages"))
})

# 交互式 / 命令行喂进来的代码 —— co_filename 长这样
_SHELL_FILENAMES = ("<string>", "<stdin>", "<console>", "<module>")


def _collect_code_ids(code, out: set) -> None:
    out.add(id(code))
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            _collect_code_ids(const, out)


def new_holder() -> dict:
    """给 build() 用的 holder（调用方自己拿着，不放进任何模块字典）"""
    return {"ids": frozenset(), "dicts": {}}


def collect_internal_objects() -> dict:
    """
    收集「我们自己 + dowhen」的两类身份：

      · `ids`  ：所有代码对象 id（含嵌套）—— 覆盖函数/方法/闭包/lambda
      · `dicts`：所有模块 `__dict__` 的 id —— 覆盖**模块级**帧

    第二类是必需的：模块顶层代码对象拿不到（不在 `vars(mod)` 里），
    漏了它，`sitecustomize.py` 自己的模块级帧就会被当成"用户代码"
    （实测：启动期撞上自己的 `tempfile` 墙，横幅和统计静默丢失）。
    """
    ids: set[int] = set()
    dict_by_file: dict[int, str] = {}
    for name, mod in list(sys.modules.items()):
        if not (name == "sitecustomize" or name.startswith("python365")
                or name.startswith("dowhen")):
            continue
        # ⚠️ 只记 dict 的 id 是不够的 —— `f_globals` 是**可以借来的对象**：
        #    types.FunctionType(compile(PROG, "<prog>", "exec"), SITE.__dict__)
        #    就能把用户程序挂到内部模块的命名空间上，整段程序"自己人"化（第五轮 R5-01）。
        #    所以 dict 身份必须与**该模块自己的文件名**配对：借来的 dict 会立刻露馅。
        dict_by_file[id(mod.__dict__)] = getattr(mod, "__file__", "") or ""
        for obj in list(vars(mod).values()):
            code = getattr(obj, "__code__", None)
            if isinstance(code, types.CodeType):
                _collect_code_ids(code, ids)
            elif isinstance(obj, type):
                for member in list(vars(obj).values()):
                    sub = getattr(member, "__code__", None)
                    if isinstance(sub, types.CodeType):
                        _collect_code_ids(sub, ids)
    return {"ids": frozenset(ids), "dicts": dict_by_file}


def collect_internal_codes() -> frozenset:
    """
    把「我们自己 + dowhen」的所有代码对象 id 收集起来（含嵌套）。

    调用两次是必要的：`dowhen.handler` 是**懒加载**的（trigger.py 在函数体里 import），
    装第一道墙时才进 sys.modules —— 只收一次会让走栈在第一帧就"撞回监控机制"而放行所有墙。
    """
    ids: set[int] = set()
    for name, mod in list(sys.modules.items()):
        if not (name == "sitecustomize" or name.startswith("python365")
                or name.startswith("dowhen")):
            continue
        for obj in list(vars(mod).values()):
            code = getattr(obj, "__code__", None)
            if isinstance(code, types.CodeType):
                _collect_code_ids(code, ids)
            elif isinstance(obj, type):
                for member in list(vars(obj).values()):
                    sub = getattr(member, "__code__", None)
                    if isinstance(sub, types.CodeType):
                        _collect_code_ids(sub, ids)
    return frozenset(ids)


def looks_like_user_path(filename: str) -> bool:
    if not filename or filename.startswith("<"):
        return False
    return not os.path.abspath(filename).startswith(_EXCLUDE)


def build(codes: dict) -> SimpleNamespace:
    """
    造一套身份判定器。**所有函数都闭包持有 codes**（一个只有调用方能拿到的 holder），
    所以运行期把 `_trust.is_internal_frame` 换成任何东西都不影响执法路径 ——
    它们持有的是这里的函数对象和这个 holder（第四轮 R4-04）。

    codes 用可变 holder 是为了解决时序：`dowhen.handler` 懒加载，装完第一道墙才会
    进 sys.modules，所以集合要在装墙之后**更新一次**；holder 让所有闭包立刻看到新值。
    """
    def is_internal_frame(frame) -> bool:
        """
        这一帧是不是监控器自己？只认身份，不认任何字符串：

          · 代码对象 id（函数/方法/闭包）—— 最硬的判据
          · 模块 `__dict__` 的 id **且** `co_filename` 与该模块的 `__file__` 一致
            （模块顶层帧的 code object 拿不到，只能靠 dict 认；但 dict 可以借来用，
              所以必须再核一个"这帧的代码是不是真的来自那个文件"。—— 第五轮 R5-01）
        """
        if id(frame.f_code) in codes["ids"]:
            return True
        want_file = codes["dicts"].get(id(frame.f_globals))
        return want_file is not None and frame.f_code.co_filename == want_file

    def trust_level(frame) -> int:
        """
        返回：0 = 确定是用户代码 · 1 = 确定可信 · 2 = 身份可疑（说不清）

        规则：
          · **`__main__` 永远不是"可信"** —— `python3 -` / `-c` / `exec` 都自带
            `sys.modules["__main__"]`，早先的"身份同一性"检查反而把它们全判成了标准库
            （第四轮 R4-01：同一个文件，`python3 - < x.py` 免费、`python3 x.py` 被拦）。
          · 自称标准库的帧必须验明正身：模块存在、`__dict__` 是同一个对象、`__file__` 对得上。
          · `<string>`/`<stdin>`/`<console>`：**顶层那一帧**（`f_back is None`）就是解释器
            的主入口，必然是用户代码；被 exec 出来的那些（`f_back` 是库帧）算可疑，
            免得把标准库导入期 exec 生成的 namedtuple 也当成用户代码收税。
        """
        filename = frame.f_code.co_filename
        name = frame.f_globals.get("__name__", "")
        if is_internal_frame(frame):
            return 1
        if filename in _SHELL_FILENAMES:
            if frame.f_back is None:          # 解释器主入口：-c / - / -m 的顶层
                return 0
            return 0 if name == "__main__" else 2
        if not filename:
            # 空 co_filename（`compile(src, "", "exec")`）：绝不能算"可信"。
            # 第五轮 R5-02：判 1 等于白送计量与语法包；判 2 让它走"可疑帧"流程 ——
            # 调用链里有真用户帧就照常收费，是标准库导入期 exec 出来的就放行。
            return 2
        if filename.startswith("<"):          # <frozen importlib...> 等解释器内部
            mod = sys.modules.get(name)
            if mod is None or mod.__dict__ is not frame.f_globals:
                return 2
            return 0 if name == "__main__" else 1
        if looks_like_user_path(filename):
            return 0
        mod = sys.modules.get(name)           # 自称标准库 → 验明正身
        if mod is None or mod.__dict__ is not frame.f_globals:
            return 2
        if os.path.abspath(getattr(mod, "__file__", "") or "") != os.path.abspath(filename):
            return 2
        return 1

    def chain_has_user(frame) -> bool:
        """调用链里有没有一帧能**确定**是用户代码"""
        p = frame.f_back
        while p is not None:
            if trust_level(p) == 0:
                return True
            p = p.f_back
        return False

    def user_frame():
        """
        返回「触发监控事件的那个栈帧」。

        监控回调的栈链：on_any_call → dowhen.{util,callback,handler,instrumenter}… → ★宿主帧
        dowhen 内部帧是连续的一段，紧挨着它上面的第一帧就是宿主帧 —— 不能再往上找，
        否则会把「调用者的调用者」也算成一次计费调用。

        ⚠️ _getframe(2) 的前提是：本函数被 on_any_call 直接调用。加中间层会错位。
        """
        try:
            f = sys._getframe(2)
        except ValueError:
            return None
        while f is not None:
            if f.f_globals.get("__name__", "").startswith("dowhen"):
                f = f.f_back
                continue
            return f
        return None

    def wall_should_fire(allow_importlib: bool = False) -> bool:
        """
        统一判定：只有当"用户代码发起了这次调用"时才收费。

        两条调用路径的栈深度不同，但 _getframe(2) 都落在"该往上找用户帧"的起点：
          · dowhen 事件路径：wall_should_fire ← wall ← dowhen 内部帧 ← 宿主帧
          · C 包装层路径 ：wall_should_fire ← wrapper ← 调用者

        allow_importlib：import 闸门必须打开 —— 导入过程的调用链里必然有 importlib 帧，
        默认规则（见到 importlib 就放行）会把闸门自己放过去。
        """
        try:
            p = sys._getframe(2)
        except ValueError:
            return False
        while p is not None and is_internal_frame(p):
            p = p.f_back          # 穿过监控机制自己的帧
        if p is None:
            return False
        while p is not None:
            mod = p.f_globals.get("__name__", "")
            if is_internal_frame(p):
                return False
            # 终结/清理路径豁免 —— 只有**非用户代码**才配享受（帧名是用户可控字段）
            if p.f_code.co_name in ("__del__", "__exit__", "__aexit__") and trust_level(p) != 0:
                return False
            if not allow_importlib and (p.f_code.co_filename.startswith("<frozen importlib")
                                        or mod.startswith("importlib")):
                return False
            if trust_level(p) == 0:
                return True
            p = p.f_back
        return False

    return SimpleNamespace(is_internal_frame=is_internal_frame, trust_level=trust_level,
                           chain_has_user=chain_has_user, user_frame=user_frame,
                           wall_should_fire=wall_should_fire)
