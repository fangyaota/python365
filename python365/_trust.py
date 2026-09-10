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
    return {"ids": frozenset(), "modcode": set(), "installing": True}


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
    modcodes: set = set()          # 模块级 code object —— **按值**比较
    for name, mod in list(sys.modules.items()):
        if not (name == "sitecustomize" or name.startswith("python365")
                or name.startswith("dowhen")):
            continue
        # 模块级帧的判据：拿"这个模块的模块级 code object **本身**"来比。
        #
        # ⚠️ 走过的弯路（五、六两轮各一次）：
        #   · 比 `id(mod.__dict__)` → 用户可以借那个 dict 当 globals（R5-01）
        #   · 再补一个 `co_filename == mod.__file__` → 他连 co_filename 一起凑（R6-01，
        #     而 co_filename 正是第一轮被打穿的那个"自报字段"）
        # 两个可读值凑一起还是可读值。代码对象没法"借"：要让它命中，
        # 只能真去执行我们那个模块的顶层 —— 那只会把付费墙装得更牢。
        #
        # 取值方式：源码加载器能按源文件重新编出**值相等**的 code object（CodeType 按值比较）；
        # 我们自己的模块另外在导入那一刻把活帧抓进 ids（见 capture_module_frame）。
        try:
            loader = getattr(getattr(mod, "__spec__", None), "loader", None)
            code = loader.get_code(name) if loader is not None else None
            if isinstance(code, types.CodeType):
                modcodes.add(code)
        except Exception:                                    # noqa: BLE001
            pass
        for obj in list(vars(mod).values()):
            code = getattr(obj, "__code__", None)
            if isinstance(code, types.CodeType):
                _collect_code_ids(code, ids)
            elif isinstance(obj, type):
                for member in list(vars(obj).values()):
                    sub = getattr(member, "__code__", None)
                    if isinstance(sub, types.CodeType):
                        _collect_code_ids(sub, ids)
    return {"ids": frozenset(ids), "modcode": modcodes}


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
        这一帧是不是监控器自己？**只认代码对象**，不认任何可以借来的属性
        （`co_filename` / `__name__` / `f_globals` 都试过了，都被借过）：

          · 代码对象 id 属于自己人（函数/方法/闭包）—— 最硬
          · 或代码对象**按值**等于某个自己模块的模块级 code object
            （CodeType 按值比较；要凑出它只能真执行我们的模块顶层，那只会把墙装得更牢）
        """
        if id(frame.f_code) in codes["ids"]:
            return True
        return frame.f_code in codes["modcode"]

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
                # ⚠️ 没有调用者的帧 = **入口帧**（新线程的根帧 / 顶层 exec），
                # 必须判用户代码(0)，不能判"说不清"(2)。
                # 第八轮 R8-01：`_thread.start_new_thread` 起的线程根帧 f_back 是 None，
                # 攻击者只要把 co_filename 写成 `<frozen x>`、`__name__` 取一个不在
                # sys.modules 里的名字，整条链上就**一帧 level-0 都没有** → 走栈走完
                # → return False → 7112 道墙 + import 闸门 + 语法闸门全部放行。
                # 判 2 的后果是"没人负责"，而入口帧的定义就是"责任起点是用户"。
                return 0 if frame.f_back is None else 2
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

    def set_installing(flag: bool) -> None:
        """装配期抑制开关（持有在闭包里，外部改不到）"""
        codes["installing"] = flag

    def wall_should_fire(allow_importlib: bool = False) -> bool:
        # 装配期不收费：那时**没有任何用户代码在跑**，装墙过程里的大量标准库调用
        # 都是监控器自己的动作。第七轮把"遇到内部帧就 return False"改成"继续往上找"
        # 之后，每次调用都要走完整条栈 —— 免费版 7112 道墙，启动 CPU 从 1.6s 涨到 5.0s，
        # 而内核 RLIMIT 是 6s：用户只剩 ~1 秒可用，卖的是 3 秒，最后收到的是 SIGKILL
        # 而不是付费墙提示（第八轮 R8-04，是上一轮修法的自伤）。
        if codes.get("installing"):
            return False
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
                # ⚠️ 这里必须"跳过继续往上找"，**不能直接 return False**。
                # 第七轮 R7-01/02/03：「链上出现内部帧就放行」是一条可以被当挡箭牌的规则 ——
                # 攻击者只要让自己的帧不是 level 0（`<string>` + `__name__ != __main__`），
                # 再把我们的模块顶层代码拿去 exec（模块体里的 set()/frozenset() 换成他的钩子），
                # "他的帧 → 内部帧"这样一叠，走栈撞到内部帧就放行：7112 道墙一道不响，
                # 而判据本身（代码对象）他根本没碰。判据换了六次，这条规则没换过。
                #
                # 跳过之后：真正的"监控器自己调标准库"整条链没有 level-0 帧，循环走完
                # 自然 return False；挡箭牌那条链上层是用户帧 → 收税。
                p = p.f_back
                continue
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

    return SimpleNamespace(set_installing=set_installing,
                           is_internal_frame=is_internal_frame, trust_level=trust_level,
                           chain_has_user=chain_has_user, user_frame=user_frame,
                           wall_should_fire=wall_should_fire)
