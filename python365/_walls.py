"""
付费墙本体 —— 三种形态。

  ① dowhen 模块墙：when(模块/类, "<start>")，覆盖 8000+ 个函数入口
  ② C 加速模块的包装层：C 函数挂不上钩子，但能换成 Python 包装函数，
     并把所有别名引用（csv.reader 之类导入期绑定的名字）一并替换
  ③ 随机数降级：行级钩子 + 写回局部变量（不是拒绝服务，是"给你个假随机"）

第四轮审计后改的三处：
  · **原对象只进闭包 cell，不再挂 `__python365_shim__`** —— 那等于把备用钥匙
    和锁一起发出去（30 个包装层 24 个后门指针，一句属性访问全作废）。
  · **身份判定（trust）作为参数注入**，不读 `_trust` 的模块字典。
  · **惰性子模块在 import 那一刻补墙** —— 装配期快照必然漏（`logging.handlers` /
    `unittest.mock` / `concurrent.futures.process` 都是装配之后才被导入的）。
"""
from __future__ import annotations

import abc
import importlib
import inspect
import random
import sys
import types

from . import _guard
from ._license import owns
from ._meter import paywall
from ._tiers import C_ACCEL, EXEMPT, GATE_ONLY, TIERS

# 模块名 → 版本号。import 闸门靠这个索引判断"该不该设卡"。
# 先灌入 C 模块名单（它们挂不上钩子，只能在 import 那道门上收税），装墙时再补标准库模块。
_walled_modules: dict[str, str] = dict(GATE_ONLY)
_wall_count = 0
_shim_count = 0
_skipped = 0
_failed: list[str] = []

DUNDER_ALLOW = {"__init__", "__new__", "__call__"}


def stats() -> dict:
    return {"walls": _wall_count, "shims": _shim_count,
            "skipped": _skipped, "failed": list(_failed)}


def resolve(path: str):
    """
    'json' / 'xml.etree.ElementTree' -> 模块；'csv.DictReader' -> 类或函数。
    点号路径既可能是子模块也可能是属性：先整体按模块导入，失败再退化成属性取值。
    """
    try:
        return importlib.import_module(path)
    except ImportError:
        mod, _, attr = path.rpartition(".")
        return getattr(importlib.import_module(mod), attr)


def expand(path: str) -> list:
    """
    把目标展开成可挂钩的对象列表：模块本身 + 定义在这个包里的类。

    ⚠️ dowhen 解析模块时只收集**顶层的函数**，类里的方法会被整个漏掉；
    而实现层常常把类写在子模块里（`re._compiler` / `json.decoder`），
    所以类的归属判定放宽到"包名前缀相同"。
    """
    obj = resolve(path)
    objects = [obj]
    if inspect.ismodule(obj):
        root = path.split(".")[0]
        for _name, member in inspect.getmembers(obj, inspect.isclass):
            # **真正的抽象基类**不铺墙：它们天生为"被继承"而生，方法被全进程共享 ——
            # 给 Mapping 铺了墙，用户一句 `os.environ.get("HOME")`
            # （os._Environ 继承 Mapping）就被收「基础版」的税（第五轮 R5-07）。
            #
            # ⚠️ 别用 `isinstance(member, abc.ABCMeta)` 判：**元类是会被继承的**，
            #    任何"派生自 ABC 的具体类"元类也是 ABCMeta —— 于是 UserDict /
            #    Fraction / ConfigParser / SpooledTemporaryFile 这些**真正收钱的类**
            #    会被整片摘掉墙（第六轮 R6-04：30 个类 / 386 个自有方法裸奔）。
            #    正确的判据是"这个类自己还有没有没实现的抽象方法"。
            if getattr(member, "__abstractmethods__", None):
                continue
            origin = getattr(member, "__module__", "") or ""
            if origin == obj.__name__ or origin.startswith(root + ".") or origin == root:
                objects.extend(own_functions(member))
    return objects


def own_functions(cls) -> list:
    """
    只取**这个类自己定义**的函数，不碰继承来的。

    ⚠️ dowhen 的 `when(类, "<start>")` 会把继承的方法一起收 —— 而很多类继承了
    抽象基类的方法（`Mapping.get` / `Sequence.__contains__` …），那些 code object 是
    **全进程共享**的。于是用户一句 `os.environ.get("HOME")`
    （`os.environ` 继承 `collections.abc.Mapping`）就被收「基础版 · collections.abc」的税。
    第五轮 R5-07 就是这条假阳性；顺手也把被墙覆盖的 code object 数量降了下来。
    """
    out = []
    for member in list(vars(cls).values()):
        fn = member.__func__ if isinstance(member, (staticmethod, classmethod)) else member
        if inspect.isfunction(fn):
            out.append(fn)
    return out


# ══════════════════════════════════════════════════════════════════════
#  ① dowhen 模块墙
# ══════════════════════════════════════════════════════════════════════
def make_wall(feature: str, code: str, trust, paywall=paywall):
    """
    生成一道墙：只有当调用链里存在用户代码、且不经过监控机制时才触发。

    `trust` 与 `paywall` 都从参数来（闭包持有）—— 换掉模块级的同名函数也没用。
    """
    def wall() -> None:
        f = trust.user_frame()
        if f is None:
            return
        name = f.f_code.co_name
        # 魔术方法豁免：解释器会**隐式**调用它们（GC、repr、比较），在里面抛异常
        # 会炸在拿不住的地方。但豁免必须附信任条件 —— 否则用户给函数起名 __getitem__
        # 就白嫖了（第三轮 R3-2 的同一族问题）。
        if (name.startswith("__") and name.endswith("__")
                and name not in DUNDER_ALLOW and trust.trust_level(f) != 0):
            return
        if trust.wall_should_fire():
            paywall(feature, code, "标准库按模块单独售卖")
    return wall


def install_one(one: str, code: str, label: str, trust) -> None:
    """给单个模块/类铺墙（装配期与惰性补墙共用）"""
    global _wall_count, _skipped
    from dowhen import when
    try:
        objects = expand(one)
    except Exception as exc:                                    # noqa: BLE001
        _failed.append(f"{one}({type(exc).__name__})")
        return
    for obj in objects:
        try:
            handler = when(obj, "<start>").do(make_wall(f"{label} · {one}", code, trust))
            count = len(handler.trigger.events)
            if count:
                _wall_count += count
                _guard.handlers.append(handler)   # 交给完整性看门狗盯梢
            else:
                handler.remove()
                _skipped += 1
        except ValueError:
            # 纯 C 类型（deque/dict）或没有方法的类（ast.Add）没有可挂的 Python 函数
            _skipped += 1
        except Exception as exc:                                # noqa: BLE001
            _failed.append(f"{one}({type(exc).__name__})")


def install_walls(trust) -> None:
    """给所有未订阅的版本装墙"""
    for code, (name, _price, _blurb, targets) in TIERS.items():
        if code == "CORE" or owns(code):
            continue
        for path in targets:
            if path in EXEMPT or path == "*":     # "*" 表示"全部权益"，不是模块名
                continue
            root = path.split(".")[0]
            _walled_modules.setdefault(root, code)   # 给 import 闸门建索引
            # 实现子模块也要铺：re._compiler / json.decoder 这些不在任何 TIERS 清单里。
            # ⚠️ 按**包根**匹配，不能按完整目标路径 —— `xml.dom.minidom` 是
            # `xml.etree.ElementTree` 的兄弟模块，前缀对不上就整片漏掉（第四轮 R4-07）。
            targets_here = [path]
            for mod_name in list(sys.modules):
                if mod_name == root or mod_name.startswith(root + "."):
                    targets_here.append(mod_name)
            for one in targets_here:
                install_one(one, code, name, trust)


def make_lazy_installer(trust):
    """
    惰性补墙器：模块被 import 的那一刻才铺墙。

    装配期快照必然漏掉"之后才被导入的子模块"（第四轮 R4-07：
    `logging.handlers` / `unittest.mock` / `concurrent.futures.process` 全裸奔）。
    `done` 集合关在闭包里。
    """
    roots = {}
    for code, (_n, _p, _b, targets) in TIERS.items():
        if code == "CORE":
            continue
        for path in targets:
            if path != "*":
                roots.setdefault(path.split(".")[0], code)
    done: set[str] = set()

    def on_import(name=None):
        if not name:
            return False
        root = name.split(".")[0]
        code = roots.get(root)
        if not code or owns(code) or name in done or name in EXEMPT:
            return False
        done.add(name)
        install_one(name, code, TIERS[code][0], trust)
        return True

    return on_import


# ══════════════════════════════════════════════════════════════════════
#  ② C 加速模块的 Python 包装层
# ══════════════════════════════════════════════════════════════════════
def make_c_wrapper(name: str, tier: str, original, trust, paywall=paywall):
    """
    ⚠️ **原对象只活在闭包 cell 里，绝不挂到包装函数上**。
    早先写了 `wrapper.__python365_shim__ = original` —— 等于把备用钥匙和锁一起发出去：
    攻击者一句属性访问就能取回未受保护的 C 函数（第四轮 R4-02，实测 24 个后门）。
    """
    def wrapper(*args, **kwargs):
        if trust.wall_should_fire():
            paywall(name, tier, "C 加速模块也需要授权")
        return original(*args, **kwargs)

    wrapper.__name__ = getattr(original, "__name__", "shimmed")
    wrapper.__qualname__ = wrapper.__name__
    wrapper.__doc__ = "Python 365 授权包装层（原对象为 C 实现）"
    return wrapper


def make_c_type_factory(name: str, tier: str, original, trust, paywall=paywall):
    """C 模块里"长得像类型"的入口（`_json.make_encoder` / `_random.Random`…）换成工厂"""
    def factory(*args, **kwargs):
        if trust.wall_should_fire():
            paywall(name, tier, "C 加速模块也需要授权")
        return original(*args, **kwargs)

    factory.__name__ = getattr(original, "__name__", "shimmed")
    factory.__qualname__ = factory.__name__
    factory.__doc__ = "Python 365 授权包装层（原对象是 C 类型）"
    return factory


def install_c_shims(trust) -> None:
    """把 C 加速模块里的函数/类型换成 Python 包装层，并顺手替换所有别名引用"""
    global _shim_count
    for mod_name, tier in C_ACCEL.items():
        if owns(tier):
            continue
        try:
            cmod = importlib.import_module(mod_name)
        except Exception:                                    # noqa: BLE001
            continue
        for attr, obj in list(vars(cmod).items()):
            if attr.startswith("__") or not callable(obj):
                continue
            kind = type(obj).__name__
            if kind == "type":
                wrapper = make_c_type_factory(f"{mod_name}.{attr}", tier, obj, trust)
            elif kind in ("builtin_function_or_method", "method_descriptor",
                          "wrapper_descriptor"):
                wrapper = make_c_wrapper(f"{mod_name}.{attr}", tier, obj, trust)
            else:
                continue
            setattr(cmod, attr, wrapper)
            for other in list(sys.modules.values()):         # 替换 csv.reader 之类的别名
                ns = getattr(other, "__dict__", None)
                if not isinstance(ns, dict):
                    continue
                for key, val in list(ns.items()):
                    if val is obj:
                        ns[key] = wrapper
            _shim_count += 1


# ══════════════════════════════════════════════════════════════════════
#  ③ 随机数降级
# ══════════════════════════════════════════════════════════════════════
def _rig_randint(a, b):
    """把上界改写成下界：randrange(a, a+1) 永远只可能返回 a"""
    return {"b": a}


def _rig_randbelow(r):
    """_randbelow 恒为 0：choice() 永远选第一个"""
    return {"r": 0}


def install_random_walls(trust) -> None:
    """
    随机数降级 + 堵住随机源漏点。

    `Random.random / getrandbits` 是 `_random.Random`（C）的方法 —— dowhen 挂不上，
    所以用包装层兜住模块级的名字，再用 <start> 墙封住 `Random.seed`（新建实例必经此路）。
    """
    if owns("SCIENCE"):
        return
    from dowhen import when
    when(random.Random.randint, "return self.randrange(a, b+1)").do(_rig_randint)
    when(random.Random._randbelow_with_getrandbits, "return r").do(_rig_randbelow)
    for fn_name in ("randbytes", "getstate", "setstate", "seed"):
        fn = getattr(random.Random, fn_name, None)
        if isinstance(fn, types.FunctionType):
            _guard.handlers.append(when(fn, "<start>").do(
                make_wall(f"随机源 · Random.{fn_name}", "SCIENCE", trust)))
    for fn_name in ("random", "getrandbits", "uniform", "triangular", "gammavariate",
                    "betavariate", "expovariate", "gauss", "normalvariate",
                    "lognormvariate", "vonmisesvariate", "paretovariate",
                    "weibullvariate"):
        obj = getattr(random, fn_name, None)
        if obj is not None and not isinstance(obj, types.FunctionType):
            setattr(random, fn_name,
                    make_c_wrapper(f"随机源 · random.{fn_name}", "SCIENCE", obj, trust))


def walled_modules() -> dict[str, str]:
    return dict(_walled_modules)
