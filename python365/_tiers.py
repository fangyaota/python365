"""
定价表 —— 唯一的事实来源。

其他模块只读这里的数据，不再各自维护一份模块清单。
"""
from __future__ import annotations

# 版本号 → (中文名, 月费, 权益说明, 目标模块/类)
TIERS: dict[str, tuple[str, int, str, list[str]]] = {
    "CORE":        ("语法包",       9, "lambda / 生成器 / async", []),
    "BASIC":       ("基础版",      19, "collections / heapq / functools / copy",
                    ["collections", "heapq", "functools", "copy"]),
    "TEXT":        ("文字版",      29, "re / textwrap / difflib / ast / tokenize",
                    ["re", "string", "textwrap", "difflib", "ast", "tokenize"]),
    "DATA":        ("数据版",      39, "json / csv / base64 / xml / zipfile / tomllib",
                    ["json", "csv", "base64", "xml.etree.ElementTree", "tomllib",
                     "configparser", "zipfile", "tarfile", "gzip"]),
    "SCIENCE":     ("科学版",      59, "statistics / fractions / calendar / uuid / random",
                    ["statistics", "fractions", "calendar", "uuid", "secrets"]),
    "NATIVE":      ("原生扩展包",  49, "math / datetime / hashlib / sqlite3 / struct / itertools …",
                    []),   # 目标在 GATE_ONLY：dowhen 挂不上 C 模块，但 import 闸门能设卡
    "DEVTOOLS":    ("开发工具版",  69, "logging / argparse / dataclasses / typing / unittest / pdb",
                    ["logging", "argparse", "dataclasses", "typing", "enum",
                     "unittest", "pdb", "doctest", "code", "zoneinfo"]),
    "SYSTEM":      ("系统版",      79, "pathlib / os.path / shutil / glob / tempfile / subprocess",
                    ["pathlib", "posixpath", "shutil", "glob", "tempfile",
                     "subprocess", "fnmatch", "fileinput"]),
    "CONCURRENCY": ("并发版",     129, "threading / asyncio / queue / multiprocessing",
                    ["threading", "asyncio", "multiprocessing", "queue",
                     "concurrent.futures"]),
    "NETWORK":     ("网络版",     199, "urllib / http.client / http.server / email / smtplib",
                    ["urllib.request", "http.client", "http.server", "email", "smtplib"]),
    "ENTERPRISE":  ("企业版",    4999, "全部权益", ["*"]),
}

# 纯 C 实现、dowhen 挂不上钩子的模块 —— 曾经是"免费版白送"的越狱通道，
# 现在改由 import 闸门在**导入那一刻**收税（挂不上钩子 ≠ 拦不住）。
GATE_ONLY: dict[str, str] = {
    "math": "NATIVE", "cmath": "NATIVE", "datetime": "NATIVE", "hashlib": "NATIVE",
    "sqlite3": "NATIVE", "struct": "NATIVE", "array": "NATIVE", "zlib": "NATIVE",
    "bisect": "NATIVE", "itertools": "NATIVE", "decimal": "NATIVE",
}

# C 加速模块 → 它对应的版本。这些模块里的函数挂不上钩子，但可以换成 Python 包装层。
C_ACCEL: dict[str, str] = {
    "_csv": "DATA", "_json": "DATA", "_heapq": "BASIC",
    "_bisect": "BASIC", "_random": "SCIENCE", "_statistics": "SCIENCE",
}

# 物理上不能锁的模块：inspect/traceback 被 dowhen 自己依赖，importlib/warnings 是机制本身。
# 锁了它们，监控器会先把自己绊倒。
EXEMPT: tuple[str, ...] = ("inspect", "traceback", "linecache", "warnings", "importlib")


def key_for(code: str) -> str:
    """购买提示：告诉用户怎么真的买到这一档"""
    return f"python3 vendor/issue.py {code}"
