"""
一个普通用户程序：想用几个标准库，结果撞上了一整套分级订阅墙。

注意：这里刻意不用 lambda / 生成器 —— 那是「语法包 CORE」的付费权益，
免费版用户根本写不出来（这本身就是付费墙的一部分）。
"""
import collections
import dataclasses
import datetime
import heapq
import itertools
import json
import logging
import math
import pathlib
import random
import re
import statistics
import threading
import urllib.request
import zipfile

SEP = "\n" + "─" * 66


def section(t):
    print(f"{SEP}\n▶ {t}")


def probe(label, fn):
    try:
        print(f"    {label} → {fn()}")
    except Exception as e:
        print(f"    ✗ {label} 被拦下：{type(e).__name__}")


def churn(n):
    """纯计算，用来烧「函数调用额度」"""
    total = 0
    for i in range(n):
        total += i
    return total


# 每个探测点写成一个具名函数（不能用 lambda！）
def t_counter():  return collections.Counter("hello").most_common(2)
def t_heap():     return heapq.nlargest(2, [3, 1, 2])
def t_re():       return re.findall(r"\d+", "a1b22c333")
def t_textwrap(): return __import__("textwrap").wrap("x" * 30, 10)[0]
def t_json():     return json.dumps({"a": 1})
def t_csv():
    return list(__import__("csv").DictReader(["a,b", "1,2"]))
def t_zip():      return zipfile.ZipFile("/tmp/x.zip", "w").close()
def t_stats():    return statistics.mean([1, 2, 3])
def t_uuid():     return __import__("uuid").uuid4().hex[:8]
def t_path():     return pathlib.Path(".").resolve()
def t_glob():     return __import__("glob").glob("*.py")[:1]
def t_log():      return logging.getLogger("x").name
def t_argparse(): return __import__("argparse").ArgumentParser("demo").prog
def t_thread():   return threading.Event()
def t_url():      return urllib.request.urlopen("http://example.com")


def t_dataclass():
    @dataclasses.dataclass
    class P:
        x: int
    return P(1)


section("1. 基础运算 —— 免费版唯一还能干的活")
print("    sum(range(10)) =", sum(range(10)), "| len('abc') =", len("abc"))

section("2. C 实现模块 —— 免费版的越狱通道 🕳")
print("    math.sqrt(2)   =", math.sqrt(2))
print("    datetime.now() =", datetime.datetime.now().year)
print("    itertools.chain =", list(itertools.chain([1], [2, 3])))
print("    threading.Lock() =", type(threading.Lock()).__name__, "(C 工厂函数)")
print("    ↑ 这些都是 C 扩展，dowhen 挂不上钩子 —— 免费版白送，属于定价体系漏洞")

section("3. 数据结构（基础版 ¥19/月）")
probe("collections.Counter", t_counter)
probe("heapq.nlargest", t_heap)

section("4. 文本处理（文字版 ¥29/月）")
probe("re.findall", t_re)
probe("textwrap.wrap", t_textwrap)

section("5. 数据格式（数据版 ¥39/月）")
probe("json.dumps", t_json)
probe("csv.DictReader", t_csv)
probe("zipfile.ZipFile", t_zip)

section("6. 科学计算（科学版 ¥59/月）")
probe("statistics.mean", t_stats)
probe("uuid.uuid4", t_uuid)
print("    random.randint(1,100) →", [random.randint(1, 100) for _ in range(5)],
      " ← 随机性已降级")

section("7. 文件与系统（系统版 ¥79/月）")
probe("pathlib.Path.resolve", t_path)
probe("glob.glob", t_glob)

section("8. 开发工具（开发工具版 ¥69/月）")
probe("logging.getLogger", t_log)
probe("argparse.ArgumentParser", t_argparse)
probe("@dataclasses.dataclass", t_dataclass)

section("9. 并发与网络（并发版 ¥129 / 网络版 ¥199）")
probe("threading.Lock", t_thread)
probe("urllib.request.urlopen", t_url)

section("10. 连跑 1000 次函数调用 —— 5 万额度够用吗？")
used = 0
try:
    for _i in range(1000):
        churn(10)
        used += 1
    print(f"    完成 {used} 次调用，一路畅通 ✅")
except Exception as e:
    print(f"    第 {used + 1} 次调用被拦下：{type(e).__name__}")

section("10b. 关于额度封顶")
# 免费版额度只能靠"跑满"来撞（见 billing_test.py / quota_test.py）。
# 客户端**没有**改额度的 API —— 续费要用厂商签名的加油包令牌：
#     python365.apply_topup("PYTHON365.xxx.yyy")     # python3 vendor/issue.py --topup 50000 3.0
# 所以这里不做"临时调低额度"的演示了：那种口子本身就不该存在。
print("    续费通道：apply_topup(厂商签名的加油包令牌)；客户端无法自造额度")

print(SEP)
print("▶ 11. 账单")
if not python365.installed():
    print("    （本进程没装付费墙 —— 原生 Python 跑的，没有账单）")
else:
    _owned = python365.owned_tiers()
    if _owned:
        print("    已购版本：" + "、".join(python365.TIERS[c][0] for c in python365.TIERS
                                        if c in _owned))
        print("    未购版本：" + "、".join(python365.TIERS[c][0] for c in python365.TIERS
                                        if c not in _owned))
    else:
        _u = python365.usage()
        print(f"    免费版：①调用 {_u['calls']}/{_u['free_quota']} 次"
              f"（剩 {_u['calls_left']}）　"
              f"②CPU {_u['cpu']:.3f}/{_u['cpu_quota']:.3f} 秒"
              f"（剩 {_u['cpu_left']:.3f}）")
        print(f"    本进程已装载 {python365.stats()['walls']} 道付费墙")

print(f"{SEP}\n■ 程序结束。")
