"""
dowhen 黑客实验室
-----------------
在运行中的 Python 进程里，对"已经编译好、正在跑的代码"动手：
不改源码、不重启、不重新导入。全部实验对象都是本文件里的玩具代码。
"""
import inspect
import random

from dowhen import when, goto, clear_all  # noqa: F401

R, B, DIM = "\033[0m", "\033[1m", "\033[2m"
C, G, Y, M, RED = "\033[36m", "\033[32m", "\033[33m", "\033[35m", "\033[31m"

HITS = {}   # Act 4 用：全局行命中计数器


def title(n, text):
    print(f"\n{C}{'─' * 64}{R}")
    print(f"  {Y}{B}Act {n}{R}  {B}{text}{R}")
    print(f"{C}{'─' * 64}{R}")


def show(label, value):
    print(f"    {DIM}{label:<30}{R} {value}")


# ══════════════════════════════════════════════════════════════
# Act 1  免密登录：把 check 的结果在 return 前改掉
# ══════════════════════════════════════════════════════════════
title(1, "免密登录 —— 劫持 return 前的局部变量")

SECRET = "correct-horse-battery-staple"


def login(password):
    ok = (password == SECRET)
    return ok


show("注入前 login('123456')", f"{RED}{login('123456')}{R}")
show("注入前 login(真密码)", f"{G}{login(SECRET)}{R}")

# 回调返回一个 dict = 写回局部变量。dowhen 会调用 PyFrame_LocalsToFast，
# 直接把栈帧里的 ok 改成 True —— 就在 return 执行前那一瞬间。
when(login, "return ok").do(lambda: {"ok": True})

show("注入后 login('123456')", f"{G}{login('123456')}{R}")
show("注入后 login('asdfghjkl')", f"{G}{login('asdfghjkl')}{R}")
clear_all()


# ══════════════════════════════════════════════════════════════
# Act 2  抽卡必出金：让概率论当场失效
# ══════════════════════════════════════════════════════════════
title(2, "抽卡必出金 —— 1% 概率变成 100%")

def draw_card():
    roll = random.randint(1, 100)
    if roll <= 1:              # 1% 出金
        return "SSR ✨"
    return "N"


before = [draw_card() for _ in range(20)]
show("注入前 20 连", f"{RED}{before.count('SSR ✨')} 个 SSR{R}  ({set(before)})")

# 行事件在"该行执行之前"触发，所以这里改 roll，紧接着的 if 就用上了假值。
when(draw_card, "if roll <= 1:").do(lambda: {"roll": 1})

after = [draw_card() for _ in range(20)]
show("注入后 20 连", f"{G}{after.count('SSR ✨')} 个 SSR{R}  {G}{after}{R}")
clear_all()


# ══════════════════════════════════════════════════════════════
# Act 3  跳过付费墙：goto 让程序"瞬移"
# ══════════════════════════════════════════════════════════════
title(3, "跳过付费墙 —— goto 改写字节码执行指针")

def read_article(is_premium):
    if not is_premium:
        return "🔒 会员专属内容，请先充值"
    return "📖 全文：dowhen 基于 sys.monitoring(PEP 669) ……"


show("注入前 非会员", f"{RED}{read_article(False)}{R}")

# 在 if 那一行直接跳到最后的 return，条件判断整段被绕过
when(read_article, "if not is_premium:").goto('return "📖 全文')

show("注入后 非会员", f"{G}{read_article(False)}{R}")
clear_all()


# ══════════════════════════════════════════════════════════════
# Act 4  代码 X 光：给整个函数埋点，生成覆盖率剖面
# ══════════════════════════════════════════════════════════════
title(4, "代码 X 光 —— 十几行代码手搓一个覆盖率工具")

def fib(n):
    if n < 2:
        return n
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a


src_lines, start_line = inspect.getsourcelines(fib)
executable = {ln for _, _, ln in fib.__code__.co_lines() if ln}
for _ln in executable:
    # 字符串回调会被 exec 在目标栈帧里 —— 相当于在那一行原生插了一句计数代码
    when(fib, _ln).do(f"HITS[{_ln}] = HITS.get({_ln}, 0) + 1")

for n in (0, 1, 6):
    fib(n)

print(f"    {M}调用 fib(0), fib(1), fib(6) 后的逐行执行剖面：{R}\n")
for i, line in enumerate(src_lines):
    ln = start_line + i
    hits = HITS.get(ln, 0)
    if hits:
        print(f"    {G}{hits:>3}×{R} {DIM}│{R} {B}{line.rstrip()}{R}")
    else:
        print(f"    {DIM}  ·{R} {DIM}│ {line.rstrip()}{R}")
print(f"\n    {M}→ 变灰的行一次都没执行过，那就是没被测试覆盖的分支{R}")
clear_all()
HITS.clear()


# ══════════════════════════════════════════════════════════════
# Act 5  线上救火：不重启热修复除零崩溃
# ══════════════════════════════════════════════════════════════
title(5, "线上救火 —— 进程开着，把 bug 修了")

def average(numbers):
    total = sum(numbers)
    count = len(numbers)
    return total / count      # 空列表直接 ZeroDivisionError


try:
    average([])
except ZeroDivisionError as e:
    show("修复前 average([])", f"{RED}💥 ZeroDivisionError: {e}{R}")

# 注入一行补丁：除法执行前，把 0 分母兜底成 1
when(average, "return total / count").do(lambda count: {"count": count or 1})

show("修复后 average([])", f"{G}{average([])}{R}")
show("修复后 average([1,2,3])", f"{G}{average([1, 2, 3])}{R}")
clear_all()


# ══════════════════════════════════════════════════════════════
# Act 6  给整个进程下蛊：连标准库一起骗
# ══════════════════════════════════════════════════════════════
title(6, "给整个进程下蛊 —— 把 random 变成预言机")

show("注入前 random.randint", [random.randint(1, 100) for _ in range(8)])

# 直接对标准库 random.Random.randint 动刀：把上界 b 改写成下界 a，
# 于是 randrange(a, a+1) 永远只可能返回 a。整个进程里所有调用者全中招。
when(random.Random.randint, "return self.randrange(a, b+1)").do(lambda a, b: {"b": a})

show("注入后 random.randint", f"{G}{[random.randint(1, 100) for _ in range(8)]}{R}")
show("换个人调用也一样", f"{G}{[random.randint(1, 100) for _ in range(8)]}{R}")
clear_all()


print(f"\n{C}{'═' * 64}{R}")
print(f"  {B}{G}6 个实验全部完成 —— 源码文件一个字节都没改{R}")
print(f"{C}{'═' * 64}{R}")
