"""
双层计费对决 —— 调用次数 vs CPU 时间

三个工作负载，看哪一层先抓住谁：
  ① 埃氏筛       几乎不调用 Python 函数，CPU 也极小        → 两层都放过
  ② 纯 C 层重活  sum(range(10**7))：167ms CPU，2 次调用    → 两层都放过
  ③ 纯 C 层重活  sum(range(10**8)) 跑两遍：3356ms CPU，4 次调用 → 第 1 层形同虚设
  ④ 碎函数调用   每次迭代都调一次函数，CPU 极小             → 第 2 层形同虚设
"""
import math

# 厂商签发的加油包令牌（+50000 次调用 / +3.0 秒 CPU）——
# 客户端只有公钥，伪造不了；这是"续费"唯一的合法通道。
TOPUP_TOKEN = (
    "PYTHON365.VE9QVVB8NTAwMDB8My4wfDIwMjcwOTEw."
    "qjPxXYaOwX8rB_BS4cFoc2_hKF1ZndetVrLNX_K3ko2XIfxFcbPkH-SbDsYK1PpUDFfvDSnRochTDZv_6DfkIKVBEK0gAiAUj2189G2vDKboTGbbGwq7xBPL_jvoSmmYBe-tsmkzXmijO3_plfnIqSdPLixB6TTOJ1hpFiN6yPw"
)


# ── 负载 ①：埃氏筛 ────────────────────────────────────────────────────
def sieve(limit):
    flags = bytearray([1]) * (limit + 1)
    flags[0:2] = b"\x00\x00"
    for i in range(2, math.isqrt(limit) + 1):
        if flags[i]:
            flags[i * i::i] = bytearray(len(flags[i * i::i]))
    return sum(flags)


# ── 负载 ②：纯 C 层运算 ──────────────────────────────────────────────
def burn_c(n):
    """sum + range 全是 C 实现：零函数调用、零行事件、零监控命中"""
    return sum(range(n))


def burn_c_heavy():
    """跑两遍 ≈ 3.35s CPU —— 第 1 层全程只看到 4 次函数调用"""
    return burn_c(100_000_000) + burn_c(100_000_000)


# ── 负载 ③：碎函数调用 ───────────────────────────────────────────────
def step(x):
    return x + 1


def burn_calls(n):
    total = 0
    for _ in range(n):
        total = step(total)
    return total


def bill():
    try:
        import python365
        if python365.owned_tiers():
            return "已订阅：两项均不限量"
        u = python365.usage()
        return (f"①调用 {u['calls']:>5}/{u['free_quota']} 次"
                f"　②CPU {u['cpu']:.3f}/{u['cpu_quota']:.3f} 秒")
    except Exception:
        return "（账单不可读）"


def run(label, fn, *args):
    import python365
    print(f"\n▶ {label}")
    print(f"  运行前 {bill()}")
    blocked = False
    try:
        fn(*args)
        print("  ✅ 通过（两层额度都没破）")
    except Exception as e:
        blocked = True
        print(f"  ✗ 被拦下：{type(e).__name__}")
        print("  → 断供中：此刻连自己写的 bill() 都调不动了（它是用户代码），")
        print("    只能调 python365.apply_topup() —— 本模块函数，豁免计量")
    if blocked:
        # 续费要凭**厂商签名的加油包令牌**（客户端造不出额度）。
        # 这张令牌是：python3 vendor/issue.py --topup 50000 3.0
        python365.apply_topup(TOPUP_TOKEN)
    print(f"  运行后 {bill()}")


run("① 埃氏筛 —— 200000 以内质数（几乎不调用函数，CPU 也小）", sieve, 200000)

run("② 纯 C 层重活 —— sum(range(10_000_000))，167ms CPU", burn_c, 10_000_000)

run("③ 纯 C 层重活 —— sum(range(10**8)) 跑两遍 ≈ 3356ms CPU ← 第 1 层看都看不见",
    burn_c_heavy)

run("④ 碎函数调用 —— 6 万次 step()：CPU 极省，但调用次数爆表", burn_calls, 60000)

print("\n▶ 收尾账单")
print(f"  {bill()}")
