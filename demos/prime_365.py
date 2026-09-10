"""
求质数 —— 在订阅制 Python 上跑跑看。

两种实现，算法上都是对的，但在「按函数调用次数计费」的模型下代价天差地别：
  ① 埃氏筛     —— 几乎全是 C 层的切片/内存操作，调用次数趋近于 0
  ② 朴素试除法 —— 每个候选数都要调一次 is_prime，调用次数 ≈ 上限值
"""
import math
import time

LIMIT = 200000


def is_prime(n):
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    limit = math.isqrt(n)          # math 是 C 模块 —— 免费版白送
    d = 3
    while d <= limit:
        if n % d == 0:
            return False
        d += 2
    return True


_naive_out = []


def primes_naive(limit):
    """每个候选数调用一次 is_prime —— 按调用次数计费时最奢侈的写法"""
    for n in range(2, limit + 1):
        if is_prime(n):
            _naive_out.append(n)
    return _naive_out


def primes_sieve(limit):
    """埃氏筛 —— 全是 bytearray 切片和 range，几乎不产生函数调用"""
    flags = bytearray([1]) * (limit + 1)
    flags[0:2] = b"\x00\x00"
    for i in range(2, math.isqrt(limit) + 1):
        if flags[i]:
            flags[i * i::i] = bytearray(len(flags[i * i::i]))
    return [i for i, f in enumerate(flags) if f]


print(f"目标：求出 {LIMIT} 以内的全部质数\n")

print("① 埃氏筛 —— 按调用次数计费时最便宜的写法")
t0 = time.perf_counter()
sieve = primes_sieve(LIMIT)
dt1 = (time.perf_counter() - t0) * 1000
print(f"   ✅ 找到 {len(sieve)} 个质数，最大 {sieve[-1]}，耗时 {dt1:.1f} ms")
print(f"   前 10 个：{sieve[:10]}")

print("\n② 朴素试除法 —— 按调用次数计费时最贵的写法")
t0 = time.perf_counter()
try:
    naive = primes_naive(LIMIT)
    dt2 = (time.perf_counter() - t0) * 1000
    print(f"   ✅ 找到 {len(naive)} 个质数，耗时 {dt2:.1f} ms")
    print("   两种算法结果一致 ✓" if naive == sieve else "   ✗ 结果不一致")
except Exception as e:
    dt2 = (time.perf_counter() - t0) * 1000
    print(f"   ✗ 被拦下了：{type(e).__name__}（已耗时 {dt2:.1f} ms）")
    print(f"   ✗ 死前只算出 {len(_naive_out)} 个质数"
          f"（最后一个 {_naive_out[-1] if _naive_out else '-'}）")
    print(f"   ✗ 但正确答案应该是 {len(sieve)} 个 —— 程序没跑完")

print("\n③ 账单")
try:
    import python365
    if python365.owned_tiers():
        print("   已订阅：函数调用不限量，无广告，全速运行")
    else:
        u = python365.usage()
        print(f"   免费版：①调用 {u['calls']} / {u['free_quota']} 次"
              f"（超出 {max(0, u['calls'] - u['free_quota'])} 次）"
              f"　②CPU {u['cpu']:.3f} / {u['cpu_quota']:.3f} 秒")
except Exception as e:
    print("   （账单读取失败）", e)
