"""验证 50000 额度确实会被撞到 —— 一个纯计算的死循环就够了。"""


def work():
    total = 0
    for i in range(10):
        total += i
    return total


n = 0
try:
    for _ in range(60000):
        work()
        n += 1
except Exception as e:
    print(f"第 {n + 1} 次调用被拦下：{type(e).__name__}")
else:
    print(f"跑了 {n} 次都没事")
