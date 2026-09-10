"""dowhen 功能演示：运行时给已有函数打钩子、改局部变量、条件触发、跳转。"""
from dowhen import when, do, goto, clear_all

# ============ 被测函数（模拟别人写好的、不想改的代码）============
def calc(a, b):
    total = a + b
    total = total * 2
    return total


print("=" * 55)
print("① 不修改源码，在指定行插入调试代码")
print("=" * 55)

def on_sum(a, b):
    print(f"   [hook] 走到 'total = a + b' 时，a={a}, b={b}")

when(calc, "total = a + b").do(on_sum)
print(f"   calc(1, 2) = {calc(1, 2)}")
clear_all()   # 清理钩子


print()
print("=" * 55)
print("② 修改局部变量（回调返回 dict 即可写回）")
print("=" * 55)

def boost(total):
    # 把 total 这个局部变量的值改掉
    return {"total": total * 100}

when(calc, "total = total * 2").do(boost)
print(f"   原逻辑 calc(1,2) 应为 6，被劫持后 = {calc(1, 2)}")
clear_all()


print()
print("=" * 55)
print("③ 条件触发：只在 a > 100 时才命中")
print("=" * 55)

def alert(a):
    print(f"   [!!] 参数过大: a={a}")

when(calc, "total = a + b", condition="a > 100").do(alert)
print(f"   calc(1, 2)   = {calc(1, 2)}   (安静)")
print(f"   calc(500, 2) = {calc(500, 2)}  (触发)")
clear_all()


print()
print("=" * 55)
print("④ 运行时跳转：让 'return total' 直接跳到指定行")
print("=" * 55)

def my_func(x):
    a = x
    a = a + 1
    return a

when(my_func, "a = a + 1").goto("return a")   # 跳过自增
print(f"   my_func(10) = {my_func(10)}   (原应 11，跳过后仍是 10)")
clear_all()

print()
print("✅ dowhen 工作正常")
