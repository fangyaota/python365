"""
厂商侧工具：生成 RSA 密钥对。

私钥默认写到 ~/.python365-vendor/private_key.json —— **不在客户端目录树里**，
否则谁能拿到客户端谁就能签发许可证（第三轮 R3-12 就是这么被打穿的）。
可用 PYTHON365_VENDOR_DIR 指向别处；真实产品应放 HSM 或独立签名服务。
客户端只内嵌公钥 (n, e)，所以即使客户端源码被完全公开，也无法伪造许可证：
伪造需要私钥，而私钥在厂商手里。

（漏洞版本用的是 sum(ord(c))%10000 校验和 —— 读一眼源码就能算出 ENTERPRISE 码。）
"""
import json
import os
import random

BITS = 1024

# ⚠️ 私钥**不能**落在客户端所在的目录树里（第三轮 R3-12 就是直接读
#    vendor/private_key.json 签出了 ENTERPRISE）。
#    默认放到用户主目录下，可以用环境变量指向别处（真实产品应在 HSM/签名服务里）。
KEY_DIR = os.environ.get(
    "PYTHON365_VENDOR_DIR", os.path.join(os.path.expanduser("~"), ".python365-vendor"))
PRIVATE_KEY = os.path.join(KEY_DIR, "private_key.json")


def is_probable_prime(n: int, rounds: int = 24) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits: int) -> int:
    while True:
        cand = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(cand):
            return cand


CLIENT_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "python365", "python365", "_license.py")


def patch_client(n: int, e: int) -> None:
    """
    把新公钥写回客户端源码。

    这样私钥就**名正言顺地不进版本库**：谁 clone 下来跑一次 genkey.py，
    就得到一套自洽的密钥对（私钥落在 vendor/，公钥内嵌进客户端）。
    否则一旦私钥换了、客户端还留着旧公钥，签发的许可证全部验不过。
    """
    import re
    src = open(CLIENT_FILE, encoding="utf-8").read()
    patched, count = re.subn(r"(PUBLIC_KEY = \(\n    )\d+(,\n    )\d+(,\n\))",
                             rf"\g<1>{n}\g<2>{e}\g<3>", src)
    if not count:
        raise SystemExit("客户端里没找到 PUBLIC_KEY —— _license.py 的结构变了？")
    with open(CLIENT_FILE, "w", encoding="utf-8") as fh:
        fh.write(patched)


def main() -> None:
    e = 65537
    while True:
        p, q = gen_prime(BITS // 2), gen_prime(BITS // 2)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if phi % e == 0:
            continue
        n = p * q
        if n.bit_length() == BITS:
            break
    d = pow(e, -1, phi)
    os.makedirs(KEY_DIR, exist_ok=True)
    with open(PRIVATE_KEY, "w") as fh:
        json.dump({"n": n, "e": e, "d": d}, fh)
    os.chmod(PRIVATE_KEY, 0o600)
    patch_client(n, e)
    client_tree = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if os.path.abspath(PRIVATE_KEY).startswith(os.path.abspath(client_tree)):
        print("⚠️  警告：私钥落在客户端目录树里 —— 谁能拿到客户端谁就能签发许可证！")
    print(f"私钥已写入 {PRIVATE_KEY}（**不在客户端目录树内**）")
    print("公钥已自动写回 python365/python365/_license.py 的 PUBLIC_KEY")
    print(f"  n = {str(n)[:24]}…（{n.bit_length()} bit）")
    print(f"  e = {e}")
    print("\n注意：换密钥会让此前签发的所有许可证失效。")


if __name__ == "__main__":
    main()
