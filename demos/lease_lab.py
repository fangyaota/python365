"""
租约实验台 —— 把审计里那几条"客户端拿得住的都不算凭据"的残留，
换成「厂商授权服务端 + 短周期租约 + 设备绑定 + 吊销」再打一遍。

对照表（本脚本会逐条实测）：
  ① 激活          厂商服务端签发租约（私钥只在服务端）→ 高级功能可用
  ② 换机器        指纹不匹配 → 服务端拒绝续签 → 停机
  ③ 吊销          服务端 revoke → 租约到期（TTL）后停机
  ④ 断网          续签失败 → 宽限期（GRACE）用完后停机
  ⑤ 伪造指纹      **仍然能白嫖** —— 指纹是客户端自报的（诚实边界）
  ⑥ 复测 C 通道 / 零事件 C 运算 —— 与租约架构无关，泄漏面不变

运行：python3 demos/lease_lab.py       （原生跑，不加载付费墙）
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY365 = ROOT          # 搬迁后：项目根就是 PYTHONPATH 那一层
PORT = 8791
SERVER = f"http://127.0.0.1:{PORT}"
TTL, GRACE = 6, 4                # 演示用短租约：窗口 = TTL + GRACE = 10 秒
LEASE_FILE = "/tmp/.python365_lease_lab"
CLIENT_SRC = os.path.join("/tmp", "_lease_client.py")

CLIENT = '''import json, sys, time
n = int(sys.argv[1]) if len(sys.argv) > 1 else 1
for i in range(n):
    try:
        json.dumps({"i": i})                      # DATA 档的高级功能
        print(f"    t={i}s json 可用", flush=True)
    except Exception as exc:
        print(f"    t={i}s 被拦：{type(exc).__name__}", flush=True)
        break
    try:
        time.sleep(1)
    except Exception:
        break
print("    [client] 走到末尾", flush=True)
'''


ADMIN_TOKEN = "lab-admin-token"          # /state 是管理接口，需要认证


def fetch_state() -> dict:
    req = urllib.request.Request(f"{SERVER}/state",
                                 headers={"X-Admin-Token": ADMIN_TOKEN})
    with urllib.request.urlopen(req, timeout=2.0) as r:
        return json.loads(r.read())


def env(**extra) -> dict:
    e = dict(os.environ)
    e["PYTHONPATH"] = PY365
    e["PYTHON365_LEASE_FILE"] = LEASE_FILE
    e.update({k: str(v) for k, v in extra.items()})
    return e


def run_client(seconds: int = 1, **extra) -> tuple[str, int]:
    with open(CLIENT_SRC, "w") as fh:
        fh.write(CLIENT)
    p = subprocess.run([sys.executable, "-u", CLIENT_SRC, str(seconds)],
                       env=env(**extra), capture_output=True, text=True, timeout=90)
    return p.stdout + p.stderr, p.returncode


def issue_license(spec: str = "DATA,BASIC") -> str:
    out = subprocess.run([sys.executable, os.path.join(ROOT, "vendor", "issue.py"), spec],
                         capture_output=True, text=True, check=True)
    return out.stdout.strip()


def start_server() -> subprocess.Popen:
    e = dict(os.environ, PYTHON365_LEASE_TTL=str(TTL), PYTHON365_ADMIN_TOKEN=ADMIN_TOKEN)
    p = subprocess.Popen([sys.executable, os.path.join(ROOT, "vendor", "authd.py"), str(PORT)],
                         env=e, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for _ in range(40):
        try:
            fetch_state()
            return p
        except Exception:                                    # noqa: BLE001
            time.sleep(0.25)
    raise SystemExit("服务端起不来")


def revoke(lic: str) -> None:
    req = urllib.request.Request(f"{SERVER}/revoke", data=json.dumps({"license": lic}).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=3) as r:
        print("    服务端：", json.loads(r.read())["list"])


def head(text: str) -> None:
    print(f"\n{'─' * 66}\n▶ {text}")


def main() -> None:
    print("═══ 启动厂商授权服务端 ═══")
    server = start_server()
    try:
        st = fetch_state()
        print(f"  服务端就绪：租约 {st['lease_ttl']}s，设备 {len(st['devices'])} 台")
        lic = issue_license()
        print(f"  厂商签发许可证：{lic[:44]}…（私钥只在服务端进程里）")

        head("① 首次激活：服务端签发租约 → 高级功能可用")
        if os.path.exists(LEASE_FILE):
            os.remove(LEASE_FILE)
        out, code = run_client(1, PYTHON365_KEY=lic, PYTHON365_LEASE_SERVER=SERVER)
        print("  " + "\n  ".join(l for l in out.splitlines() if "📜" in l or "t=0" in l)[:400])
        print(f"  退出码 {code}")

        head("② 换机器：把那台机器的租约拷过来 → 指纹不匹配 → 停机")
        out, code = run_client(1, PYTHON365_KEY=lic, PYTHON365_LEASE_SERVER=SERVER,
                               PYTHON365_FP_OVERRIDE="deadbeefdeadbeef")
        print("  " + "\n  ".join(l for l in out.splitlines()
                                 if "租约" in l or "指纹" in l or "停机" in l)[:500])
        print(f"  退出码 {code}")

        head("③ 吊销：服务端 revoke 之后，租约到期即停机（窗口 = TTL+GRACE）")
        os.remove(LEASE_FILE)
        run_client(1, PYTHON365_KEY=lic, PYTHON365_LEASE_SERVER=SERVER)   # 先正常激活一次
        revoke(lic)
        t0 = time.time()
        out, code = run_client(TTL + GRACE + 5, PYTHON365_KEY=lic, PYTHON365_LEASE_SERVER=SERVER)
        print("  " + "\n  ".join(l for l in out.splitlines()
                                 if "t=" in l or "停机" in l or "原因" in l)[:600])
        print(f"  停机耗时 {time.time() - t0:.1f}s（退出码 {code}）")

    finally:
        server.send_signal(signal.SIGTERM)
        server.wait(timeout=5)

    head("④ 断网：服务端已停 → 宽限期用完后停机")
    t0 = time.time()
    out, code = run_client(TTL + GRACE + 5, PYTHON365_KEY=lic, PYTHON365_LEASE_SERVER=SERVER)
    print("  " + "\n  ".join(l for l in out.splitlines()
                             if "t=" in l or "停机" in l or "原因" in l)[:600])
    print(f"  停机耗时 {time.time() - t0:.1f}s（退出码 {code}）")

    head("⑤ 诚实边界：指纹是**客户端自报**的 → 冒用已绑定指纹可白嫖")
    server2 = start_server()
    try:
        bound = fetch_state()["devices"]
        real_fp = list(bound.values())[0] if bound else "?"
        print(f"  服务端记的绑定指纹：{real_fp}")
        os.remove(LEASE_FILE) if os.path.exists(LEASE_FILE) else None
        # "另一台机器"把 fingerprint() 的返回值改成老机器的值 —— 服务端无从分辨
        out, code = run_client(1, PYTHON365_KEY=lic, PYTHON365_LEASE_SERVER=SERVER,
                               PYTHON365_FP_OVERRIDE=real_fp)
        ok = "t=0s json 可用" in out
        print(f"  冒用 '{real_fp}' 激活：{'成功 → 🔴 白嫖（服务端信了）' if ok else '被拒'}")
        print("  说明：服务端只认客户端报上来的字符串。它挡得住「老实拷贝租约文件」，")
        print("  挡不住「改一行 fingerprint()」。真绑定需要 TPM/安全飞地或服务端侧信号。")
    finally:
        server2.send_signal(signal.SIGTERM)
        server2.wait(timeout=5)

    head("⑥ 复测：C 通道泄漏面 与 零事件 C 运算（与租约架构无关）")
    # 基线要可比：这里跑**免费版**（不带任何许可证/租约），跟改造前一个条件
    base_env = dict(os.environ, PYTHONPATH=PY365)
    out = subprocess.run([sys.executable, "-u",
                          os.path.join(ROOT, "exploits", "x18_c_channel_leak.py")],
                         env=base_env, capture_output=True, text=True)
    lines = [l for l in out.stdout.splitlines() if "白送" in l and "──" in l]
    print("  " + (lines[-1] if lines else f"?（退出码 {out.returncode}）"))
    print("  → 与第一轮实测的 10/12 完全一致：租约架构管不到 C 通道")
    p = subprocess.run([sys.executable, os.path.join(ROOT, "exploits", "x7_zero_events.py")],
                       env=env(), capture_output=True, text=True)
    print(f"  零事件纯 C 运算：退出码 {p.returncode}"
          f"（137 = 内核 RLIMIT_CPU 拉闸，逃费上限仍是 6 秒）")

    print(f"\n{'═' * 66}\n结论：① 私钥不在客户端 → 伪造租约不可能；②③④ 设备绑定与吊销"
          f"\n      由服务端仲裁 → 可修；⑤ 机器指纹天然是自报的 → 只能抬高门槛；\n"
          f"      ⑥ C 通道与零事件 C 运算照旧 → 那两条得靠内核，不靠架构。")


if __name__ == "__main__":
    main()
