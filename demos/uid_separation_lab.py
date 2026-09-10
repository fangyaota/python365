"""
"私钥到底谁能用"实验 —— 用两个不依赖文件权限的实验来证明分离：

  实验 A：把私钥**移出文件系统**（藏到别处）
          → 客户端（带许可证、走租约）照常工作 ✅
          → 服务端立刻瘫（它才是需要私钥的那一方）✅
          结论：客户端**不需要**私钥 —— 不是"不该有"，是"没有也行"。

  实验 B：客户端自己伪造一张 ENTERPRISE 租约
          → 验签返回 None ✅（它只有公钥，签名伪造不出来）

⚠️ 为什么不用"以 nobody 运行 + 文件权限"来演示？
   本沙箱是 proot（fake-root）环境：`setpriv` 能改 uid（`id` 显示 nobody），
   但 proot 把文件权限检查放宽了 —— nobody 照样读得到 0600 root 的文件。
   也就是说**权限语义在这个环境里测不出来**，测了会得出错误结论。
   在普通系统上，`0700 vendor 目录 + 0600 私钥 + 客户端以非特权用户运行`
   就是正确的隔离配置（这点仍然成立，只是没法在这里演示）。

真实部署的隔离强度：同机不同 uid < 不同机器 < HSM/签名服务。
厂商的私钥在厂商机器上 —— 客户端用户永远够不着，这才是根本。

运行：python3 demos/uid_separation_lab.py
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY365 = ROOT          # 搬迁后：项目根就是 PYTHONPATH 那一层
PORT = 8796
SERVER = f"http://127.0.0.1:{PORT}"
LEASE_FILE = "/tmp/.python365_lease_iso"
KEYDIR = os.path.expanduser("~/.python365-vendor")
KEY = os.path.join(KEYDIR, "private_key.json")
HIDDEN = "/tmp/.key_hidden_during_test"


ADMIN_TOKEN = "lab-admin-token"          # /state 是管理接口，需要认证


def fetch_state() -> dict:
    req = urllib.request.Request(f"{SERVER}/state",
                                 headers={"X-Admin-Token": ADMIN_TOKEN})
    with urllib.request.urlopen(req, timeout=2.0) as r:
        return json.loads(r.read())


def head(t: str) -> None:
    print(f"\n{'─' * 66}\n▶ {t}")


def client_env(**extra) -> dict:
    e = dict(os.environ, PYTHONPATH=PY365, PYTHON365_LEASE_FILE=LEASE_FILE)
    e.update({k: str(v) for k, v in extra.items()})
    return e


def run_client(lic: str, seconds: int = 1) -> subprocess.CompletedProcess:
    path = "/tmp/_iso_client.py"
    with open(path, "w") as fh:
        fh.write("import json, sys, time\n"
                 "try:\n"
                 "    json.dumps({'a': 1}); print('    json 可用', flush=True)\n"
                 "except Exception as e:\n"
                 "    print('    json 被拦:', type(e).__name__, flush=True)\n"
                 "time.sleep(float(sys.argv[1]) if len(sys.argv) > 1 else 0)\n")
    return subprocess.run([sys.executable, "-u", path, str(seconds)],
                          env=client_env(PYTHON365_LEASE_SERVER=SERVER, PYTHON365_KEY=lic),
                          capture_output=True, text=True, timeout=120)


def start_server(env_extra: dict | None = None):
    return subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "vendor", "authd.py"), str(PORT)],
        env=dict(os.environ, PYTHON365_LEASE_TTL="30", **(env_extra or {})),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def wait_server(proc, timeout: float = 10.0) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        if proc.poll() is not None:
            return False
        try:
            fetch_state()
            return True
        except Exception:                                    # noqa: BLE001
            time.sleep(0.25)
    return False


def main() -> None:
    print("═══ 权限配置（在普通系统上就是隔离配置）═══")
    os.makedirs(KEYDIR, exist_ok=True)
    os.chmod(KEYDIR, 0o700)
    if os.path.exists(KEY):
        os.chmod(KEY, 0o600)
    print(f"  {KEYDIR} → {oct(os.stat(KEYDIR).st_mode)[-3:]}（仅厂商可进）")
    print(f"  {KEY} → {oct(os.stat(KEY).st_mode)[-3:]}（仅厂商可读）")
    print("  ⚠️ 本沙箱是 proot(fake-root)：权限语义测不出来，所以下面用两个"
          "\n     不依赖文件权限的实验来证明分离。")

    head("① 服务端以**有私钥**的状态启动 → 正常，并签发一张许可证")
    srv = start_server()
    if not wait_server(srv):
        raise SystemExit(srv.stdout.read()[-400:])
    print(f"  服务端就绪 :{PORT}")
    lic = subprocess.run([sys.executable, os.path.join(ROOT, "vendor", "issue.py"), "DATA,BASIC"],
                         capture_output=True, text=True, check=True).stdout.strip()
    print(f"  许可证：{lic[:44]}…")

    head("② 客户端首次激活（服务端签租约）→ 高级功能可用")
    if os.path.exists(LEASE_FILE):
        os.remove(LEASE_FILE)
    out = run_client(lic, 1)
    print("  " + "\n  ".join(l for l in out.stdout.splitlines() if "json" in l))

    head("③ 实验 A：把私钥**移出文件系统**，客户端照常跑（它压根不需要）")
    try:
        _experiment_a(lic, srv)
    finally:
        if not os.path.exists(KEY) and os.path.exists(HIDDEN):
            shutil.move(HIDDEN, KEY)             # 崩溃也要还原（上次被崩溃的 lab 藏走过）
            os.chmod(KEY, 0o600)
            print(f"\n  （私钥已还原到 {KEY}）")


def _experiment_a(lic: str, srv) -> None:
    shutil.move(KEY, HIDDEN)
    print(f"  私钥已藏到 {HIDDEN}（原路径不存在了）")
    out = run_client(lic, 1)
    banner = [l for l in out.stdout.splitlines() if "📜" in l]
    print("  " + (banner[0].strip()[:100] if banner else ""))
    print("  " + "\n  ".join(l for l in out.stdout.splitlines() if "json" in l))
    print("  → 客户端不需要私钥，租约流程照常 ✅")

    head("④ 实验 A 的另一半：没有私钥，**签发动作**全瘫")
    print("  注意：服务端**启动**时不读私钥（只在签发那一刻才读），所以要看签发：")

    sys.path.insert(0, PY365)
    from python365._lease import fingerprint as _fp          # 本脚本原生跑，不加载付费墙
    real_fp = _fp()

    def activate() -> str:
        req = urllib.request.Request(f"{SERVER}/activate",
                                     data=json.dumps({"license": lic, "fp": real_fp}).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return "✅ 成功签发租约"
        except Exception as exc:                             # noqa: BLE001
            body = ""
            try:
                body = json.loads(exc.read().decode()).get("error", "")
            except Exception:                                # noqa: BLE001
                pass
            return f"✗ 失败：{type(exc).__name__} {body}"

    issue = subprocess.run([sys.executable, os.path.join(ROOT, "vendor", "issue.py"), "DATA"],
                           capture_output=True, text=True)
    print(f"  厂商签发许可证（issue.py） → "
          f"{'✗ 失败：' + issue.stderr.strip().splitlines()[-1][-60:] if issue.returncode else '居然成功'}")
    print(f"  服务端 /activate           → {activate()}")
    print("  → 私钥只对**厂商侧**有用：没有它，许可证和租约都签不出来 ✅")

    shutil.move(HIDDEN, KEY)                     # 还原
    os.chmod(KEY, 0o600)
    print(f"  （私钥已还原到 {KEY}）")
    time.sleep(0.3)
    print(f"  还原后再试 /activate       → {activate()}")
    srv.send_signal(signal.SIGTERM)
    srv.wait(timeout=5)

    head("⑤ 实验 B：客户端自己伪造一张 ENTERPRISE 租约")
    forge = (
        "import base64, time, sys\n"
        "sys.path.insert(0, %r)\n"
        "from python365._license import PUBLIC_KEY\n"
        "from python365._lease import parse_lease\n"
        "p = ('LEASE|deadbeef|0123456789abcdef|' + str(int(time.time()) + 9999) + '|ENTERPRISE').encode()\n"
        "n, e = PUBLIC_KEY\n"
        "sig = pow(123456789, e, n).to_bytes(128, 'big')\n"
        "enc = base64.urlsafe_b64encode\n"
        "tok = enc(p).decode().rstrip('=') + '.' + enc(sig).decode().rstrip('=')\n"
        "print('    伪造 ENTERPRISE 租约 →', parse_lease(tok))\n"
    ) % PY365
    out = subprocess.run([sys.executable, "-c", forge],
                         env=client_env(), capture_output=True, text=True)
    print(out.stdout.strip() or out.stderr.strip()[-200:])
    print("  → None = 无效：客户端只有公钥，签名伪造不出来 ✅")

    print(f"\n{'═' * 66}\n结论：\n"
          "  ✅ 客户端**不需要**私钥（实验 A：藏起来照常跑）\n"
          "  ✅ 服务端**才是**需要私钥的一方（实验 A：藏起来它起得来、但签不出任何东西）\n"
          "  ✅ 拿不到私钥 ⇒ 伪造不出许可证与租约（实验 B）\n"
          "  ⚠️ 本沙箱测不了文件权限语义（proot fake-root）——在普通系统上\n"
          "     0700/0600 + 非特权客户端 = 读不到；真实的根本隔离是「私钥在厂商机器上」")


if __name__ == "__main__":
    main()
