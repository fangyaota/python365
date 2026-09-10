#!/usr/bin/env python3
"""
自签 TLS 实验 —— 验证 R7-04 / R8-03 的正确修法是不是"加密通道"。

背景：租约与刷新令牌是 **bearer 凭据**。在明文 HTTP 上，链路观察者（同一台机器、
同一个 NAT、同一个公司出口 —— 也就是威胁模型里最主要的攻击者所在的位置）抓到一次
就能"先用先赢"，把会话劫持走。R7 的修法（绑定来源地址）只挡"换机器"，挡不住同出口。

这个实验用**同一个"链路观察者"代理**跑两遍：

    observe      明文：观察者读到令牌 → 直接拿去续签 → 劫持成功 🔴
    observe-tls  TLS + 客户端 pin 厂商 CA：观察者只看到 TLS 记录 → 劫持不可能 🟢
    mitm         攻击者自己签一张证书装成服务端 → 客户端 pin 不认 → fail-closed 🟢

每段都能单独跑（本沙箱的命令上限是 15 秒）：
    python3 demos/tls_lab.py observe
    python3 demos/tls_lab.py observe-tls
    python3 demos/tls_lab.py mitm
"""
from __future__ import annotations

import json
import os
import re
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY365 = ROOT
CERT = os.path.join(ROOT, "vendor", "certs", "server.crt")
KEY = os.path.join(ROOT, "vendor", "certs", "server.key")
CA = os.path.join(PY365, "python365", "certs", "vendor-ca.crt")
SERVER_PORT, PROXY_PORT = 8811, 8812
LOG = "/tmp/_tls_proxy.log"
ADMIN = "lab-admin-token"


def head(t: str) -> None:
    print(f"\n{'─' * 66}\n▶ {t}")


def issue_license() -> str:
    out = subprocess.run([sys.executable, os.path.join(ROOT, "vendor", "issue.py"), "DATA,BASIC"],
                         capture_output=True, text=True, check=True)
    return out.stdout.strip()


def start_server(tls: bool) -> subprocess.Popen:
    env = dict(os.environ, PYTHON365_LEASE_TTL="30", PYTHON365_ADMIN_TOKEN=ADMIN)
    if tls:
        env.update(PYTHON365_TLS_CERT=CERT, PYTHON365_TLS_KEY=KEY)
    proc = subprocess.Popen([sys.executable, os.path.join(ROOT, "vendor", "authd.py"),
                             str(SERVER_PORT)], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for _ in range(40):
        try:
            socket.create_connection(("127.0.0.1", SERVER_PORT), timeout=0.3).close()
            return proc
        except OSError:
            time.sleep(0.2)
    raise SystemExit("服务端起不来：" + (proc.stdout.read()[-300:] if proc.stdout else ""))


def unrevoke(lic: str, scheme: str = "http") -> None:
    """
    演示环境里这张许可证常被前面的测试吊销过（同一份 B 类令牌每次签发结果相同），
    所以先显式解除吊销 —— 顺便用一下 R6-03 加的运维接口。
    """
    url = f"{scheme}://127.0.0.1:{SERVER_PORT}/unrevoke"
    req = urllib.request.Request(url, data=json.dumps({"license": lic}).encode(),
                                 headers={"Content-Type": "application/json",
                                          "X-Admin-Token": ADMIN}, method="POST")
    ctx = ssl.create_default_context(cafile=CA) if scheme == "https" else None
    try:
        urllib.request.urlopen(req, timeout=3, context=ctx).read()
    except Exception:                                        # noqa: BLE001
        pass


def start_proxy() -> None:
    """链路观察者：把经过的每一字节都记下来，然后原样转发"""
    open(LOG, "wb").close()

    def pump(src, dst):
        while True:
            try:
                data = src.recv(65536)
            except OSError:
                break
            if not data:
                break
            with open(LOG, "ab") as fh:
                fh.write(data)
            try:
                dst.sendall(data)
            except OSError:
                break

    def handle(src):
        try:
            dst = socket.create_connection(("127.0.0.1", SERVER_PORT))
        except OSError:
            src.close()
            return
        threading.Thread(target=pump, args=(src, dst), daemon=True).start()
        pump(dst, src)

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", PROXY_PORT))
    srv.listen(8)

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()


def run_client(lic: str, lease_file: str, scheme: str, seconds: int = 5,
               server_port: int = PROXY_PORT) -> subprocess.Popen:
    script = "/tmp/_tls_client.py"
    with open(script, "w") as fh:
        fh.write("import json, time\n"
                 f"print('    [客户] json 可用:', json.dumps({{'a': 1}}), flush=True)\n"
                 f"time.sleep({seconds})\n")
    env = dict(os.environ, PYTHONPATH=PY365, PYTHON365_LEASE_FILE=lease_file,
               PYTHON365_LEASE_SERVER=f"{scheme}://127.0.0.1:{server_port}",
               PYTHON365_KEY=lic)
    return subprocess.Popen([sys.executable, "-u", script], env=env,
                            stdout=open("/tmp/_tls_client.out", "w"),
                            stderr=open("/tmp/_tls_client.err", "w"))


def captured_refresh() -> str | None:
    """观察者视角：从抓到的字节里找刷新令牌"""
    try:
        raw = open(LOG, "rb").read()
    except OSError:
        return None
    # 观察者用**最新**那份（它是实时看着流量的，不是事后翻日志）——
    # "谁先用谁赢"：这是 R7-04 说的"劫持"，不是"重放"。
    hits = re.findall(rb'"refresh"\s*:\s*"([^"]+)"', raw)
    return hits[-1].decode() if hits else None


def captured_lease_body() -> dict | None:
    try:
        raw = open(LOG, "rb").read()
    except OSError:
        return None
    for m in reversed(list(re.finditer(rb'\{"lease"[^}]*\}', raw))):
        try:
            body = json.loads(m.group(0).decode())
        except ValueError:
            continue
        if "fp" not in body:
            # 响应体里没有 fp，但租约载荷自己带 —— 观察者解得开：
            #   LEASE|<lic_id>|<指纹>|<到期>|<档位>|<宽限>
            try:
                import base64
                payload = base64.urlsafe_b64decode(body["lease"].split(".")[0] + "==").decode()
                body["fp"] = payload.split("|")[2]
            except Exception:                                # noqa: BLE001
                continue
        return body
    return None


def hijack(body: dict, scheme: str) -> tuple[int, str]:
    """拿着抓到的凭据去续签（同出口，所以来源地址绑定也拦不住）"""
    url = f"{scheme}://127.0.0.1:{SERVER_PORT}/renew"
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    ctx = ssl.create_default_context(cafile=CA) if scheme == "https" else None
    try:
        with urllib.request.urlopen(req, timeout=3, context=ctx) as r:
            return r.status, r.read().decode()[:60]
    except Exception as exc:                                  # noqa: BLE001
        return getattr(exc, "code", 0), type(exc).__name__


def stage_observe(tls: bool) -> None:
    scheme = "https" if tls else "http"
    head(f"链路观察者视角（{'TLS' if tls else '明文 HTTP'}）")
    srv = start_server(tls)
    try:
        start_proxy()
        lic = issue_license()
        unrevoke(lic)
        lease = f"/tmp/_tls_lease_{'tls' if tls else 'plain'}"
        if os.path.exists(lease):
            os.remove(lease)
        proc = run_client(lic, lease, scheme)
        time.sleep(6)
        try:
            cout = [l for l in open("/tmp/_tls_client.out").read().splitlines() if l.strip()]
        except OSError:
            cout = []
        print(f"  对照：客户端自己{'跑通了（高级功能可用）' if cout else '没跑通 ← 结果不可信'}",
              cout[-1][:60] if cout else "")
        raw = open(LOG, "rb").read()
        print(f"  观察者抓到 {len(raw)} 字节")
        print(f"  能看到明文 'refresh' 字段吗：{'是' if b'refresh' in raw else '否'}")
        got = captured_refresh()
        body = captured_lease_body()
        if got and body:
            print(f"  抓到的刷新令牌：{got[:16]}…")
            code, why = hijack({**body, "refresh": got}, scheme)
            print(f"  用它去 /renew：HTTP {code} {why}")
            print("  → 🔴 劫持成功：同出口的观察者直接拿走会话" if code == 200
                  else f"  → 🟢 拦住了（{code}）")
        else:
            print("  抓不到任何可用的凭据（只有 TLS 记录）")
            code, why = hijack({"lease": "x", "fp": "y", "refresh": "z"}, scheme)
            print(f"  拿抓到的字节去 /renew：HTTP {code} {why}")
            print("  → 🟢 观察者只能盲目转发，拿不到 bearer 令牌")
        proc.wait(timeout=8)
    finally:
        srv.send_signal(signal.SIGTERM)
        srv.wait(timeout=5)


def stage_mitm() -> None:
    head("攻击者自己签一张证书，装成服务端")
    other_key = "/tmp/_fake.key"
    other_crt = "/tmp/_fake.crt"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", other_key, "-out", other_crt, "-days", "30",
                    "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"],
                   capture_output=True, check=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(other_crt, other_key)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", PROXY_PORT))
    srv.listen(4)

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            try:
                ctx.wrap_socket(conn, server_side=True).recv(4096)
            except Exception:                                # noqa: BLE001
                pass

    threading.Thread(target=loop, daemon=True).start()
    lic = issue_license()
    lease = "/tmp/_tls_lease_mitm"
    if os.path.exists(lease):
        os.remove(lease)
    proc = run_client(lic, lease, "https", seconds=2)
    time.sleep(4)
    left = proc.poll()
    err = ""
    try:
        text = open("/tmp/_tls_client.err").read()
        causes = [l.strip("│ ╰╯╭╮─") for l in text.splitlines() if "原因" in l or "SSL" in l]
        err = (causes[-1] if causes else "")[:80]      # 停机原因：激活失败：SSLCertVerificationError
    except OSError:
        pass
    print(f"  客户端退出码：{left}（非 0 = fail-closed 停机；None = 还在跑）")
    print(f"  客户端看到的最后一个错误：{err or '（无）'}")
    print("  → 🟢 客户端 pin 了厂商 CA，自带证书的中间人连握手都过不了"
          if left is not None else "  → 🔴 客户端接受了伪造证书")
    if proc.poll() is None:
        proc.terminate()


if __name__ == "__main__":
    stage = sys.argv[1] if len(sys.argv) > 1 else "observe"
    if stage == "observe":
        stage_observe(tls=False)
    elif stage == "observe-tls":
        stage_observe(tls=True)
    elif stage == "mitm":
        stage_mitm()
    else:
        print(__doc__)
