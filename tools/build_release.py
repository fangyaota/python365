#!/usr/bin/env python3
"""
构建**客户交付版**（release）—— 只带客户需要的东西。

    python3 tools/build_release.py          # 产出 python365_release/
    python3 tools/build_release.py --zip    # 另外打一个 zip

为什么要写脚本而不是手拷：交付版**绝不能**包含下面这些，而"手拷"迟早会漏一个 ——

    vendor/        私钥 + 发证工具 + 授权服务端   ← R3-12 / R4-06 的教训：私钥泄露 = 全局归零
    exploits/      约 65 个可用 PoC + 审计报告     ← 等于把破解工具一起发货
    demos/ tools/  开发与演示材料
    AUDIT.md       内部审计记录（含每一轮的攻击手法）
    __pycache__/   编译产物；certs/server.key 证书私钥

所以这几条在脚本里是**断言**：白名单里一旦出现它们，构建直接失败。
最后还会跑一次冒烟测试（装上 → 拦一道墙 → 带许可证解锁），避免发出一个跑不起来的东西。

注意：**授权服务端（vendor/authd.py）不在交付版里** —— 它在厂商侧运行，
客户端只带公钥和 pin 的 CA（python365/certs/vendor-ca.crt）。
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "python365_release")

# ── 白名单：交付版**只有**这些 ────────────────────────────────────────
FILES = [
    "sitecustomize.py",
    "python365/__init__.py",
    "python365/_tiers.py",
    "python365/_trust.py",
    "python365/_license.py",
    "python365/_meter.py",
    "python365/_walls.py",
    "python365/_guard.py",
    "python365/_gate.py",
    "python365/_lease.py",
    "python365/_ui.py",
    "python365/certs/vendor-ca.crt",
]

# ── 黑名单：出现即失败（不光是"不拷"，而是**断言**）──────────────────
# 目录名按**路径分量**精确比（否则 vendor-ca.crt 这种合法文件名会被误杀 —— 第一次构建就踩了）
FORBIDDEN_PARTS = {"vendor", "exploits", "demos", "tools", "__pycache__", "audit"}
# 文件名/内容里的危险子串，按子串比
FORBIDDEN_PATH = ("private_key", "server.key", ".pyc", "REPORT_ROUND", "FORGED")
FORBIDDEN_TEXT = ("private_key", "PRIVATE KEY-----", "REPORT_ROUND", "exploits/", "AUDIT.md")
TEXT_SUFFIX = (".py", ".md", ".txt", ".crt")


def strip_dev_notes(src: str) -> str:
    """
    去掉注释与文档字符串。

    交付版不该附带"我们过去哪儿被打穿过"的叙述 —— 开发树里的注释写得很厚
    （44 处「第 N 轮 R-XX」），那是审计材料，不是客户材料。
    只在**产物**上做，开发树一字不动；剥离后必须能编译，并由冒烟测试兜底。
    """
    import ast
    import io
    import tokenize

    lines = src.splitlines(keepends=True)
    drop: set[int] = set()

    for tok in tokenize.generate_tokens(io.StringIO(src).readline):     # ① 注释
        if tok.type != tokenize.COMMENT:
            continue
        row, col = tok.start
        if lines[row - 1][:col].strip():        # 行尾注释：切掉后半段
            lines[row - 1] = lines[row - 1][:col].rstrip() + "\n"
        else:                                   # 整行注释：删掉
            drop.add(row)

    tree = ast.parse(src)                                                # ② 文档字符串
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.FunctionDef,
                                 ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        body = getattr(node, "body", [])
        if not body:
            continue
        first = body[0]
        if not (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)):
            continue
        start = first.lineno
        end = first.end_lineno or start
        if len(body) == 1 and not isinstance(node, ast.Module):
            # 函数体只有 docstring → 删了会变空，塞一个 pass 进去
            indent = " " * (first.col_offset)
            lines[start - 1:end] = [indent + "pass\n"]
        else:
            drop.update(range(start, end + 1))

    out = "".join(line for i, line in enumerate(lines, 1) if i not in drop)
    compile(out, "<stripped>", "exec")          # 剥完必须还是合法 Python
    return out


def build_readme() -> str:
    """客户版 README：定价表从 _tiers.py 现场生成，永不漂移"""
    sys.path.insert(0, ROOT)
    from python365._tiers import TIERS

    rows = []
    for code, (name, price, blurb, _targets) in TIERS.items():
        rows.append(f"| **{code}** {name} | ¥{price}/月 | {blurb} |")
    template = open(os.path.join(ROOT, "tools", "release_README.md")).read()
    version = open(os.path.join(ROOT, "tools", "release_VERSION.txt")).read().strip()
    return template.replace("{{PRICING}}", "\n".join(rows)).replace("{{VERSION}}", version)


def check_no_forbidden(path: str, rel: str) -> None:
    low = rel.lower()
    parts = set(low.replace("\\", "/").split("/"))
    for bad in FORBIDDEN_PARTS:
        assert bad not in parts, f"交付版里出现了禁止目录：{rel}（命中 {bad!r}）"
    for bad in FORBIDDEN_PATH:
        assert bad not in low, f"交付版里出现了禁止项：{rel}（命中 {bad!r}）"
    if rel.endswith(TEXT_SUFFIX):
        text = open(path, encoding="utf-8", errors="replace").read()
        for bad in FORBIDDEN_TEXT:
            assert bad not in text, f"{rel} 里出现了敏感内容：{bad!r}"


def smoke_test(py_path: str) -> str:
    """跑一遍：装上 → 拦一道墙 → 带许可证解锁。跑不起来就不许发。

    PYTHONDONTWRITEBYTECODE=1：否则测试本身会在产物里留下 __pycache__
    （第一次构建就发生了：25 个文件里 11 个是编译产物）。
    """
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    blocked = subprocess.run(
        [sys.executable, "-c", "import json; json.dumps({'a': 1})"],
        env=dict(os.environ, PYTHONPATH=py_path), capture_output=True, text=True)
    assert blocked.returncode != 0, "冒烟失败：免费版居然没拦住 json.dumps"

    banner = subprocess.run(
        [sys.executable, "-c", "pass"],
        env=dict(os.environ, PYTHONPATH=py_path), capture_output=True, text=True)
    assert "Python 365" in (banner.stderr + banner.stdout), "冒烟失败：启动横幅没出现"

    lic = subprocess.run(
        [sys.executable, os.path.join(ROOT, "vendor", "issue.py"), "DATA,BASIC"],
        capture_output=True, text=True, check=True).stdout.strip()
    activated = subprocess.run(
        [sys.executable, "-c", "import json; print(json.dumps({'a': 1}))"],
        env=dict(os.environ, PYTHONPATH=py_path, PYTHON365_KEY=lic),
        capture_output=True, text=True)
    assert '"a": 1' in activated.stdout, f"冒烟失败：带许可证也解不开\n{activated.stderr[-300:]}"
    return "免费版拦住 json.dumps ✓ · 横幅出现 ✓ · 带许可证解锁 ✓"


def main() -> None:
    if os.path.exists(OUT):
        shutil.rmtree(OUT)
    os.makedirs(OUT)

    copied = 0
    for rel in FILES:
        src = os.path.join(ROOT, rel)
        assert os.path.exists(src), f"缺文件：{rel}"
        check_no_forbidden(src, rel)
        dst = os.path.join(OUT, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if rel.endswith(".py") and "--keep-comments" not in sys.argv:
            with open(src, encoding="utf-8") as fh:
                stripped = strip_dev_notes(fh.read())
            with open(dst, "w", encoding="utf-8") as fh:
                fh.write(stripped)
        else:
            shutil.copy2(src, dst)
        copied += 1

    readme = build_readme()
    for bad in FORBIDDEN_TEXT:
        assert bad not in readme, f"交付版 README 里有敏感内容：{bad!r}"
    with open(os.path.join(OUT, "README.md"), "w", encoding="utf-8") as fh:
        fh.write(readme)
    shutil.copy2(os.path.join(ROOT, "tools", "release_VERSION.txt"),
                 os.path.join(OUT, "VERSION"))

    result = smoke_test(OUT)

    # 交付前最后一道：对**整个产物目录**再走一遍黑名单
    # （冒烟测试、编译产物、以后新增的东西都可能混进来）
    for r, dirs, files in os.walk(OUT):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for f in files:
            full = os.path.join(r, f)
            check_no_forbidden(full, os.path.relpath(full, OUT))
    for r, dirs, files in os.walk(OUT, topdown=False):
        if os.path.basename(r) == "__pycache__":
            shutil.rmtree(r)

    total = sum(len(files) for _r, _d, files in os.walk(OUT))
    size = sum(os.path.getsize(os.path.join(r, f))
               for r, _d, files in os.walk(OUT) for f in files)
    print(f"交付版已生成：{OUT}")
    print(f"  {total} 个文件 · {size / 1024:.0f} KB · 白名单 {copied} 项 + README + VERSION")
    print(f"  冒烟测试：{result}")

    if "--zip" in sys.argv:
        dest = os.path.join(ROOT, "python365_release.zip")
        with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
            for r, _d, files in os.walk(OUT):
                for f in files:
                    full = os.path.join(r, f)
                    # 带上顶层目录名，解压时不会散落一地
                    zf.write(full, os.path.join("python365_release",
                                                os.path.relpath(full, OUT)))
        print(f"  已打包：{dest}（{os.path.getsize(dest) / 1024:.0f} KB）")


if __name__ == "__main__":
    main()
