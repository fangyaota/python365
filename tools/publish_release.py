#!/usr/bin/env python3
"""
发布 GitHub Release（建 Release + 附上交付版 zip）。

    export GITHUB_TOKEN=ghp_xxx          # 细粒度 token 即可：只需 Contents: Read and write
    python3 tools/publish_release.py v1.0.0

为什么需要单独一个脚本：**git 只能推 commit 和 tag，Release 是 API 对象** ——
SSH 推送不会产生 Release（tag 会出现在 Tags 页，但 Releases 页是空的）。
所以这一步必须有凭据。两条路随你选：

    ① 网页（不用密码学凭据）：仓库 → Releases → Draft a new release → 选 v1.0.0 →
       把 RELEASE_NOTES.md 的内容粘进去 → 附上 python365_release.zip → Publish
    ② 本脚本：给一个只限本仓库的细粒度 token（Contents: Read and write），一条命令搞定

脚本做的事：读 RELEASE_NOTES.md 当说明 → POST 建 Release → 上传 zip 资产。
tag 已存在时不会重复创建；Release 已存在时只补上传资产。
"""
from __future__ import annotations

import json
import os
import sys
import urllib.request

REPO = os.environ.get("GITHUB_REPOSITORY", "fangyaota/python365")
TOKEN = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
API = "https://api.github.com"


# ⚠️ 上传资产走的是 **uploads.github.com**，不是 api.github.com（用错会得到 404）
UPLOAD_API = "https://uploads.github.com"


def api(method: str, path: str, payload: dict | None = None, raw: bytes | None = None,
        ctype: str = "application/json", host: str | None = None) -> tuple[int, dict]:
    data = raw if raw is not None else (json.dumps(payload).encode() if payload else None)
    req = urllib.request.Request(f"{host or API}{path}", data=data, method=method,
                                 headers={"Authorization": f"Bearer {TOKEN}",
                                          "Accept": "application/vnd.github+json",
                                          "Content-Type": ctype,
                                          "User-Agent": "python365-release"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = resp.read()
            return resp.status, (json.loads(body) if body else {})
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def main() -> None:
    tag = sys.argv[1] if len(sys.argv) > 1 else "v1.0.0"
    if not TOKEN:
        raise SystemExit("缺少 GITHUB_TOKEN（见文件头注释里的两条路）")

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    notes = open(os.path.join(root, "RELEASE_NOTES.md"), encoding="utf-8").read()
    zip_path = os.path.join(root, "python365_release.zip")
    if not os.path.exists(zip_path):
        raise SystemExit("缺 python365_release.zip —— 先跑 tools/build_release.py --zip")

    code, rel = api("POST", f"/repos/{REPO}/releases",
                    {"tag_name": tag, "name": f"Python 365 {tag}",
                     "body": notes, "draft": False, "prerelease": False})
    if code == 422:                                   # 已存在
        code, rel = api("GET", f"/repos/{REPO}/releases/tags/{tag}")
    if code >= 300:
        raise SystemExit(f"建 Release 失败：{code} {rel}")
    print(f"  Release 就绪：{rel['html_url']}")

    def upload(target: dict) -> tuple[int, dict]:
        with open(zip_path, "rb") as fh:
            blob = fh.read()
        return api("POST", f"/repos/{REPO}/releases/{target['id']}/assets"
                           f"?name=python365_release.zip", raw=blob,
                   ctype="application/zip", host=UPLOAD_API)

    code, asset = upload(rel)
    if code == 422:                                   # 同名资产已存在 → 先删再传
        for existing in rel.get("assets", []):
            if existing["name"] == "python365_release.zip":
                api("DELETE", f"/repos/{REPO}/releases/assets/{existing['id']}")
        code, asset = upload(rel)
    if code >= 300:
        print(f"  资产上传失败：{code} {asset.get('errors') or asset.get('message')}")
    else:
        print(f"  资产已上传：{asset['name']}（{asset['size'] / 1024:.0f} KB）")
        print(f"  下载地址：{asset['browser_download_url']}")


if __name__ == "__main__":
    main()
