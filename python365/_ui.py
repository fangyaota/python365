"""终端输出：配色与方框。所有面向用户的排版都从这里出，避免各模块各画一套。"""
from __future__ import annotations

import sys

R, B, DIM = "\033[0m", "\033[1m", "\033[2m"
GOLD, RED, GREY, CYAN, GREEN = "\033[33m", "\033[31m", "\033[90m", "\033[36m", "\033[32m"
WIDTH = 66


def box(title: str, lines: list[str], color: str = RED, indent: str = "") -> None:
    """画一个 ⛔/🚨 提示框到 stderr（先 flush stdout 保证时序不乱）"""
    sys.stdout.flush()
    print(f"\n{indent}{R}{color}╭{'─' * WIDTH}╮{R}", file=sys.stderr)
    print(f"{indent}{color}│{R}  {B}{title}{R}", file=sys.stderr)
    for line in lines:
        print(f"{indent}{color}│{R}  {DIM}{line}{R}", file=sys.stderr)
    print(f"{indent}{color}╰{'─' * WIDTH}╯{R}", file=sys.stderr, flush=True)


def banner_box(lines: list[str]) -> None:
    """顶部横幅（stdout，带边框）"""
    print(f"\n{CYAN}╔{'═' * (WIDTH + 2)}╗{R}")
    for line in lines:
        print(f"{CYAN}║{R} {line}")
    print(f"{CYAN}╚{'═' * (WIDTH + 2)}╝{R}", flush=True)


def ad(text: str) -> None:
    print(f"\n{GREY}   ┌── 广告 ─────────────────────────────────────────────"
          f"\n   │ 📢 {text}"
          f"\n   └─────────────────────────────────────────────────────{R}", flush=True)
