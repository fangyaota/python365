"""CPython 启动时自动加载 —— 把任何进程变成订阅制 Python。

这是整套系统的**安装点**：按设计由 `PYTHONPATH` 提供，不做隐藏。
"""
import python365

python365.install()
