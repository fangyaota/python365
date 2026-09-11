# Python 365 · v{{VERSION}}

> 订阅制 Python 运行时。装上之后，**没买的部分会拦住你** ——
> 标准库按模块卖，语言特性按版本卖。

## 安装

不需要 `pip`，把 `PYTHONPATH` 指向本目录即可：

```bash
# 免费版：任何程序一启动就上锁
PYTHONPATH=/path/to/python365_release python3 你的程序.py

# 原生对照（不装这套）
python3 你的程序.py
```

**要求**：Python 3.12 及以上（依赖 PEP 669 的 `sys.monitoring`）。

## 激活

```bash
# ① 离线许可证：厂商签发的一串激活码
PYTHON365_KEY='PYTHON365.xxx.yyy' \
PYTHONPATH=/path/to/python365_release python3 你的程序.py

# 多个版本叠加用逗号
PYTHON365_KEY='码1,码2' PYTHONPATH=... python3 你的程序.py

# ② 在线租约（推荐：可绑定设备、可吊销、短周期续签）
PYTHON365_LEASE_SERVER=https://auth.vendor.example \
PYTHON365_KEY='PYTHON365.xxx.yyy' \
PYTHONPATH=/path/to/python365_release python3 你的程序.py
```

租约模式会把许可证绑到本机指纹、周期性向厂商续签；续签失败（换机 / 被吊销 / 长期离线）即停机。

## 价目表

| 版本 | 价格 | 一句话 |
|---|---|---|
{{PRICING}}

`ENTERPRISE` 一次解锁全部版本。

**免费版包含**：算术与 `print`、每 5 万次函数调用、3 秒 CPU 时间（随机数被降级为常量，并带广告）。

## 程序侧 API（只读）

```python
import python365

python365.installed()          # 这个进程装墙了吗
python365.owned_tiers()        # 已订阅的版本号
python365.usage()              # 账单快照：① 调用次数 ② CPU 时间
python365.stats()              # 装配统计（墙数 / 包装层 / 加固状态）
python365.apply_topup(token)   # 续费：应用厂商签名的加油包令牌
```

## 已知限制

诚实说明，免得期待错位：

- **它拦得住的是"没打算绕"的人。** 执法逻辑运行在你自己的进程里，本机内存里的一切
  对进程内的代码都是可改的 —— 这是"进程内计费"这一形态的固有上限，不是配置问题。
- **C 实现的标准库**（`math` / `datetime` / `hashlib` / `sqlite3` …）挂不上钩子，
  只有「原生扩展包 NATIVE」那道 import 闸门能设卡，且默认关闭。
- **若干 C 通道**（`os.urandom`、`ctypes` 等）不经过 Python 层，无法计费。
- **为限制零事件的纯 C 运算**，免费版会设置内核 `RLIMIT_CPU`（约 6 秒/进程）：
  超支时你收到的是内核的 `Killed`，而不是我们的付费墙提示。
- 免费版启动比原生慢一些（要装载数千道付费墙）。
- 机器指纹由客户端上报，因此设备绑定只能挡住"老实拷贝"。

## 卸载

不带这套 `PYTHONPATH` 启动即可 —— 它只在被显式指定时生效，不会污染系统 Python。

## 版本

`{{VERSION}}` · 客户端只包含**公钥**与厂商 CA 证书；签名能力只在厂商侧。
