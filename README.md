# Python 365 — 订阅制 Python 运行时

用 [dowhen](https://github.com/gaogaotiantian/dowhen) 在解释器启动时把**付费墙挂到语言和标准库上**。
不改 Python 源码，不改你的程序，一个字节都不动。

## 文件地图

```
python365/
├── sitecustomize.py          ← 安装点：CPython 启动时自动加载
├── README.md
└── python365/                ← 包（1258 行，按职责拆分）
    ├── __init__.py           公开 API + 装配流程（顺序见文件头注释）
    ├── _tiers.py             定价表（唯一的事实来源）
    ├── _trust.py             身份验真："这一帧到底是谁" —— 整套系统的地基
    ├── _meter.py             双层计费（调用次数 + CPU）、断供话术、广告
    ├── _walls.py             付费墙本体（dowhen 模块墙 / C 包装层 / 随机数降级）
    ├── _guard.py             反篡改（冗余监控器 / 探针自测 / 蜜罐 / 内核兜底 / fork）
    ├── _gate.py              import 闸门（三层，默认关闭）
    ├── _license.py           RSA 签名许可证
    └── _ui.py                终端输出（配色与方框）
```

> `sitecustomize.py` 必须留在 `python365/` 顶层（它是被 `site` 作为顶层模块导入的），
> 包则嵌在里面供 `import python365` 使用 —— 所以 `PYTHONPATH` 始终指向 `python365/` 这一层。

## 用法

```bash
# 免费版：任何程序一启动就上锁
PYTHONPATH=/workspace/python365 python3 你的程序.py

# 加购（许可证由厂商私钥签发，客户端只有公钥，伪造不了）
PYTHON365_KEY='PYTHON365.xxx.yyy' PYTHONPATH=/workspace/python365 python3 你的程序.py

# 打开 import 闸门：连 import 都要收费（会打断现有脚本的顶层 import，默认关闭）
PYTHON365_IMPORT_GATE=1 PYTHONPATH=/workspace/python365 python3 你的程序.py
```

程序侧只需要一个只读 API：

```python
import python365
python365.installed()          # 这个进程装墙了吗
python365.owned_tiers()        # 已订阅的版本号
python365.usage()              # 账单快照：①调用次数 ②CPU 时间
python365.stats()              # 装配统计：付费墙数 / C 包装层数 / 加固状态
python365.apply_topup(token)   # 续费：应用**厂商签名的**加油包令牌
```

> ⚠️ 客户端公开面里**没有** `set_quota` / `topup` —— 额度只能靠厂商签名的令牌变更。
> 早先那对脚手架函数挂在公开 API 上，等于自助充值（第三轮 R3-6）。

## 定价表

| 版本 | 价格 | 解锁内容 |
|---|---|---|
| Free | ¥0 | 只能算术 + `print`。**5 万次函数调用 + 3.0 秒 CPU 时间/月**，带广告，随机数恒为 0 |
| CORE 语法包 | ¥9/月 | `lambda` / 生成器 / `async` |
| BASIC 基础版 | ¥19/月 | `collections` `heapq` `functools` `copy` |
| TEXT 文字版 | ¥29/月 | `re` `string` `textwrap` `difflib` `ast` `tokenize` |
| DATA 数据版 | ¥39/月 | `json` `csv` `base64` `xml` `tomllib` `configparser` `zipfile` `tarfile` `gzip` |
| NATIVE 原生扩展包 | ¥49/月 | `math` `datetime` `hashlib` `sqlite3` `struct` `itertools` …（C 模块，只能在 import 那道门收税） |
| SCIENCE 科学版 | ¥59/月 | `statistics` `fractions` `calendar` `uuid` `secrets` + 随机数降级（含 `_random` 入口；`os.urandom` 那条 C 通道封不住，见下） |
| DEVTOOLS 开发工具版 | ¥69/月 | `logging` `argparse` `dataclasses` `typing` `enum` `unittest` `pdb` `doctest` `zoneinfo` |
| SYSTEM 系统版 | ¥79/月 | `pathlib` `os.path` `shutil` `glob` `tempfile` `subprocess` `fnmatch` |
| CONCURRENCY 并发版 | ¥129/月 | `threading` `asyncio` `multiprocessing` `queue` `concurrent.futures` |
| NETWORK 网络版 | ¥199/月 | `urllib` `http.client` `http.server` `email` `smtplib` |
| ENTERPRISE 企业版 | ¥4999/年 | 全部权益，0 道付费墙 |

## 双层计费

| 层 | 计什么 | 实现 | 抓得住 | 漏得掉 |
|---|---|---|---|---|
| ① 函数调用 | 5 万次/月 | `when(None, "<start>")` 全局事件，每调用记一笔 | 函数拆得碎的代码 | C 层运算（`sum(range(10**8))` 是 **0 次调用**） |
| ② CPU 时间 | 3.0 秒/月 | 后台心跳线程 50Hz 采样 `os.times()` / `clock_gettime` / `process_time` 三源取最大 | 一切烧 CPU 的东西，含 C 层 | 几乎不漏（20ms 采样粒度） |

**断供点**：`<start>` 与 `<return>` 两个全局事件 —— 超支后在下一个 Python 边界抛 `SubscriptionRequired`。
单个超长 C 调用无法被打断，只能等它回到 Python 边界。

## 加固（红队审计后）

经历 12 项攻击（11 项攻破）后做了针对性加固，现在 **11/11 全部封堵**（详见 `exploits/REPORT.md`）：

| 机制 | 挡住的攻击 |
|---|---|
| **双源时钟**：三个来源取最大，导入期缓存函数对象 | 篡改 `time.process_time` |
| **身份验真**：自称标准库的帧要过 `sys.modules[name].__dict__ is frame.f_globals` 同一性校验 | 伪造 `co_filename` / `__name__` |
| **冗余监控器**（3 号工具位）+ **探针自测** + **额度影子值** → 篡改即终止 | `dowhen.clear_all()` / 改计量表 |
| **删掉对手的武器**：`del sys.monitoring`（不在 `sys.modules` 里，删除不可逆）+ 原位放**蜜罐** | 任何试图关闭监控的路径 |
| **C 模块 Python 包装层**（并替换所有别名引用） | 用 `_csv` / `_json` / `_heapq` 白嫖 |
| **内核 `RLIMIT_CPU`**（soft==hard）+ fork 时收紧到剩余额度 | 零事件纯 C 运算 / fork 逃逸 |
| **RSA 签名许可证**（私钥只在厂商侧）+ 到期日 | 伪造激活码 |
| **授权决策启动期固化**：墙 / CORE 语法闸门 / import 闸门全部在启动期定好，运行期不再读授权表 → 改 `_owned` 结构上失效；另有冻结副本同步比对，篡改即终止 | 运行期篡改授权表 |
| **可信时间**：到期判定不用系统时钟 —— 网络时间（HTTPS `Date`）/ 高水位（本地记录见过的最大时间）/ 本地时钟**三者取最大**，所以回拨无效；高水位文件还有内存副本兜底（删掉会被看门狗抓到） | 拨回系统时钟复活过期许可证 |
| **import 闸门**三层（`_find_and_load` 钩子 + `__import__` 包装层 + `meta_path` Finder） | C 模块的越狱通道 |
| **顶层帧一律是用户代码**：`python3 - < x.py` / `-c` 的 `__main__` 不再被当成"可信"，`__main__` 从可信分支里彻底移除（R4-01/02/03） | 换启动方式白嫖 |
| **原对象只进闭包**：包装层不再挂 `__python365_shim__`（R4-02） | 从包装层身上取回未受保护的 C 函数 |
| **账户只导出函数**：去掉 `state`/`busy_state`/`bind_checker`，`renew` 收进 `apply_topup` 内部验签（R4-03） | 双写影子值 / 卡死计量总闸 |
| **判定器全参数化**：`terminate`/`alarm`/`registry_size`/`high_water` 也进默认参数，`os._exit` 导入期缓存（R4-05） | 劫持 `_guard.os` 吃掉终止动作 |
| **惰性补墙**：快照按包根匹配 + 挂在真正会被调用的 `_find_and_load` 上（R4-07） | `logging.handlers` / `xml.dom.minidom` 等后加载子模块裸奔 |
| **身份只认代码对象身份**：`__name__` 是用户可写字段，改用它判"是不是自己人"= 一行白嫖全部（第三轮 R3-1） | 改名冒充监控器 |
| **执法动作闭包化**：额度/用量/判定器/探针全部住进启动期构造的闭包，模块字典里不留可替换的名字（R3-3/4/5） | 改 `_syntax_gate`、换 `on_tamper`、回退用量计数器 |
| **句柄指纹**：装墙时快照 dowhen 内部注册表，`clear_all()` 那种"清 dict 不设标志"的招数也能发现（R3-7） | dowhen 一把清空所有钩子 |
| **魔术方法豁免附信任条件**：帧名不该是免死金牌，命名成 `__exit__` 不能白嫖（R3-2） | 帧名冒充清理路径 |
| **实现子模块也铺墙**：`re._compiler` / `json.decoder` 这类实现层不能留空地（R3-8） | 绕过父模块直接调实现层 |
| **C 类型换成包装工厂**：`_json.make_encoder` / `_random.Random` 这类"长得像类型"的入口（R3-9/10） | 用未包装的 C 类型白嫖 |
| **续费要凭厂商签名令牌**：客户端公开面移除 `set_quota`/`topup`（R3-6） | 用官方 API 自助充值 |
| **私钥搬出客户端目录树**（默认 `~/.python365-vendor/`，R3-12） | 谁能拿到客户端谁就能签发许可证 |

**防线清单**（第五轮上了租约架构之后重新分类 —— 详见 `exploits/REPORT_ARCH_LEASE.md`）：

| 残留 | 现状 | 靠什么 |
|---|---|---|
| 私钥与客户端同机 | 🟢 **架构上解决**：客户端只验签、不签名（本地演示同机，真实部署需独立主机/uid/HSM） | 架构 |
| 无机器绑定 / 无吊销 | 🟢 **可修**：设备绑定 + 服务端吊销 → 换机/吊销后一个租约周期内停机 | 架构 |
| 进程内反篡改只是门槛 | 🟡 局部改善：本地检查全被 patch，也只剩"租约 TTL + 宽限期"的离线窗口 | 架构 + 内核 |
| **机器指纹是客户端自报的** | 🟡 只能抬高门槛：挡得住拷贝租约，挡不住改一行 `fingerprint()` —— 真绑定需 TPM/安全飞地或服务端侧信号 | 硬件 |
| **借 `__dict__` 冒充内部模块** | 🟢 已封：模块 `__dict__` 身份 + `co_filename` 双重校验（第六轮 R5-01） | 架构 |
| **服务端续签不验签 / 状态接口裸奔** | 🟢 已封：`/renew` 先验签；`/state` 需 `X-Admin-Token`（默认关闭）；状态文件不存许可证原文 | 架构 |
| **CORE 语法包只对免费用户存在** | 🟢 已封：语法闸门独立成钩子，CORE 未购就装 | 架构 |
| **`os.urandom` / `ctypes` / 指针通道** | 🔴 **依旧**：实测免费版 10/12 白送，与租约架构无关 | 内核 |
| **零事件的纯 C 运算** | 🔴 **依旧**：逃费上限 = 内核 `RLIMIT_CPU` 6 秒 | 内核 |

## 在线授权（租约模式）

审计的最后一批残留是"客户端拿得住的都不算凭据"。把授权判定搬到独立的厂商服务端之后，
其中三条从"不可修"变成"可修"：

```bash
# ① 启动厂商授权服务端（私钥只在它内存里；客户端进程/客户端机器都不需要）
#    /state 是管理接口，需要 X-Admin-Token；不配就一律 403（默认关闭）
PYTHON365_ADMIN_TOKEN='换成你自己的随机串' python3 vendor/authd.py 8787

# ② 客户端用短周期租约运行（租约默认 8 秒，演示可调 PYTHON365_LEASE_TTL）
PYTHON365_LEASE_SERVER=http://127.0.0.1:8787 \
PYTHON365_KEY='PYTHON365.xxx.yyy' \
PYTHONPATH=/workspace/python365 python3 你的程序.py
```

| 机制 | 治好了什么 |
|---|---|
| **私钥不上客户端**：只验签不签名 | 客户端被完全攻破也签不出许可证/租约（R4-06 的架构解） |
| **短周期租约**（默认 8 秒 + 宽限期） | 授权档由服务端每次签，客户端缓存的是"快到期的凭据" |
| **设备绑定**：激活时绑定机器指纹 | 拷贝租约到别的机器 → 续签被拒 → 停机 |
| **吊销**：服务端 revoke | 续签立即失败 → 一个租约周期内停机 |
| **独立闸门线程**：每 0.5s 查租约 | ⚠️ **不能挂在计费钩子上** —— 计费钩子只在免费版注册，"已付费"进程反而不受吊销约束（实测踩过：吊销后照跑 15 秒） |
| **`/renew` 先验签**；`/state` 需管理令牌；状态文件只存派生信息 | 服务端不能把"客户端报上来的东西"当成可信输入 —— 否则纯协议一条链就能换到服务端签名的租约（第五轮 R5-05/06/09） |

实测见 `exploits/REPORT_ARCH_LEASE.md`，一键复现：

```bash
python3 demos/lease_lab.py             # 六个场景：激活 / 换机停机 / 吊销停机 / 断网停机 / 冒用指纹 / 复测老洞
python3 demos/uid_separation_lab.py    # "私钥到底谁能用"：藏起来 → 客户端照常、厂商签发全瘫
```

**"私钥不可达"是可验证的**：`uid_separation_lab.py` 把私钥移出文件系统后，
客户端（带许可证、走租约）照常工作，而 `issue.py` 与 `/activate` 全部失败 ——
说明**只有厂商侧需要私钥**，客户端连"有它"都不需要。

**仍然只能抬高门槛的**：机器指纹是**客户端自报**的 —— 服务端只认那个字符串，
所以"老实拷贝租约文件"挡得住，"改一行 `fingerprint()` 冒用已绑定的指纹"挡不住。
真绑定需要 TPM/安全飞地或服务端侧信号。

**实例**：
```bash
python3 demos/lease_lab.py      # 六个场景：激活 / 换机停机 / 吊销停机 / 断网停机 / 冒用指纹 / 复测老洞
```

## 发证（厂商侧）

```bash
python3 vendor/genkey.py                 # 生成 RSA 密钥对（私钥留在 vendor/，不随客户端分发）
python3 vendor/issue.py DATA,BASIC       # 签发许可证，默认 1 年有效
python3 vendor/issue.py ENTERPRISE 3650  # 自定义有效天数
```

## 配套

| 目录 | 内容 |
|---|---|
| `demos/` | 演示脚本（`billing_test.py` 双层计费对决、`demo_app_365.py` 标准库全家桶、`prime_365.py` 质数程序、`net_time_lab.py` 可信时间实验、`dowhen_demo.py` / `hack_lab.py` 裸 dowhen 演示） |
| `exploits/` | 约 50 个攻击脚本 + **四套 `run_suite.sh`** + 五份报告（`REPORT.md` / `REPORT_ROUND3` / `REPORT_ROUND4` / `REPORT_ROUND5` / `REPORT_ARCH_LEASE`） |
| `AUDIT.md` | **审计总览**：五个阶段的战绩、攻击面演进主线、全部防线、跨阶段教训 |
| `vendor/` | 密钥生成 / 发证 / 私钥（**不随客户端分发**） |

## 已知"特性"

- **传递依赖也要税**：买了数据版，`zipfile.ZipFile` 照样被拦 —— 它内部要 `threading.RLock()`。
- **免费版启动 0.4~0.6 秒，企业版 0.1 秒** —— 免费版要装载 6400+ 道墙 + 启用全局事件插桩。（这是特性）
- **抽象基类不铺墙**：ABC 天生为"被继承"而生，方法被全进程共享 —— 给 `Mapping` 铺墙
  会让 `os.environ.get("HOME")` 这种无关调用被收「基础版」的税（第五轮 R5-07）。
  具体子类（`Counter` / `UserDict` / `Path` …）照旧铺。
- **`_gcd_import` 在语句式 `import` 的路径上根本不会被调用**（实测 0 命中）：要拦"模块被加载"得挂 `_find_and_load`。
  已加载的模块两者都不经过 —— 那由 `__import__` 包装层与 `meta_path` Finder 兜。**多层防线必须逐层验。**
- **广告频率随额度缩放**：`额度/10`，即跑满额度 10 条广告。
- 拦截构造函数会留下半初始化对象，析构时可能抛 `AttributeError`（真实系统同理）。
- 试用期 30 天，时间戳在 `/tmp/.python365_install`，删掉即可重置。
- `inspect` / `traceback` / `importlib` / `warnings` 豁免 —— 锁了监控机制自己先崩。

### 开发环境（这个沙箱）的两条坑

1. **跨目录移动目录不能用 `mv`**：本沙箱的文件系统把 `mv` 实现成"惰性拷贝 + 符号链接" ——
   移动后的 `.git` 里全是**指向旧路径的悬空软链**，清理时会连数据一起删掉。
   本项目就因为 `mv .git` 丢过一次 git 历史。请用 `cp -r` + `rm -rf`。
2. **文件权限语义测不出来**：沙箱是 proot（fake-root），`setpriv` 能改 uid（`id` 显示 nobody），
   但 nobody 照样读得到 `0600 root` 的文件。所以"用 uid 隔离证明私钥不可达"这条路在此环境中无效 ——
   `demos/uid_separation_lab.py` 改用「把私钥移出文件系统」这种不依赖权限语义的实验。
