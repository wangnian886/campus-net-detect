# 校园网状态检测方案实测对比

> 附一个可用的 Windows 深澜（Srun）Portal 自动认证客户端

做校园网自动登录时，真正难的不是登录，而是**怎么低成本地判断"现在需不需要重新登录"**。
判断得太粗，掉线要等很久才恢复；判断得太勤，又白白消耗流量和 CPU。

这个仓库记录了我实测的六种方案，以及最终选定的三层设计。文末是据此实现的
完整工具（已在电子科技大学沙河校区有线网络实测通过）。

## 实测数据

同一台机器、同一条校园网，各方案单次耗时与开销：

| 方案 | 耗时 | 流量性质 | 能否反映认证状态 |
| --- | --- | --- | --- |
| HTTP 204 外网探测 | 141 ms | 518 字节外网流量 | 能，但代价最高 |
| **门户 `rad_user_info` 查询** | **24 ms** | **走局域网，不计费** | **能，直接回答"本 IP 是否已认证"** |
| Windows NCSI（WMI） | 19 ms | 零 | 能，但最多滞后 15 秒 |
| UDP `connect` 探测 | 0.12 ms | 零 | 只能判断"有没有 IP" |
| TCP 连接表 | 1.2 ms | 零 | 不能（僵死连接也算） |
| DNS 解析 | 18 ms | 少量 | 不能（不存在的域名要 11 秒才超时） |

## 为什么放弃 Windows 自带的联网判断

看起来最省事的做法是读 Windows 的 `NetworkListManager.IsConnectedToInternet`。实测两个问题：

1. **不可靠**：本机上 `NlaSvc` 服务是 `Stopped` 状态，该接口恒返回 `False`，而实际外网是通的。
2. **太慢**：`IPv4Connectivity` 虽然准确，但受注册表 `PassivePollPeriod=15` 限制，
   掉线后最多要 15 秒才更新，达不到快速重连的要求。

另外 `NotifyAddrChange`（网卡变化通知）在 Python ctypes 下实测也不可靠：即使
`OVERLAPPED.hEvent` 已正确挂上事件、返回 `997 ERROR_IO_PENDING`，等真实地址变化
仍然 15 秒超时。所以最终没有走事件驱动，而是用极轻量的轮询。

## 最终的三层设计

```
每 1 秒   UDP connect (0.12ms)      没 IP → 睡，什么都不做
每 2 秒   门户 rad_user_info (24ms)  已认证 → 睡，不写日志、不碰外网
每 60 秒  HTTP 204 实测 (141ms)      仅兜底「会话还在但网关不通」
```

第 2 层是主判断：查询校园网门户"本 IP 是否已认证"，数据在校园网内部交换机就返回，
不经过计费网关，因此不消耗套餐流量。第 3 层保留是为了排除边界情况——门户认为在线、
但实际出不去网。

实测运行开销（守护进程持续运行）：

| 指标 | 数值 |
| --- | --- |
| CPU | 约 0.16% 单核（120 秒内 187ms） |
| 内存 | 24 MB |
| 外网流量 | 约 4 MB/月（仅 60 秒兜底） |
| 稳定在线时日志 | 60 秒零新增 |
| 掉线恢复 | 约 2 秒 |

## 一个只有中文密码才会暴露的 bug

深澜的用户信息用 XXTEA 加密，输入必须按 JavaScript `charCodeAt` 语义打包
（UTF-16 码元每 4 个打进一个 32 位字），不能直接喂 UTF-8 字节。

坑在于：**纯 ASCII 密码两种写法结果完全相同**，所以用 `test123` 之类的密码测
永远发现不了；只有密码含中文时才会加密出不同结果、导致登录失败。

`selftest.py` 里专门为此保留了一条 `test_js_utf16_packing` 检查，因为纯 ASCII
的测试向量抓不到它。

---

# 工具本身

## 特性

- **开机自动认证**：登录 Windows 后自动连接，无需打开浏览器
- **断网自动重连**：掉线后约 2 秒内恢复
- **插网线自动识别**：检测到网络连接立即认证
- **稳定在线时零打扰**：不发外网请求、不写日志、CPU 占用可忽略
- **密码错误保护**：服务器拒绝密码时停止重试，避免账号被锁定
- **凭据加密存储**：用 Windows DPAPI 加密，仅当前用户可解密

## 快速开始

需要 Python 3.9+（Windows 自带 `python` 命令即可）。

```bash
# 1. 设置账号密码（密码输入时不回显）
python srun_core.py setpass

# 2. 安装开机自启并启动守护进程
python install.py

# 3. 查看状态
python install.py --status
```

Windows 用户也可以直接双击 `setup.cmd`（会自动完成上述两步）。

## 常用命令

```bash
python install.py --status      # 状态：自启、进程、凭据、在线
python srun_core.py status      # 门户在线信息与用量
python srun_core.py verify      # 验证密码是否正确（会短暂断网，需确认）
python selftest.py              # 自检（离线，20+ 项）
python selftest.py --online     # 自检 + 门户与外网连通性
python install.py --uninstall   # 卸载：移除自启并停止守护进程
```

## 认证协议

深澜 Portal 的登录参数需要三重加密，实现见 `srun_core.py`：

- 用户信息：XXTEA 加密 → 自定义字母表 Base64 → `{SRBX1}` 前缀
- 密码：`MD5(密码 + token)`
- 校验：`SHA1(token+用户名 + token+MD5 + token+ac_id + token+ip + token+n + token+type + token+info)`

加密实现依据门户页面的行为重写，并用固定测试向量（`crypto_vectors.json`）做回归验证。

### 凭据存储

密码用 Windows `CryptProtectData`（DPAPI）加密后存放在
`%LOCALAPPDATA%\srun-auto\cred.bin`，只有当前 Windows 账户能解密。
密码不会写入日志，也不会出现在命令行历史里。

首次配置必须手动输入一次：浏览器保存的密码是应用绑定加密（Chrome/Edge v20），
且 cookies 数据库在浏览器运行时被独占锁定，外部程序按设计无法读取。

## 配置其他校区

如果门户地址或域名不同，创建 `%LOCALAPPDATA%\srun-auto\config.json`：

```json
{
  "portal_host": "192.168.9.8",
  "ac_id": "6",
  "domain": "@uestc"
}
```

`portal_host` 可从浏览器地址栏的认证页 URL 看到；`ac_id` 是 URL 里的参数；`domain` 是账号后缀（登录页的下拉选项，如 `@cmccgx` 移动、`@dx` 电信）。

## 排查

日志位置：`%LOCALAPPDATA%\srun-auto\srun.log`（超过 512KB 自动截断）

| 日志内容 | 含义 | 处理 |
| --- | --- | --- |
| `password_error` / `E2553` | 密码错 | 重跑 `setpass` |
| `sign_error` | 协议不匹配 | 门户可能改版了，需更新加密实现 |
| `ip_already_online_error` | 该 IP 已在线 | 正常，视为成功 |
| `门户不可达` | 没插网线 / 不在校园网 | 检查物理连接 |

## 文件说明

| 文件 | 作用 |
| --- | --- |
| `srun_core.py` | 认证协议、凭据存取、网络探测 |
| `srun_daemon.py` | 守护进程：三层探测 + 失败退避 + 密码保护 |
| `install.py` | 安装/卸载开机自启（启动文件夹快捷方式，免管理员） |
| `selftest.py` | 自检脚本 |
| `crypto_vectors.json` | 加密测试向量（回归用，不含门户原始代码） |
| `setup.cmd` | Windows 首次配置入口 |

## 致谢与协议来源

深澜 Portal 的认证协议（XXTEA + 自定义 Base64 + MD5/SHA1 校验）是社区长期逆向
得出的公开知识，本项目并未原创这套协议。相关参考实现包括：

- [coffeehat/BIT-srun-login-script](https://github.com/coffeehat/BIT-srun-login-script)（MIT，2020）
- [Mmx233/BitSrunLoginGo](https://github.com/Mmx233/BitSrunLoginGo)（AGPL-3.0）

本项目的加密实现是依据门户页面 `Portal.js` 的行为重写的，并用固定测试向量
（`crypto_vectors.json`）做回归验证，未复制上述项目的源代码，也不包含门户原始代码。

相比上述项目，本项目的额外工作集中在**状态检测策略**与**运行可靠性**：三层探测
降低开销、密码错误保护、凭据热更新、DPAPI 加密存储。

## 免责声明

仅供个人在自己的设备上自动完成已获授权的网络认证。请勿用于批量登录、
绕过计费或其他违反学校网络使用规定的用途。使用风险自负。

## 许可

MIT，见 [LICENSE](LICENSE)。
