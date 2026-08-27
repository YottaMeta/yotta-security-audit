---
name: yotta-security-audit
version: 0.1.5
description: 元安 —— 检测 AI 技能中的恶意模式（13 类检测器）与系统安全基线（Windows/Linux），纯只读、零依赖、有纪律。触发：用户提到 安全审计 / 技能安全检查 / 恶意检测 / 供应链安全 / 系统安全基线 / scan skills / supply chain / malicious skill / 扫描技能 等。边界：本工具只检测与报告，绝不执行修复、删除或查杀动作。
license: MIT
---

# 元安（yotta-security-audit）

YottaMeta 自有安全扫描引擎，面向 AI 技能供应链与所在系统：

- **技能模式**（--target skill，默认）：扫描 AI 技能目录中的恶意模式，13 类检测器覆盖后门、凭据窃取、数据外传、持久化、供应链安装钩子等。
- **系统模式**（--target system）：系统安全基线扫描，Windows / Linux 平台感知，只读不改系统。

纯 Python 3.8+ 标准库实现，零外部依赖；Windows + Linux 通用。

## 何时使用

- 安装任何新技能前，先扫描其目录；
- 定期扫描本机已安装的全部技能（自动发现 17 类智能体技能目录）；
- 怀疑技能存在恶意行为、需要审计时；
- 检查系统安全基线（启动项、计划任务、服务、防火墙、共享、权限点等）。

**Do NOT trigger**：本工具只读检测。发现风险后应向用户报告并给出建议，不得自行删除、隔离或修复。

## 快速使用

```bash
# 扫描所有已发现的技能（17 类智能体目录）
python3 scripts/yotta_audit.py --target skill

# 扫描单个技能目录
python3 scripts/yotta_audit.py --path ./some-skill

# 系统安全基线（当前平台）
python3 scripts/yotta_audit.py --target system --platform auto

# JSON 输出 + 生成 Markdown 报告
python3 scripts/yotta_audit.py --path ./some-skill --json --report report.md

# 只报告 high 及以上
python3 scripts/yotta_audit.py --path ./some-skill --severity high
```

Windows 下同样用 python 运行；控制台编码已加固（GBK 环境不崩）。

## 工作流程（AI 智能体执行审计时）

1. **确定范围**：用户指定目录用 --path；未指定则自动发现全部技能目录。
2. **运行扫描**：执行上述命令，先看文本报告，必要时 --json 拿结构化结果。
3. **分析结果**：按严重级排序逐条核对；区分「真风险」与「需结合上下文的提示」（NetworkCall / 高熵 / URL 等多为上下文相关）。
4. **报告用户**：给出 发现数（按级别）、关键发现的位置与描述、建议动作。
5. **决策纪律**：发现高风险时，建议用户先隔离/停止使用该技能，再人工复核；工具本身不做任何变更。

## 13 类检测器

| 检测器 | 关注点 | 默认级别 |
|---|---|---|
| DownloadExec | 下载后通过管道或落地文件交给 shell 执行 | critical |
| Obfuscation | 动态求值、编码字符串构造、base64 解码后执行 | high |
| Persistence | 定时任务、启动代理/守护、shell 配置、注册表启动项写入 | high |
| Exfiltration | 读取敏感文件后外传、打包上传 | high |
| CredentialTheft | SSH/云凭据/浏览器数据/钥匙串访问 | critical |
| NetworkCall | 反向连接、原始套接字、HTTP 客户端（多为上下文相关） | medium |
| PrivilegeEscalation | 权限位修改、setuid、加入管理员组 | high |
| SocialEngineering | 社会工程话术命名（文件名） | medium |
| Base64 | 超长 base64 编码串（解码含敏感关键字则升级） | medium→high |
| IOCMatch | 已知恶意 IP/域名/URL 模式/文件哈希 | critical |
| PostInstallHook | 安装期生命周期脚本（下载/执行为 critical） | high→critical |
| HiddenChar | 零宽字符与双向覆盖字符 | medium |
| Entropy | 高熵编码串（疑似混淆/加密载荷） | medium |

规则表位于 scripts/audit_rules.py（签名数据文件，自扫豁免），可用 --ioc-db 传入自有威胁情报。

## exit code 语义（三技能统一）

| 值 | 含义 |
|---|---|
| 0 | 干净 / 仅有 low 提示 |
| 1 | 存在 medium |
| 2 | 存在 high |
| 3 | 存在 critical |
| 4 | 扫描器自身错误（参数错误/致命异常） |

## 安全边界（Scope Guard）

- **只读**：所有检测均为读取操作；系统模式只运行只读命令（注册表查询、任务枚举等），绝无写入/删除。
- **授权与法律**：仅允许对已获授权的目标进行检测（自己的系统、自己将要安装的技能、明确授权测试的目标）。未经授权扫描他人系统违反《网络安全法》与《刑法》285/286 条，使用者自行承担法律责任。
- **报告脱敏**：默认不输出私钥内容、环境变量值、完整凭据，只给路径、模式与建议。
- **自扫**：扫描器可扫描自身而不产生中高危误报（签名规则数据文件自动豁免，--include-self 强制包含）。

## 参考文档

- references/threat-patterns.md — 恶意技能攻击模式详解
- references/remediation-guide.md — 发现风险后的处置建议
- references/system-baseline.md — 系统基线检查项说明
