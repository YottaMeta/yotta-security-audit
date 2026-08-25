<p align="center">
  <img src="assets/banner.png" alt="yotta-security-audit banner" width="100%" />
</p>

# yotta-security-audit（元安）

元安 —— 检测 AI 技能中的恶意模式与所在系统的安全基线。纯只读、零依赖、有纪律。

- **技能模式**：13 类检测器扫描 AI 技能目录（后门、凭据窃取、数据外传、持久化、供应链安装钩子等），自动发现 17 类智能体技能目录。
- **系统模式**：系统安全基线扫描（Windows / Linux，平台感知，只读不改系统）。
- **零依赖**：Python 3.8+ 标准库实现，Windows + Linux 通用。
- **有纪律**：只读检测、报告默认脱敏、含授权与法律边界声明。

## 安装

本技能为「技能包」：先装到你的智能体技能目录，再由智能体按需调用其中的脚本。

### 方式一：npm（推荐，Windows / Linux / macOS）

```bash
npx -y @yottameta/yotta-security-audit --agent codex      # 装到 Codex
npx -y @yottameta/yotta-security-audit --agent claude    # 装到 Claude Code
npx -y @yottameta/yotta-security-audit --agent cursor    # 装到 Cursor
npx -y @yottameta/yotta-security-audit -g                # 装到全部已知智能体
npx -y @yottameta/yotta-security-audit --list            # 查看智能体 → 默认目录
```

### 方式二：install.sh（Linux / macOS）

```bash
git clone https://github.com/YottaMeta/yotta-security-audit.git
cd yotta-security-audit
bash install.sh --agent codex        # 或 --agent claude / --dir <路径> / -g
```

### 方式三：手动复制

把本仓库内容复制到你的智能体技能目录：

| 智能体 | 用户级目录 | 项目级目录 |
|---|---|---|
| Claude Code | ~/.claude/skills/ | .claude/skills/ |
| Cursor | ~/.cursor/skills/ | .cursor/skills/ |
| Codex | ~/.codex/skills/（或 $CODEX_HOME/skills） | .codex/skills/ |
| 通用 Agent | ~/.agents/skills/ | .agents/skills/ |

改了目录的智能体请用 --dir 指定，不要依赖默认位置。

## 快速使用

```bash
# 扫描单个技能目录
python3 scripts/yotta_audit.py --path ./some-skill

# 扫描全部已发现技能
python3 scripts/yotta_audit.py --target skill

# 系统安全基线
python3 scripts/yotta_audit.py --target system --platform auto

# JSON + 报告文件
python3 scripts/yotta_audit.py --path ./some-skill --json --report report.md
```

exit code：0 = 干净/仅 low 提示；1 = medium；2 = high；3 = critical；4 = 扫描器错误。

## 安全边界

- 只读检测，绝不执行修复、删除或查杀动作。
- 仅允许扫描已获授权的目标；未经授权扫描他人系统违反《网络安全法》与《刑法》285/286 条，使用者自行承担法律责任。
- 报告默认脱敏：不输出私钥内容、环境变量值、完整凭据，只给路径、模式与建议。
- 扫描器可扫描自身而不产生中高危误报（签名规则数据文件自动豁免）。

## 测试

```bash
python3 scripts/test_yotta_audit.py
```

覆盖：干净/恶意样本、13 类检测器全命中、自扫不误报、空目录/超大文件/非 UTF-8 边界、JSON 与报告输出、exit code 语义、系统基线冒烟、GBK 控制台加固。

## 许可证与品牌

- MIT License（Copyright © 2026 YottaMeta），详见 LICENSE。
- 品牌声明见 NOTICE：YottaMeta / 元忆 / 元安 / yotta-* 为 YottaMeta 品牌，派生作品须改名并声明无关联。
- 上游来源致谢：检测方向受 SlowMist 公开的 ClawHub 恶意技能威胁情报报告启发，实现为 YottaMeta 自有。
