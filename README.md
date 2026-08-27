<p align="center"><b>Language</b>: English · <a href="./README.zh-CN.md">中文</a></p>

<p align="center">
  <img src="assets/banner.png" alt="yotta-security-audit banner" width="100%" />
</p>

<h1 align="center">yotta-security-audit · 元安 (Yuan'an)</h1>

<p align="center">YottaMeta's AI-skill supply-chain & system security scan engine: <b>detects malicious skill patterns · scans system security baselines</b>, purely read-only, zero-dependency and disciplined. Use it before installing a new skill, for periodic audits of installed skills, or to check system security baselines — wherever correctness and safety matter.</p>
<p align="center">Activates when the user mentions security audit / skill security check / malicious detection / supply-chain security / system security baseline / scan skills / supply chain / malicious skill, or asks to scan a skill; running it before installing any new skill is recommended — <b>judged by the target, not keyword luck</b>.</p>
<p align="center">Python 3.8+ standard library, zero external dependencies; Windows + Linux; read-only detection, reports masked by default, with authorization & legal boundaries declared.</p>

<p align="center">
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue" /></a>
  <a href="https://agentskills.io/"><img alt="Standard: agentskills.io" src="https://img.shields.io/badge/standard-agentskills.io-orange" /></a>
  <a href="https://www.npmjs.com/package/@yottameta/yotta-security-audit"><img alt="npm package" src="https://img.shields.io/npm/v/@yottameta/yotta-security-audit" /></a>
  <a href="https://github.com/YottaMeta/yotta-security-audit"><img alt="GitHub stars" src="https://img.shields.io/github/stars/YottaMeta/yotta-security-audit" /></a>
  <a href="https://github.com/YottaMeta/yotta-security-audit/commits/main"><img alt="last commit" src="https://img.shields.io/github/last-commit/YottaMeta/yotta-security-audit" /></a>
  <a href="https://github.com/YottaMeta/yotta-security-audit"><img alt="PRs welcome" src="https://img.shields.io/badge/PRs-welcome-brightgreen" /></a>
</p>

## What it is

AI skills are becoming a new entry point for supply-chain attacks: a "normal-looking" skill can quietly steal credentials, exfiltrate data, or plant backdoors during install or runtime. Yuan'an turns these high-risk patterns into 13 detector classes, plus a system security baseline scan, to identify risk before install and during operation.

It is not tied to any single platform: an agent-agnostic toolkit that works in any agent supporting Agent Skills. Read-only detection, masked reports, never modifies the system, no resident service.

## Core value

- **Dual-mode coverage** — skill mode (default) scans AI skill directories; system mode scans system security baselines (Windows / Linux platform-aware).
- **13 detector classes** — covering backdoors, credential theft, data exfiltration, persistence, supply-chain install hooks, hidden characters, high-entropy payloads and other high-risk patterns.
- **Read-only & disciplined** — every check is a read operation; system mode also only runs read-only commands and never performs remediation, deletion or quarantine.
- **Masked by default** — reports do not output private-key contents, environment variable values or full credentials; only paths, patterns and suggestions.
- **Auto-discover skill directories** — scanning all installed skills auto-discovers 17 agent skill directories.
- **Self-scan without false positives** — the scanner can scan itself without medium/high false positives (signature data files are auto-exempted).

## Why use it

| Advantage | Description |
|---|---|
| **Explainable detectors** | Each of the 13 detector classes has a clear focus and default level; a hit pinpoints the exact pattern and remediation suggestion |
| **Platform-aware** | System mode adapts to Windows / Linux; read-only commands never write to the system |
| **Graded exit codes** | 0=clean / 1=medium / 2=high / 3=critical / 4=error, easy to wire into automation and CI |
| **Extensible rules** | The rule table lives in scripts/audit_rules.py; --ioc-db accepts your own threat-intel feeds |
| **Authorization & legal boundaries** | Only authorized targets may be audited; scanning others' systems without authorization violates the Cybersecurity Law and Articles 285/286 of the Criminal Law |
| **Zero dependency** | Python 3.8+ standard library; no daemon / database; Windows + Linux |
| **Ecosystem distribution** | GitHub + npm synced; install via npx / install.sh / manual copy |

## Commands

| Capability | Description |
|---|---|
| Skill mode (--target skill) | Scan AI skill directories with 13 detector classes; auto-discovers 17 agent skill directories |
| System mode (--target system) | System security baseline scan (startup entries, scheduled tasks, services, firewall, shares, permission points, etc.) |
| Single directory (--path) | Scan a skill directory before installing it |
| Report output | text + structured --json + --report Markdown report |
| Severity filter (--severity) | Report only high and above |

## The 13 detector classes

| Detector | Focus | Default level |
|---|---|---|
| DownloadExec | Download then pipe or drop a file to shell execution | critical |
| Obfuscation | Dynamic eval, encoded string construction, base64-decoded execution | high |
| Persistence | Scheduled tasks, startup agents/daemons, shell config, registry startup writes | high |
| Exfiltration | Read sensitive files then exfiltrate / archive and upload | high |
| CredentialTheft | SSH/cloud credentials, browser data, keychain access | critical |
| NetworkCall | Reverse connections, raw sockets, HTTP clients (mostly context-dependent) | medium |
| PrivilegeEscalation | Permission-bit changes, setuid, joining admin groups | high |
| SocialEngineering | Social-engineering wording in names (file names) | medium |
| Base64 | Overlong base64 strings (upgraded if decoding reveals sensitive keywords) | medium→high |
| IOCMatch | Known malicious IP/domain/URL patterns/file hashes | critical |
| PostInstallHook | Install-time lifecycle scripts (download/execute is critical) | high→critical |
| HiddenChar | Zero-width and bidirectional override characters | medium |
| Entropy | High-entropy encoded strings (suspected obfuscated/encrypted payloads) | medium |

> The rule table lives in scripts/audit_rules.py (signature data file, self-scan exempt); --ioc-db accepts your own threat-intel feeds.

## Usage examples

```bash
# Scan all discovered skills (17 agent directories)
python3 scripts/yotta_audit.py --target skill

# Scan a single skill directory
python3 scripts/yotta_audit.py --path ./some-skill

# System security baseline (current platform)
python3 scripts/yotta_audit.py --target system --platform auto

# JSON + generate a Markdown report
python3 scripts/yotta_audit.py --path ./some-skill --json --report report.md

# Report only high and above
python3 scripts/yotta_audit.py --path ./some-skill --severity high
```

**Exit codes**: **0** = clean / low only; **1** = medium; **2** = high; **3** = critical; **4** = scanner error.

## Install

Pick any one of the three methods; skill files are fetched from **npm** (GitHub is slower without a proxy; npm can use a domestic mirror).

### Method 1: npm (recommended, one-liner)
```bash
# domestic mirror (optional): npm config set registry https://registry.npmmirror.com
npx -y @yottameta/yotta-security-audit -g
npx -y @yottameta/yotta-security-audit --dir <your-skills-dir>   # any agent: install to a specific directory
```
> Not in the preset list? Use --dir to point at the agent's skills directory, or manual copy (method 3). --list shows each agent's default directory. You can also npm pack @yottameta/yotta-security-audit and unpack it to install via method 2 / 3.

### Method 2: install.sh one-shot
```bash
bash install.sh -g    # user level; bash install.sh --list shows all directories
bash install.sh --agent codex   # specific agent (--list shows available ones)
bash install.sh       # project level: auto-detect existing .claude/.cursor/.codex skills dirs
bash install.sh --dir /path/to/skills
```
> Covers 17 agent families including Trae / Qwen / Comate / CodeBuddy / Kimi. Windows users: works with Git Bash; otherwise use method 3.

### Method 3: manual copy
Copy the whole `yotta-security-audit` folder into the target agent's skills directory. Common locations (user level; Windows uses %USERPROFILE%, Linux/macOS uses ~):

| Agent | User-level directory | Project-level directory |
|---|---|---|
| Codex | %USERPROFILE%\.codex\skills\yotta-security-audit\ | .codex\skills\ |
| Claude Code | %USERPROFILE%\.claude\skills\yotta-security-audit\ | .claude\skills\ |
| Cursor | %USERPROFILE%\.cursor\skills\yotta-security-audit\ | .cursor\skills\ |
| Windsurf | %USERPROFILE%\.codeium\windsurf\skills\yotta-security-audit\ | .windsurf\skills\ |
| opencode | %USERPROFILE%\.config\opencode\skills\yotta-security-audit\ | .opencode\skills\ |
| Gemini | %USERPROFILE%\.gemini\skills\yotta-security-audit\ | .gemini\skills\ |
| Goose | %USERPROFILE%\.config\goose\skills\yotta-security-audit\ | .goose\skills\ |
| Amp | %USERPROFILE%\.config\agents\skills\yotta-security-audit\ | .agents\skills\ |
| Kiro | %USERPROFILE%\.kiro\skills\yotta-security-audit\ | .kiro\skills\ |
| WorkBuddy | %USERPROFILE%\.workbuddy\skills\yotta-security-audit\ | .workbuddy\skills\ |
| Trae Code CLI | %USERPROFILE%\.traecli\skills\yotta-security-audit\ | .traecli\skills\ |
| Trae IDE (CN) | %USERPROFILE%\.trae-cn\skills\yotta-security-audit\ | .trae\skills\ |
| Qwen Code | %USERPROFILE%\.qwen\skills\yotta-security-audit\ | .qwen\skills\ |
| Comate | %USERPROFILE%\.comate\skills\yotta-security-audit\ | .comate\skills\ |
| CodeBuddy | %USERPROFILE%\.codebuddy\skills\yotta-security-audit\ | .codebuddy\skills\ |
| Kimi | %USERPROFILE%\.kimi\skills\yotta-security-audit\ | .kimi\skills\ |
| Generic AGENTS.md | %USERPROFILE%\.agents\skills\yotta-security-audit\ | .agents\skills\ |

> If Codex's CODEX_HOME is set, it overrides the default; the same applies to opencode's XDG_CONFIG_HOME. .agents\skills is not a universal directory — only OpenCode / Cursor / Cline / Amp / Kimi / Gemini CLI / GitHub Copilot etc. read it; **Claude Code and Codex do not read it by default**. When unsure, use --dir or let the agent install it.

## Upgrade / uninstall

- **Upgrade**: reinstall the latest version to overwrite — npx -y @yottameta/yotta-security-audit -g or rerun bash install.sh -g. Old files inside the skill folder are overwritten; other project files are untouched.
- **Uninstall**: delete the yotta-security-audit folder under the target agent's skills directory (see the table above). The skill stops taking effect after removal.

## FAQ

- **Does it actively fix risks?** No. Yuan'an only reads, detects and reports; it never performs remediation, deletion or quarantine. On findings, suggest the user isolate and stop using the skill first, then review manually.
- **Isn't scanning skills enough — why system mode?** Malicious skills often persist to the system via startup entries, scheduled tasks or services. System mode checks these baseline points; the two modes complement each other.
- **Is scanning other machines legal?** Only authorized targets may be audited. Scanning others' systems without authorization violates the Cybersecurity Law and Articles 285/286 of the Criminal Law; the user bears the legal responsibility.
- **Will the first run false-positive?** Detectors assign levels by pattern and context; NetworkCall / high-entropy / URL findings are mostly context-dependent hints that need scenario judgment; the scanner's self-scan has exemptions and does not produce medium/high false positives.

## Related skills

Part of the YottaMeta skill matrix (security family): [yotta-vetter](https://github.com/YottaMeta/yotta-vetter) (YuanShen, four-phase pre-install review) first runs source → code → permissions → risk review and guides high-and-above findings into Yuan'an deep scanning; [yotta-memory](https://github.com/YottaMeta/yotta-memory) (Yuanyi) handles cross-session long-term memory.

## Boundaries (security red lines)

- **Authorized targets only** — audit only explicitly authorized targets; unauthorized scanning of others' systems is illegal and the user's own responsibility.
- **Detect & report only** — never performs remediation, deletion or quarantine; remediation decisions belong to the user.
- **Masked by default** — no private keys, environment values or full credentials in output; only paths, patterns and suggestions.

## Development & validation

- Run at the project root: python tools/validate-skill.py yotta-security-audit
- Tests: python scripts/test_yotta_audit.py and python scripts/test_yotta_audit_cis.py (Windows: python)
- Details: references/threat-patterns.md, references/system-baseline.md, references/remediation-guide.md

Keep tests green and bump the version before releasing changes.

## Changelog

See [CHANGELOG.md](./CHANGELOG.md).

## License

[MIT](./LICENSE) © YottaMeta. "Yuan'an" / "yotta-security-audit" and the YottaMeta family names (yotta-* prefix) are YottaMeta brand identifiers; derived works must not reuse them, see [NOTICE](./NOTICE). The detection direction is inspired by SlowMist's public ClawHub malicious-skill threat-intel reporting; the implementation is YottaMeta's own.
