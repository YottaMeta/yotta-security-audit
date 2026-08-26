# 更新日志

## v0.1.4 (2026-08-26)

系统基线新增 **CIS 合规检测器**（Linux，只读，接入 run_linux_baseline 尾部）：

- 空密码账号（/etc/shadow 密码字段为空 = 无需密码可登录，high）。
- sudo NOPASSWD 免密提权条目（/etc/sudoers 与 /etc/sudoers.d，medium）。
- 内核参数加固（sysctl 只读查询）：fs.suid_dumpable / kernel.randomize_va_space
  （ASLR）/ net.ipv4.conf.all.accept_redirects / send_redirects / ip_forward。
- 登录历史：lastb 失败登录（medium，暴力破解迹象）+ last 近期登录提示（low）。
- 不可读文件 / 命令缺失统一降级为 info 提示，不阻断基线扫描。

测试：新增 scripts/test_yotta_audit_cis.py（11 项，mock 只读命令，跨平台可跑）；
py3.8 + py3.13 全量 24/24 通过；自扫 exit 0 无中高危误报（新增 2 条 LOW 为 CIS 检测代码提及 sudo 的预期提示）。


## v0.1.3 (2026-08-26)

banner 大标题加功能后缀「元安安全审计」，与 YottaMeta 技能矩阵视觉统一；无功能变更。

## v0.1.2 (2026-08-26)

README 按标准补全：新增「这是什么 / 核心价值 / 核心优势 / 功能体系 / 常见问题 / 相关技能 / 升级卸载」等章节，与 YottaMeta 技能矩阵 README 标准对齐；无功能变更。


## v0.1.1 (2026-08-26)

包打包修正：移除误入的 __pycache__/*.pyc（Python 字节码缓存，运行时自动重建，不影响功能）。


## v0.1.0 (2026-08-26)

YottaMeta 自有实现首版（重写自第三方技术包 skill-security-audit v2.0.0，已完全重写，无上游代码）：

- 双模式：--target skill（默认，13 类技能恶意模式检测）/ --target system（系统安全基线，平台感知）。
- 13 类检测器全新实现：DownloadExec / Obfuscation / Persistence / Exfiltration / CredentialTheft /
  NetworkCall / PrivilegeEscalation / SocialEngineering / Base64 / IOCMatch / PostInstallHook /
  HiddenChar / Entropy。
- 系统安全基线（只读）：Windows（注册表启动项/计划任务/服务/防火墙/共享/管理员组/持久化点/浏览器凭据位置提示）、
  Linux（SUID-SGID/全局可写/启动项/SSH 配置/开放端口/用户 crontab/PATH 劫持）。
- 17 类智能体技能目录自动发现（与 install.js 权威映射一致）；签名数据文件豁免自扫。
- 报告：文本 / --json / --report report.md，默认脱敏（不打印私钥/环境变量值/完整凭据）。
- 零依赖（Python 3.8+ 标准库），Windows + Linux 通用，UTF-8 加固（GBK 控制台不崩）。
- exit code 语义：0=干净/仅 low，1=medium，2=high，3=critical，4=错误。
- 版权：YottaMeta 纯自有 MIT + NOTICE 品牌声明；README 一行上游致谢。
