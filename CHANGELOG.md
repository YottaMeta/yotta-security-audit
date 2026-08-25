# 更新日志

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
