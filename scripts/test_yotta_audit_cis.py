# -*- coding: utf-8 -*-
"""yotta-security-audit（元安）CIS 合规检测器单元测试。

用法：
  python3 scripts/test_yotta_audit_cis.py

覆盖：空密码账号 / sudoers NOPASSWD / sysctl 内核参数（ASLR、suid_dumpable、
ICMP 重定向、IP 转发）/ 登录历史（lastb 失败登录、last 近期登录）/ 不可读文件
降级不崩 / run_linux_baseline 集成（mock 全部只读命令）。

通过 monkeypatch 审计模块的 _run 与 _linux_read_lines，在任何平台（含 Windows）
均可验证 Linux CIS 检测逻辑，无需真实 Linux 环境。
"""
import sys
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import yotta_audit as ya  # noqa: E402


def run_map(cmds):
    """构造按命令列表精确匹配的 _run 假实现。返回 (returncode, stdout, stderr)。"""
    def fake_run(cmd, timeout=30):
        key = tuple(cmd)
        if key in cmds:
            code, out, err = cmds[key]
            return code, out, err
        return None, "", "not mocked"
    return fake_run


def mk_rd(files):
    """构造按路径匹配的 _linux_read_lines 假实现；缺失返回 None。"""
    def fake_read(path):
        return files.get(path)
    return fake_read


SYSCTL_OK = (
    "fs.suid_dumpable = 0\n"
    "kernel.randomize_va_space = 2\n"
    "net.ipv4.conf.all.accept_redirects = 0\n"
    "net.ipv4.conf.all.send_redirects = 0\n"
    "net.ipv4.ip_forward = 0\n"
)

SYSCTL_BAD = (
    "fs.suid_dumpable = 1\n"
    "kernel.randomize_va_space = 0\n"
    "net.ipv4.conf.all.accept_redirects = 1\n"
    "net.ipv4.conf.all.send_redirects = 1\n"
    "net.ipv4.ip_forward = 1\n"
)


class CisEmptyPasswdTest(unittest.TestCase):
    def test_empty_password_flagged(self):
        files = {
            "/etc/shadow": [
                "root:$6$abc$def:19000:0:99999:7:::",       # 正常
                "nopass::19000:0:99999:7:::",               # 空密码
                "locked:!:19000:0:99999:7:::",              # 锁定
                "svc:*:19000:0:99999:7:::",                 # 服务锁定
                "# comment line",
            ],
        }
        findings = []
        with mock.patch.object(ya, "_linux_read_lines", mk_rd(files)):
            ya._linux_cis_empty_passwd(findings)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "high")
        self.assertIn("nopass", findings[0].detail)

    def test_no_empty_password(self):
        files = {
            "/etc/shadow": [
                "root:$6$abc$def:19000:0:99999:7:::",
                "user:$y$j9T:19000:0:99999:7:::",
            ],
        }
        findings = []
        with mock.patch.object(ya, "_linux_read_lines", mk_rd(files)):
            ya._linux_cis_empty_passwd(findings)
        self.assertEqual(findings, [])

    def test_unreadable_shadow_info(self):
        findings = []
        with mock.patch.object(ya, "_linux_read_lines", lambda p: None):
            ya._linux_cis_empty_passwd(findings)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "info")


class CisSudoersTest(unittest.TestCase):
    def test_nopasswd_flagged(self):
        files = {
            "/etc/sudoers": [
                "root ALL=(ALL) ALL",
                "deploy ALL=(ALL) NOPASSWD: ALL",
                "# admin ALL=(ALL) NOPASSWD: ALL",
                "",
            ],
            "/etc/sudoers.d": None,  # 目录按文件处理（不存在）
        }
        findings = []
        with mock.patch.object(ya, "_linux_read_lines", mk_rd(files)):
            ya._linux_cis_sudoers(findings)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "medium")
        self.assertIn("deploy", findings[0].detail)

    def test_no_nopasswd_clean(self):
        files = {
            "/etc/sudoers": [
                "root ALL=(ALL) ALL",
                "%wheel ALL=(ALL) ALL",
                "Defaults env_reset",
            ],
        }
        findings = []
        with mock.patch.object(ya, "_linux_read_lines", mk_rd(files)):
            ya._linux_cis_sudoers(findings)
        self.assertEqual(findings, [])


class CisSysctlTest(unittest.TestCase):
    def test_bad_values_flagged(self):
        cmds = {("sysctl", "fs.suid_dumpable", "kernel.randomize_va_space",
                 "net.ipv4.conf.all.accept_redirects",
                 "net.ipv4.conf.all.send_redirects", "net.ipv4.ip_forward"):
                (0, SYSCTL_BAD, "")}
        findings = []
        with mock.patch.object(ya, "_run", run_map(cmds)):
            ya._linux_cis_sysctl(findings)
        descs = [f.description for f in findings]
        self.assertEqual(len(findings), 5)
        sevs = {f.severity for f in findings}
        self.assertIn("high", sevs)
        self.assertIn("medium", sevs)
        self.assertTrue(any("fs.suid_dumpable=1" in d for d in descs))
        self.assertTrue(any("kernel.randomize_va_space=0" in d for d in descs))
        self.assertTrue(any("net.ipv4.ip_forward=1" in d for d in descs))

    def test_safe_values_no_findings(self):
        cmds = {("sysctl", "fs.suid_dumpable", "kernel.randomize_va_space",
                 "net.ipv4.conf.all.accept_redirects",
                 "net.ipv4.conf.all.send_redirects", "net.ipv4.ip_forward"):
                (0, SYSCTL_OK, "")}
        findings = []
        with mock.patch.object(ya, "_run", run_map(cmds)):
            ya._linux_cis_sysctl(findings)
        self.assertEqual(findings, [])

    def test_sysctl_unavailable_info(self):
        cmds = {("sysctl", "fs.suid_dumpable", "kernel.randomize_va_space",
                 "net.ipv4.conf.all.accept_redirects",
                 "net.ipv4.conf.all.send_redirects", "net.ipv4.ip_forward"):
                (None, "", "no such file")}
        findings = []
        with mock.patch.object(ya, "_run", run_map(cmds)):
            ya._linux_cis_sysctl(findings)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "info")


class CisLoginHistoryTest(unittest.TestCase):
    def test_failed_logins_flagged(self):
        cmds = {
            ("lastb", "-n", "50"): (0, "root     ssh:notty   10.0.0.5   Wed Aug 26 01:00\n"
                                       "admin    ssh:notty   10.0.0.5   Wed Aug 26 01:02\n", ""),
            ("last", "-n", "10"): (0, "root     pts/0    192.168.1.10   Tue Aug 25 22:00   still logged in\n", ""),
        }
        findings = []
        with mock.patch.object(ya, "_run", run_map(cmds)):
            ya._linux_cis_login_history(findings)
        descs = [f.description for f in findings]
        self.assertTrue(any("失败登录记录 2 条" in d for d in descs))
        self.assertTrue(any("近期登录 1 条" in d for d in descs))
        sevs = {f.severity for f in findings}
        self.assertIn("medium", sevs)
        self.assertIn("low", sevs)

    def test_no_history_info(self):
        cmds = {
            ("lastb", "-n", "50"): (1, "", "No such file or directory"),
            ("last", "-n", "10"): (1, "", "No such file or directory"),
        }
        findings = []
        with mock.patch.object(ya, "_run", run_map(cmds)):
            ya._linux_cis_login_history(findings)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "info")


class RunLinuxBaselineCisTest(unittest.TestCase):
    def test_run_linux_baseline_includes_cis(self):
        """run_linux_baseline 集成：mock 全部只读命令后应产出 CIS 发现且不崩。"""
        cmds = {
            ("sysctl", "fs.suid_dumpable", "kernel.randomize_va_space",
             "net.ipv4.conf.all.accept_redirects",
             "net.ipv4.conf.all.send_redirects", "net.ipv4.ip_forward"):
                (0, SYSCTL_BAD, ""),
            ("lastb", "-n", "50"): (0, "root ssh:notty 10.0.0.5 Wed Aug 26 01:00\n", ""),
            ("last", "-n", "10"): (1, "", "no"),
        }
        files = {
            "/etc/shadow": ["nopass::19000:0:99999:7:::"],
            "/etc/sudoers": ["deploy ALL=(ALL) NOPASSWD: ALL"],
        }
        with mock.patch.object(ya, "_run", run_map(cmds)), \
             mock.patch.object(ya, "_linux_read_lines", mk_rd(files)):
            findings = ya.run_linux_baseline()
        descs = [f.description for f in findings]
        self.assertTrue(any("CIS" in d for d in descs), descs)
        self.assertTrue(any("空密码账号" in d for d in descs))
        self.assertTrue(any("NOPASSWD" in d for d in descs))
        self.assertTrue(any("CIS：" in d for d in descs))


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    ok = runner.run(suite).wasSuccessful()
    sys.exit(0 if ok else 1)
