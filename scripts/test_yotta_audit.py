# -*- coding: utf-8 -*-
"""yotta-security-audit（元安）测试套件。

用法：
  python3 scripts/test_yotta_audit.py [--keep]
覆盖：干净样本 / 恶意样本（13 类检测器全命中）/ 自扫不误报 / 边界
（空目录、超大文件、非 UTF-8）/ JSON 与报告输出 / exit code 语义 /
系统基线（Windows 冒烟）/ GBK 控制台加固。
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "yotta_audit.py"
FIX = HERE.parent.parent.parent / ".tmp" / "audit-fixtures"
KEEP = "--keep" in sys.argv

EVIL_DETECTORS = {
    "DownloadExec", "IOCMatchDetector", "PostInstallHookDetector", "Base64Detector",
    "Obfuscation", "Persistence", "PrivilegeEscalation", "CredentialTheft",
    "Exfiltration", "SocialEngineering", "NetworkCall", "EntropyDetector",
    "HiddenCharDetector", "FilenameDetector",
}


def run_cli(args, cwd=None, env=None):
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    return subprocess.run(
        [sys.executable, str(SCRIPT)] + args,
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=cwd, env=full_env, timeout=120,
    )


def isolated_env(home):
    """把 HOME/USERPROFILE 重定向到临时目录，隔离真实用户级技能目录。"""
    e = {
        "USERPROFILE": str(home),
        "HOMEDRIVE": str(home)[:3],
        "HOMEPATH": str(home)[2:],
        "CODEX_HOME": str(home / ".codex"),
        "XDG_CONFIG_HOME": str(home / ".config"),
    }
    return e


class AuditCliTest(unittest.TestCase):
    def test_clean_skill_exit0_no_findings(self):
        r = run_cli(["--path", str(FIX / "clean-skill"), "--no-color"])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("未发现安全问题", r.stdout)

    def test_evil_skill_exit3_all_detectors(self):
        r = run_cli(["--path", str(FIX / "evil-skill"),
                     "--ioc-db", str(FIX / "custom-ioc.json"), "--no-color"])
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        for det in EVIL_DETECTORS:
            if det == "FilenameDetector":
                continue  # FilenameDetector 产出 CredentialTheft/SocialEngineering 两条
            self.assertIn(det, r.stdout, "检测器 %s 未命中恶意样本" % det)
        self.assertIn("FIL-SENS", r.stdout, ".env 文件名未命中凭据文件检测")
        self.assertIn("SocialEngineering", r.stdout, "社会工程文件名未命中")

    def test_json_output(self):
        r = run_cli(["--path", str(FIX / "evil-skill"),
                     "--ioc-db", str(FIX / "custom-ioc.json"), "--json"])
        self.assertEqual(r.returncode, 3)
        data = json.loads(r.stdout)
        self.assertEqual(data["tool"], "yotta-security-audit")
        self.assertIn("summary", data)
        self.assertGreaterEqual(data["summary"]["critical"], 1)
        self.assertTrue(all("severity" in f for f in data["findings"]))

    def test_report_markdown(self):
        with tempfile.TemporaryDirectory() as td:
            rep = Path(td) / "report.md"
            r = run_cli(["--path", str(FIX / "evil-skill"),
                         "--ioc-db", str(FIX / "custom-ioc.json"),
                         "--report", str(rep), "--no-color"])
            self.assertEqual(r.returncode, 3)
            self.assertTrue(rep.exists())
            txt = rep.read_text(encoding="utf-8")
            self.assertIn("## 汇总", txt)
            self.assertIn("critical", txt.lower())

    def test_severity_filter(self):
        r = run_cli(["--path", str(FIX / "evil-skill"),
                     "--ioc-db", str(FIX / "custom-ioc.json"),
                     "--severity", "critical", "--no-color"])
        self.assertEqual(r.returncode, 3)
        self.assertNotIn("[MEDIUM]", r.stdout)
        self.assertIn("[CRITICAL]", r.stdout)

    def test_empty_dir_exit0(self):
        with tempfile.TemporaryDirectory() as td:
            r = run_cli(["--path", td, "--no-color"])
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_huge_file_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            big = Path(td) / "big.py"
            big.write_text("x = 1\n" * 200000, encoding="utf-8")  # >1MB
            r = run_cli(["--path", td, "--json"])
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            data = json.loads(r.stdout)
            self.assertEqual(data["scope"]["files_scanned"], 0)

    def test_non_utf8_file_no_crash(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad.py"
            p.write_bytes(b"# -*- coding: latin-1 -*-\nx = '\xff\xfe\x80'\n")
            r = run_cli(["--path", td])
            self.assertIn(r.returncode, (0, 1, 2, 3), r.stdout + r.stderr)

    def test_bad_args_exit4(self):
        r = run_cli(["--platform", "nonsense"])
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)

    def test_self_scan_no_high_critical(self):
        """自扫：扫描元安自身不产生中高危误报（签名数据文件已豁免）。"""
        r = run_cli(["--path", str(SCRIPT.parent), "--no-color"])
        self.assertLessEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertNotIn("[HIGH]", r.stdout)
        self.assertNotIn("[CRITICAL]", r.stdout)

    def test_discovery_skips_own_package(self):
        """自动发现默认跳过元安自身（--include-self 才包含）。"""
        cwd = FIX / "discovery-root"
        shutil.rmtree(cwd, ignore_errors=True)
        (cwd / ".codex" / "skills" / "some-skill").mkdir(parents=True)
        (cwd / ".codex" / "skills" / "some-skill" / "SKILL.md").write_text(
            "---\nname: some-skill\ndescription: test\n---\n", encoding="utf-8")
        # 把元安完整包复制成另一个技能目录（模拟已安装）
        target = cwd / ".codex" / "skills" / "yotta-security-audit"
        shutil.copytree(SCRIPT.parent.parent, target,
                        ignore=shutil.ignore_patterns("__pycache__", ".git"))
        env = isolated_env(cwd)
        r = run_cli(["--json"], cwd=str(cwd), env=env)
        data = json.loads(r.stdout)
        self.assertEqual(data["scope"]["skills_scanned"], 1, r.stdout + r.stderr)
        r2 = run_cli(["--json", "--include-self"], cwd=str(cwd), env=env)
        data2 = json.loads(r2.stdout)
        self.assertGreaterEqual(data2["scope"]["skills_scanned"], 2, r2.stdout + r2.stderr)
        self.assertIn(r2.returncode, (0, 1, 2, 3), r2.stdout + r2.stderr)

    def test_system_baseline_windows_smoke(self):
        if os.name != "nt":
            self.skipTest("Windows 基线仅在 Windows 上冒烟")
        r = run_cli(["--target", "system", "--platform", "auto", "--no-color"])
        self.assertIn(r.returncode, (0, 1, 2, 3), r.stdout + r.stderr)
        self.assertIn("平台: windows", r.stdout)

    def test_gbk_console_no_crash(self):
        """模拟 GBK 控制台：强制 stdout 编码 gbk 也不崩（reconfigure 已加固）。"""
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "gbk"
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "--path", str(FIX / "clean-skill"), "--no-color"],
            capture_output=True, env=env, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout.decode("gbk", errors="replace") + r.stderr.decode("gbk", errors="replace"))
        self.assertNotIn(b"UnicodeEncodeError", r.stderr)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    ok = runner.run(suite).wasSuccessful()
    sys.exit(0 if ok else 1)
