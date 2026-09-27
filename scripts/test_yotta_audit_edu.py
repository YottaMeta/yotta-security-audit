# -*- coding: utf-8 -*-
"""yotta-security-audit（元安）教育版（--target edu）测试套件。

覆盖：参数纪律（--path 必填 / 输出路径防护）/ 15 条规则命中与不命中 /
脱敏（不外泄原文）/ 只读性 / 确定性 / xlsx + docx 轻解析 / 自定义规则包 /
severity 过滤 / 跳过格式统计。

用法：
  python3 scripts/test_yotta_audit_edu.py
"""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "yotta_audit.py"

ID_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
ID_CHECK = "10X98765432"


def run_cli(args, cwd=None):
    return subprocess.run(
        [sys.executable, str(SCRIPT)] + args,
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=cwd, timeout=120,
    )


def valid_id():
    """构造校验位合法的合成身份证号（用于测试，不指向真实个人）。"""
    base = "11010120120101123"
    total = sum(int(base[i]) * ID_WEIGHTS[i] for i in range(17))
    return base + ID_CHECK[total % 11]


def invalid_id():
    """同前 17 位但校验位错误。"""
    ok = valid_id()
    return ok[:-1] + ("0" if ok[-1] != "0" else "1")


def write_csv(path, rows):
    lines = [",".join(r) for r in rows]
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def col_letter(idx):
    s = ""
    i = idx + 1
    while i:
        i, rem = divmod(i - 1, 26)
        s = chr(65 + rem) + s
    return s


def write_xlsx(path, rows):
    body = []
    for r, row in enumerate(rows, 1):
        cells = []
        for c, value in enumerate(row):
            cells.append(
                '<c r="%s%d" t="inlineStr"><is><t>%s</t></is></c>'
                % (col_letter(c), r, xml_escape(str(value))))
        body.append('<row r="%d">%s</row>' % (r, "".join(cells)))
    sheet = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        "<sheetData>%s</sheetData></worksheet>" % "".join(body))
    workbook = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/></sheets>'
        "</workbook>")
    with zipfile.ZipFile(str(path), "w") as z:
        z.writestr("xl/workbook.xml", workbook)
        z.writestr("xl/worksheets/sheet1.xml", sheet)


def write_docx(path, paragraphs):
    body = "".join(
        "<w:p><w:r><w:t>%s</w:t></w:r></w:p>" % xml_escape(p) for p in paragraphs)
    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        "<w:body>%s</w:body></w:document>" % body)
    with zipfile.ZipFile(str(path), "w") as z:
        z.writestr("word/document.xml", document)


def tree_fingerprint(root):
    """目录内容 + 修改时间指纹（用于只读性断言）。"""
    items = []
    for p in sorted(Path(root).rglob("*")):
        if p.is_file():
            items.append((str(p.relative_to(root)), p.stat().st_mtime_ns,
                          p.read_bytes()))
    return items


class EduScanTest(unittest.TestCase):
    def test_requires_explicit_path(self):
        r = run_cli(["--target", "edu", "--no-color"])
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertIn("edu", (r.stdout + r.stderr))
        self.assertIn("--path", (r.stdout + r.stderr))

    def test_missing_path_exit4(self):
        with tempfile.TemporaryDirectory() as td:
            r = run_cli(["--target", "edu", "--path", str(Path(td) / "nope"),
                         "--no-color"])
            self.assertEqual(r.returncode, 4, r.stdout + r.stderr)

    def test_id_card_checksum_hit_and_masked(self):
        rid = valid_id()
        with tempfile.TemporaryDirectory() as td:
            write_csv(Path(td) / "roster.csv",
                      [["姓名", "身份证号"], ["张*", rid]])
            r = run_cli(["--target", "edu", "--path", td, "--json"])
            self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
            data = json.loads(r.stdout)
            hits = [f for f in data["findings"] if f["rule_id"] == "EDU-ID-001"]
            self.assertTrue(hits, r.stdout)
            self.assertNotIn(rid, r.stdout)
            self.assertIn("****", json.dumps(data, ensure_ascii=False))

    def test_id_card_bad_checksum_not_reported(self):
        rid = invalid_id()
        with tempfile.TemporaryDirectory() as td:
            write_csv(Path(td) / "roster.csv", [["身份证号"], [rid]])
            r = run_cli(["--target", "edu", "--path", td, "--json"])
            data = json.loads(r.stdout)
            self.assertEqual(
                [f for f in data["findings"] if f["rule_id"] == "EDU-ID-001"], [])

    def test_phone_email_and_severity_filter(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, "notes.txt").write_text(
                "家长联系电话 13812345678，邮箱 parent@example.com\n",
                encoding="utf-8")
            r = run_cli(["--target", "edu", "--path", td, "--json"])
            self.assertEqual(r.returncode, 2, r.stdout + r.stderr)  # phone=high
            data = json.loads(r.stdout)
            ids = {f["rule_id"] for f in data["findings"]}
            self.assertIn("EDU-ID-002", ids)
            self.assertIn("EDU-ID-003", ids)
            self.assertNotIn("13812345678", r.stdout)
            r2 = run_cli(["--target", "edu", "--path", td, "--json",
                          "--severity", "critical"])
            data2 = json.loads(r2.stdout)
            self.assertEqual(data2["findings"], [])

    def test_field_rules_student_no_birth_address_guardian(self):
        with tempfile.TemporaryDirectory() as td:
            write_csv(Path(td) / "info.csv", [
                ["学籍号", "出生日期", "家庭住址", "家长手机"],
                ["G12345678901234567", "2012-01-01", "某市某区某路 1 号", "13812345678"],
            ])
            r = run_cli(["--target", "edu", "--path", td, "--json"])
            self.assertEqual(r.returncode, 2, r.stdout + r.stderr)  # 住址/家长=high
            ids = {f["rule_id"] for f in json.loads(r.stdout)["findings"]}
            for rid in ("EDU-ID-004", "EDU-QI-002", "EDU-QI-003", "EDU-QI-004"):
                self.assertIn(rid, ids)

    def test_name_score_combo(self):
        with tempfile.TemporaryDirectory() as td:
            write_csv(Path(td) / "scores.csv", [["姓名", "数学成绩"], ["张*", "95"]])
            r = run_cli(["--target", "edu", "--path", td, "--json"])
            self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
            ids = {f["rule_id"] for f in json.loads(r.stdout)["findings"]}
            self.assertIn("EDU-QI-001", ids)

    def test_sensitive_fields_are_critical(self):
        with tempfile.TemporaryDirectory() as td:
            write_csv(Path(td) / "care.csv", [
                ["姓名", "健康状况", "低保", "人脸照片"],
                ["张*", "有过敏史", "是", "已采集"],
            ])
            r = run_cli(["--target", "edu", "--path", td, "--json"])
            self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
            ids = {f["rule_id"] for f in json.loads(r.stdout)["findings"]}
            for rid in ("EDU-SA-001", "EDU-SA-002", "EDU-SA-003"):
                self.assertIn(rid, ids)

    def test_minor_marker_keyword(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, "policy.txt").write_text("本表适用于未成年学生。\n", encoding="utf-8")
            r = run_cli(["--target", "edu", "--path", td, "--json"])
            self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
            hit = [f for f in json.loads(r.stdout)["findings"]
                   if f["rule_id"] == "EDU-SA-004"]
            self.assertTrue(hit)
            self.assertIn("元规", hit[0]["description"] + json.dumps(hit[0], ensure_ascii=False))

    def test_path_risk_requires_content_hit(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "OneDrive" / "班级"
            root.mkdir(parents=True)
            write_csv(root / "clean.csv", [["科目"], ["数学"]])
            r = run_cli(["--target", "edu", "--path", str(Path(td) / "OneDrive"), "--json"])
            data = json.loads(r.stdout)
            self.assertEqual(
                [f for f in data["findings"] if f["rule_id"] == "EDU-HR-001"], [])
            write_csv(root / "roster.csv", [["姓名", "成绩"], ["张*", "95"]])
            r2 = run_cli(["--target", "edu", "--path", str(Path(td) / "OneDrive"), "--json"])
            self.assertEqual(r2.returncode, 2, r2.stdout + r2.stderr)
            ids = {f["rule_id"] for f in json.loads(r2.stdout)["findings"]}
            self.assertIn("EDU-HR-001", ids)

    def test_ai_tmp_dir_medium(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "uploads"
            root.mkdir()
            Path(root, "a.txt").write_text("手机 13812345678\n", encoding="utf-8")
            r = run_cli(["--target", "edu", "--path", td, "--json"])
            self.assertEqual(r.returncode, 2, r.stdout + r.stderr)  # phone high > hr medium
            ids = {f["rule_id"] for f in json.loads(r.stdout)["findings"]}
            self.assertIn("EDU-HR-003", ids)

    def test_filename_rule(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, "张三-期末成绩单.txt").write_text("见附件\n", encoding="utf-8")
            r = run_cli(["--target", "edu", "--path", td, "--json"])
            self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
            ids = {f["rule_id"] for f in json.loads(r.stdout)["findings"]}
            self.assertIn("EDU-HR-002", ids)
            self.assertNotIn("张三-期末成绩单", r.stdout)

    def test_unsupported_files_are_counted(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, "scan.pdf").write_bytes(b"%PDF-1.4 fake")
            r = run_cli(["--target", "edu", "--path", td, "--json"])
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            data = json.loads(r.stdout)
            self.assertEqual(data["scope"]["skipped_ext"][".pdf"], 1)

    def test_xlsx_container_scan(self):
        with tempfile.TemporaryDirectory() as td:
            write_xlsx(Path(td) / "scores.xlsx", [["姓名", "身份证号"], ["张*", valid_id()]])
            r = run_cli(["--target", "edu", "--path", td, "--json"])
            self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
            self.assertIn("EDU-ID-001",
                          {f["rule_id"] for f in json.loads(r.stdout)["findings"]})

    def test_docx_container_scan(self):
        with tempfile.TemporaryDirectory() as td:
            write_docx(Path(td) / "note.docx", ["家长联系电话：13812345678"])
            r = run_cli(["--target", "edu", "--path", td, "--json"])
            self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
            self.assertIn("EDU-ID-002",
                          {f["rule_id"] for f in json.loads(r.stdout)["findings"]})

    def test_report_never_echoes_raw_values(self):
        rid = valid_id()
        with tempfile.TemporaryDirectory() as td:
            write_csv(Path(td) / "roster.csv",
                      [["姓名", "身份证号", "家长手机"],
                       ["张*", rid, "13812345678"]])
            out = Path(td).parent / (Path(td).name + "-report.md")
            r = run_cli(["--target", "edu", "--path", td, "--report", str(out)])
            self.assertIn(r.returncode, (2, 3), r.stdout + r.stderr)
            text = out.read_text(encoding="utf-8") + r.stdout
            self.assertNotIn(rid, text)
            self.assertNotIn("13812345678", text)
            self.assertIn("****", text)
            out.unlink(missing_ok=True)

    def test_scan_is_readonly(self):
        with tempfile.TemporaryDirectory() as td:
            write_csv(Path(td) / "roster.csv", [["手机号"], ["13812345678"]])
            before = tree_fingerprint(td)
            r = run_cli(["--target", "edu", "--path", td])
            self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
            self.assertEqual(before, tree_fingerprint(td))

    def test_report_path_guard(self):
        with tempfile.TemporaryDirectory() as td:
            write_csv(Path(td) / "roster.csv", [["手机号"], ["13812345678"]])
            r = run_cli(["--target", "edu", "--path", td,
                         "--report", str(Path(td) / "out.md")])
            self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
            r2 = run_cli(["--target", "edu", "--path", str(Path(td) / "roster.csv"),
                          "--report", str(Path(td) / "roster.csv")])
            self.assertEqual(r2.returncode, 4, r2.stdout + r2.stderr)

    def test_determinism(self):
        with tempfile.TemporaryDirectory() as td:
            write_csv(Path(td) / "roster.csv", [["姓名", "成绩"], ["张*", "95"]])
            r1 = json.loads(run_cli(["--target", "edu", "--path", td, "--json"]).stdout)
            r2 = json.loads(run_cli(["--target", "edu", "--path", td, "--json"]).stdout)
            r1.pop("scanned_at", None)
            r2.pop("scanned_at", None)
            self.assertEqual(r1, r2)

    def test_custom_rule_pack(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, "a.txt").write_text("校车线路：3 号线\n", encoding="utf-8")
            pack = Path(td).parent / (Path(td).name + "-pack.json")
            pack.write_text(json.dumps({
                "schema_version": "1.0",
                "pack_version": "test.1",
                "field_vocab": {"student_name": ["姓名"]},
                "content_rules": [{
                    "id": "EDU-CUSTOM-001", "title": "校车线路",
                    "category": "handling_risk", "severity": "medium",
                    "kind": "keyword_any", "keywords": ["校车线路"],
                    "remediation": "限制流转范围",
                }],
                "field_rules": [], "combo_rules": [],
                "path_rules": [], "filename_rules": [],
            }, ensure_ascii=False), encoding="utf-8")
            r = run_cli(["--target", "edu", "--path", td, "--json",
                         "--edu-rules", str(pack)])
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertEqual(
                {f["rule_id"] for f in json.loads(r.stdout)["findings"]},
                {"EDU-CUSTOM-001"})
            pack.write_text("{ not json", encoding="utf-8")
            r2 = run_cli(["--target", "edu", "--path", td,
                          "--edu-rules", str(pack)])
            self.assertEqual(r2.returncode, 4, r2.stdout + r2.stderr)
            pack.unlink()

    def test_help_and_defaults(self):
        r = run_cli(["--help"])
        self.assertIn("edu", r.stdout)
        self.assertIn("--edu-rules", r.stdout)

    def test_skill_mode_regression_clean(self):
        with tempfile.TemporaryDirectory() as td:
            r = run_cli(["--path", td, "--no-color"])
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


if __name__ == "__main__":
    if "--keep" in sys.argv and shutil.which("true"):  # 保持与主套件一致的参数习惯
        pass
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    ok = runner.run(suite).wasSuccessful()
    sys.exit(0 if ok else 1)
