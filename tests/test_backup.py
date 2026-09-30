import unittest
import os
import sys
import tempfile
from pathlib import Path

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core.backup.data_scanner import DataScanner
from core.backup.encryptor import Encryptor
from core.backup.safe_backup_manager import SafeBackupManager

class TestBackup(unittest.TestCase):
    def test_scanner_finds_critical_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            critical = Path(tmpdir) / "customer_records.csv"
            ignored = Path(tmpdir) / "image.tmp"
            critical.write_text("id,name\n1,Ada\n", encoding="utf-8")
            ignored.write_text("ignore", encoding="utf-8")

            scanner = DataScanner({
                "backup": {
                    "critical_paths": [tmpdir],
                    "critical_extensions": [".csv"],
                }
            })
            res = scanner.find_critical_files()

        self.assertEqual(res, [str(critical.resolve())])

    def test_scanner_empty_for_missing_path(self):
        scanner = DataScanner({"backup": {"critical_paths": ["./path-that-does-not-exist"]}})
        res = scanner.find_critical_files()
        self.assertEqual(len(res), 0)

    def test_encryptor_empty(self):
        encryptor = Encryptor()
        res = encryptor.encrypt_file("temp.txt")
        self.assertEqual(res, b"")

    def test_safe_backup_manager_creates_manifest(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = Path(tmpdir) / "source"
            backup_dir = Path(tmpdir) / "backup"
            source_dir.mkdir()
            (source_dir / "critical.txt").write_text("protect me", encoding="utf-8")

            manager = SafeBackupManager({
                "backup": {
                    "enabled": True,
                    "critical_paths": [str(source_dir)],
                    "critical_extensions": [".txt"],
                    "local_destination": str(backup_dir),
                }
            })
            snapshot = manager.protect_now("unit test")

            self.assertEqual(snapshot["status"], "created")
            self.assertEqual(snapshot["file_count"], 1)
            self.assertTrue(Path(snapshot["snapshot_dir"], "manifest.json").exists())

if __name__ == "__main__":
    unittest.main()
