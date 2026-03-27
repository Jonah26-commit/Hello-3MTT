"""
AntiWorm Test Suite
Tests detection logic using safe, synthetic test cases.
Run with: python -m pytest tests/ -v
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detectors.signature import SignatureDetector
from detectors.heuristic import HeuristicDetector
from actions.quarantine import QuarantineManager


class TestSignatureDetector(unittest.TestCase):
    def setUp(self):
        self.detector = SignatureDetector()

    def test_double_extension_detected(self):
        with tempfile.NamedTemporaryFile(suffix=".jpg.exe", delete=False) as f:
            f.write(b"fake content")
            path = f.name
        try:
            result = self.detector.scan(path)
            self.assertIsNotNone(result)
            self.assertEqual(result["severity"], "HIGH")
        finally:
            os.unlink(path)

    def test_autorun_pattern_detected(self):
        with tempfile.NamedTemporaryFile(suffix=".inf", delete=False, mode="wb") as f:
            f.write(b"[autorun]\nopen=worm.exe\n")
            path = f.name
        try:
            result = self.detector.scan(path)
            self.assertIsNotNone(result)
        finally:
            os.unlink(path)

    def test_clean_file_not_flagged(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="wb") as f:
            f.write(b"Hello, this is a normal text file with no threats.")
            path = f.name
        try:
            result = self.detector.scan(path)
            self.assertIsNone(result)
        finally:
            os.unlink(path)

    def test_network_share_copy_detected(self):
        with tempfile.NamedTemporaryFile(suffix=".bat", delete=False, mode="wb") as f:
            f.write(b"@echo off\ncopy /y %0 \\\\server\\share\\worm.bat\n")
            path = f.name
        try:
            result = self.detector.scan(path)
            self.assertIsNotNone(result)
            self.assertEqual(result["severity"], "HIGH")
        finally:
            os.unlink(path)


class TestHeuristicDetector(unittest.TestCase):
    def setUp(self):
        self.detector = HeuristicDetector()

    def test_python_worm_skeleton_detected(self):
        worm_code = """
import socket
import os
import shutil

def spread():
    for ip in range(1, 255):
        s = socket.connect(('192.168.1.' + str(ip), 445))
        shutil.copy(__file__, '/tmp/worm.py')
        os.execv('/tmp/worm.py', [])
"""
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
            f.write(worm_code)
            path = f.name
        try:
            results = self.detector.scan(path, deep=True)
            self.assertTrue(len(results) > 0)
            severities = [r["severity"] for r in results]
            self.assertIn("HIGH", severities)
        finally:
            os.unlink(path)

    def test_registry_persistence_detected(self):
        code = """
import winreg
key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run")
winreg.SetValueEx(key, "Updater", 0, winreg.REG_SZ, "C:\\\\worm.exe")
"""
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
            f.write(code)
            path = f.name
        try:
            results = self.detector.scan(path)
            self.assertTrue(len(results) > 0)
        finally:
            os.unlink(path)

    def test_clean_python_not_flagged(self):
        clean_code = """
def greet(name):
    return f"Hello, {name}!"

if __name__ == "__main__":
    print(greet("World"))
"""
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
            f.write(clean_code)
            path = f.name
        try:
            results = self.detector.scan(path)
            self.assertEqual(len(results), 0)
        finally:
            os.unlink(path)


class TestQuarantineManager(unittest.TestCase):
    def setUp(self):
        self.mgr = QuarantineManager()

    def test_quarantine_and_restore(self):
        # Create a temp file
        with tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".py") as f:
            f.write("# test file\nprint('hello')\n")
            original_path = f.name

        self.assertTrue(os.path.exists(original_path))

        # Quarantine it
        qid = self.mgr.quarantine(original_path)
        self.assertIsNotNone(qid)
        self.assertFalse(os.path.exists(original_path))  # Should be gone

        # Restore it
        self.mgr.restore(qid)
        self.assertTrue(os.path.exists(original_path))   # Should be back

        # Cleanup
        os.unlink(original_path)

    def test_quarantine_nonexistent_file(self):
        result = self.mgr.quarantine("/nonexistent/path/file.py")
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
