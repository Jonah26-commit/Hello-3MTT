"""
Heuristic Detector
Analyzes files for worm-like behavioral traits without relying on signatures.
Looks for combinations of: self-replication logic, network spreading, 
persistence mechanisms, and obfuscation techniques.
"""

import os
import re
import math
import stat
from collections import Counter


# Scoring thresholds
HEURISTIC_THRESHOLD_MEDIUM = 30
HEURISTIC_THRESHOLD_HIGH = 60


# Heuristic rules: (pattern_or_check, score, label)
# Each matching rule adds its score to the total.
TEXT_HEURISTIC_RULES = [
    # Self-replication
    (r"shutil\.copy|shutil\.copy2|shutil\.copytree", 15, "Python file self-copy"),
    (r"os\.system\s*\(\s*['\"]copy", 20, "OS copy command"),
    (r"subprocess.*copy|subprocess.*xcopy", 20, "Subprocess file copy"),
    (r"open\(__file__\)|__file__", 10, "Self-referential file access"),
    (r"sys\.argv\[0\].*copy|copyfile.*sys\.argv", 15, "Self-copy via argv"),

    # Network spreading
    (r"socket\.connect|socket\.bind|socket\.listen", 10, "Raw socket usage"),
    (r"paramiko|ftplib|pysftp", 10, "Remote file transfer library"),
    (r"smtplib\.SMTP|sendmail|send_message", 15, "SMTP email sending"),
    (r"urllib.*open|requests\.get|requests\.post", 5, "HTTP network request"),
    (r"for.*ip.*range|ipaddress\.ip_network", 15, "IP range scanning"),
    (r"nmap|masscan|zmap", 20, "Network scanner usage"),

    # Persistence mechanisms
    (r"HKEY_CURRENT_USER.*Run|HKEY_LOCAL_MACHINE.*Run", 20, "Windows registry Run key"),
    (r"winreg|_winreg|OpenKey.*Registry", 15, "Windows registry manipulation"),
    (r"crontab|/etc/cron\.", 15, "Cron job persistence"),
    (r"~/.bashrc|~/.profile|~/.bash_profile", 10, "Shell startup modification"),
    (r"systemctl enable|rc\.local|init\.d", 15, "System service persistence"),
    (r"LaunchAgent|LaunchDaemon|plist", 10, "macOS launch persistence"),

    # Obfuscation
    (r"base64\.b64decode|base64\.decode", 10, "Base64 decoding"),
    (r"eval\(.*decode|exec\(.*decode", 20, "Eval with decode (obfuscation)"),
    (r"\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}", 15, "Hex-encoded payload"),
    (r"chr\(\d+\)\s*\+\s*chr\(\d+\)", 15, "Char-by-char string construction"),
    (r"zlib\.decompress|gzip\.decompress", 10, "Compressed payload"),

    # Payload delivery
    (r"os\.execv|os\.execve|subprocess\.Popen.*shell=True", 15, "Dynamic execution"),
    (r"ctypes\.windll|ctypes\.cdll|LoadLibrary", 15, "DLL injection"),
    (r"WriteProcessMemory|VirtualAlloc|CreateRemoteThread", 25, "Memory injection"),
    (r"__import__\(.*\)|importlib\.import_module", 10, "Dynamic import"),

    # Credential harvesting (common in worm+stealer combos)
    (r"keylogger|GetAsyncKeyState|SetWindowsHookEx", 20, "Keylogger behavior"),
    (r"/etc/passwd|/etc/shadow", 15, "Unix credential file access"),
    (r"SAM|lsass\.exe|mimikatz", 25, "Windows credential dumping"),
]

# Suspicious string combinations (multiple must appear together)
COMBO_RULES = [
    (["socket", "copy", "os.walk"], 30, "Network + copy + filesystem traversal combo"),
    (["smtp", "os.walk", "attach"], 25, "Email worm: SMTP + file traversal + attach"),
    (["socket", "base64", "exec"], 30, "Network download + obfuscated exec"),
    (["winreg", "socket", "copy"], 30, "Registry persistence + network + copy"),
]


class HeuristicDetector:
    def __init__(self):
        self.text_extensions = {
            ".py", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".sh",
            ".pl", ".rb", ".php", ".lua", ".wsf", ".hta"
        }
        self.binary_extensions = {".exe", ".dll", ".com", ".scr", ".sys"}

    def scan(self, filepath: str, deep: bool = False) -> list:
        """
        Scan a file heuristically.
        Returns list of threat dicts (may be empty).
        """
        threats = []
        try:
            _, ext = os.path.splitext(filepath.lower())

            # Text-based script heuristics
            if ext in self.text_extensions:
                threats.extend(self._scan_text(filepath, deep))

            # Binary entropy check (packed/obfuscated executables)
            if ext in self.binary_extensions or deep:
                entropy_threat = self._check_entropy(filepath)
                if entropy_threat:
                    threats.append(entropy_threat)

            # Permission anomalies (Linux/Mac)
            perm_threat = self._check_permissions(filepath)
            if perm_threat:
                threats.append(perm_threat)

        except (PermissionError, OSError):
            pass

        return threats

    def _scan_text(self, filepath: str, deep: bool) -> list:
        threats = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            total_score = 0
            matched_labels = []

            # Apply individual rules
            for pattern, score, label in TEXT_HEURISTIC_RULES:
                if re.search(pattern, content, re.IGNORECASE):
                    total_score += score
                    matched_labels.append(label)

            # Apply combo rules
            for keywords, score, label in COMBO_RULES:
                if all(kw in content for kw in keywords):
                    total_score += score
                    matched_labels.append(label)

            if total_score >= HEURISTIC_THRESHOLD_HIGH:
                threats.append({
                    "type": "HEURISTIC",
                    "description": f"High-confidence worm behavior: {', '.join(matched_labels[:3])}",
                    "severity": "HIGH",
                    "indicator": f"Score: {total_score}",
                })
            elif total_score >= HEURISTIC_THRESHOLD_MEDIUM:
                threats.append({
                    "type": "HEURISTIC",
                    "description": f"Suspicious worm-like behavior: {', '.join(matched_labels[:3])}",
                    "severity": "MEDIUM",
                    "indicator": f"Score: {total_score}",
                })

        except Exception:
            pass

        return threats

    def _check_entropy(self, filepath: str) -> dict | None:
        """High entropy = likely packed/encrypted payload."""
        try:
            file_size = os.path.getsize(filepath)
            if file_size < 512 or file_size > 10 * 1024 * 1024:
                return None

            with open(filepath, "rb") as f:
                data = f.read(65536)  # Sample first 64KB

            entropy = self._shannon_entropy(data)

            if entropy > 7.4:  # Near-random = likely packed
                return {
                    "type": "HEURISTIC",
                    "description": "Extremely high entropy — likely packed or encrypted payload",
                    "severity": "MEDIUM",
                    "indicator": f"Entropy: {entropy:.2f}/8.0",
                }
        except Exception:
            pass
        return None

    def _check_permissions(self, filepath: str) -> dict | None:
        """Detect unusual permission combinations (e.g., world-writable executables)."""
        try:
            if os.name == "nt":
                return None  # Skip on Windows
            file_stat = os.stat(filepath)
            mode = file_stat.st_mode

            # World-writable + executable = very suspicious
            if (mode & stat.S_IWOTH) and (mode & stat.S_IXUSR):
                return {
                    "type": "HEURISTIC",
                    "description": "World-writable executable file",
                    "severity": "MEDIUM",
                    "indicator": oct(mode),
                }
        except Exception:
            pass
        return None

    def _shannon_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of bytes (0-8 scale)."""
        if not data:
            return 0.0
        counts = Counter(data)
        length = len(data)
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in counts.values()
        )
        return entropy
