"""
Detector module — evaluates processes and files for keylogger-like behavior.
Uses a heuristic scoring system (0–10) based on known keylogger patterns.
"""

import psutil
import os
import re
from config import Config

# Known suspicious keywords in process names / file paths
SUSPICIOUS_KEYWORDS = [
    "hook", "keylog", "spy", "monitor", "capture", "record",
    "input", "intercept", "stealth", "hide", "inject"
]

# Known suspicious DLLs / libraries associated with keylogging
SUSPICIOUS_MODULES = [
    "SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState",
    "keyboard", "pynput", "pyxhook", "xinput"
]

# File content patterns that suggest keylogging
KEYLOGGER_PATTERNS = [
    r"SetWindowsHookEx",
    r"GetAsyncKeyState",
    r"pynput\.keyboard",
    r"keyboard\.on_press",
    r"open\(.+['\"]a['\"]\).+write",  # append-write pattern (logging keys)
    r"VK_[A-Z]+",                      # virtual key codes
]


class KeyloggerDetector:
    def __init__(self, config: Config):
        self.config = config

    def evaluate(self, proc: psutil.Process) -> tuple[float, list[str]]:
        """
        Score a process 0–10 for keylogger likelihood.
        Returns (score, list_of_reasons).
        """
        score = 0.0
        reasons = []

        try:
            name = (proc.name() or "").lower()
            cmdline = " ".join(proc.cmdline()).lower()
            exe = (proc.exe() or "").lower()

            # 1. Suspicious name keywords
            for kw in SUSPICIOUS_KEYWORDS:
                if kw in name or kw in cmdline:
                    score += 1.5
                    reasons.append(f"Suspicious keyword '{kw}' in process name/cmdline")
                    break

            # 2. Unusual open file handles (writing to .txt/.log in background)
            try:
                for f in proc.open_files():
                    if f.path.endswith(('.txt', '.log', '.dat')):
                        if f.mode in ('a', 'w', 'r+'):
                            score += 1.5
                            reasons.append(f"Writing to log-like file: {f.path}")
                            break
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            # 3. High CPU with no visible window (common in background spyware)
            try:
                cpu = proc.cpu_percent(interval=0.1)
                if cpu > 15 and not self._has_window(proc):
                    score += 1.0
                    reasons.append(f"High CPU ({cpu:.1f}%) with no visible window")
            except Exception:
                pass

            # 4. Network connections from a process that shouldn't have them
            try:
                conns = proc.connections()
                if conns and any(c.status == 'ESTABLISHED' for c in conns):
                    if any(kw in name for kw in ['hook', 'key', 'spy']):
                        score += 2.0
                        reasons.append("Active network connection from suspicious process")
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            # 5. Running from temp / hidden directory
            suspicious_dirs = ['temp', 'tmp', 'appdata\\local\\temp', '/tmp']
            if any(d in exe for d in suspicious_dirs):
                score += 1.5
                reasons.append(f"Executable running from suspicious path: {exe}")

            # 6. Module names in cmdline
            for mod in SUSPICIOUS_MODULES:
                if mod.lower() in cmdline:
                    score += 2.0
                    reasons.append(f"Suspicious module reference: {mod}")
                    break

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        return min(round(score, 1), 10.0), reasons

    def evaluate_file(self, filepath: str) -> float:
        """Score a file path based on name alone."""
        name = os.path.basename(filepath).lower()
        score = sum(1.0 for kw in SUSPICIOUS_KEYWORDS if kw in name)
        return min(score * 2, 10.0)

    def evaluate_file_content(self, content: str) -> float:
        """Score file content based on known keylogger code patterns."""
        score = 0.0
        for pattern in KEYLOGGER_PATTERNS:
            if re.search(pattern, content):
                score += 2.0
        return min(score, 10.0)

    def _has_window(self, proc: psutil.Process) -> bool:
        """Heuristic: check if a process likely has a UI window."""
        try:
            name = proc.name().lower()
            windowed_indicators = ['python', 'node', 'java', 'chrome', 'firefox']
            return any(ind in name for ind in windowed_indicators)
        except Exception:
            return False
