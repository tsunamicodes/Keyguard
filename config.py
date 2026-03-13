"""
Configuration for KeyGuard.
"""

from dataclasses import dataclass, field


@dataclass
class Config:
    scan_interval: int = 10          # Seconds between scans
    alert_threshold: float = 3.0     # Risk score (0–10) to trigger alert
    log_file: str = "logs/keyguard.log"
    max_log_size_mb: int = 50
    whitelist_pids: list = field(default_factory=list)
    whitelist_names: list = field(default_factory=lambda: [
        "systemd", "kernel", "kworker", "sshd"
    ])
