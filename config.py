from dataclasses import dataclass, field

@dataclass
class Config:
    scan_interval: int = 10
    alert_threshold: float = 3.0
    log_file: str = "logs/keyguard.log"
    max_log_size_mb: int = 50
    whitelist_pids: list = field(default_factory=list)
    whitelist_names: list = field(default_factory=lambda: ["systemd", "kernel", "kworker", "sshd"])
