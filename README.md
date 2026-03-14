# KeyGuard 🛡️

A Python-based **system activity monitor** that detects keylogger-like behavior on Linux and Windows systems. Built as part of cybersecurity research — KeyGuard does *not* log keystrokes; it identifies processes and files that exhibit patterns consistent with known keylogging malware.

> **Context:** This project was developed to understand how keyloggers operate at the OS level, as part of studying for CEH (Certified Ethical Hacker) and applied OS security coursework.

---

## What It Does

- Scans all running processes continuously at a configurable interval
- Scores each process from 0–10 using a heuristic detection engine
- Flags processes that match known keylogger behavior patterns
- Checks startup persistence locations for suspicious entries
- Writes all findings to a structured JSON log
- Generates human-readable security reports from log history

---

## Detection Heuristics

KeyGuard uses a weighted scoring system based on:

| Signal | Score Weight |
|--------|-------------|
| Suspicious keywords in process name/cmdline | +1.5 |
| Writing to .txt/.log files in background | +1.5 |
| High CPU usage with no visible window | +1.0 |
| Active network connections from flagged process | +2.0 |
| Executable running from temp/hidden directory | +1.5 |
| Known suspicious module references (e.g. `pynput`, `GetAsyncKeyState`) | +2.0 |

Processes scoring ≥ 3.0 (configurable) trigger an alert.

---

## Project Structure

```
keyguard/
├── keyguard.py       # Main monitoring loop
├── detector.py       # Heuristic scoring engine
├── logger.py         # JSON log writer / reader
├── config.py         # Configuration dataclass
├── report.py         # Report generator from log data
├── requirements.txt
└── logs/             # Auto-created on first run
```

---

## Setup & Usage

```bash
# Clone the repo
git clone https://github.com/tsunamicodes/keyguard.git
cd keyguard

# Install dependencies
pip install -r requirements.txt

# Run the monitor (Ctrl+C to stop)
python keyguard.py

# Generate a report from saved logs
python report.py
```

---

## Configuration

Edit `config.py` to tune behavior:

```python
scan_interval   = 10     # seconds between scans
alert_threshold = 3.0    # risk score (0–10) to trigger alert
log_file        = "logs/keyguard.log"
```

---

## Sample Output

```
[KeyGuard] Starting monitor — scan interval: 10s
[KeyGuard] Alert threshold: 3.0/10

[2025-09-14T22:10:01] ✓ Clean scan
[2025-09-14T22:10:11] ✓ Clean scan

⚠️  ALERT #1 — 2025-09-14T22:10:21
  PID 4821 | suspicious_proc.py | Score: 5.5/10
    → Suspicious keyword 'hook' in process name/cmdline
    → Writing to log-like file: /tmp/output.log
    → Executable running from suspicious path: /tmp/suspicious_proc.py
```

---

## Tech Stack

- Python 3.10+
- `psutil` — cross-platform process and system utilities
- Standard library: `re`, `json`, `os`, `hashlib`, `dataclasses`

---

## Disclaimer

This tool is strictly for **defensive security research and educational purposes**. It monitors for malicious behavior — it does not perform any keylogging itself. Always obtain proper authorization before running monitoring tools on any system.

---

## Author

**Suhani Rastogi** — B.Tech CSE (Cybersecurity), Bennett University  
CEH v13 Certified
