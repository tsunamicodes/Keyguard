"""
Logger module for KeyGuard.
"""
import json
import os
from datetime import datetime

class ActivityLogger:
    def __init__(self, log_file):
        os.makedirs(os.path.dirname(log_file) if os.path.dirname(log_file) else ".", exist_ok=True)
        self._file = open(log_file, 'a')

    def log(self, data):
        self._file.write(json.dumps(data) + "\n")
        self._file.flush()

    def close(self):
        self._file.close()

    @staticmethod
    def read_log(log_file):
        if not os.path.exists(log_file):
            return []
        with open(log_file, 'r') as f:
            return [json.loads(line) for line in f if line.strip()]
