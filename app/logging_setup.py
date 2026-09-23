"""
Structured logging. Every request produces exactly ONE JSON object on ONE line
(JSON Lines / .jsonl). This format is what the SIEM ingests in Phase 3 — each line
is a self-contained event, so Filebeat/Elastic can parse it with zero glue.
"""
import json
import os
import sys
import datetime


def _ensure_dir(path: str) -> None:
    directory = os.path.dirname(path)
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)


class EventLogger:
    def __init__(self, log_file: str):
        self.log_file = log_file
        _ensure_dir(log_file)

    def log(self, event: dict) -> None:
        event.setdefault(
            "timestamp",
            datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )
        line = json.dumps(event, ensure_ascii=False, default=str)
        with open(self.log_file, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        print(line, file=sys.stdout, flush=True)
