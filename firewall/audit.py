"""JSON-lines audit log plus an in-memory ring of recent decisions for the dashboard."""
import json
import threading
from collections import deque
from datetime import datetime, timezone


class Audit:
    def __init__(self, path: str | None, keep: int = 200):
        self.path, self._recent, self._lock = path, deque(maxlen=keep), threading.Lock()

    def log(self, **event) -> dict:
        event = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), **event}
        line = json.dumps(event, ensure_ascii=False)
        with self._lock:
            self._recent.append(event)
            if self.path:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
        return event

    def recent(self) -> list:
        with self._lock:
            return list(self._recent)
