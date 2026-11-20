"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Track a request's input and start time until record_output is called."""
        import time
        key = request_id or user_id
        if not hasattr(self, "_pending"):
            self._pending = {}
        self._open[key] = time.perf_counter()
        self._pending[key] = {
            "request_id": request_id,
            "user_id": user_id,
            "input": text,
            "started_at": utc_now_iso(),
        }

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Close the matching pending entry and record outcome + elapsed milliseconds."""
        import time
        key = request_id or user_id
        start = self._open.pop(key, None)
        pending = getattr(self, "_pending", {}).pop(key, {})
        elapsed = (time.perf_counter() - start) * 1000 if start is not None else None
        row = {
            **pending,
            "request_id": request_id,
            "user_id": user_id,
            "response": text,
            "blocked": bool(blocked),
            "layer": layer,
            "finished_at": utc_now_iso(),
            "latency_ms": round(elapsed, 2) if elapsed is not None else None,
        }
        self.logs.append(row)
        return row

    def export_json(self, filepath: str | None = None):
        """Persist the real audit events under repo-root outputs by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.logs, ensure_ascii=False, indent=2), encoding="utf-8")
        return str(path)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
