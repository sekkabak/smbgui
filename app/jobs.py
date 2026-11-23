"""Background job manager for long-running SMB operations (hours-scale)."""

from __future__ import annotations

import threading
import time
import traceback
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Optional

from .logging_util import setup_logging, log_event
from .progress import hub as progress_hub
from .activity import activity

logger = setup_logging()


@dataclass
class Job:
    job_id: str
    action: str
    host: str = ""
    path: str = ""
    status: str = "queued"  # queued|running|done|error|cancelled
    message: str = ""
    result: Any = None
    error: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    started_at: float = 0.0
    finished_at: float = 0.0
    bytes_done: int = 0
    bytes_total: int = 0
    cancel_event: threading.Event = field(default_factory=threading.Event, repr=False)
    future: Optional[Future] = field(default=None, repr=False)

    def to_dict(self) -> dict[str, Any]:
        pct = 0.0
        if self.bytes_total > 0:
            pct = round(100.0 * self.bytes_done / self.bytes_total, 2)
        elif self.status == "done":
            pct = 100.0
        return {
            "job_id": self.job_id,
            "action": self.action,
            "host": self.host,
            "path": self.path,
            "status": self.status,
            "message": self.message,
            "error": self.error,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "bytes_done": self.bytes_done,
            "bytes_total": self.bytes_total,
            "percent": pct,
            "cancelled": self.cancel_event.is_set(),
            "has_result": self.result is not None,
        }

    def cancel(self) -> None:
        self.cancel_event.set()
        self.message = "cancel requested"
        progress_hub.update(self.job_id, status="running", message="cancel requested")


class JobManager:
    def __init__(self, max_workers: int = 4):
        self._jobs: dict[str, Job] = {}
        self._lock = threading.RLock()
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="smbgui-job")

    def get(self, job_id: str) -> Optional[Job]:
        with self._lock:
            return self._jobs.get(job_id)

    def list(self, limit: int = 50) -> list[dict]:
        with self._lock:
            jobs = sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)[:limit]
            return [j.to_dict() for j in jobs]

    def cancel(self, job_id: str) -> bool:
        job = self.get(job_id)
        if not job:
            return False
        job.cancel()
        return True

    def submit(
        self,
        action: str,
        fn: Callable[[Job], Any],
        *,
        host: str = "",
        path: str = "",
        bytes_total: int = 0,
    ) -> Job:
        job_id = progress_hub.new_job(action, host=host, path=path, total=bytes_total)
        job = Job(job_id=job_id, action=action, host=host, path=path, bytes_total=bytes_total)
        with self._lock:
            self._jobs[job_id] = job

        def runner():
            job.status = "running"
            job.started_at = time.time()
            progress_hub.update(job_id, status="running", message="started")
            activity.set(action if action in ("downloading","uploading","refreshing") else "waiting",
                         f"{action} started: {path or host}", host=host, path=path, action=action)
            log_event(logger, "job_started", action=action, host=host, job_id=job_id)
            activity.set("waiting", f"job {action} started", host=host, path=path, action=action)
            try:
                if job.cancel_event.is_set():
                    raise RuntimeError("cancelled before start")
                result = fn(job)
                if job.cancel_event.is_set():
                    job.status = "cancelled"
                    job.message = "cancelled"
                    progress_hub.update(job_id, status="error", message="cancelled")
                else:
                    job.result = result
                    job.status = "done"
                    job.message = "done"
                    if job.bytes_total > 0:
                        job.bytes_done = job.bytes_total
                    progress_hub.done(job_id, message="done")
                    activity.idle(f"job {action} done")
            except Exception as e:
                job.error = str(e)
                job.status = "cancelled" if job.cancel_event.is_set() else "error"
                job.message = str(e)
                progress_hub.error(job_id, str(e))
                activity.error(f"job {action} failed: {e}", host=host, path=path)
                log_event(logger, "job_error", action=action, host=host, job_id=job_id, error=str(e))
                logger.error("job %s failed: %s\n%s", job_id, e, traceback.format_exc())
            finally:
                job.finished_at = time.time()

        job.future = self._pool.submit(runner)
        return job

    def update_progress(self, job: Job, bytes_done: int, bytes_total: Optional[int] = None, message: str = "") -> None:
        job.bytes_done = bytes_done
        if bytes_total is not None:
            job.bytes_total = bytes_total
        if message:
            job.message = message
        progress_hub.update(
            job.job_id,
            bytes_done=bytes_done,
            bytes_total=job.bytes_total,
            message=message or job.message,
            status="running",
        )


# Global manager
jobs = JobManager()
