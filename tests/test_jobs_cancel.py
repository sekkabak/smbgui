import threading
import time

from app.jobs import JobManager


def test_job_cancel():
    mgr = JobManager(max_workers=2)
    started = threading.Event()
    finished = threading.Event()

    def work(job):
        started.set()
        for _ in range(50):
            if job.cancel_event.is_set():
                raise RuntimeError("cancelled")
            time.sleep(0.02)
        finished.set()
        return "done"

    job = mgr.submit("test", work, host="h", path="p")
    assert started.wait(2)
    assert mgr.cancel(job.job_id)
    # wait for runner to finish
    for _ in range(100):
        if job.status in ("cancelled", "error", "done"):
            break
        time.sleep(0.05)
    assert job.status in ("cancelled", "error")
    assert job.cancel_event.is_set()
