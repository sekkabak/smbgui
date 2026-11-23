import asyncio

import pytest

from app.progress import ProgressHub


@pytest.mark.asyncio
async def test_progress_subscribe():
    hub = ProgressHub()
    loop = asyncio.get_running_loop()
    hub.set_loop(loop)
    q = hub.subscribe()
    jid = hub.new_job("upload", host="h", path="a/b", total=100)
    hub.update(jid, bytes_done=50, bytes_total=100)
    hub.done(jid)
    # drain a few events
    got = []
    for _ in range(5):
        try:
            got.append(await asyncio.wait_for(q.get(), timeout=0.5))
        except asyncio.TimeoutError:
            break
    assert any(e.get("job_id") == jid for e in got)
    assert any(e.get("status") == "done" for e in got)
    hub.unsubscribe(q)
