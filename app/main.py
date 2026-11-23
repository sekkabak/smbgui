"""smbgui entrypoint — FastAPI app serving API + WebSocket + dark web UI."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .api import create_router, create_ws_router
from .bookmarks import BookmarkStore
from .cache import CacheStore, DEFAULT_TTL_SECONDS
from .config import bind_host, bind_port, data_dir, settings as reliability_settings, web_dir
from .logging_util import setup_logging
from .progress import hub as progress_hub
from .activity import activity
from .session_log import SessionLog
from .smb_client import SMBPool

DATA = data_dir()
WEB = web_dir()

logger = setup_logging()
pool = SMBPool(reliability=reliability_settings)
cache = CacheStore(DATA, default_ttl=DEFAULT_TTL_SECONDS)
slog = SessionLog()
bookmarks = BookmarkStore(DATA / "bookmarks.json")


@asynccontextmanager
async def lifespan(app: FastAPI):
    loop = asyncio.get_running_loop()
    progress_hub.set_loop(loop)
    activity.set_loop(loop)
    logger.info(
        "smbgui starting data_dir=%s connect_timeout=%s io_timeout=%s",
        str(DATA),
        reliability_settings.connect_timeout,
        reliability_settings.io_timeout,
    )
    yield
    logger.info("smbgui stopping")


app = FastAPI(
    title="smbgui",
    version="1.2.0",
    description="Full-featured SMB file explorer (Impacket + FastAPI) — resilience for unstable nets",
    lifespan=lifespan,
)
app.include_router(create_router(pool, cache, slog, bookmarks))
app.include_router(create_ws_router())


@app.get("/")
def index():
    return FileResponse(WEB / "index.html")


app.mount("/static", StaticFiles(directory=str(WEB)), name="static")


def run():
    import uvicorn

    # Long keep-alive; actual multi-hour transfers use background jobs, not one HTTP request.
    uvicorn.run(
        "app.main:app",
        host=bind_host(),
        port=bind_port(),
        reload=False,
        timeout_keep_alive=75,
        # no request timeout — uvicorn does not enforce one by default
    )


if __name__ == "__main__":
    run()
