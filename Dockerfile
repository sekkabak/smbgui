# smbgui — Impacket SMB file explorer (FastAPI)
# IMPORTANT: publish only to localhost on the host, e.g.
#   docker run -p 127.0.0.1:8787:8787 ...
# The app has no built-in authentication and holds credentials in memory.

FROM python:3.13-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SMBGUI_DATA_DIR=/app/data \
    SMBGUI_HOST=0.0.0.0 \
    SMBGUI_PORT=8787

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY web ./web
COPY README.md LICENSE ./

RUN mkdir -p /app/data && useradd --system --uid 10001 --home /app --shell /usr/sbin/nologin smbgui \
    && chown -R smbgui:smbgui /app

USER smbgui

EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/', timeout=3)" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8787"]
