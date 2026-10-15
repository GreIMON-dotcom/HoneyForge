FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt requirements.lock ./
RUN pip install --no-cache-dir -r requirements.txt && groupadd -g 10001 honeyforge && useradd -u 10001 -g honeyforge -M honeyforge && mkdir /spool /bridge && chown honeyforge:honeyforge /spool /bridge
COPY --chown=honeyforge:honeyforge backend backend
COPY --chown=honeyforge:honeyforge shared shared
COPY --chown=honeyforge:honeyforge agent agent
COPY --chown=honeyforge:honeyforge honeypots honeypots
COPY --chown=honeyforge:honeyforge controller controller
COPY --chown=honeyforge:honeyforge notifier notifier
COPY --chown=honeyforge:honeyforge frontend frontend
COPY alembic.ini .
USER 10001:10001
CMD ["python", "-m", "uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
