FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends bash strace coreutils procps iproute2 curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10001 lab && useradd -u 10001 -g lab -d /home/lab -s /bin/bash lab \
    && mkdir -p /bridge /home/lab && chown 10001:10001 /bridge /home/lab
COPY sandbox/worker.py /opt/worker.py
USER 10001:10001
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /home/lab
CMD ["python", "/opt/worker.py"]
