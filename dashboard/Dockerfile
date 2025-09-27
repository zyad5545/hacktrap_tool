# dashboard/Dockerfile - lightweight production-ish image
FROM python:3.10-slim

WORKDIR /app

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1

COPY requirements.txt /app/requirements.txt

RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc build-essential ca-certificates \
 && pip install --no-cache-dir -r /app/requirements.txt \
 && apt-get remove -y gcc build-essential \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

EXPOSE 5000

CMD ["gunicorn", "server:app", "-b", "0.0.0.0:5000", "--workers", "2", "--timeout", "120"]
