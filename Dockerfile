# hacktrap/Dockerfile
FROM python:3.10-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /app

# minimal system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# copy project files (expect backend/ dir or a flattened structure)
COPY backend/ /app/

# create venv and install requirements if present
RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip setuptools wheel && \
    if [ -f requirements.txt ]; then \
      /opt/venv/bin/pip install --no-cache-dir -r requirements.txt ; \
    fi

# copy entrypoint
COPY docker-entrypoint-hacktrap.sh /usr/local/bin/docker-entrypoint-hacktrap.sh
RUN chmod +x /usr/local/bin/docker-entrypoint-hacktrap.sh

ENV PATH="/opt/venv/bin:${PATH}"

EXPOSE 8000

ENTRYPOINT ["/usr/local/bin/docker-entrypoint-hacktrap.sh"]
CMD ["gunicorn", "app:app", "-b", "0.0.0.0:8000", "--workers", "2"]
