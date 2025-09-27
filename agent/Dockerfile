FROM python:3.9-alpine

WORKDIR /app

# Install system dependencies required for psutil and other build tools
RUN apk add --no-cache \
    gcc \
    musl-dev \
    linux-headers \
    && pip install --upgrade pip

COPY requirements.txt .
RUN pip install requests
RUN pip install -r requirements.txt

COPY . .

CMD ["python", "collector.py"]
