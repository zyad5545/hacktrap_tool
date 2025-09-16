FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["gunicorn", "app:app", "-b", "0.0.0.0:8000", "--workers", "4"]
# تثبيت sqlite3 CLI
RUN apt-get update && apt-get install -y sqlite3 && rm -rf /var/lib/apt/lists/*


