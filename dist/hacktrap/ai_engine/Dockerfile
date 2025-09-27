FROM python:3.9-slim

WORKDIR /app

# أسرع mirrors
RUN pip install --upgrade pip -i https://pypi.org/simple

COPY requirements.txt .

# نستخدم index-url سريع + نجبر على الإصدارات اللي تشتغل
RUN pip install --no-cache-dir -r requirements.txt \
    --index-url https://pypi.org/simple

COPY . .

CMD ["python", "app.py"]
