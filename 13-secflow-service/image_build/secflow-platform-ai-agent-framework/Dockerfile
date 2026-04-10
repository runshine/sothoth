FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY plugins/ ./plugins/
COPY examples/ ./examples/
COPY prompts/ ./prompts/
COPY config.json ./config.json
COPY config.pi_vuln.example.json ./config.pi_vuln.example.json
COPY config.yaml ./config.yaml

ENV PYTHONPATH=/app

CMD ["python", "-m", "app.main"]
