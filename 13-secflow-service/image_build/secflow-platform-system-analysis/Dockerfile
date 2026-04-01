FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 10011

ENV CONFIG_PATH=/app/config.yaml

CMD ["python", "-m", "app.main"]

