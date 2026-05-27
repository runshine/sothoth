FROM python:3.11-slim
ARG SECFLOW_BUILD_VERSION=""

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN printf '{"build_version":"%s"}\n' "$SECFLOW_BUILD_VERSION" > /app/build_meta.json

EXPOSE 10011

ENV CONFIG_PATH=/app/config.yaml

CMD ["python", "-m", "app.main"]
