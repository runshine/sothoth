FROM public.ecr.aws/docker/library/python:3.11-slim

WORKDIR /app

ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY cli.py /app/cli.py
COPY core/ /app/core/
COPY config.yaml /app/config.yaml

CMD ["python", "cli.py", "--help"]
