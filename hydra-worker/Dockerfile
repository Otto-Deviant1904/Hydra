FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    hashcat \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -e .

CMD ["python", "-m", "hydra_worker.main", "--server", "${HYDRA_SERVER_URL:-ws://hydra-server:8080/ws}"]
