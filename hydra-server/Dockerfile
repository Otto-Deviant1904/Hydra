FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    hashcat john \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -e ".[ml]"

EXPOSE 8080
CMD ["uvicorn", "hydra.api.main:app", "--host", "0.0.0.0", "--port", "8080"]
