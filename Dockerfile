FROM python:3.11-slim

LABEL maintainer="OpenCryptoDetect Contributors"
LABEL description="Cross-architecture cryptographic primitive detection CLI for firmware binaries"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    libcapstone-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY models/ ./models/
COPY signatures/ ./signatures/

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -e ".[all]"

ENTRYPOINT ["ocd"]
CMD ["--help"]
