FROM rust:1.94.1-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends\
    pkg-config \
    libssl-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy shit
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --bin rdrive-server

FROM debian:stable-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    openssl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/rdrive-server /app/rdrive-server

COPY docker-entrypoint.sh /app/docker-entrypoint.sh

RUN chmod +x /app/docker-entrypoint.sh

# Create config and storage directories upfront
RUN mkdir -p /home/rdrive/.rdrive/storage

EXPOSE 3000
ENV HOME=/home/rdrive
ENV LOG_LEVEL=trace
ENV PORT=3000
ENV MAX_CONNECTIONS=128
ENV MAX_FILE_SIZE_GB='6 * 1024 * 1024 * 1024'
ENV ENABLE_ECHO=true
ENV ENABLE_CLIENT_WHITELIST=false
ENV RATE_LIMIT_MAX_TOKENS=100
ENV RATE_LIMIT_REFILL_RATE=10
ENV CONNECTION_LIFETIME_SECS=6400

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD test -f /app/rdrive-server || exit 1

ENTRYPOINT ["/app/docker-entrypoint.sh"]

CMD ["serve"]
