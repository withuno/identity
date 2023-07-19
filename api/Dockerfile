FROM rust:bookworm as builder
WORKDIR /app
COPY . .
RUN rustup show
RUN rm rust-toolchain.toml
RUN cargo test -p api --release
RUN cargo install --path api --root . --features "s3 twilio openai brandfetch"

FROM debian:bookworm-slim
RUN apt update && apt install -y libcurl4 && rm -rf /var/lib/apt/lists/*
WORKDIR /root
EXPOSE 8080
COPY --from=builder /app/bin/ /usr/local/bin/
COPY --from=builder /app/api/res/ /usr/local/lib/api/
CMD [ "api" ]
