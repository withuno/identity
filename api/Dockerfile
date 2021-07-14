FROM rust:latest as builder
WORKDIR /app
COPY . .
RUN cargo test --release
RUN cargo install --path api --root . --features s3

FROM debian:buster-slim
RUN apt update && apt install -y libcurl4
WORKDIR /root
EXPOSE 8080
COPY --from=builder /app/bin/ /usr/local/bin/
CMD [ "api" ]

