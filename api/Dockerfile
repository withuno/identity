FROM rust:latest as builder
WORKDIR /app
COPY . .
RUN cargo test
RUN cargo install --path api --root .

FROM debian:buster-slim
WORKDIR /root
COPY --from=builder /app/bin/ /usr/local/bin/
EXPOSE 8080
CMD ["api"]

