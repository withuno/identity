FROM rustlang/rust:nightly as builder
WORKDIR /app
COPY . .
RUN cargo test --release
RUN cargo install --path api --root . --features "s3 twilio openai brandfetch"

FROM debian:stable-slim
RUN apt update && apt install -y libcurl4
WORKDIR /root
EXPOSE 8080
COPY --from=builder /app/bin/ /usr/local/bin/
COPY --from=builder /app/api/res/ /usr/local/lib/api/
CMD [ "api" ]
