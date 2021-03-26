FROM rust:latest as builder
WORKDIR /app
COPY . .
RUN cargo test --release
RUN cargo install --path api --root .

FROM debian:buster-slim
RUN apt update && apt install -y s3fs
WORKDIR /root
# ARG AWSACCESSKEYID
# ARG AWSSECRETACCESSKEY
# RUN echo "$AWSACCESSKEYID:$AWSSECRETACCESSKEY" > .passwd-s3fs
# RUN chmod 600 .passwd-s3fs
RUN mkdir vaults sessions services
ENTRYPOINT [ \
"/bin/sh", "-c", \
  "s3fs", "vaults.u1o.dev", "vaults", \
    "-o", "host=https://nyc3.digitaloceanspaces.com", \
    "-o", "use_path_request_style", "&&", \
  "s3fs", "sessions.u1o.dev", "sessions", \
    "-o", "host=https://nyc3.digitaloceanspaces.com", \
    "-o", "use_path_request_style", "&&", \
  "s3fs", "services.u1o.dev", "services", \
    "-o", "host=https://nyc3.digitaloceanspaces.com", \
    "-o", "use_path_request_style", "&&", \
]
EXPOSE 8080
COPY --from=builder /app/bin/ /usr/local/bin/
CMD ["api"]

