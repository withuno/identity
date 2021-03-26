FROM rust:latest as builder
WORKDIR /app
COPY . .
RUN cargo test --release
RUN cargo install --path api --root .

FROM debian:buster-slim
RUN apt update && apt install -y s3fs
WORKDIR /root
RUN mkdir vaults sessions services
RUN echo "#!/bin/sh \
set -ex \n\
s3fs vaults.u1o.dev vaults \\\\\n\
  -o host=https://nyc3.digitaloceanspaces.com \\\\\n\
  -o use_path_request_style \n\
s3fs sessions.u1o.dev sessions \\\\\n\
  -o host=https://nyc3.digitaloceanspaces.com \\\\\n\
  -o use_path_request_style \n\
s3fs services.u1o.dev services \\\\\n\
  -o host=https://nyc3.digitaloceanspaces.com \\\\\n\
  -o use_path_request_style \n\
exec "'"$@"'"" \
> entrypoint.sh
RUN chmod a+x entrypoint.sh
ENTRYPOINT [ "/bin/sh", "entrypoint.sh" ]
EXPOSE 8080
COPY --from=builder /app/bin/ /usr/local/bin/
CMD [ "api" ]

