# Builds `glowport-sync` from source and packs it into a small image.
# Run in the project folder (one level above this folder):
#   docker build -f server/Dockerfile -t glowport-sync .
# Guide: docs/sync-server.md

FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
# On Alpine the result is a program without external dependencies. Only the server is built, not Glowport.
RUN cargo build --release --locked -p glowport-sync-server

FROM alpine:3
# A user of its own without privileges; only the data folder belongs to it.
RUN adduser -D -H -u 10001 glowport && mkdir /data && chown glowport:glowport /data && chmod 700 /data
COPY --from=build /src/target/release/glowport-sync /usr/local/bin/glowport-sync
USER glowport
ENV GLOWPORT_SYNC_LISTEN=0.0.0.0:8787 \
    GLOWPORT_SYNC_DATA=/data
VOLUME /data
EXPOSE 8787
ENTRYPOINT ["glowport-sync"]
CMD ["serve"]
