# Baut `glowport-sync` aus dem Quelltext und packt es in ein kleines Abbild.
# Aufruf im Projektordner (eine Ebene über diesem Ordner):
#   docker build -f server/Dockerfile -t glowport-sync .
# Anleitung: docs/sync-server.md

FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
# Unter Alpine entsteht ein Programm ohne äußere Abhängigkeiten. Gebaut wird nur der Server, nicht Glowport.
RUN cargo build --release --locked -p glowport-sync-server

FROM alpine:3
# Ein eigener Benutzer ohne Rechte; ihm gehört nur der Datenordner.
RUN adduser -D -H -u 10001 glowport && mkdir /data && chown glowport:glowport /data && chmod 700 /data
COPY --from=build /src/target/release/glowport-sync /usr/local/bin/glowport-sync
USER glowport
ENV GLOWPORT_SYNC_LISTEN=0.0.0.0:8787 \
    GLOWPORT_SYNC_DATA=/data
VOLUME /data
EXPOSE 8787
ENTRYPOINT ["glowport-sync"]
CMD ["serve"]
