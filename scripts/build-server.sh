#!/bin/sh
# Baut den Sync-Server für Linux: ein Programm ohne äußere Abhängigkeiten, das auf jedem 64-Bit-Linux (x86) läuft.
# Aufruf in einem Linux (etwa WSL) im Projektordner:   sh scripts/build-server.sh
# Braucht dort: Rust mit dem Ziel x86_64-unknown-linux-musl und das Paket musl-tools (für SQLite und ring).
# Ergebnis: der Ordner dist-server mit allem, was auf den Server gehört (Programm, Dienst-Datei, Einrichtungsskript).
set -eu

cd "$(dirname "$0")/.."
# Nicht in den Ordner `target` des Projekts: Der gehört dem Bau unter Windows, und auf dessen Laufwerk wäre es langsam.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/glowport-target}"
target=x86_64-unknown-linux-musl

cargo build --release --locked -p glowport-sync-server --target "$target"
mkdir -p dist-server
cp "$CARGO_TARGET_DIR/$target/release/glowport-sync" dist-server/glowport-sync
cp server/glowport-sync.service server/install.sh dist-server/
ls -l dist-server
