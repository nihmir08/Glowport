#!/bin/sh
# Builds the sync server for Linux: a program without external dependencies that runs on any 64-bit Linux (x86).
# Run on Linux (e.g. WSL) in the project folder:   sh scripts/build-server.sh
# Needs there: Rust with the target x86_64-unknown-linux-musl and the musl-tools package (for SQLite and ring).
# Result: the dist-server folder with everything that belongs on the server (program, service file, setup script).
set -eu

cd "$(dirname "$0")/.."
# Not into the project's `target` folder: it belongs to the Windows build, and on that drive it would be slow.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/glowport-target}"
target=x86_64-unknown-linux-musl

cargo build --release --locked -p glowport-sync-server --target "$target"
mkdir -p dist-server
cp "$CARGO_TARGET_DIR/$target/release/glowport-sync" dist-server/glowport-sync
cp server/glowport-sync.service server/install.sh dist-server/
ls -l dist-server
