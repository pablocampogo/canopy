#!/bin/sh

# if BIN_PATH its defined we make a link to it from its volume to our system
if [ -z "${BIN_PATH}" ]; then
  echo "BIN_PATH not provided using /bin/cli as default"
  export BIN_PATH="/bin/cli"
else
  echo "using existing BIN_PATH $BIN_PATH"
fi

# resolve data dir: --data-dir flag, then DATA_DIR env, then default
DATA_DIR="${DATA_DIR:-${HOME:-/root}/.canopy}"
prev=""
for arg in "$@"; do
  case "$prev" in
    --data-dir) DATA_DIR="$arg" ;;
  esac
  case "$arg" in
    --data-dir=*) DATA_DIR="${arg#--data-dir=}" ;;
  esac
  prev="$arg"
done
echo "using data directory $DATA_DIR"

mkdir -p "$DATA_DIR"

# Persisting current version
# Check if it exist
if [ -f "$DATA_DIR/cli" ]; then
  echo "Found existing persistent cli version"
else
  echo "Persisting build version for current cli"
  cp "$BIN_PATH" "$DATA_DIR/cli"
fi
ln -sf "$DATA_DIR/cli" "$BIN_PATH"

exec /app/canopy "$@"
