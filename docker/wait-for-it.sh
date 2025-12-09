#!/usr/bin/env bash
# Simple wait-for-it style script (lightweight). Waits for host:port to be open.
# Usage: /wait-for-it.sh host:port --timeout=60 --strict -- command args...
set -e

TIMEOUT=60
STRICT=0

# parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --timeout=*)
      TIMEOUT="${1#*=}"
      shift
      ;;
    --strict)
      STRICT=1
      shift
      ;;
    --) shift; break ;;
    *) break ;;
  esac
done

HOSTPORT="$1"
shift || true

if [ -z "$HOSTPORT" ]; then
  echo "Usage: $0 host:port -- command"
  exit 2
fi

HOST="${HOSTPORT%%:*}"
PORT="${HOSTPORT#*:}"

echo "Waiting for $HOST:$PORT (timeout=${TIMEOUT}s)..."

START_TS=$(date +%s)
while :
do
  if nc -z "$HOST" "$PORT" >/dev/null 2>&1; then
    echo "$HOST:$PORT is available"
    break
  fi
  NOW=$(date +%s)
  ELAPSED=$((NOW - START_TS))
  if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
    echo "Timeout waiting for $HOST:$PORT"
    if [ "$STRICT" -eq 1 ]; then
      exit 1
    else
      break
    fi
  fi
  sleep 1
done

# execute remaining command if any
if [ $# -gt 0 ]; then
  exec "$@"
fi
