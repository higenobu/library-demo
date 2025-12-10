#!/usr/bin/env bash
set -euo pipefail

echo "=== run.sh: starting ==="

# DB connection config (fallbacks)
DATABASE_URL="${DATABASE_URL:-postgresql://library_user:library_pass@db:5432/library_db}"
RETRIES="${DB_WAIT_RETRIES:-60}"
SLEEP_SEC="${DB_WAIT_SLEEP:-1}"

# Wait until DB is reachable
i=0
echo "Waiting for database to accept connections..."
while true; do
  i=$((i+1))
  python3 - <<PY 2>/tmp/db_check_err || true
import os,sys
try:
    import psycopg2
    dsn = os.environ.get("DATABASE_URL", "")
    if not dsn:
        raise SystemExit(2)
    conn = psycopg2.connect(dsn)
    conn.close()
    print("DB_OK")
    sys.exit(0)
except Exception as e:
    print("DB_ERR", e)
    sys.exit(1)
PY
  rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "Database reachable."
    break
  fi
  if [ "$i" -ge "$RETRIES" ]; then
    echo "Timed out waiting for database after ${RETRIES} attempts." >&2
    [ -f /tmp/db_check_err ] && cat /tmp/db_check_err || true
    exit 1
  fi
  echo "  DB not ready yet (attempt $i/${RETRIES}), sleeping ${SLEEP_SEC}s..."
  sleep "${SLEEP_SEC}"
done

# Decide what to forward to app.py:
# - If explicit args include --run or --create-* or --help, forward them.
# - If args include unknown flags (like --config), ignore them and default to --run.
KNOWN=()
for a in "$@"; do
  case "$a" in
    --run|--help|--create-*)
      KNOWN+=("$a")
      ;;
    --create-*)
      KNOWN+=("$a")
      ;;
    *)
      # ignore other args
      ;;
  esac
done

if [ "${#KNOWN[@]}" -gt 0 ]; then
  echo "Forwarding known args to app.py: ${KNOWN[*]}"
  exec python3 -u app.py "${KNOWN[@]}"
fi

# If user called run.sh with no args or only unknown args, start server
if [ "$#" -gt 0 ]; then
  echo "Received args but none recognized for forwarding; starting app.py --run"
else
  echo "No args provided. Starting app.py --run"
fi
exec python3 -u app.py --run
