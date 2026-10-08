#!/bin/sh
set -e

# If running as container root, configure data directory permissions and drop to unprivileged 'node' user
if [ "$(id -u)" = '0' ]; then
  mkdir -p /app/data
  chown -R node:node /app/data
  chmod 750 /app/data

  # If persistent SQLite files exist, ensure node owns them with restricted 640 permissions
  for f in /app/data/hookarmor.db /app/data/hookarmor.db-wal /app/data/hookarmor.db-shm; do
    if [ -e "$f" ]; then
      chown node:node "$f"
      chmod 640 "$f"
    fi
  done

  exec gosu node "$@"
fi

exec "$@"
