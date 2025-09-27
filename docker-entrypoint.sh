#!/usr/bin/env bash
set -e

# init db if script exists
if [ -f ./init_db.sh ]; then
  echo "Running init_db.sh"
  ./init_db.sh || true
fi

# ensure data dir exists and proper perms
mkdir -p data
chown -R "$(id -u)":"$(id -g)" data || true

exec "$@"
