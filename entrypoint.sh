#!/bin/sh
set -e

if [ "$AUTO_MIGRATE" = "true" ]; then
    echo "Running database migrations and seeds..."
    /app/migrate -migrate up -seed
fi

exec "$@"
