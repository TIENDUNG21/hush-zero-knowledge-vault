#!/bin/sh
# Apply pending migrations before the web server (or any other command) starts.
set -eu
php /app/bin/hush-admin migrate
exec "$@"
