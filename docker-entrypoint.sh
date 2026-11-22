#!/bin/sh
# Aplica las migraciones pendientes y arranca el comando recibido (Gunicorn por defecto).
set -e

python manage.py migrate --noinput

exec "$@"
