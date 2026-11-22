"""Configuración de Gunicorn para producción. Valores ajustables por variables de entorno."""

import multiprocessing
import os

# 0.0.0.0 es necesario dentro del contenedor; compose solo publica en 127.0.0.1.
bind = os.environ.get("GUNICORN_BIND", "0.0.0.0:8000")

# Los análisis esperan a la red (escaneos, peticiones HTTP): hilos por worker.
worker_class = "gthread"
workers = int(os.environ.get("GUNICORN_WORKERS", min(4, multiprocessing.cpu_count() * 2 + 1)))
threads = int(os.environ.get("GUNICORN_THREADS", 4))

# Un análisis de headers puede tardar varios segundos (redirecciones + TLS).
timeout = int(os.environ.get("GUNICORN_TIMEOUT", 60))
graceful_timeout = 30
keepalive = 5

# Reinicia workers periódicamente para contener posibles fugas de memoria.
max_requests = 1000
max_requests_jitter = 100

accesslog = "-"
errorlog = "-"
loglevel = os.environ.get("GUNICORN_LOG_LEVEL", "info")
# No registrar la cadena de consulta (puede contener datos del usuario).
access_log_format = '%(h)s "%(m)s %(U)s %(H)s" %(s)s %(b)s %(L)ss "%(a)s"'

# Solo confiar en X-Forwarded-* si viene del proxy configurado.
forwarded_allow_ips = os.environ.get("FORWARDED_ALLOW_IPS", "127.0.0.1")

# Socket de control de Gunicorn 27 (gunicornc): no se usa y el sistema de
# archivos del contenedor es de solo lectura.
control_socket_disable = True
