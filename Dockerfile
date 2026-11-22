# syntax=docker/dockerfile:1
# Imagen de producción de SecureScan: Python slim, usuario sin privilegios,
# estáticos precompilados y Gunicorn como servidor.

FROM python:3.15-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # SQLite por defecto en un directorio con permisos de escritura (docker run sin compose).
    DATABASE_URL=sqlite:////app/data/db.sqlite3

WORKDIR /app

# Dependencias primero para aprovechar la caché de capas.
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# collectstatic no necesita secretos reales: se usa una clave temporal solo en el build.
RUN SECRET_KEY=solo-para-build DEBUG=False python manage.py collectstatic --noinput \
    && useradd --system --uid 10001 --home-dir /app securescan \
    && mkdir -p /app/data \
    && chown -R securescan:securescan /app/data

USER securescan

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; r=urllib.request.Request('http://127.0.0.1:8000/salud/', headers={'Host':'localhost'}); sys.exit(0 if urllib.request.urlopen(r, timeout=4).status==200 else 1)"]

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["gunicorn", "--config", "gunicorn.conf.py", "securescan.wsgi:application"]
