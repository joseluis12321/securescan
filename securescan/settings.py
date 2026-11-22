"""Configuración de Django para SecureScan.

Todo lo sensible o dependiente del entorno se lee de variables de entorno o del
archivo .env (ver .env.example). Las variables de entorno reales tienen
prioridad sobre el archivo .env.

Docs: https://docs.djangoproject.com/en/6.0/ref/settings/
"""

from pathlib import Path

import environ

BASE_DIR = Path(__file__).resolve().parent.parent

env = environ.Env()
environ.Env.read_env(BASE_DIR / '.env')


# ---------------------------------------------------------------------------
# Núcleo
# ---------------------------------------------------------------------------

# Obligatoria: si no está definida, Django no arranca.
SECRET_KEY = env('SECRET_KEY')

# Nunca True en producción.
DEBUG = env.bool('DEBUG', default=False)

ALLOWED_HOSTS = env.list('ALLOWED_HOSTS', default=['localhost', '127.0.0.1'])

# Orígenes https://... desde los que se aceptan formularios (necesario tras un proxy).
CSRF_TRUSTED_ORIGINS = env.list('CSRF_TRUSTED_ORIGINS', default=[])

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django_ratelimit',
    'scanner',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'securescan.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'securescan.wsgi.application'

# Ruta del panel de administración (cambiarla reduce el ruido de bots).
ADMIN_URL = env('ADMIN_URL', default='admin/')


# ---------------------------------------------------------------------------
# Base de datos y caché
# ---------------------------------------------------------------------------

# SQLite por defecto; en producción: DATABASE_URL=postgres://usuario:clave@host:5432/db
DATABASES = {
    'default': env.db('DATABASE_URL', default=f'sqlite:///{BASE_DIR / "db.sqlite3"}'),
}
DATABASES['default']['CONN_MAX_AGE'] = env.int('DB_CONN_MAX_AGE', default=60)
DATABASES['default']['CONN_HEALTH_CHECKS'] = True

# Usada por el límite de peticiones. Desarrollo: memoria local.
# Producción: CACHE_URL=redis://host:6379/0
CACHES = {'default': env.cache_url('CACHE_URL', default='locmemcache://')}

# El backend Redis nativo de Django funciona bien con django-ratelimit aunque
# no esté en su lista "oficial".
SILENCED_SYSTEM_CHECKS = ['django_ratelimit.W001']
if DEBUG and CACHES['default']['BACKEND'].endswith('LocMemCache'):
    # Con runserver (un solo proceso) la caché local es suficiente. Sin DEBUG
    # este check sigue activo y obliga a configurar una caché compartida.
    SILENCED_SYSTEM_CHECKS.append('django_ratelimit.E003')


# ---------------------------------------------------------------------------
# Autenticación
# ---------------------------------------------------------------------------

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {'min_length': 12},
    },
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = 'home'
LOGOUT_REDIRECT_URL = 'login'


# ---------------------------------------------------------------------------
# Seguridad HTTP
# ---------------------------------------------------------------------------

X_FRAME_OPTIONS = 'DENY'
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = 'same-origin'
SECURE_CROSS_ORIGIN_OPENER_POLICY = 'same-origin'

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_AGE = env.int('SESSION_COOKIE_AGE', default=60 * 60 * 8)  # 8 horas
# El JS lee el token CSRF de una etiqueta <meta>, no de la cookie.
CSRF_COOKIE_HTTPONLY = True

if not DEBUG:
    SECURE_SSL_REDIRECT = env.bool('SECURE_SSL_REDIRECT', default=True)
    SESSION_COOKIE_SECURE = env.bool('SECURE_COOKIES', default=True)
    CSRF_COOKIE_SECURE = env.bool('SECURE_COOKIES', default=True)
    SECURE_HSTS_SECONDS = env.int('SECURE_HSTS_SECONDS', default=60 * 60 * 24 * 365)
    SECURE_HSTS_INCLUDE_SUBDOMAINS = env.bool('SECURE_HSTS_INCLUDE_SUBDOMAINS', default=True)
    # El preload es difícil de revertir: se activa a propósito, no por defecto.
    SECURE_HSTS_PRELOAD = env.bool('SECURE_HSTS_PRELOAD', default=False)
    if not SECURE_HSTS_PRELOAD:
        SILENCED_SYSTEM_CHECKS.append('security.W021')

# Activar SOLO si la app está detrás de un proxy inverso de confianza (Nginx,
# Caddy, Traefik...) que fija X-Forwarded-Proto y X-Real-IP.
if env.bool('BEHIND_PROXY', default=False):
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    # IP real del cliente para el límite de peticiones (si no, todos
    # compartirían la IP del proxy).
    RATELIMIT_IP_META_KEY = 'HTTP_X_REAL_IP'

# Límite del cuerpo de peticiones que no son archivos (JSON de la API).
DATA_UPLOAD_MAX_MEMORY_SIZE = 1024 * 1024


# ---------------------------------------------------------------------------
# Internacionalización y estáticos
# ---------------------------------------------------------------------------

LANGUAGE_CODE = 'es'
TIME_ZONE = env('TIME_ZONE', default='UTC')
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'simple': {'format': '{asctime} {levelname} {name}: {message}', 'style': '{'},
    },
    'handlers': {
        'console': {'class': 'logging.StreamHandler', 'formatter': 'simple'},
    },
    'root': {'handlers': ['console'], 'level': 'WARNING'},
    'loggers': {
        'django': {'handlers': ['console'], 'level': 'INFO', 'propagate': False},
        'scanner': {
            'handlers': ['console'],
            'level': env('LOG_LEVEL', default='INFO'),
            'propagate': False,
        },
    },
}


# ---------------------------------------------------------------------------
# SecureScan
# ---------------------------------------------------------------------------

# Permite escanear redes privadas/localhost (192.168.x.x, 127.0.0.1...).
# Desactivado por defecto para evitar SSRF. Actívalo solo en uso local.
SECURESCAN_PERMITIR_REDES_PRIVADAS = env.bool('SECURESCAN_PERMITIR_REDES_PRIVADAS', default=False)

# Tamaño máximo del archivo de log subido, en MB.
SECURESCAN_MAX_LOG_MB = env.int('SECURESCAN_MAX_LOG_MB', default=10)

# Máximo de puertos extra que se pueden pedir en un escaneo.
SECURESCAN_MAX_PUERTOS_EXTRA = 100

# Escaneos de puertos simultáneos en todo el servidor (por proceso).
SECURESCAN_MAX_ESCANEOS_SIMULTANEOS = env.int('SECURESCAN_MAX_ESCANEOS_SIMULTANEOS', default=4)

# Límites de peticiones (django-ratelimit). Formato: "<n>/<s|m|h|d>".
SECURESCAN_RATE_LOGIN = '5/m'
SECURESCAN_RATE_ANALISIS = '20/m'
SECURESCAN_RATE_ESCANEO = '10/m'
SECURESCAN_RATE_HEADERS = '20/m'
SECURESCAN_RATE_PDF = '30/m'
