# 🛡️ SecureScan

> Herramienta web de ciberseguridad defensiva: análisis de logs, escaneo de puertos y auditoría de headers HTTP, con reportes PDF.

[![CI](https://github.com/joseluis12321/securescan/actions/workflows/ci.yml/badge.svg)](https://github.com/joseluis12321/securescan/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.14-blue?style=flat-square&logo=python)
![Django](https://img.shields.io/badge/Django-6.0-green?style=flat-square&logo=django)
![Cobertura](https://img.shields.io/badge/cobertura-94%25-brightgreen?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

---

## ¿Qué es SecureScan?

Una aplicación web para revisar la seguridad de tus propios sistemas sin instalar herramientas externas:
sube un log y detecta ataques, escanea los puertos expuestos de un servidor o audita la configuración HTTPS
y los headers de seguridad de un sitio web. Cada análisis se guarda y se puede exportar como reporte PDF.

## Módulos

### 1. Analizador de logs
- Formatos: **Apache/Nginx** (common/combined), **auth.log/SSH**, **syslog** e **ISO-8601**.
- Detecta **SQL Injection, XSS, Path Traversal, inyección de comandos (RCE), Log4Shell** y **búsqueda de archivos sensibles** (`.env`, `.git`, `phpmyadmin`…).
- Decodifica la URL antes de analizar: detecta ataques ofuscados (`%3Cscript%3E`, `union+select`, doble codificación).
- **Fuerza bruta por IP**, herramientas de hacking en el User-Agent (sqlmap, nikto, nuclei…) y escaneo de rutas (404 masivos).
- Ranking de IPs sospechosas y gráfica de actividad por hora.
- Procesa archivos de 10 MB en ~1,5 s, línea a línea y con memoria acotada.

### 2. Escáner de puertos
- 23 puertos comunes en paralelo, más hasta 100 puertos personalizados.
- **Identificación pasiva del servicio** (banner): muestra, por ejemplo, `SSH-2.0-OpenSSH_6.6.1` sin enviar nada al servidor.
- Marca los servicios peligrosos expuestos (Redis, MongoDB, RDP, SMB…) con recomendaciones concretas.

### 3. Verificador de headers HTTP
- 7 headers de seguridad, **validando su valor** (HSTS corto, CSP con `'unsafe-inline'`, `nosniff` mal escrito…).
- Cookies sin `Secure`/`HttpOnly`/`SameSite`, fugas de información (`Server` con versión, `X-Powered-By`) y headers obsoletos.
- Certificado TLS: validez, días hasta que caduca, versión de TLS, cifrado y emisor.
- Comprueba de verdad la **redirección HTTP → HTTPS**. Puntuación sobre 100.

### 4. Reportes PDF
- Resumen ejecutivo, hallazgos, tablas y recomendaciones, con paginación.
- Se generan en el servidor a partir del análisis guardado: no se pueden falsificar desde el navegador.

---

## Seguridad de la propia aplicación

Una herramienta de seguridad tiene que ser segura. SecureScan incluye:

| Medida | Detalle |
|---|---|
| **Anti-SSRF** | No permite analizar localhost, redes privadas ni metadatos cloud (`169.254.169.254`), ni siquiera mediante redirecciones o *DNS rebinding*. |
| **Anti-XSS** | Plantillas JS que escapan por defecto y **CSP estricta** (`script-src 'self'`, sin `unsafe-inline`). |
| **Autenticación** | Login obligatorio, límite de intentos contra fuerza bruta, contraseñas de 12+ caracteres. |
| **CSRF** | Activo en todas las peticiones. |
| **Rate limiting** | Límite de peticiones por usuario en cada análisis. |
| **Aislamiento** | Cada usuario solo ve y descarga sus propios análisis. |
| **Entradas** | Validación de tamaño y tipo de archivo, puertos y URLs; protección contra ReDoS. |
| **PDF** | Escapado del contenido (evita inyección de markup y `<img src>` en ReportLab). |
| **HTTP** | HSTS, cookies seguras, `X-Frame-Options: DENY`, `Referrer-Policy`, COOP. |
| **Cadena de suministro** | Dependencias fijadas, `pip-audit`, `bandit` y Dependabot en CI. |

¿Encontraste una vulnerabilidad? Lee [SECURITY.md](SECURITY.md).

---

## Inicio rápido

### Con Docker (recomendado)

```bash
git clone https://github.com/joseluis12321/securescan.git
cd securescan
cp .env.example .env
# Edita .env y pon una SECRET_KEY:  python3 -c "import secrets; print(secrets.token_urlsafe(50))"

docker compose up -d --build
docker compose exec web python manage.py createsuperuser
```

Abre http://127.0.0.1:8000. El stack incluye PostgreSQL y Redis; el contenedor web corre sin privilegios y con el sistema de archivos en solo lectura.

### En local (desarrollo)

Requiere Python 3.12 o superior (probado con 3.14).

```bash
git clone https://github.com/joseluis12321/securescan.git
cd securescan
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt

cp .env.example .env
# En .env: pon una SECRET_KEY y DEBUG=True

python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

Para probar el analizador tienes logs de ejemplo en [`ejemplos/`](ejemplos/).

> Para escanear tu red local o `localhost` (bloqueado por defecto) pon `SECURESCAN_PERMITIR_REDES_PRIVADAS=True` en `.env`. Úsalo solo en local.

---

## Configuración

Todo se configura con variables de entorno o el archivo `.env` (plantilla: [.env.example](.env.example)).

| Variable | Por defecto | Descripción |
|---|---|---|
| `SECRET_KEY` | — (obligatoria) | Clave secreta de Django. |
| `DEBUG` | `False` | Solo `True` en desarrollo. |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1` | Dominios permitidos. |
| `DATABASE_URL` | SQLite | Ej.: `postgres://usuario:clave@host:5432/db` |
| `CACHE_URL` | memoria local | Obligatoria en producción: `redis://host:6379/0` |
| `CSRF_TRUSTED_ORIGINS` | — | Ej.: `https://securescan.midominio.com` |
| `BEHIND_PROXY` | `False` | `True` detrás de Nginx/Caddy/Traefik (usa `X-Forwarded-Proto` y `X-Real-IP`). |
| `SECURE_SSL_REDIRECT` / `SECURE_HSTS_SECONDS` | `True` / 1 año | HTTPS en producción. |
| `ADMIN_URL` | `admin/` | Ruta del panel de administración. |
| `TIME_ZONE` / `LOG_LEVEL` | `UTC` / `INFO` | Zona horaria y nivel de logs. |
| `SECURESCAN_PERMITIR_REDES_PRIVADAS` | `False` | Permite escanear redes internas. |
| `SECURESCAN_MAX_LOG_MB` | `10` | Tamaño máximo de log subido. |
| `SECURESCAN_MAX_ESCANEOS_SIMULTANEOS` | `4` | Escaneos de puertos a la vez por proceso. |

### Checklist de producción

- [ ] `DEBUG=False`, `SECRET_KEY` única y `ALLOWED_HOSTS` con tu dominio.
- [ ] PostgreSQL (`DATABASE_URL`) y Redis (`CACHE_URL`).
- [ ] Proxy inverso con HTTPS delante de Gunicorn y `BEHIND_PROXY=True`.
- [ ] `python manage.py check --deploy` sin avisos.
- [ ] Copias de seguridad de la base de datos.

---

## Desarrollo

```bash
pytest --cov              # tests + cobertura (mínimo 85 %)
ruff check . && ruff format --check .   # lint y formato
bandit -c pyproject.toml -r scanner securescan   # análisis de seguridad del código
pip-audit -r requirements.txt          # vulnerabilidades en dependencias
pre-commit install        # ejecuta ruff y otros checks antes de cada commit
```

La integración continua ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) ejecuta lint, tests, auditoría de seguridad, `check --deploy` y el build de la imagen Docker en cada push y pull request.

### Estructura

```
securescan/            Configuración de Django (settings por entorno)
scanner/
├── analyzer.py        Analizador de logs
├── port_scanner.py    Escáner de puertos y banners
├── header_checker.py  Auditoría de headers, cookies y TLS
├── http_seguro.py     Cliente HTTP saliente protegido contra SSRF
├── seguridad.py       Validación de entradas y resolución segura de IPs
├── pdf_generator.py   Reportes PDF
├── views.py           Vistas y API JSON
├── static/scanner/    CSS y JS (sin código inline, compatible con CSP)
├── templates/         Plantillas HTML y páginas de error
└── tests/             Tests por módulo
ejemplos/              Logs de ejemplo para probar el analizador
```

### API

Todos los endpoints requieren sesión iniciada y token CSRF (`X-CSRFToken`).

| Método | Ruta | Cuerpo | Descripción |
|---|---|---|---|
| `POST` | `/analizar/` | `multipart`: `archivo_log` | Analiza un log. |
| `POST` | `/escanear/` | `{"host": "...", "puertos_extra": [8080]}` | Escanea puertos. |
| `POST` | `/headers/` | `{"url": "..."}` | Audita headers y TLS. |
| `GET` | `/analisis/<id>/pdf/` | — | Descarga el reporte PDF. |
| `GET` | `/salud/` | — | Healthcheck (sin login). |

Errores: `400` entrada inválida u objetivo no permitido · `401` sin sesión · `413` archivo demasiado grande · `429` demasiadas peticiones · `502` el sitio no responde · `503` servidor ocupado.

---

## Autor

**Jose Luis Gomez**
- GitHub: https://github.com/joseluis12321
- Email: joseluisgomez20232@gmail.com

## Licencia

[MIT](LICENSE)

---

> ⚠️ **Aviso:** esta herramienta es exclusivamente para uso defensivo y educativo. Úsala solo en sistemas propios o con autorización explícita de su propietario.
