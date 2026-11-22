# Changelog

## [2.0.0] — 2026-11-22

### Seguridad
- Corregido XSS en la interfaz (los resultados se insertaban sin escapar).
- Protección SSRF en el escáner de puertos y el verificador de headers, incluidas redirecciones y DNS rebinding.
- Corregida la inyección de markup en los PDF (`<img src>` permitía que el servidor descargara URLs).
- Login obligatorio, CSRF activo, límite de peticiones y de intentos de login.
- Los PDF se generan desde análisis guardados y cada usuario solo accede a los suyos.
- `SECRET_KEY` y configuración sensible fuera del código; clave rotada.
- CSP estricta, HSTS, cookies seguras y demás headers de seguridad.
- Actualizados Django, sqlparse y Pillow por vulnerabilidades conocidas.

### Añadido
- Detección de RCE, Log4Shell, archivos sensibles y fuerza bruta por IP; soporte de auth.log, syslog e ISO-8601.
- Validación del valor de los headers, cookies inseguras, fugas de información, versión TLS y redirección HTTPS real.
- Identificación pasiva de servicios (banners) en el escáner de puertos.
- Historial, vista de detalle, exportación JSON, borrado de análisis y comando `purgar_analisis`.
- Confirmación de autorización antes de escanear y registro de auditoría.
- Docker, docker-compose (PostgreSQL + Redis), Gunicorn, WhiteNoise y endpoint `/salud/`.
- CI en GitHub Actions, Dependabot, pre-commit, 100 tests con 94 % de cobertura.

### Cambiado
- El analizador procesa los logs línea a línea y es 3,4 veces más rápido.
- CSS y JS en archivos estáticos; nueva plantilla base y páginas de error.
