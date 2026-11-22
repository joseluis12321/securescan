# Política de seguridad

## Versiones soportadas

Solo la última versión de la rama `main` recibe correcciones de seguridad.

## Reportar una vulnerabilidad

**No abras un issue público.** Usa el reporte privado de GitHub:
pestaña **Security → Report a vulnerability** del repositorio.

Incluye, si puedes:

- Descripción del problema y su impacto.
- Pasos para reproducirlo (petición, archivo de log, URL de prueba…).
- Versión o commit afectado.

Recibirás respuesta en un plazo de 7 días. Cuando la corrección esté publicada
se te dará crédito en las notas de la versión, si así lo deseas.

## Alcance

Entran en el alcance, entre otros: XSS, CSRF, SSRF (escaneo de redes internas),
inyección en reportes PDF, acceso a análisis de otros usuarios, evasión del
límite de peticiones y denegación de servicio con archivos de log manipulados.

## Uso responsable

SecureScan es una herramienta defensiva. Úsala solo contra sistemas propios o
con autorización explícita y por escrito de su propietario.
