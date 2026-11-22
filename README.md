# 🛡️ SecureScan

> Herramienta web de ciberseguridad defensiva desarrollada con Python y Django.

![Python](https://img.shields.io/badge/Python-3.12-blue?style=flat-square&logo=python)
![Django](https://img.shields.io/badge/Django-6.0-green?style=flat-square&logo=django)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

---

## ¿Qué es SecureScan?

Aplicación web de ciberseguridad defensiva que permite analizar logs de servidor, escanear puertos abiertos y verificar la seguridad de sitios web. Todo desde una interfaz visual moderna sin instalar herramientas externas.

---

## Módulos

**1. Analizador de Logs**
- Detecta intentos de login fallidos y fuerza bruta
- Identifica SQL Injection, XSS y Path Traversal
- Detecta herramientas de hacking en User-Agent (sqlmap, nikto, nmap)
- Gráfica de actividad por hora
- Exporta reporte PDF profesional

**2. Escáner de Puertos**
- Escanea 23 puertos comunes en paralelo
- Identifica servicios peligrosos expuestos
- Recomendaciones específicas por cada puerto
- Soporta puertos personalizados adicionales

**3. Verificador de Headers HTTP**
- Analiza 8 headers de seguridad críticos
- Verifica certificado SSL y días hasta vencimiento
- Comprueba redirección HTTP a HTTPS
- Puntuación de seguridad sobre 100

**4. Exportación PDF**
- Genera reportes profesionales de cualquier análisis
- Incluye resumen ejecutivo, hallazgos y recomendaciones

---

## Tecnologías

| Tecnología | Uso |
|---|---|
| Python 3.12 | Lenguaje principal |
| Django 6.0 | Framework web backend |
| Django REST Framework | API endpoints |
| ReportLab | Generación de reportes PDF |
| HTML / CSS / JavaScript | Interfaz de usuario |
| SQLite | Base de datos |

---

## Instalación

```bash
git clone https://github.com/joseluis12321/securescan.git
cd securescan
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configuración: copia la plantilla y pon una SECRET_KEY propia
cp .env.example .env
python3 -c "import secrets; print(secrets.token_urlsafe(50))"   # pega el resultado en SECRET_KEY

python3 manage.py migrate
python3 manage.py createsuperuser   # usuario para iniciar sesión
python3 manage.py runserver
```

Abre tu navegador en: http://127.0.0.1:8000 e inicia sesión.

Para escanear tu red local o `localhost` (bloqueado por defecto para evitar SSRF), pon
`SECURESCAN_PERMITIR_REDES_PRIVADAS=True` en tu `.env`. Úsalo solo en local.

---

## Seguridad

- Login obligatorio, protección CSRF y límite de intentos de inicio de sesión.
- Protección SSRF: no se permiten objetivos internos (localhost, redes privadas, metadatos cloud), ni siquiera mediante redirecciones.
- Límite de peticiones por usuario en todos los análisis.
- Subida de logs validada (extensión, tamaño máximo y contenido de texto).
- Los reportes PDF se generan en el servidor a partir de análisis guardados, y cada usuario solo accede a los suyos.
- En producción: `DEBUG=False`, `ALLOWED_HOSTS` con tu dominio y `CACHE_URL=redis://...` (caché compartida para el límite de peticiones).

Ejecutar los tests:

```bash
python3 manage.py test scanner
```

---

## Tipos de amenazas detectadas

| Amenaza | Nivel |
|---|---|
| Fuerza bruta / login fallido | ALTO |
| SQL Injection | ALTO |
| XSS Cross-Site Scripting | ALTO |
| Path Traversal | ALTO |
| Herramientas de hacking | ALTO |
| Escaneo de rutas 404 excesivos | MEDIO |
| Errores internos del servidor | BAJO |

---

## Autor

**Jose Luis Gomez**
- GitHub: https://github.com/joseluis12321
- Email: joseluisgomez20232@gmail.com

---

> Aviso: Esta herramienta es exclusivamente para uso defensivo y educativo. Usala solo en sistemas propios o con autorización explícita.
