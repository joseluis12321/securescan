# 🛡️ SecureScan

> Herramienta web de ciberseguridad defensiva desarrollada con Python y Django.

![Python](https://img.shields.io/badge/Python-3.12-blue?style=flat-square&logo=python)
![Django](https://img.shields.io/badge/Django-6.0-green?style=flat-square&logo=django)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

---

## 📌 ¿Qué es SecureScan?

SecureScan es una aplicación web de ciberseguridad **defensiva** que permite analizar logs de servidor, escanear puertos abiertos y verificar la seguridad de sitios web. Todo desde una interfaz visual moderna, sin instalar herramientas externas.

Desarrollado como proyecto de portafolio para demostrar conocimientos en seguridad informática, desarrollo backend con Django y análisis de amenazas.

---

## 🖥️ Vista previa

| Módulo | Descripción |
|--------|-------------|
| ![Logs](https://img.shields.io/badge/Módulo-Analizador%20de%20Logs-red?style=flat-square) | Detecta amenazas en archivos de logs |
| ![Puertos](https://img.shields.io/badge/Módulo-Escáner%20de%20Puertos-orange?style=flat-square) | Escanea puertos y servicios peligrosos |
| ![Headers](https://img.shields.io/badge/Módulo-Headers%20HTTP-blue?style=flat-square) | Verifica seguridad de sitios web |
| ![PDF](https://img.shields.io/badge/Módulo-Reporte%20PDF-purple?style=flat-square) | Exporta reportes profesionales |

---

## 🔍 Módulos

### 1. 📄 Analizador de Logs
Sube un archivo `.log` o `.txt` y SecureScan detecta automáticamente:

- ✅ Intentos de login fallidos y ataques de fuerza bruta
- ✅ SQL Injection en URLs
- ✅ Ataques XSS (Cross-Site Scripting)
- ✅ Path Traversal (`../../etc/passwd`)
- ✅ Herramientas de hacking en User-Agent (sqlmap, nikto, nmap...)
- ✅ IPs sospechosas con más de 10 apariciones
- ✅ Gráfica de actividad por hora
- ✅ Exportación a PDF profesional

### 2. 🔌 Escáner de Puertos
Ingresa una IP o dominio y obtén:

- ✅ Escaneo de 23+ puertos comunes en paralelo
- ✅ Identificación de servicios peligrosos (RDP, MongoDB, Redis sin auth...)
- ✅ Recomendaciones específicas por cada puerto peligroso
- ✅ Soporte para puertos personalizados adicionales
- ✅ Exportación a PDF profesional

### 3. 🔒 Verificador de Headers HTTP
Analiza cualquier sitio web y verifica:

- ✅ 8 headers de seguridad críticos (HSTS, CSP, X-Frame-Options...)
- ✅ Certificado SSL — validez y días hasta vencimiento
- ✅ Redirección HTTP → HTTPS
- ✅ Puntuación de seguridad sobre 100
- ✅ Recomendaciones de cómo agregar cada header faltante
- ✅ Exportación a PDF profesional

---

## 🛠️ Tecnologías utilizadas

| Tecnología | Uso |
|------------|-----|
| Python 3.12 | Lenguaje principal |
| Django 6.0 | Framework web backend |
| Django REST Framework | API endpoints |
| ReportLab | Generación de reportes PDF |
| HTML / CSS / JavaScript | Interfaz de usuario |
| SQLite | Base de datos |
| Git | Control de versiones |

---

## 🚀 Instalación y uso local

### Requisitos previos
- Python 3.10 o superior
- Git

### Pasos

```bash
# 1. Clonar el repositorio
git clone https://github.com/TU_USUARIO/securescan.git
cd securescan

# 2. Crear entorno virtual
python3 -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate

# 3. Instalar dependencias
pip install -r requirements.txt

# 4. Aplicar migraciones
python3 manage.py migrate

# 5. Correr el servidor
python3 manage.py runserver
```

Abre tu navegador en: **http://127.0.0.1:8000**

---

## 📁 Estructura del proyecto
securescan/
├── scanner/
│   ├── templates/scanner/
│   │   └── home.html          # Interfaz principal
│   ├── analyzer.py            # Motor de análisis de logs
│   ├── port_scanner.py        # Escáner de puertos
│   ├── header_checker.py      # Verificador de headers HTTP
│   ├── pdf_generator.py       # Generador de reportes PDF
│   ├── views.py               # Vistas y endpoints
│   ├── models.py              # Modelos de base de datos
│   └── urls.py                # Rutas
├── securescan/
│   ├── settings.py
│   └── urls.py
├── requirements.txt
└── README.md
---

## 📊 Tipos de amenazas detectadas

| Amenaza | Descripción | Nivel |
|---------|-------------|-------|
| Fuerza bruta | Múltiples intentos de login fallidos | 🔴 ALTO |
| SQL Injection | Queries maliciosas en URLs | 🔴 ALTO |
| XSS | Scripts maliciosos en peticiones | 🔴 ALTO |
| Path Traversal | Intento de acceder a archivos del sistema | 🔴 ALTO |
| Hacking tools | sqlmap, nikto, nmap en User-Agent | 🔴 ALTO |
| Escaneo de rutas | Exceso de errores 404 | 🟡 MEDIO |
| Errores de servidor | Errores 500 internos | 🟢 BAJO |

---

## 👨‍💻 Autor

**Jose Luis**
- GitHub: [@TU_USUARIO](https://github.com/TU_USUARIO)
- Email: joseluisgomez20232@gmail.com

---

## 📄 Licencia

Este proyecto está bajo la licencia MIT. Ver el archivo [LICENSE](LICENSE) para más detalles.

---

> ⚠️ **Aviso:** Esta herramienta es exclusivamente para uso **defensivo y educativo**. Úsala solo en sistemas propios o con autorización explícita.
