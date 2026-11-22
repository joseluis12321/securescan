import datetime
import http.client
import socket
import ssl
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from .seguridad import EntradaInvalida, crear_conexion_segura, resolver_ip_publica

HEADERS_SEGURIDAD = {
    "Strict-Transport-Security": {
        "descripcion": "Fuerza conexiones HTTPS y previene downgrade attacks",
        "nivel": "ALTO",
        "recomendacion": "Agregar: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    },
    "Content-Security-Policy": {
        "descripcion": "Previene ataques XSS definiendo fuentes de contenido permitidas",
        "nivel": "ALTO",
        "recomendacion": "Agregar: Content-Security-Policy: default-src self"
    },
    "X-Frame-Options": {
        "descripcion": "Previene ataques de clickjacking bloqueando iframes",
        "nivel": "MEDIO",
        "recomendacion": "Agregar: X-Frame-Options: DENY o SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "descripcion": "Previene MIME type sniffing en el navegador",
        "nivel": "MEDIO",
        "recomendacion": "Agregar: X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "descripcion": "Controla que informacion se envia como referrer",
        "nivel": "BAJO",
        "recomendacion": "Agregar: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "descripcion": "Controla el acceso a APIs del navegador como camara y microfono",
        "nivel": "BAJO",
        "recomendacion": "Agregar: Permissions-Policy: camera=(), microphone=(), geolocation=()"
    },
    "X-XSS-Protection": {
        "descripcion": "Activa el filtro XSS integrado del navegador",
        "nivel": "MEDIO",
        "recomendacion": "Agregar: X-XSS-Protection: 1; mode=block"
    },
    "Cache-Control": {
        "descripcion": "Controla el cacheo de informacion sensible",
        "nivel": "BAJO",
        "recomendacion": "Agregar: Cache-Control: no-store para paginas con datos sensibles"
    }
}

MAX_LONGITUD_URL = 2048
MAX_REDIRECCIONES = 5


class _ConexionHTTPSegura(http.client.HTTPConnection):
    """Conexión HTTP que valida la IP de destino antes de conectar (anti-SSRF)."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = crear_conexion_segura


class _ConexionHTTPSSegura(http.client.HTTPSConnection):
    """Conexión HTTPS que valida la IP de destino antes de conectar (anti-SSRF)."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = crear_conexion_segura


class _ManejadorHTTPSeguro(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_ConexionHTTPSegura, req)


class _ManejadorHTTPSSeguro(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_ConexionHTTPSSegura, req, context=self._context)


class _RedireccionSegura(urllib.request.HTTPRedirectHandler):
    """Solo sigue redirecciones http/https y con un máximo de saltos."""

    max_redirections = MAX_REDIRECCIONES

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(newurl).scheme not in ("http", "https"):
            raise urllib.error.HTTPError(newurl, code, "Redirección a un esquema no permitido", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _crear_opener():
    """Opener con solo los manejadores necesarios.

    No incluye file://, ftp:// ni proxies del entorno: así una redirección no
    puede usarse para leer archivos locales ni para saltarse la validación.
    El certificado no se verifica aquí a propósito (se analiza aparte en
    verificar_ssl) para poder revisar headers de sitios con certificados malos.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.OpenerDirector()
    for manejador in (
        _ManejadorHTTPSeguro(),
        _ManejadorHTTPSSeguro(context=ctx),
        _RedireccionSegura(),
        urllib.request.HTTPDefaultErrorHandler(),
        urllib.request.HTTPErrorProcessor(),
        urllib.request.UnknownHandler(),
    ):
        opener.add_handler(manejador)
    return opener


def normalizar_url(url):
    """Devuelve (url, host, puerto_tls) o lanza EntradaInvalida."""
    if not isinstance(url, str):
        raise EntradaInvalida("La URL debe ser texto")
    url = url.strip()
    if not url or len(url) > MAX_LONGITUD_URL:
        raise EntradaInvalida("URL vacía o demasiado larga")
    if "://" not in url:
        url = "https://" + url

    partes = urlsplit(url)
    if partes.scheme not in ("http", "https"):
        raise EntradaInvalida("Solo se permiten URLs http:// o https://")
    if not partes.hostname:
        raise EntradaInvalida("La URL no contiene un host válido")
    try:
        puerto = partes.port
    except ValueError as e:
        raise EntradaInvalida("Puerto inválido en la URL") from e

    puerto_tls = puerto if (partes.scheme == "https" and puerto) else 443
    return url, partes.hostname, puerto_tls


def verificar_ssl(host, puerto=443):
    try:
        ip = resolver_ip_publica(host, puerto)
        ctx = ssl.create_default_context()
        with socket.create_connection((ip, puerto), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as conn:
                cert = conn.getpeercert()
        fecha_exp = datetime.datetime.fromtimestamp(
            ssl.cert_time_to_seconds(cert["notAfter"]), tz=datetime.UTC)
        dias_restantes = (fecha_exp - datetime.datetime.now(datetime.UTC)).days
        return {
            "valido": True,
            "expira": fecha_exp.strftime("%d/%m/%Y"),
            "dias_restantes": dias_restantes,
            "nivel": "ALTO" if dias_restantes < 15 else "MEDIO" if dias_restantes < 30 else "BAJO",
            "sujeto": dict(x[0] for x in cert.get("subject", [])),
            "emisor": dict(x[0] for x in cert.get("issuer", []))
        }
    except (OSError, KeyError, ValueError) as e:  # incluye SSLError y EntradaInvalida
        return {"valido": False, "error": str(e)}

def verificar_headers(url):
    """Analiza los headers de seguridad de `url`.

    Lanza EntradaInvalida/ObjetivoNoPermitido si la URL no es válida o apunta
    (directamente o mediante redirecciones) a una red interna.
    """
    url, host, puerto_tls = normalizar_url(url)
    # Validación temprana para dar un error claro antes de conectar.
    resolver_ip_publica(host)

    resultado = {
        "url": url,
        "headers_presentes": [],
        "headers_faltantes": [],
        "todos_headers": {},
        "ssl_info": verificar_ssl(host, puerto_tls),
        "resumen": {}
    }

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecureScan/2.0"})
        with _crear_opener().open(req, timeout=8) as response:
            headers_reales = dict(response.headers)
            resultado["todos_headers"] = headers_reales
            resultado["codigo_estado"] = response.status
            resultado["redireccion_https"] = response.geturl().startswith("https://")
    except EntradaInvalida:
        # Una redirección intentó llevarnos a una red interna.
        raise
    except (OSError, http.client.HTTPException, ValueError) as e:
        return {"error": f"No se pudo conectar con {url}: {e}"}

    for header, info in HEADERS_SEGURIDAD.items():
        encontrado = any(h.lower() == header.lower() for h in headers_reales)
        if encontrado:
            valor = next(v for k, v in headers_reales.items() if k.lower() == header.lower())
            resultado["headers_presentes"].append({
                "header": header,
                "valor": valor,
                "descripcion": info["descripcion"],
                "nivel": info["nivel"]
            })
        else:
            resultado["headers_faltantes"].append({
                "header": header,
                "descripcion": info["descripcion"],
                "nivel": info["nivel"],
                "recomendacion": info["recomendacion"]
            })

    total = len(HEADERS_SEGURIDAD)
    presentes = len(resultado["headers_presentes"])
    puntuacion = int((presentes / total) * 100)
    faltantes_altos = sum(1 for h in resultado["headers_faltantes"] if h["nivel"] == "ALTO")

    resultado["resumen"] = {
        "puntuacion": puntuacion,
        "presentes": presentes,
        "faltantes": len(resultado["headers_faltantes"]),
        "total": total,
        "nivel_riesgo": "ALTO" if faltantes_altos >= 2 else "MEDIO" if faltantes_altos == 1 else "BAJO"
    }

    return resultado
