"""Cliente HTTP saliente protegido contra SSRF.

Cada conexión (incluidas las de las redirecciones) valida la IP de destino justo
antes de conectar y se conecta a esa misma IP, lo que también evita ataques de
DNS rebinding.
"""

import http.client
import ssl
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from .seguridad import EntradaInvalida, crear_conexion_segura

MAX_LONGITUD_URL = 2048
MAX_REDIRECCIONES = 5
USER_AGENT = "SecureScan/2.0 (+verificador de headers defensivo)"


class _ConexionHTTPSegura(http.client.HTTPConnection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = crear_conexion_segura


class _ConexionHTTPSSegura(http.client.HTTPSConnection):
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


def crear_opener() -> urllib.request.OpenerDirector:
    """Opener con solo los manejadores necesarios.

    No incluye file://, ftp:// ni proxies del entorno: así una redirección no
    puede usarse para leer archivos locales ni para saltarse la validación.
    El certificado no se verifica aquí a propósito (se analiza aparte) para
    poder revisar los headers de sitios con certificados inválidos.
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


def normalizar_url(url) -> tuple[str, str, int]:
    """Valida la URL. Devuelve (url, host, puerto_tls) o lanza EntradaInvalida."""
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


def obtener(url: str, timeout: float = 8):
    """GET seguro. Devuelve (código, headers, url_final) también en respuestas 4xx/5xx.

    Lanza EntradaInvalida si la URL o alguna redirección apunta a una red
    interna, y OSError/HTTPException si el sitio no responde.
    """
    # Seguro: el opener solo tiene manejadores http/https (sin file:// ni ftp://).
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})  # noqa: S310
    try:
        with crear_opener().open(req, timeout=timeout) as respuesta:
            return respuesta.status, respuesta.headers, respuesta.geturl()
    except urllib.error.HTTPError as e:
        # Una respuesta 4xx/5xx también trae headers que se pueden analizar.
        # e.headers es None si el error lo generó nuestro propio manejador.
        # Las 3xx que llegan aquí son redirecciones rechazadas (bucle, esquema...).
        if e.headers is None or 300 <= e.code < 400:
            raise
        try:
            return e.code, e.headers, e.geturl()
        finally:
            e.close()
