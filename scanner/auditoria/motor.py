"""Ejecuta el catálogo de comprobaciones contra un sitio web."""

import http.client
import logging
import socket
import ssl
import threading
import time
import urllib.error

from django.conf import settings

from ..http_seguro import normalizar_url
from ..seguridad import EntradaInvalida, ObjetivoNoPermitido, ServidorOcupado, resolver_ip_publica
from .base import Categoria, Comprobacion, Estado, Gravedad, Resultado, catalogo
from .cliente import ClienteAuditoria, LimiteAuditoria
from .contexto import Contexto
from .puntuacion import calcular_nota, nivel_riesgo

logger = logging.getLogger(__name__)

VERSION_FORMATO = 1

# Limita las auditorías simultáneas del proceso, igual que los escaneos de puertos.
_auditorias_activas = threading.BoundedSemaphore(getattr(settings, "SECURESCAN_MAX_ESCANEOS_SIMULTANEOS", 4))

_ORDEN_ESTADO = {Estado.FALLO: 0, Estado.OK: 1, Estado.NO_APLICA: 2}


def describir_error(error: Exception) -> str:
    """Mensaje comprensible para un error de red."""
    if isinstance(error, urllib.error.URLError) and not isinstance(error, urllib.error.HTTPError):
        error = error.reason if isinstance(error.reason, Exception) else error
    if isinstance(error, TimeoutError):
        return "el servidor tardó demasiado en responder"
    if isinstance(error, ConnectionRefusedError):
        return "el servidor rechazó la conexión"
    if isinstance(error, ConnectionResetError):
        return "el servidor cortó la conexión"
    if isinstance(error, ssl.SSLError):
        return f"error en la conexión segura (TLS): {getattr(error, 'reason', None) or error}"
    if isinstance(error, socket.gaierror):
        return "no se pudo resolver el nombre del dominio"
    return str(error) or error.__class__.__name__


def _ejecutar_una(comprobacion: Comprobacion, ctx: Contexto) -> Resultado:
    if ctx.cliente.tiempo_agotado():
        return comprobacion.no_aplica("No se pudo comprobar: se agotó el tiempo máximo de la auditoría")
    try:
        resultado = comprobacion.ejecutar(ctx)
    except ObjetivoNoPermitido as e:
        logger.warning("Auditoría: %s apunta a una red interna: %s", comprobacion.id, e)
        return comprobacion.no_aplica(f"No se pudo comprobar: {e}")
    except LimiteAuditoria as e:
        return comprobacion.no_aplica(f"No se pudo comprobar: {e}")
    except (OSError, http.client.HTTPException, EntradaInvalida) as e:
        return comprobacion.no_aplica(f"No se pudo comprobar: {describir_error(e)}")
    except Exception:
        logger.exception("Error inesperado en la comprobación %s", comprobacion.id)
        return comprobacion.no_aplica("No se pudo comprobar: error interno de SecureScan")
    if not isinstance(resultado, Resultado):
        logger.error("La comprobación %s no devolvió un Resultado", comprobacion.id)
        return comprobacion.no_aplica("No se pudo comprobar: error interno de SecureScan")
    return resultado


def _orden(resultado: Resultado):
    """Primero los fallos (de más a menos graves), después los correctos y al final los que no aplican."""
    return _ORDEN_ESTADO[resultado.estado], -resultado.gravedad.peso


def _agrupar(resultados: list[Resultado]) -> list[dict]:
    categorias = []
    for categoria in Categoria:
        de_la_categoria = sorted((r for r in resultados if r.categoria == categoria), key=_orden)
        if de_la_categoria:
            categorias.append(
                {
                    "id": str(categoria),
                    "nombre": categoria.nombre,
                    "fallos": sum(1 for r in de_la_categoria if r.estado == Estado.FALLO),
                    "resultados": [r.como_dict() for r in de_la_categoria],
                }
            )
    return categorias


def _resumen(resultados: list[Resultado], nota: float) -> dict:
    fallos = [r for r in resultados if r.estado == Estado.FALLO]
    return {
        "nota": nota,
        "nivel_riesgo": nivel_riesgo(nota),
        "total": len(resultados),
        "ok": sum(1 for r in resultados if r.estado == Estado.OK),
        "fallos": len(fallos),
        "no_aplica": sum(1 for r in resultados if r.estado == Estado.NO_APLICA),
        "fallos_por_gravedad": {
            str(g): sum(1 for r in fallos if r.gravedad == g) for g in reversed(Gravedad)
        },
    }


def auditar(url: str, *, cliente=None, comprobaciones=None) -> dict:
    """Audita el sitio web de `url` con todas las comprobaciones pasivas del catálogo.

    Lanza EntradaInvalida/ObjetivoNoPermitido si la URL no es válida o apunta a
    una red interna, y ServidorOcupado si hay demasiadas auditorías en curso.
    Si el sitio no responde devuelve {"error": ...}.
    """
    url, host, _puerto = normalizar_url(url)
    resolver_ip_publica(host)  # error claro antes de conectar

    if not _auditorias_activas.acquire(timeout=10):
        raise ServidorOcupado("El servidor está ocupado con otras auditorías. Inténtalo en unos segundos.")
    try:
        inicio = time.monotonic()
        cliente = cliente or ClienteAuditoria()
        ctx = Contexto(url, cliente)
        try:
            principal = ctx.principal
        except EntradaInvalida:
            raise
        except (OSError, http.client.HTTPException, ValueError, LimiteAuditoria) as e:
            return {"error": f"No se pudo conectar con {url}: {describir_error(e)}"}

        lista = catalogo() if comprobaciones is None else comprobaciones
        resultados = [_ejecutar_una(c, ctx) for c in lista]
        nota = calcular_nota(resultados)
        return {
            "version": VERSION_FORMATO,
            "url": url,
            "url_final": principal.url_final,
            "codigo_estado": principal.codigo,
            "nota": nota,
            "resumen": _resumen(resultados, nota),
            "categorias": _agrupar(resultados),
            "peticiones": cliente.peticiones,
            "duracion": round(time.monotonic() - inicio, 1),
        }
    finally:
        _auditorias_activas.release()
