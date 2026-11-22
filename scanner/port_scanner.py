"""Escáner de puertos TCP con identificación pasiva de servicios (banners)."""

import concurrent.futures
import socket
import string
import threading

from django.conf import settings

from .seguridad import EntradaInvalida, resolver_ip_publica, validar_puertos

TIMEOUT_CONEXION = 1.0
TIMEOUT_BANNER = 1.5
MAX_LONGITUD_BANNER = 120
MAX_HILOS = 100

PUERTOS_COMUNES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "Jupyter",
    9200: "Elasticsearch",
    27017: "MongoDB",
    11211: "Memcached",
}

PUERTOS_PELIGROSOS = {
    21: "FTP transmite credenciales en texto plano. Usar SFTP en su lugar.",
    23: "Telnet es inseguro, reemplazar con SSH.",
    445: "SMB expuesto puede ser vulnerable a EternalBlue/WannaCry.",
    1433: "Base de datos MSSQL expuesta publicamente es un riesgo critico.",
    1521: "Base de datos Oracle expuesta publicamente.",
    3306: "MySQL no deberia estar expuesto publicamente.",
    3389: "RDP es objetivo frecuente de ataques de fuerza bruta.",
    5900: "VNC sin cifrado expone el escritorio remoto.",
    6379: "Redis sin autenticacion permite acceso total a los datos.",
    8888: "Jupyter Notebook puede permitir ejecucion de codigo remoto.",
    9200: "Elasticsearch expuesto puede filtrar todos los datos.",
    27017: "MongoDB sin autenticacion permite acceso total.",
    11211: "Memcached puede ser usado para ataques DDoS de amplificacion.",
}


class ServidorOcupado(EntradaInvalida):
    status = 503


# Limita los escaneos simultáneos en el proceso para no agotar hilos y sockets.
_escaneos_activos = threading.BoundedSemaphore(getattr(settings, "SECURESCAN_MAX_ESCANEOS_SIMULTANEOS", 4))

_IMPRIMIBLES = set(string.printable) - set("\x0b\x0c")


def _limpiar_banner(datos: bytes) -> str | None:
    texto = datos.decode("latin-1")
    texto = "".join(c if c in _IMPRIMIBLES else " " for c in texto)
    texto = " ".join(texto.split())[:MAX_LONGITUD_BANNER]
    return texto or None


def escanear_puerto(ip: str, puerto: int, timeout: float = TIMEOUT_CONEXION):
    """Devuelve (puerto, abierto, banner). Solo escucha: nunca envía datos."""
    try:
        with socket.create_connection((ip, puerto), timeout=timeout) as sock:
            sock.settimeout(TIMEOUT_BANNER)
            try:
                banner = _limpiar_banner(sock.recv(256))
            except OSError:
                banner = None  # el servicio no habla primero (HTTP, Redis...)
            return puerto, True, banner
    except OSError:
        return puerto, False, None


def escanear_host(host: str, puertos_extra=None) -> dict:
    """Escanea los puertos comunes (y extra) de `host`.

    Lanza EntradaInvalida/ObjetivoNoPermitido si el host o los puertos no son
    válidos o si el host resuelve a una red interna (protección SSRF), y
    ServidorOcupado si ya hay demasiados escaneos en curso.
    """
    puertos_extra = validar_puertos(puertos_extra)
    ip = resolver_ip_publica(host)

    puertos_a_escanear = dict(PUERTOS_COMUNES)
    for p in puertos_extra:
        puertos_a_escanear.setdefault(p, "Personalizado")

    if not _escaneos_activos.acquire(timeout=10):
        raise ServidorOcupado("El servidor está ocupado con otros escaneos. Inténtalo en unos segundos.")
    try:
        hilos = min(MAX_HILOS, len(puertos_a_escanear))
        with concurrent.futures.ThreadPoolExecutor(max_workers=hilos) as executor:
            resultados_puertos = list(executor.map(lambda p: escanear_puerto(ip, p), puertos_a_escanear))
    finally:
        _escaneos_activos.release()

    abiertos, recomendaciones = [], []
    for puerto, abierto, banner in sorted(resultados_puertos):
        if not abierto:
            continue
        servicio = puertos_a_escanear[puerto]
        peligroso = puerto in PUERTOS_PELIGROSOS
        entrada = {"puerto": puerto, "servicio": servicio, "peligroso": peligroso, "banner": banner}
        if peligroso:
            entrada["recomendacion"] = PUERTOS_PELIGROSOS[puerto]
            recomendaciones.append(
                {
                    "puerto": puerto,
                    "servicio": servicio,
                    "recomendacion": PUERTOS_PELIGROSOS[puerto],
                }
            )
        abiertos.append(entrada)

    peligrosos = [p["puerto"] for p in abiertos if p["peligroso"]]
    return {
        "host": host,
        "ip": ip,
        "puertos_abiertos": abiertos,
        "puertos_peligrosos": peligrosos,
        "recomendaciones": recomendaciones,
        "resumen": {
            "total_abiertos": len(abiertos),
            "total_peligrosos": len(peligrosos),
            "total_verificados": len(puertos_a_escanear),
            "nivel_riesgo": "ALTO" if peligrosos else ("MEDIO" if abiertos else "BAJO"),
        },
    }
