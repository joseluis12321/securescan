"""Validaciones de seguridad compartidas por los módulos de SecureScan.

- Protección SSRF: solo se permiten objetivos que resuelvan a IPs públicas.
- Validación de entradas del usuario (hosts y puertos).
"""

import ipaddress
import socket

from django.conf import settings

MAX_LONGITUD_HOST = 253
PUERTO_MIN, PUERTO_MAX = 1, 65535


class EntradaInvalida(ValueError):
    """Datos de entrada no válidos. Se responde al cliente con `status`."""

    status = 400


class ObjetivoNoPermitido(EntradaInvalida):
    """El objetivo resuelve a una dirección interna, privada o reservada."""


class ServidorOcupado(EntradaInvalida):
    """Hay demasiados escaneos o auditorías en curso en este proceso."""

    status = 503


def _permitir_redes_privadas() -> bool:
    return getattr(settings, "SECURESCAN_PERMITIR_REDES_PRIVADAS", False)


def ip_es_publica(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True solo si la IP es enrutable en Internet (no privada, loopback, etc.)."""
    if ip.version == 6:
        # Direcciones IPv6 que encapsulan una IPv4 (::ffff:127.0.0.1, 6to4, Teredo).
        embebidas = [ip.ipv4_mapped, ip.sixtofour, ip.teredo[1] if ip.teredo else None]
        if any(e is not None and not ip_es_publica(e) for e in embebidas):
            return False
    return ip.is_global and not (ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def resolver_ip_publica(host: str, puerto: int | None = None) -> str:
    """Resuelve `host` y devuelve una IP segura a la que conectarse.

    Se rechaza el objetivo si CUALQUIERA de las IPs resueltas es interna, para
    evitar trucos con varios registros DNS. Conectar siempre a la IP devuelta
    (y no volver a resolver el nombre) evita ataques de DNS rebinding.
    """
    if not isinstance(host, str):
        raise EntradaInvalida("El host debe ser texto")
    host = host.strip().strip("[]")
    if not host or len(host) > MAX_LONGITUD_HOST:
        raise EntradaInvalida("Host vacío o demasiado largo")

    try:
        infos = socket.getaddrinfo(host, puerto, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, ValueError) as e:
        raise EntradaInvalida(f"No se pudo resolver el host: {host}") from e

    ips = []
    for _familia, _tipo, _proto, _canon, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0].split("%")[0])
        if ip not in ips:
            ips.append(ip)

    if not ips:
        raise EntradaInvalida(f"No se pudo resolver el host: {host}")

    if not _permitir_redes_privadas():
        internas = [str(ip) for ip in ips if not ip_es_publica(ip)]
        if internas:
            raise ObjetivoNoPermitido(
                f"Objetivo no permitido: {host} resuelve a una dirección interna "
                f"({', '.join(internas)}). Por seguridad solo se permiten objetivos públicos."
            )

    # Preferimos IPv4 por compatibilidad.
    ips.sort(key=lambda ip: ip.version)
    return str(ips[0])


def crear_conexion_segura(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None, **kwargs):
    """Sustituto de `socket.create_connection` que valida la IP antes de conectar.

    Se usa en las conexiones HTTP salientes para que también las redirecciones
    queden protegidas contra SSRF.
    """
    host, puerto = address[0], address[1]
    ip = resolver_ip_publica(host, puerto)
    return socket.create_connection((ip, puerto), timeout, source_address, **kwargs)


def validar_puertos(puertos, maximo: int | None = None) -> list[int]:
    """Valida la lista de puertos extra: enteros 1-65535, sin duplicados, con tope."""
    if puertos is None:
        return []
    if not isinstance(puertos, list):
        raise EntradaInvalida("puertos_extra debe ser una lista de números")

    if maximo is None:
        maximo = getattr(settings, "SECURESCAN_MAX_PUERTOS_EXTRA", 100)
    if len(puertos) > maximo:
        raise EntradaInvalida(f"Máximo {maximo} puertos extra por escaneo")

    validos = []
    for p in puertos:
        # bool es subclase de int: se excluye explícitamente.
        if isinstance(p, bool) or not isinstance(p, int) or not PUERTO_MIN <= p <= PUERTO_MAX:
            raise EntradaInvalida(f"Puerto inválido: {p!r} (debe ser un entero entre 1 y 65535)")
        if p not in validos:
            validos.append(p)
    return validos
