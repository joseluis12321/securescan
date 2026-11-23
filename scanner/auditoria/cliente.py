"""Cliente HTTP de la auditoría: solo peticiones pasivas y con límites estrictos.

Las reglas no dependen de que cada comprobación "se porte bien": el cliente
las impone a todas.

- Solo GET y HEAD, sin cuerpo, cookies ni credenciales.
- Como mucho PETICIONES_POR_SEGUNDO, MAX_PETICIONES en total y un tiempo
  total de PRESUPUESTO_SEGUNDOS para toda la auditoría.
- Tiempo de espera corto por petición y lectura limitada del cuerpo.
- Todas las conexiones pasan por la protección anti-SSRF de http_seguro.
"""

import threading
import time
from dataclasses import dataclass
from email.message import Message

from ..http_seguro import METODOS_PERMITIDOS, solicitar

PETICIONES_POR_SEGUNDO = 5
TIMEOUT_PETICION = 5
MAX_PETICIONES = 60
PRESUPUESTO_SEGUNDOS = 45
MAX_BYTES_RESPUESTA = 256 * 1024
# Únicas cabeceras que una comprobación puede añadir a la petición.
CABECERAS_PERMITIDAS = frozenset({"Accept", "Range"})


class LimiteAuditoria(Exception):
    """Se alcanzó el máximo de peticiones o de tiempo de la auditoría."""


@dataclass(frozen=True)
class Respuesta:
    codigo: int
    cabeceras: Message
    url: str
    url_final: str
    cuerpo: bytes = b""

    @property
    def texto(self) -> str:
        charset = self.cabeceras.get_content_charset() or "utf-8"
        try:
            return self.cuerpo.decode(charset, errors="replace")
        except LookupError:  # charset desconocido
            return self.cuerpo.decode("utf-8", errors="replace")


class ClienteAuditoria:
    def __init__(
        self,
        *,
        peticiones_por_segundo: float = PETICIONES_POR_SEGUNDO,
        timeout: float = TIMEOUT_PETICION,
        max_peticiones: int = MAX_PETICIONES,
        presupuesto: float = PRESUPUESTO_SEGUNDOS,
        transporte=solicitar,
        reloj=time.monotonic,
        dormir=time.sleep,
    ):
        self.intervalo = 1 / peticiones_por_segundo
        self.timeout = timeout
        self.max_peticiones = max_peticiones
        self.presupuesto = presupuesto
        self._transporte = transporte
        self._reloj = reloj
        self._dormir = dormir
        self._inicio = reloj()
        self._ultima = None
        self._lock = threading.Lock()
        self.peticiones = 0

    def segundos_restantes(self) -> float:
        return self.presupuesto - (self._reloj() - self._inicio)

    def tiempo_agotado(self) -> bool:
        return self.segundos_restantes() <= 0

    def get(self, url: str, **opciones) -> Respuesta:
        return self.peticion("GET", url, **opciones)

    def head(self, url: str, **opciones) -> Respuesta:
        return self.peticion("HEAD", url, **opciones)

    def peticion(
        self,
        metodo: str,
        url: str,
        *,
        max_bytes: int = 0,
        seguir_redirecciones: bool = True,
        cabeceras: dict | None = None,
    ) -> Respuesta:
        if metodo not in METODOS_PERMITIDOS:
            raise ValueError(f"La auditoría es pasiva: método {metodo} no permitido")
        no_permitidas = set(cabeceras or {}) - CABECERAS_PERMITIDAS
        if no_permitidas:
            raise ValueError(f"Cabeceras no permitidas en la auditoría: {', '.join(sorted(no_permitidas))}")
        max_bytes = max(0, min(max_bytes, MAX_BYTES_RESPUESTA))

        with self._lock:
            if self.peticiones >= self.max_peticiones:
                raise LimiteAuditoria(f"se alcanzó el máximo de {self.max_peticiones} peticiones")
            if self._ultima is not None:
                espera = self._ultima + self.intervalo - self._reloj()
                if espera > 0:
                    self._dormir(espera)
            if self.tiempo_agotado():
                raise LimiteAuditoria("se agotó el tiempo máximo de la auditoría")
            self._ultima = self._reloj()
            self.peticiones += 1

        timeout = max(1.0, min(self.timeout, self.segundos_restantes()))
        codigo, headers, url_final, cuerpo = self._transporte(
            url,
            metodo=metodo,
            timeout=timeout,
            max_bytes=max_bytes,
            seguir_redirecciones=seguir_redirecciones,
            cabeceras=cabeceras,
        )
        return Respuesta(codigo=codigo, cabeceras=headers, url=url, url_final=url_final, cuerpo=cuerpo)
