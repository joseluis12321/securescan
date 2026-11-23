"""Información del objetivo compartida por todas las comprobaciones.

Los datos se obtienen la primera vez que alguna comprobación los necesita y se
reutilizan después, para no repetir peticiones al servidor.
"""

import re
from functools import cached_property

from ..http_seguro import normalizar_url
from .cliente import MAX_BYTES_RESPUESTA, Respuesta

_RE_META_CSP = re.compile(
    r"""<meta\s[^>]*http-equiv\s*=\s*["']?content-security-policy["']?[^>]*>""", re.IGNORECASE
)
_RE_CONTENT = re.compile(r"""content\s*=\s*(?:"([^"]*)"|'([^']*)')""", re.IGNORECASE)


class Contexto:
    def __init__(self, url: str, cliente):
        self.url, self.host, self.puerto_tls = normalizar_url(url)
        self.cliente = cliente

    @cached_property
    def principal(self) -> Respuesta:
        """Respuesta de la URL analizada (tras seguir las redirecciones)."""
        return self.cliente.get(self.url, max_bytes=MAX_BYTES_RESPUESTA)

    @property
    def url_final(self) -> str:
        return self.principal.url_final

    @property
    def es_https(self) -> bool:
        return self.url_final.lower().startswith("https://")

    def cabecera(self, nombre: str) -> str | None:
        """Valor de una cabecera de la respuesta principal (varias se unen con comas)."""
        valores = self.cabeceras(nombre)
        return ", ".join(valores) if valores else None

    def cabeceras(self, nombre: str) -> list[str]:
        return [v.strip() for v in self.principal.cabeceras.get_all(nombre) or []]

    @cached_property
    def html(self) -> str:
        tipo = (self.principal.cabeceras.get_content_type() or "").lower()
        if "html" not in tipo:
            return ""
        return self.principal.texto

    @cached_property
    def csp_meta(self) -> str | None:
        """CSP definida con <meta http-equiv="Content-Security-Policy"> en el HTML."""
        etiqueta = _RE_META_CSP.search(self.html)
        if not etiqueta:
            return None
        contenido = _RE_CONTENT.search(etiqueta.group(0))
        return (contenido.group(1) or contenido.group(2) or "").strip() if contenido else None
