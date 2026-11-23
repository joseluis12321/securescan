"""Piezas comunes de la auditoría web: gravedades, estados, resultados y catálogo.

Cada comprobación es una subclase de `Comprobacion`. Al definirla se registra
sola en `CATALOGO`, así que añadir una comprobación nueva consiste solo en
escribir su clase en el módulo de su categoría:

    class MiComprobacion(Comprobacion):
        id = "cabeceras.mi_comprobacion"
        categoria = Categoria.CABECERAS
        titulo = "..."
        gravedad = Gravedad.BAJA
        explicacion = "..."      # para alguien no técnico
        recomendacion = "..."
        referencia = "https://..."

        def ejecutar(self, ctx):
            return self.ok("evidencia") / self.fallo("evidencia") / self.no_aplica("motivo")

Para una clase base intermedia o de pruebas que no deba registrarse se usa
`class Base(Comprobacion, registrar=False)`.
"""

import enum
from dataclasses import asdict, dataclass
from typing import ClassVar

MAX_EVIDENCIA = 600


class Gravedad(enum.StrEnum):
    INFO = "info"
    BAJA = "baja"
    MEDIA = "media"
    ALTA = "alta"
    CRITICA = "critica"

    @property
    def etiqueta(self) -> str:
        return ETIQUETAS_GRAVEDAD[self]

    @property
    def peso(self) -> int:
        """Posición de menor (0) a mayor gravedad, para ordenar."""
        return list(Gravedad).index(self)


class Estado(enum.StrEnum):
    OK = "ok"
    FALLO = "fallo"
    NO_APLICA = "no_aplica"

    @property
    def etiqueta(self) -> str:
        return ETIQUETAS_ESTADO[self]


class Categoria(enum.StrEnum):
    """Categorías en el orden en que se ejecutan y se muestran."""

    CABECERAS = "cabeceras"
    TLS = "tls"
    COOKIES = "cookies"
    DNS = "dns"
    WORDPRESS = "wordpress"
    ARCHIVOS = "archivos"
    VERSIONES = "versiones"

    @property
    def nombre(self) -> str:
        return NOMBRES_CATEGORIA[self]


ETIQUETAS_GRAVEDAD = {
    Gravedad.INFO: "Info",
    Gravedad.BAJA: "Baja",
    Gravedad.MEDIA: "Media",
    Gravedad.ALTA: "Alta",
    Gravedad.CRITICA: "Crítica",
}
ETIQUETAS_ESTADO = {Estado.OK: "OK", Estado.FALLO: "Fallo", Estado.NO_APLICA: "No aplica"}
NOMBRES_CATEGORIA = {
    Categoria.CABECERAS: "Cabeceras HTTP",
    Categoria.TLS: "HTTPS y TLS",
    Categoria.COOKIES: "Cookies",
    Categoria.DNS: "DNS y correo",
    Categoria.WORDPRESS: "WordPress",
    Categoria.ARCHIVOS: "Archivos sensibles expuestos",
    Categoria.VERSIONES: "Versiones y vulnerabilidades conocidas",
}


@dataclass(frozen=True, slots=True)
class Resultado:
    id: str
    categoria: Categoria
    titulo: str
    gravedad: Gravedad
    estado: Estado
    evidencia: str
    explicacion: str
    recomendacion: str
    referencia: str

    def como_dict(self) -> dict:
        return {campo: str(valor) for campo, valor in asdict(self).items()}


CATALOGO: dict[str, type["Comprobacion"]] = {}

_CAMPOS_OBLIGATORIOS = ("id", "titulo", "explicacion", "recomendacion", "referencia")


class Comprobacion:
    id: ClassVar[str]
    categoria: ClassVar[Categoria]
    titulo: ClassVar[str]
    gravedad: ClassVar[Gravedad]
    explicacion: ClassVar[str]
    recomendacion: ClassVar[str]
    referencia: ClassVar[str]

    def __init_subclass__(cls, registrar: bool = True, **kwargs):
        super().__init_subclass__(**kwargs)
        if not registrar:
            return
        faltan = [campo for campo in _CAMPOS_OBLIGATORIOS if not getattr(cls, campo, None)]
        if faltan:
            raise TypeError(f"{cls.__name__}: faltan los atributos {', '.join(faltan)}")
        if not isinstance(getattr(cls, "categoria", None), Categoria):
            raise TypeError(f"{cls.__name__}: la categoría debe ser un valor de Categoria")
        if not isinstance(getattr(cls, "gravedad", None), Gravedad):
            raise TypeError(f"{cls.__name__}: la gravedad debe ser un valor de Gravedad")
        existente = CATALOGO.get(cls.id)
        if existente is not None and existente.__qualname__ != cls.__qualname__:
            raise ValueError(f"Identificador de comprobación duplicado: {cls.id}")
        CATALOGO[cls.id] = cls

    def ejecutar(self, ctx) -> Resultado:
        raise NotImplementedError

    # --- Resultados ---------------------------------------------------------
    def _resultado(self, estado, evidencia, gravedad=None, recomendacion=None) -> Resultado:
        evidencia = " ".join(str(evidencia).split())
        if len(evidencia) > MAX_EVIDENCIA:
            evidencia = evidencia[: MAX_EVIDENCIA - 1] + "…"
        return Resultado(
            id=self.id,
            categoria=self.categoria,
            titulo=self.titulo,
            gravedad=gravedad or self.gravedad,
            estado=estado,
            evidencia=evidencia,
            explicacion=self.explicacion,
            recomendacion=recomendacion or self.recomendacion,
            referencia=self.referencia,
        )

    def ok(self, evidencia: str) -> Resultado:
        return self._resultado(Estado.OK, evidencia)

    def fallo(self, evidencia: str, *, gravedad: Gravedad | None = None, recomendacion: str | None = None):
        """Fallo con la gravedad de la comprobación, o con otra si el caso lo requiere."""
        return self._resultado(Estado.FALLO, evidencia, gravedad, recomendacion)

    def no_aplica(self, motivo: str) -> Resultado:
        return self._resultado(Estado.NO_APLICA, motivo)


def catalogo() -> list[Comprobacion]:
    """Instancias de todas las comprobaciones, por categoría y en orden de definición."""
    orden = list(Categoria)
    clases = sorted(CATALOGO.values(), key=lambda c: orden.index(c.categoria))
    return [clase() for clase in clases]
