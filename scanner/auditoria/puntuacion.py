"""Nota global de la auditoría (1 a 10) según la gravedad de los fallos.

Se parte de 10 y cada fallo resta según su gravedad. Un fallo crítico limita la
nota a 4 y uno alto a 7, para que un problema grave nunca quede escondido tras
muchas comprobaciones correctas. Las comprobaciones correctas y las que no
aplican no restan.
"""

from .base import Estado, Gravedad

PENALIZACION = {
    Gravedad.INFO: 0,
    Gravedad.BAJA: 0.5,
    Gravedad.MEDIA: 1,
    Gravedad.ALTA: 2,
    Gravedad.CRITICA: 4,
}
NOTA_MAXIMA_CON = {Gravedad.CRITICA: 4, Gravedad.ALTA: 7}
NOTA_MINIMA = 1


def calcular_nota(resultados) -> float:
    fallos = [r for r in resultados if r.estado == Estado.FALLO]
    nota = 10 - sum(PENALIZACION[r.gravedad] for r in fallos)
    for gravedad, tope in NOTA_MAXIMA_CON.items():
        if any(r.gravedad == gravedad for r in fallos):
            nota = min(nota, tope)
    return round(max(NOTA_MINIMA, nota), 1)


def nivel_riesgo(nota: float) -> str:
    """Traduce la nota al nivel de riesgo que usan el historial y los demás módulos."""
    if nota >= 8:
        return "BAJO"
    if nota >= 5:
        return "MEDIO"
    return "ALTO"
