"""Auditoría web pasiva y modular.

- base.py: gravedades, estados, resultados y el catálogo de comprobaciones.
- cliente.py: cliente HTTP que solo hace peticiones pasivas y con límites.
- contexto.py: datos del objetivo compartidos entre comprobaciones.
- motor.py: ejecuta el catálogo y agrupa los resultados.
- puntuacion.py: nota global del 1 al 10.
- comprobaciones/: una comprobación por clase, agrupadas por categoría.
"""

from . import comprobaciones  # noqa: F401  (registra las comprobaciones en el catálogo)
from .motor import auditar

__all__ = ["auditar"]
