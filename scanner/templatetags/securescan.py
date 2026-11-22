from django import template

register = template.Library()


@register.filter
def nivel(valor) -> str:
    """Normaliza un nivel de riesgo a ALTO/MEDIO/BAJO (seguro para usar como clase CSS)."""
    texto = str(valor or "").upper()
    for opcion in ("ALTO", "MEDIO", "BAJO"):
        if opcion in texto:
            return opcion
    return "BAJO"
