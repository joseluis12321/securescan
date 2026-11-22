from django.conf import settings
from django.db import models


class Analisis(models.Model):
    """Resultado de cualquier análisis (logs, puertos o headers) de un usuario.

    Los reportes PDF se generan siempre a partir de estos registros, nunca a
    partir de datos enviados por el cliente.
    """

    class Tipo(models.TextChoices):
        LOGS = "logs", "Análisis de logs"
        PUERTOS = "puertos", "Escaneo de puertos"
        HEADERS = "headers", "Verificación de headers HTTP"

    # null=True solo para conservar análisis antiguos creados antes del login.
    usuario = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="analisis",
    )
    tipo = models.CharField(max_length=10, choices=Tipo.choices)
    objetivo = models.CharField(max_length=255)
    nivel_riesgo = models.CharField(max_length=10, blank=True)
    resultado = models.JSONField(default=dict)
    fecha = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-fecha"]
        verbose_name = "análisis"
        verbose_name_plural = "análisis"

    def __str__(self):
        return f"{self.get_tipo_display()} - {self.objetivo} ({self.fecha:%d/%m/%Y %H:%M})"
