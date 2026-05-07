from django.db import models

class LogAnalysis(models.Model):
    archivo_nombre = models.CharField(max_length=255)
    fecha_analisis = models.DateTimeField(auto_now_add=True)
    total_lineas = models.IntegerField(default=0)
    amenazas_encontradas = models.IntegerField(default=0)
    resultado = models.TextField(blank=True)

    def __str__(self):
        return f"{self.archivo_nombre} - {self.fecha_analisis}"