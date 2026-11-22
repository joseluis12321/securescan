"""Borra los análisis más antiguos que el periodo de retención.

Uso:  python manage.py purgar_analisis [--dias 90] [--simular]
Pensado para ejecutarse a diario (cron, systemd timer o tarea programada).
"""

from datetime import timedelta

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from scanner.models import Analisis


class Command(BaseCommand):
    help = "Borra los análisis con más días de antigüedad que el periodo de retención."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dias",
            type=int,
            default=settings.SECURESCAN_RETENCION_DIAS,
            help="Antigüedad máxima en días (por defecto: SECURESCAN_RETENCION_DIAS).",
        )
        parser.add_argument("--simular", action="store_true", help="Muestra cuántos se borrarían sin borrar.")

    def handle(self, *args, dias, simular, **options):
        if dias < 1:
            raise CommandError("--dias debe ser 1 o más")
        limite = timezone.now() - timedelta(days=dias)
        antiguos = Analisis.objects.filter(fecha__lt=limite)
        total = antiguos.count()
        if simular:
            self.stdout.write(f"Se borrarían {total} análisis anteriores al {limite:%d/%m/%Y}.")
            return
        antiguos.delete()
        self.stdout.write(self.style.SUCCESS(f"Borrados {total} análisis anteriores al {limite:%d/%m/%Y}."))
