from django.contrib import admin

from .models import Analisis


@admin.register(Analisis)
class AnalisisAdmin(admin.ModelAdmin):
    list_display = ("id", "tipo", "objetivo", "nivel_riesgo", "usuario", "fecha")
    list_filter = ("tipo", "nivel_riesgo", "fecha")
    search_fields = ("objetivo", "usuario__username")
    readonly_fields = ("fecha",)
