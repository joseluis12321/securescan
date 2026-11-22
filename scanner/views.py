import json
import re
from functools import wraps

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.utils.decorators import method_decorator
from django.views.decorators.http import require_GET, require_POST
from django_ratelimit.decorators import ratelimit
from django_ratelimit.exceptions import Ratelimited

from .analyzer import analizar_logs
from .header_checker import verificar_headers as _verificar_headers
from .models import Analisis
from .pdf_generator import generar_reporte_pdf
from .port_scanner import escanear_host
from .seguridad import EntradaInvalida

# .log, .txt y logs rotados como access.log.1
EXTENSIONES_LOG = re.compile(r"\.(log|txt)(\.\d+)?$", re.IGNORECASE)


class ArchivoDemasiadoGrande(EntradaInvalida):
    status = 413


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------

def vista_api(vista):
    """Decorador para endpoints JSON.

    - Exige sesión iniciada (401 en JSON en vez de redirigir al login).
    - Convierte EntradaInvalida en una respuesta de error con su código.
    - Convierte el límite de peticiones superado en un 429.
    """
    @wraps(vista)
    def envoltura(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({"error": "Debes iniciar sesión"}, status=401)
        try:
            return vista(request, *args, **kwargs)
        except EntradaInvalida as e:
            return JsonResponse({"error": str(e)}, status=e.status)
        except Ratelimited:
            return JsonResponse(
                {"error": "Demasiadas peticiones. Espera un minuto e inténtalo de nuevo."},
                status=429,
            )
    return envoltura


def _leer_json(request) -> dict:
    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise EntradaInvalida("El cuerpo de la petición no es JSON válido") from e
    if not isinstance(data, dict):
        raise EntradaInvalida("Se esperaba un objeto JSON")
    return data


def _max_bytes_log() -> int:
    return int(settings.SECURESCAN_MAX_LOG_MB * 1024 * 1024)


def _validar_archivo_log(archivo):
    if not EXTENSIONES_LOG.search(archivo.name or ""):
        raise EntradaInvalida("Formato no permitido. Sube un archivo .log o .txt")
    if archivo.size > _max_bytes_log():
        raise ArchivoDemasiadoGrande(
            f"El archivo supera el tamaño máximo de {settings.SECURESCAN_MAX_LOG_MB} MB"
        )
    inicio = archivo.read(4096)
    archivo.seek(0)
    if b"\x00" in inicio:
        raise EntradaInvalida("El archivo no parece ser texto plano")


def _lineas(archivo):
    """Lee el archivo subido línea a línea sin cargarlo entero en memoria."""
    for bruta in archivo:
        yield bruta.decode("utf-8", errors="replace").rstrip("\r\n")


def _guardar(request, tipo, objetivo, resultado):
    return Analisis.objects.create(
        usuario=request.user,
        tipo=tipo,
        objetivo=str(objetivo)[:255],
        nivel_riesgo=resultado.get("resumen", {}).get("nivel_riesgo", ""),
        resultado=resultado,
    )


# ---------------------------------------------------------------------------
# Vistas
# ---------------------------------------------------------------------------

@method_decorator(
    ratelimit(key="ip", rate=settings.SECURESCAN_RATE_LOGIN, method="POST", block=False),
    name="post",
)
class LoginConLimite(LoginView):
    """Login con límite de intentos por IP contra fuerza bruta."""

    template_name = "registration/login.html"
    redirect_authenticated_user = True

    def post(self, request, *args, **kwargs):
        if getattr(request, "limited", False):
            contexto = self.get_context_data(form=self.get_form_class()(request), limitado=True)
            return self.render_to_response(contexto, status=429)
        return super().post(request, *args, **kwargs)


@login_required
def home(request):
    return render(request, "scanner/home.html", {"max_log_mb": settings.SECURESCAN_MAX_LOG_MB})


@require_POST
@vista_api
@ratelimit(key="user_or_ip", rate=settings.SECURESCAN_RATE_ANALISIS, block=True)
def analizar(request):
    archivo = request.FILES.get("archivo_log")
    if not archivo:
        raise EntradaInvalida("No se subió ningún archivo")
    _validar_archivo_log(archivo)

    resultado = analizar_logs(_lineas(archivo))
    analisis = _guardar(request, Analisis.Tipo.LOGS, archivo.name, resultado)
    return JsonResponse({"success": True, "id": analisis.id, "resultado": resultado})


@require_POST
@vista_api
@ratelimit(key="user_or_ip", rate=settings.SECURESCAN_RATE_ESCANEO, block=True)
def escanear_puertos(request):
    data = _leer_json(request)
    host = data.get("host", "")
    if not isinstance(host, str) or not host.strip():
        raise EntradaInvalida("Host requerido")

    resultado = escanear_host(host.strip(), data.get("puertos_extra", []))
    analisis = _guardar(request, Analisis.Tipo.PUERTOS, host.strip(), resultado)
    return JsonResponse({"success": True, "id": analisis.id, "resultado": resultado})


@require_POST
@vista_api
@ratelimit(key="user_or_ip", rate=settings.SECURESCAN_RATE_HEADERS, block=True)
def verificar_headers(request):
    data = _leer_json(request)
    url = data.get("url", "")
    if not isinstance(url, str) or not url.strip():
        raise EntradaInvalida("URL requerida")

    resultado = _verificar_headers(url.strip())
    if "error" in resultado:
        # Fallo al contactar con el sitio (no es culpa de la petición).
        return JsonResponse({"error": resultado["error"]}, status=502)
    analisis = _guardar(request, Analisis.Tipo.HEADERS, resultado["url"], resultado)
    return JsonResponse({"success": True, "id": analisis.id, "resultado": resultado})


@require_GET
@vista_api
@ratelimit(key="user_or_ip", rate=settings.SECURESCAN_RATE_PDF, block=True)
def exportar_pdf(request, pk):
    # Filtrar por usuario impide descargar reportes ajenos (IDOR).
    analisis = get_object_or_404(Analisis, pk=pk, usuario=request.user)
    buffer = generar_reporte_pdf(
        analisis.tipo, analisis.resultado, analisis.objetivo, fecha=analisis.fecha
    )
    return HttpResponse(
        buffer,
        content_type="application/pdf",
        headers={
            "Content-Disposition":
                f'attachment; filename="securescan_{analisis.tipo}_{analisis.pk}.pdf"'
        },
    )
