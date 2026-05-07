from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from .analyzer import analizar_logs
from .models import LogAnalysis
import json

def home(request):
    historial = LogAnalysis.objects.order_by("-fecha_analisis")[:10]
    return render(request, "scanner/home.html", {"historial": historial})

@csrf_exempt
def analizar(request):
    if request.method == "POST":
        archivo = request.FILES.get("archivo_log")
        if not archivo:
            return JsonResponse({"error": "No se subio ningun archivo"}, status=400)
        contenido = archivo.read().decode("utf-8", errors="ignore")
        resultado = analizar_logs(contenido)
        analisis = LogAnalysis.objects.create(
            archivo_nombre=archivo.name,
            total_lineas=resultado["total_lineas"],
            amenazas_encontradas=len(resultado["amenazas"]),
            resultado=json.dumps(resultado)
        )
        return JsonResponse({"success": True, "id": analisis.id, "resultado": resultado})
    return JsonResponse({"error": "Metodo no permitido"}, status=405)

@csrf_exempt
def escanear_puertos(request):
    if request.method == "POST":
        data = json.loads(request.body)
        host = data.get("host", "").strip()
        puertos_extra = data.get("puertos_extra", [])
        if not host:
            return JsonResponse({"error": "Host requerido"}, status=400)
        from .port_scanner import escanear_host
        resultado = escanear_host(host, puertos_extra)
        return JsonResponse({"success": True, "resultado": resultado})
    return JsonResponse({"error": "Metodo no permitido"}, status=405)

@csrf_exempt
def verificar_headers(request):
    if request.method == "POST":
        data = json.loads(request.body)
        url = data.get("url", "").strip()
        if not url:
            return JsonResponse({"error": "URL requerida"}, status=400)
        from .header_checker import verificar_headers as check
        resultado = check(url)
        return JsonResponse({"success": True, "resultado": resultado})
    return JsonResponse({"error": "Metodo no permitido"}, status=405)

@csrf_exempt
def exportar_pdf(request):
    if request.method == "POST":
        data = json.loads(request.body)
        tipo = data.get("tipo")
        datos = data.get("datos")
        objetivo = data.get("objetivo", "")
        if not tipo or not datos:
            return JsonResponse({"error": "Datos incompletos"}, status=400)
        from .pdf_generator import generar_reporte_pdf
        buffer = generar_reporte_pdf(tipo, datos, objetivo)
        response = HttpResponse(buffer, content_type="application/pdf")
        response["Content-Disposition"] = f"attachment; filename=securescan_reporte_{tipo}.pdf"
        return response
    return JsonResponse({"error": "Metodo no permitido"}, status=405)
