"""Generación de PDF: los tres tipos de reporte y contenido malicioso."""

from django.test import SimpleTestCase

from scanner.pdf_generator import generar_reporte_pdf

PAYLOAD = '<img src="http://127.0.0.1:9/x.png"/> <b>sin cerrar <font color="red"> & <para>'

DATOS_COMPLETOS = {
    "resumen": {"nivel_riesgo": "ALTO", "total_lineas": 3, "puntuacion": 40},
    "amenazas": [{
        "tipo": "<script>", "nivel": "ALTO", "cantidad": 1,
        "detalle": [{"linea": 1, "contenido": PAYLOAD}, {"linea": None, "contenido": PAYLOAD}],
    }],
    "ips_sospechosas": [{"ip": "1.2.3.4", "apariciones": 9, "eventos_maliciosos": 2,
                         "fallos_login": 5, "nivel": "ALTO"}],
    "puertos_abiertos": [{"puerto": 22, "servicio": "SSH", "peligroso": False, "banner": PAYLOAD},
                         {"puerto": 6379, "servicio": "Redis", "peligroso": True, "banner": None}],
    "recomendaciones": [{"puerto": 1, "servicio": PAYLOAD, "recomendacion": PAYLOAD}],
    "ssl_info": {"valido": True, "dias_restantes": 10, "expira": "01/01/2027",
                 "version_tls": "TLSv1.3", "cifrado": "TLS_AES_256_GCM_SHA384",
                 "emisor": {"organizationName": PAYLOAD}},
    "headers_presentes": [{"header": "Strict-Transport-Security", "valor": PAYLOAD,
                           "advertencia": PAYLOAD, "descripcion": "x"}],
    "headers_faltantes": [{"header": "Content-Security-Policy", "nivel": "ALTO", "recomendacion": PAYLOAD}],
    "advertencias": [{"tipo": "Fuga", "header": "Server", "valor": PAYLOAD,
                      "detalle": PAYLOAD, "recomendacion": PAYLOAD}],
    "redireccion_https": None,
}


class PdfTests(SimpleTestCase):
    def test_contenido_malicioso_no_rompe_ni_inyecta(self):
        # Sin escapar, ReportLab intentaría descargar la imagen (SSRF/lectura local).
        for tipo in ("logs", "puertos", "headers"):
            with self.subTest(tipo=tipo):
                pdf = generar_reporte_pdf(tipo, DATOS_COMPLETOS, "<i>objetivo</i>").read()
                self.assertTrue(pdf.startswith(b"%PDF"))

    def test_datos_vacios_o_antiguos(self):
        """Análisis guardados por versiones anteriores (campos ausentes, niveles con emoji)."""
        for tipo in ("logs", "puertos", "headers", "desconocido"):
            with self.subTest(tipo=tipo):
                self.assertTrue(generar_reporte_pdf(tipo, {}).read().startswith(b"%PDF"))
        antiguo = {"resumen": {"nivel_riesgo": "MEDIO 🟡"}, "amenazas": [
            {"tipo": "x", "nivel": "MEDIO 🟡", "cantidad": 1, "detalle": [{"linea": 1, "contenido": "y"}]}]}
        self.assertTrue(generar_reporte_pdf("logs", antiguo).read().startswith(b"%PDF"))

    def test_muchas_filas_generan_varias_paginas(self):
        datos = {"puertos_abiertos": [
            {"puerto": p, "servicio": "x", "peligroso": False, "banner": "b" * 100} for p in range(1, 120)]}
        pdf = generar_reporte_pdf("puertos", datos).read()
        self.assertGreater(pdf.count(b"/Type /Page") - pdf.count(b"/Type /Pages"), 1)
