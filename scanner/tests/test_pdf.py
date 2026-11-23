"""Generación de PDF: los cuatro tipos de reporte y contenido malicioso."""

from django.test import SimpleTestCase
from reportlab.platypus import KeepTogether, Paragraph

from scanner import pdf_generator
from scanner.pdf_generator import generar_reporte_pdf

PAYLOAD = '<img src="http://127.0.0.1:9/x.png"/> <b>sin cerrar <font color="red"> & <para>'

DATOS_COMPLETOS = {
    "resumen": {"nivel_riesgo": "ALTO", "total_lineas": 3, "puntuacion": 40},
    "amenazas": [
        {
            "tipo": "<script>",
            "nivel": "ALTO",
            "cantidad": 1,
            "detalle": [{"linea": 1, "contenido": PAYLOAD}, {"linea": None, "contenido": PAYLOAD}],
        }
    ],
    "ips_sospechosas": [
        {"ip": "1.2.3.4", "apariciones": 9, "eventos_maliciosos": 2, "fallos_login": 5, "nivel": "ALTO"}
    ],
    "puertos_abiertos": [
        {"puerto": 22, "servicio": "SSH", "peligroso": False, "banner": PAYLOAD},
        {"puerto": 6379, "servicio": "Redis", "peligroso": True, "banner": None},
    ],
    "recomendaciones": [{"puerto": 1, "servicio": PAYLOAD, "recomendacion": PAYLOAD}],
    "ssl_info": {
        "valido": True,
        "dias_restantes": 10,
        "expira": "01/01/2027",
        "version_tls": "TLSv1.3",
        "cifrado": "TLS_AES_256_GCM_SHA384",
        "emisor": {"organizationName": PAYLOAD},
    },
    "headers_presentes": [
        {"header": "Strict-Transport-Security", "valor": PAYLOAD, "advertencia": PAYLOAD, "descripcion": "x"}
    ],
    "headers_faltantes": [{"header": "Content-Security-Policy", "nivel": "ALTO", "recomendacion": PAYLOAD}],
    "advertencias": [
        {"tipo": "Fuga", "header": "Server", "valor": PAYLOAD, "detalle": PAYLOAD, "recomendacion": PAYLOAD}
    ],
    "redireccion_https": None,
}


def _comprobacion(estado, gravedad, texto=PAYLOAD, referencia="https://owasp.org/"):
    return {
        "id": "cabeceras.x",
        "categoria": "cabeceras",
        "titulo": texto,
        "gravedad": gravedad,
        "estado": estado,
        "evidencia": texto,
        "explicacion": texto,
        "recomendacion": texto,
        "referencia": referencia,
    }


DATOS_WEB = {
    "url": "https://ejemplo.com",
    "url_final": PAYLOAD,
    "codigo_estado": 200,
    "nota": 6.5,
    "peticiones": 1,
    "resumen": {
        "nivel_riesgo": "MEDIO",
        "total": 4,
        "ok": 1,
        "fallos": 2,
        "no_aplica": 1,
        "fallos_por_gravedad": {"critica": 0, "alta": 1, "media": 0, "baja": 1, "info": 0},
    },
    "categorias": [
        {
            "id": "cabeceras",
            "nombre": PAYLOAD,
            "fallos": 2,
            "resultados": [
                _comprobacion("fallo", "alta"),
                _comprobacion("fallo", "<x>", referencia='javascript:alert(1)"'),
                _comprobacion("ok", "media", texto="HSTS correcto"),
                _comprobacion("no_aplica", "media", texto="Sin HTTPS"),
            ],
        }
    ],
}


def _textos(elementos) -> list[str]:
    """Texto (markup) de todos los Paragraph de una lista de elementos del PDF."""
    textos = []
    for e in elementos:
        if isinstance(e, Paragraph):
            textos.append(e.text)
        elif isinstance(e, KeepTogether):
            textos += _textos(e._content)
    return textos


class PdfTests(SimpleTestCase):
    def test_contenido_malicioso_no_rompe_ni_inyecta(self):
        # Sin escapar, ReportLab intentaría descargar la imagen (SSRF/lectura local).
        for tipo, datos in (
            ("logs", DATOS_COMPLETOS),
            ("puertos", DATOS_COMPLETOS),
            ("headers", DATOS_COMPLETOS),
            ("web", DATOS_WEB),
        ):
            with self.subTest(tipo=tipo):
                pdf = generar_reporte_pdf(tipo, datos, "<i>objetivo</i>").read()
                self.assertTrue(pdf.startswith(b"%PDF"))

    def test_datos_vacios_o_antiguos(self):
        """Análisis guardados por versiones anteriores (campos ausentes, niveles con emoji)."""
        for tipo in ("logs", "puertos", "headers", "web", "desconocido"):
            with self.subTest(tipo=tipo):
                self.assertTrue(generar_reporte_pdf(tipo, {}).read().startswith(b"%PDF"))
        antiguo = {
            "resumen": {"nivel_riesgo": "MEDIO 🟡"},
            "amenazas": [
                {"tipo": "x", "nivel": "MEDIO 🟡", "cantidad": 1, "detalle": [{"linea": 1, "contenido": "y"}]}
            ],
        }
        self.assertTrue(generar_reporte_pdf("logs", antiguo).read().startswith(b"%PDF"))

    def test_muchas_filas_generan_varias_paginas(self):
        datos = {
            "puertos_abiertos": [
                {"puerto": p, "servicio": "x", "peligroso": False, "banner": "b" * 100} for p in range(1, 120)
            ]
        }
        pdf = generar_reporte_pdf("puertos", datos).read()
        self.assertGreater(pdf.count(b"/Type /Page") - pdf.count(b"/Type /Pages"), 1)


class PdfAuditoriaWebTests(SimpleTestCase):
    def setUp(self):
        self.story = []
        pdf_generator._web(self.story, DATOS_WEB)
        self.textos = _textos(self.story)
        self.todo = "\n".join(self.textos)

    def test_resumen_con_nota_y_gravedades(self):
        self.assertIn("Resumen de la Auditoría", self.todo)
        self.assertIn("La nota parte de 10", self.todo)
        self.assertIn("se hizo 1 petición normal al sitio", self.todo)
        celdas = [
            c.text for t in self.story if hasattr(t, "_cellvalues") for fila in t._cellvalues for c in fila
        ]
        self.assertIn("6,5 / 10", celdas)
        self.assertIn("Crítica: 0 · Alta: 1 · Media: 0 · Baja: 1 · Info: 0", celdas)

    def test_cada_comprobacion_con_explicacion_evidencia_y_recomendacion(self):
        for etiqueta in ("Qué significa", "Evidencia", "Recomendación", "Referencia"):
            self.assertIn(f"<b>{etiqueta}:</b>", self.todo)
        self.assertIn("[FALLO · Alta]", self.todo)
        self.assertIn("[FALLO · Info]", self.todo)  # gravedad desconocida
        self.assertIn("[OK] HSTS correcto", self.todo)
        self.assertIn("[NO APLICA] Sin HTTPS", self.todo)

    def test_contenido_escapado_y_referencias_seguras(self):
        self.assertNotIn("<img", self.todo)
        self.assertNotIn("<font color", self.todo.replace('<font color="#', ""))
        self.assertIn("&lt;img", self.todo)
        self.assertNotIn("javascript:", self.todo)
        self.assertIn('<a href="https://owasp.org/" color="#1a56db">', self.todo)

    def test_datos_raros_no_rompen(self):
        raros = {"nota": "no-numero", "resumen": {"fallos_por_gravedad": {"alta": "x"}}, "categorias": [{}]}
        story = []
        pdf_generator._web(story, raros)
        celdas = [c.text for t in story if hasattr(t, "_cellvalues") for fila in t._cellvalues for c in fila]
        self.assertIn("1,0 / 10", celdas)


class PdfPuertosTests(SimpleTestCase):
    def test_explicacion_por_puerto(self):
        story = []
        pdf_generator._puertos(story, DATOS_COMPLETOS)
        todo = "\n".join(_textos(story))
        self.assertIn("Detalle por Puerto", todo)
        self.assertIn("Puerto :22 — SSH [ABIERTO]", todo)
        self.assertIn("Puerto :6379 — Redis [RIESGO]", todo)
        self.assertIn("requirepass", todo)  # recomendación específica de Redis
        for etiqueta in ("Qué es", "Riesgo", "Recomendación", "Servicio identificado (banner)"):
            self.assertIn(f"<b>{etiqueta}:</b>", todo)
        self.assertNotIn("<img", todo)

    def test_puerto_desconocido_o_invalido(self):
        story = []
        datos = {"puertos_abiertos": [{"puerto": 4444, "servicio": "Personalizado"}, {"puerto": "x"}]}
        pdf_generator._puertos(story, datos)
        todo = "\n".join(_textos(story))
        self.assertIn("Servicio Personalizado escuchando en el puerto 4444", todo)
        self.assertIn("puerto 0", todo)
