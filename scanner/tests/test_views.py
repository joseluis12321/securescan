"""Vistas: autenticación, CSRF, límites de peticiones, validación e IDOR."""

import io
from datetime import timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from scanner.models import Analisis
from scanner.port_scanner import ServidorOcupado
from scanner.templatetags.securescan import nivel

# django-ratelimit usa ventanas fijas de tiempo: si un test cruza el borde de
# una ventana el contador se reinicia y el test falla de forma intermitente.
VENTANA_FIJA = mock.patch("django_ratelimit.core._get_window", return_value=1_800_000_000)

LOG_XSS = b'1.2.3.4 - - [07/May/2026:10:23:01] "GET /?q=<script>alert(1)</script> HTTP/1.1" 200 1\n'


class VistasTests(TestCase):
    def setUp(self):
        cache.clear()  # reinicia los contadores del límite de peticiones
        User = get_user_model()
        self.usuario = User.objects.create_user("ana", password="clave-segura-123")
        self.otro = User.objects.create_user("beto", password="clave-segura-456")
        self.client.force_login(self.usuario)

    def post_json(self, nombre, datos, client=None, **extra):
        """POST JSON. Añade autorizado=True salvo que el test lo indique."""
        if isinstance(datos, dict) and nombre in ("escanear", "headers"):
            datos = {"autorizado": True, **datos}
        return (client or self.client).post(reverse(nombre), datos, content_type="application/json", **extra)

    # --- autenticación ---
    def test_home_requiere_login(self):
        r = Client().get(reverse("home"))
        self.assertRedirects(r, f"{reverse('login')}?next=/", fetch_redirect_response=False)

    def test_api_requiere_login(self):
        r = self.post_json("escanear", {"host": "8.8.8.8"}, client=Client())
        self.assertEqual(r.status_code, 401)

    def test_login_correcto(self):
        r = Client().post(reverse("login"), {"username": "ana", "password": "clave-segura-123"})
        self.assertRedirects(r, reverse("home"), fetch_redirect_response=False)

    @VENTANA_FIJA
    def test_login_limita_fuerza_bruta(self, _):
        c = Client()
        for _ in range(5):
            self.assertEqual(
                c.post(reverse("login"), {"username": "ana", "password": "mal"}).status_code, 200
            )
        r = c.post(reverse("login"), {"username": "ana", "password": "clave-segura-123"})
        self.assertEqual(r.status_code, 429)
        self.assertContains(r, "Demasiados intentos", status_code=429)

    # --- CSRF ---
    def test_csrf_obligatorio(self):
        c = Client(enforce_csrf_checks=True)
        c.force_login(self.usuario)
        self.assertEqual(self.post_json("escanear", {"host": "127.0.0.1"}, client=c).status_code, 403)

        c.get(reverse("home"))
        token = c.cookies["csrftoken"].value
        r = self.post_json("escanear", {"host": "127.0.0.1"}, client=c, HTTP_X_CSRFTOKEN=token)
        self.assertEqual(r.status_code, 400)  # pasa CSRF; lo frena el bloqueo SSRF

    # --- SSRF y validación en las vistas ---
    def test_escaneo_ip_privada_bloqueado(self):
        r = self.post_json("escanear", {"host": "127.0.0.1"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("no permitido", r.json()["error"])
        self.assertFalse(Analisis.objects.exists())

    def test_headers_metadatos_bloqueado(self):
        r = self.post_json("headers", {"url": "http://169.254.169.254/"})
        self.assertEqual(r.status_code, 400)

    def test_puertos_extra_invalidos(self):
        for puertos in [["abc"], [0], list(range(1, 200))]:
            with self.subTest(puertos=puertos):
                r = self.post_json("escanear", {"host": "8.8.8.8", "puertos_extra": puertos})
                self.assertEqual(r.status_code, 400)

    def test_json_invalido_y_metodo(self):
        r = self.client.post(reverse("escanear"), "{no es json", content_type="application/json")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.client.get(reverse("escanear")).status_code, 405)

    @mock.patch("scanner.views.escanear_host")
    def test_escaneo_valido_se_guarda(self, escanear):
        escanear.return_value = {"host": "8.8.8.8", "ip": "8.8.8.8", "resumen": {"nivel_riesgo": "BAJO"}}
        r = self.post_json("escanear", {"host": "8.8.8.8", "puertos_extra": [8000]})
        self.assertEqual(r.status_code, 200)
        escanear.assert_called_once_with("8.8.8.8", [8000])
        a = Analisis.objects.get(pk=r.json()["id"])
        self.assertEqual((a.tipo, a.usuario, a.nivel_riesgo), ("puertos", self.usuario, "BAJO"))

    @mock.patch("scanner.views._verificar_headers", return_value={"error": "timeout"})
    def test_headers_sitio_caido(self, _):
        r = self.post_json("headers", {"url": "example.com"})
        self.assertEqual(r.status_code, 502)
        self.assertFalse(Analisis.objects.exists())

    # --- subida de logs ---
    def test_subida_log_valida(self):
        r = self.client.post(reverse("analizar"), {"archivo_log": SimpleUploadedFile("access.log", LOG_XSS)})
        self.assertEqual(r.status_code, 200)
        a = Analisis.objects.get(pk=r.json()["id"])
        self.assertEqual((a.tipo, a.usuario, a.objetivo), ("logs", self.usuario, "access.log"))

    def test_subida_extension_no_permitida(self):
        r = self.client.post(reverse("analizar"), {"archivo_log": SimpleUploadedFile("virus.exe", LOG_XSS)})
        self.assertEqual(r.status_code, 400)

    def test_subida_archivo_binario(self):
        r = self.client.post(
            reverse("analizar"), {"archivo_log": SimpleUploadedFile("a.log", b"\x7fELF\x00\x01")}
        )
        self.assertEqual(r.status_code, 400)

    @override_settings(SECURESCAN_MAX_LOG_MB=0.001)  # ~1 KB
    def test_subida_demasiado_grande(self):
        r = self.client.post(reverse("analizar"), {"archivo_log": SimpleUploadedFile("a.log", LOG_XSS * 50)})
        self.assertEqual(r.status_code, 413)

    # --- PDF desde la base de datos ---
    def _analisis(self, usuario):
        return Analisis.objects.create(
            usuario=usuario,
            tipo="logs",
            objetivo="a.log",
            nivel_riesgo="BAJO",
            resultado={"resumen": {"nivel_riesgo": "BAJO"}, "amenazas": [], "ips_sospechosas": []},
        )

    def test_pdf_propio(self):
        r = self.client.get(reverse("exportar_pdf", args=[self._analisis(self.usuario).pk]))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r["Content-Type"], "application/pdf")
        self.assertTrue(r.content.startswith(b"%PDF"))

    def test_pdf_ajeno_no_accesible(self):
        r = self.client.get(reverse("exportar_pdf", args=[self._analisis(self.otro).pk]))
        self.assertEqual(r.status_code, 404)

    def test_pdf_anonimo_y_post(self):
        pk = self._analisis(self.usuario).pk
        self.assertEqual(Client().get(reverse("exportar_pdf", args=[pk])).status_code, 401)
        self.assertEqual(self.client.post(reverse("exportar_pdf", args=[pk])).status_code, 405)

    # --- límite de peticiones ---
    @VENTANA_FIJA
    def test_rate_limit_escaneo(self, _):
        for _ in range(10):
            self.assertEqual(self.post_json("escanear", {"host": "127.0.0.1"}).status_code, 400)
        self.assertEqual(self.post_json("escanear", {"host": "127.0.0.1"}).status_code, 429)

    # --- errores ---
    @mock.patch("scanner.views.escanear_host", side_effect=ServidorOcupado("ocupado"))
    def test_servidor_ocupado_devuelve_503(self, _):
        self.assertEqual(self.post_json("escanear", {"host": "8.8.8.8"}).status_code, 503)

    @mock.patch("scanner.views.escanear_host", side_effect=RuntimeError("detalle interno secreto"))
    def test_error_inesperado_no_filtra_detalles(self, _):
        with self.assertLogs("scanner.views", level="ERROR"):
            r = self.post_json("escanear", {"host": "8.8.8.8"})
        self.assertEqual(r.status_code, 500)
        self.assertEqual(r.json(), {"error": "Error interno del servidor"})

    def test_ssrf_bloqueado_queda_registrado(self):
        with self.assertLogs("scanner.views", level="WARNING") as logs:
            self.post_json("escanear", {"host": "127.0.0.1"})
        self.assertIn("SSRF bloqueado", logs.output[0])

    def test_host_no_texto(self):
        for datos in [{"host": 123}, {"host": ""}, {}, []]:
            with self.subTest(datos=datos):
                self.assertEqual(self.post_json("escanear", datos).status_code, 400)

    def test_log_rotado_aceptado(self):
        r = self.client.post(
            reverse("analizar"), {"archivo_log": SimpleUploadedFile("access.log.1", LOG_XSS)}
        )
        self.assertEqual(r.status_code, 200)

    def test_pdf_de_cada_tipo(self):
        for tipo in ("logs", "puertos", "headers"):
            with self.subTest(tipo=tipo):
                a = Analisis.objects.create(usuario=self.usuario, tipo=tipo, objetivo="x", resultado={})
                r = self.client.get(reverse("exportar_pdf", args=[a.pk]))
                self.assertEqual(r.status_code, 200)
                self.assertIn(f"securescan_{tipo}_{a.pk}.pdf", r["Content-Disposition"])

    def test_autorizacion_obligatoria(self):
        for nombre, datos in (("escanear", {"host": "8.8.8.8"}), ("headers", {"url": "example.com"})):
            for autorizado in (None, False, "true", 1):
                with self.subTest(nombre=nombre, autorizado=autorizado):
                    cuerpo = dict(datos) if autorizado is None else {**datos, "autorizado": autorizado}
                    r = self.client.post(reverse(nombre), cuerpo, content_type="application/json")
                    self.assertEqual(r.status_code, 400)
                    self.assertIn("autorización", r.json()["error"])

    @mock.patch("scanner.views.escanear_host", return_value={"resumen": {}})
    def test_escaneo_queda_en_el_registro_de_auditoria(self, _):
        with self.assertLogs("scanner.views", level="INFO") as logs:
            self.post_json("escanear", {"host": "8.8.8.8"})
        self.assertIn(f"usuario={self.usuario.pk} host=8.8.8.8", logs.output[0])


class PaginasTests(TestCase):
    """Plantillas, estáticos, CSP y healthcheck."""

    def setUp(self):
        cache.clear()
        self.usuario = get_user_model().objects.create_user("ana", password="clave-segura-123")

    def test_home_con_csp_estricta_y_sin_inline(self):
        self.client.force_login(self.usuario)
        r = self.client.get(reverse("home"))
        csp = r["Content-Security-Policy"]
        self.assertIn("script-src 'self'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertNotIn("unsafe-inline", csp)
        html = r.content.decode()
        self.assertNotIn("onclick=", html)
        self.assertNotIn("style=", html)
        self.assertIn('id="config-securescan" type="application/json"', html)
        self.assertEqual(r.context["config"]["urls"]["escanear"], reverse("escanear"))

    def test_login_sin_inline(self):
        html = self.client.get(reverse("login")).content.decode()
        self.assertNotIn("<style>", html)
        self.assertNotIn("style=", html)

    def test_estaticos_existen(self):
        from django.contrib.staticfiles import finders

        for ruta in ("scanner/css/app.css", "scanner/js/app.js"):
            with self.subTest(ruta=ruta):
                self.assertIsNotNone(finders.find(ruta))

    def test_pagina_404_propia(self):
        r = self.client.get("/no-existe/")
        self.assertEqual(r.status_code, 404)
        self.assertContains(r, "La página que buscas no existe", status_code=404)

    def test_salud(self):
        r = Client().get(reverse("salud"))
        self.assertEqual((r.status_code, r.json()), (200, {"estado": "ok"}))

    @mock.patch("scanner.views.connection.ensure_connection", side_effect=RuntimeError("bd caída"))
    def test_salud_con_fallo(self, _):
        with self.assertLogs("scanner.views", level="ERROR"):
            r = Client().get(reverse("salud"))
        self.assertEqual((r.status_code, r.json()), (503, {"estado": "error"}))


class HistorialTests(TestCase):
    """Historial, detalle, exportación JSON, borrado y retención."""

    def setUp(self):
        User = get_user_model()
        self.usuario = User.objects.create_user("ana", password="clave-segura-123")
        self.otro = User.objects.create_user("beto", password="clave-segura-456")
        self.client.force_login(self.usuario)

    def crear(self, usuario=None, tipo="logs", objetivo="a.log", nivel_riesgo="ALTO", **resultado):
        return Analisis.objects.create(
            usuario=usuario or self.usuario,
            tipo=tipo,
            objetivo=objetivo,
            nivel_riesgo=nivel_riesgo,
            resultado=resultado or {"resumen": {"nivel_riesgo": nivel_riesgo}},
        )

    def test_historial_solo_muestra_lo_propio(self):
        self.crear(objetivo="mio.log")
        self.crear(usuario=self.otro, objetivo="ajeno.log")
        r = self.client.get(reverse("historial"))
        self.assertContains(r, "mio.log")
        self.assertNotContains(r, "ajeno.log")

    def test_historial_filtra_por_tipo(self):
        self.crear(tipo="logs", objetivo="access.log")
        self.crear(tipo="puertos", objetivo="scanme.nmap.org")
        r = self.client.get(reverse("historial"), {"tipo": "puertos"})
        self.assertContains(r, "scanme.nmap.org")
        self.assertNotContains(r, "access.log")
        # Un tipo desconocido se ignora en vez de fallar.
        self.assertEqual(self.client.get(reverse("historial"), {"tipo": "<x>"}).status_code, 200)

    def test_historial_paginado(self):
        for i in range(25):
            self.crear(objetivo=f"log{i}.log")
        r = self.client.get(reverse("historial"))
        self.assertEqual(len(r.context["pagina"].object_list), 20)
        self.assertContains(r, "Página 1 de 2")
        r = self.client.get(reverse("historial"), {"pagina": "999"})
        self.assertEqual(r.context["pagina"].number, 2)

    def test_historial_y_detalle_requieren_login(self):
        a = self.crear()
        for url in (reverse("historial"), reverse("detalle", args=[a.pk])):
            with self.subTest(url=url):
                self.assertEqual(Client().get(url).status_code, 302)

    def test_detalle_propio(self):
        a = self.crear(objetivo="<script>x</script>.log")
        r = self.client.get(reverse("detalle", args=[a.pk]))
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, 'id="datos-analisis" type="application/json"')
        self.assertNotContains(r, "<script>x</script>")  # el objetivo se escapa
        self.assertNotIn("style=", r.content.decode())

    def test_detalle_ajeno_404(self):
        a = self.crear(usuario=self.otro)
        self.assertEqual(self.client.get(reverse("detalle", args=[a.pk])).status_code, 404)

    def test_exportar_json(self):
        a = self.crear(tipo="headers", objetivo="https://ejemplo.com")
        r = self.client.get(reverse("exportar_json", args=[a.pk]))
        self.assertEqual(r.status_code, 200)
        self.assertIn(f"securescan_headers_{a.pk}.json", r["Content-Disposition"])
        datos = r.json()
        self.assertEqual(
            (datos["id"], datos["tipo"], datos["objetivo"]), (a.pk, "headers", "https://ejemplo.com")
        )

    def test_exportar_json_ajeno_y_anonimo(self):
        a = self.crear(usuario=self.otro)
        self.assertEqual(self.client.get(reverse("exportar_json", args=[a.pk])).status_code, 404)
        self.assertEqual(Client().get(reverse("exportar_json", args=[a.pk])).status_code, 401)

    def test_eliminar(self):
        a = self.crear()
        r = self.client.post(reverse("eliminar", args=[a.pk]), follow=True)
        self.assertRedirects(r, reverse("historial"))
        self.assertContains(r, "Análisis eliminado")
        self.assertFalse(Analisis.objects.filter(pk=a.pk).exists())

    def test_eliminar_solo_por_post_y_solo_lo_propio(self):
        propio, ajeno = self.crear(), self.crear(usuario=self.otro)
        self.assertEqual(self.client.get(reverse("eliminar", args=[propio.pk])).status_code, 405)
        self.assertEqual(self.client.post(reverse("eliminar", args=[ajeno.pk])).status_code, 404)
        self.assertTrue(Analisis.objects.filter(pk=ajeno.pk).exists())

    def test_eliminar_exige_csrf(self):
        a = self.crear()
        c = Client(enforce_csrf_checks=True)
        c.force_login(self.usuario)
        self.assertEqual(c.post(reverse("eliminar", args=[a.pk])).status_code, 403)
        self.assertTrue(Analisis.objects.filter(pk=a.pk).exists())

    def test_purgar_analisis_antiguos(self):
        viejo, reciente = self.crear(objetivo="viejo.log"), self.crear(objetivo="reciente.log")
        Analisis.objects.filter(pk=viejo.pk).update(fecha=timezone.now() - timedelta(days=100))
        salida = io.StringIO()
        call_command("purgar_analisis", "--dias", "90", "--simular", stdout=salida)
        self.assertIn("Se borrarían 1", salida.getvalue())
        self.assertEqual(Analisis.objects.count(), 2)
        call_command("purgar_analisis", "--dias", "90", stdout=io.StringIO())
        self.assertEqual(list(Analisis.objects.values_list("pk", flat=True)), [reciente.pk])

    def test_filtro_nivel(self):
        self.assertEqual(
            [nivel(v) for v in ("ALTO", "MEDIO 🟡", "", None, '"><x>')],
            ["ALTO", "MEDIO", "BAJO", "BAJO", "BAJO"],
        )
