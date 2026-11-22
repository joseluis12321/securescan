"""Vistas: autenticación, CSRF, límites de peticiones, validación e IDOR."""

from unittest import mock

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from scanner.models import Analisis
from scanner.port_scanner import ServidorOcupado

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
