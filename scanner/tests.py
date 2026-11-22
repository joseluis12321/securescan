"""Tests de regresión de los arreglos de seguridad (Fase 1).

No hacen peticiones a Internet: los destinos externos se simulan con mocks y
los servidores de prueba escuchan solo en 127.0.0.1.
"""

import http.server
import threading
import time
import urllib.error
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from . import seguridad
from .analyzer import analizar_logs
from .header_checker import _crear_opener, normalizar_url, verificar_headers
from .models import Analisis
from .pdf_generator import generar_reporte_pdf
from .port_scanner import escanear_host
from .seguridad import (
    EntradaInvalida,
    ObjetivoNoPermitido,
    crear_conexion_segura,
    resolver_ip_publica,
    validar_puertos,
)


# ---------------------------------------------------------------------------
# SSRF
# ---------------------------------------------------------------------------

class ResolverIpPublicaTests(SimpleTestCase):
    INTERNAS = [
        "127.0.0.1", "127.1", "2130706433", "localhost", "0.0.0.0",
        "10.0.0.5", "172.16.0.1", "192.168.1.1", "100.64.0.1",
        "169.254.169.254",          # metadatos de AWS/GCP/Azure
        "224.0.0.1",                # multicast
        "::1", "fe80::1", "fc00::1",
        "::ffff:127.0.0.1",         # IPv4 mapeada en IPv6
        "2002:7f00:1::1",           # 6to4 que encapsula 127.0.0.1
    ]

    def test_bloquea_direcciones_internas(self):
        for host in self.INTERNAS:
            with self.subTest(host=host):
                with self.assertRaises(ObjetivoNoPermitido):
                    resolver_ip_publica(host)

    def test_permite_ips_publicas(self):
        self.assertEqual(resolver_ip_publica("8.8.8.8"), "8.8.8.8")
        self.assertEqual(resolver_ip_publica("[2001:4860:4860::8888]"), "2001:4860:4860::8888")

    @override_settings(SECURESCAN_PERMITIR_REDES_PRIVADAS=True)
    def test_redes_privadas_se_pueden_habilitar(self):
        self.assertEqual(resolver_ip_publica("127.0.0.1"), "127.0.0.1")

    def test_hosts_invalidos(self):
        for host in [None, 123, "", "   ", "a" * 300, "host\x00malo"]:
            with self.subTest(host=host):
                with self.assertRaises(EntradaInvalida):
                    resolver_ip_publica(host)

    def test_conexion_segura_rechaza_ip_interna(self):
        with self.assertRaises(ObjetivoNoPermitido):
            crear_conexion_segura(("127.0.0.1", 80), timeout=1)


class _ServidorPrueba:
    """Servidor HTTP mínimo en 127.0.0.1 que registra las rutas pedidas."""

    def __init__(self, location=None):
        rutas = self.rutas = []

        class Manejador(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                rutas.append(self.path)
                if location and self.path == "/":
                    self.send_response(302)
                    self.send_header("Location", location.format(puerto=self.server.server_port))
                else:
                    self.send_response(200)
                self.end_headers()

            def log_message(self, *args):
                pass

        self.servidor = http.server.HTTPServer(("127.0.0.1", 0), Manejador)
        self.puerto = self.servidor.server_port
        threading.Thread(target=self.servidor.serve_forever, daemon=True).start()

    def cerrar(self):
        self.servidor.shutdown()
        self.servidor.server_close()


class OpenerSeguroTests(SimpleTestCase):
    def test_no_conecta_a_localhost(self):
        srv = _ServidorPrueba()
        try:
            with self.assertRaises(ObjetivoNoPermitido):
                _crear_opener().open(f"http://127.0.0.1:{srv.puerto}/", timeout=2)
            self.assertEqual(srv.rutas, [])
        finally:
            srv.cerrar()

    def test_redireccion_a_red_interna_bloqueada(self):
        """El primer salto se permite (simulado como público); la redirección no."""
        srv = _ServidorPrueba(location="http://localhost:{puerto}/secreto")
        original = seguridad.resolver_ip_publica

        def resolver_falso(host, puerto=None):
            if host == "127.0.0.1":
                return "127.0.0.1"  # se finge que es un sitio público
            return original(host, puerto)

        try:
            with mock.patch.object(seguridad, "resolver_ip_publica", side_effect=resolver_falso):
                with self.assertRaises(ObjetivoNoPermitido):
                    _crear_opener().open(f"http://127.0.0.1:{srv.puerto}/", timeout=2)
            self.assertEqual(srv.rutas, ["/"])
        finally:
            srv.cerrar()

    def test_redireccion_a_ftp_bloqueada(self):
        srv = _ServidorPrueba(location="ftp://127.0.0.1/archivo")
        try:
            with mock.patch.object(seguridad, "resolver_ip_publica", return_value="127.0.0.1"):
                with self.assertRaises(urllib.error.HTTPError):
                    _crear_opener().open(f"http://127.0.0.1:{srv.puerto}/", timeout=2)
        finally:
            srv.cerrar()


class NormalizarUrlTests(SimpleTestCase):
    def test_añade_https(self):
        self.assertEqual(normalizar_url("github.com")[:2], ("https://github.com", "github.com"))

    def test_rechaza_esquemas_peligrosos(self):
        for url in ["file:///etc/passwd", "ftp://example.com", "gopher://x", "https://:80", "https://x:abc/"]:
            with self.subTest(url=url):
                with self.assertRaises(EntradaInvalida):
                    normalizar_url(url)

    def test_headers_a_metadatos_bloqueado(self):
        with self.assertRaises(ObjetivoNoPermitido):
            verificar_headers("http://169.254.169.254/latest/meta-data/")


# ---------------------------------------------------------------------------
# Validación de puertos
# ---------------------------------------------------------------------------

class ValidarPuertosTests(SimpleTestCase):
    def test_valida_y_elimina_duplicados(self):
        self.assertEqual(validar_puertos([8000, 9000, 8000]), [8000, 9000])
        self.assertEqual(validar_puertos(None), [])

    def test_rechaza_valores_invalidos(self):
        for puertos in ["80", [0], [65536], [-1], ["80"], [True], [80.5], list(range(1, 200))]:
            with self.subTest(puertos=puertos):
                with self.assertRaises(EntradaInvalida):
                    validar_puertos(puertos)

    def test_escaneo_a_localhost_bloqueado(self):
        with self.assertRaises(ObjetivoNoPermitido):
            escanear_host("127.0.0.1")


# ---------------------------------------------------------------------------
# Analizador y PDF
# ---------------------------------------------------------------------------

class AnalizadorTests(SimpleTestCase):
    def test_detecta_ataques_desde_iterable(self):
        lineas = iter([
            '1.2.3.4 - - [07/May/2026:10:23:01] "GET /?q=<script>alert(1)</script> HTTP/1.1" 200 1',
            '1.2.3.4 - - [07/May/2026:10:23:02] "GET /?id=1 UNION SELECT pass FROM users HTTP/1.1" 200 1',
            '1.2.3.4 - - [07/May/2026:10:23:03] "GET /../../etc/passwd HTTP/1.1" 404 1',
        ])
        r = analizar_logs(lineas)
        self.assertEqual(r["total_lineas"], 3)
        tipos = {a["tipo"] for a in r["amenazas"]}
        self.assertIn("Posible ataque XSS detectado", tipos)
        self.assertIn("Posible SQL Injection detectado", tipos)
        self.assertIn("Intento de Path Traversal", tipos)

    def test_linea_gigante_no_provoca_redos(self):
        inicio = time.monotonic()
        analizar_logs(["union " * 200_000])
        self.assertLess(time.monotonic() - inicio, 3)


class PdfTests(SimpleTestCase):
    def test_contenido_con_markup_no_rompe_el_pdf(self):
        # Sin escapar, ReportLab intentaría descargar la imagen (SSRF/lectura local).
        payload = '<img src="http://127.0.0.1:9/x.png"/> <b>sin cerrar <font color="red"> &'
        datos = {
            "resumen": {"nivel_riesgo": "ALTO", "total_lineas": 1},
            "amenazas": [{
                "tipo": "<script>", "nivel": "ALTO", "cantidad": 1,
                "detalle": [{"linea": 1, "contenido": payload}],
            }],
            "recomendaciones": [{"puerto": 1, "servicio": payload, "recomendacion": payload}],
            "ssl_info": {"valido": False, "error": payload},
        }
        for tipo in ("logs", "puertos", "headers"):
            with self.subTest(tipo=tipo):
                pdf = generar_reporte_pdf(tipo, datos, "<i>objetivo</i>").read()
                self.assertTrue(pdf.startswith(b"%PDF"))


# ---------------------------------------------------------------------------
# Vistas: autenticación, CSRF, límites, IDOR
# ---------------------------------------------------------------------------

LOG_XSS = b'1.2.3.4 - - [07/May/2026:10:23:01] "GET /?q=<script>alert(1)</script> HTTP/1.1" 200 1\n'


class VistasTests(TestCase):
    def setUp(self):
        cache.clear()  # reinicia los contadores del límite de peticiones
        User = get_user_model()
        self.usuario = User.objects.create_user("ana", password="clave-segura-123")
        self.otro = User.objects.create_user("beto", password="clave-segura-456")
        self.client.force_login(self.usuario)

    def post_json(self, nombre, datos, client=None, **extra):
        return (client or self.client).post(
            reverse(nombre), datos, content_type="application/json", **extra)

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

    def test_login_limita_fuerza_bruta(self):
        c = Client()
        for _ in range(5):
            self.assertEqual(c.post(reverse("login"), {"username": "ana", "password": "mal"}).status_code, 200)
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
        r = self.client.post(reverse("analizar"), {"archivo_log": SimpleUploadedFile("a.log", b"\x7fELF\x00\x01")})
        self.assertEqual(r.status_code, 400)

    @override_settings(SECURESCAN_MAX_LOG_MB=0.001)  # ~1 KB
    def test_subida_demasiado_grande(self):
        r = self.client.post(reverse("analizar"), {"archivo_log": SimpleUploadedFile("a.log", LOG_XSS * 50)})
        self.assertEqual(r.status_code, 413)

    # --- PDF desde la base de datos ---
    def _analisis(self, usuario):
        return Analisis.objects.create(
            usuario=usuario, tipo="logs", objetivo="a.log", nivel_riesgo="BAJO",
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
    def test_rate_limit_escaneo(self):
        for _ in range(10):
            self.assertEqual(self.post_json("escanear", {"host": "127.0.0.1"}).status_code, 400)
        self.assertEqual(self.post_json("escanear", {"host": "127.0.0.1"}).status_code, 429)
