"""Verificador de headers: validación de valores, advertencias y puntuación."""

import http.client
import io
from unittest import mock

from django.test import SimpleTestCase

from scanner import header_checker as hc
from scanner.seguridad import ObjetivoNoPermitido


def _headers(texto: str) -> http.client.HTTPMessage:
    return http.client.parse_headers(io.BytesIO(texto.strip().replace("\n", "\r\n").encode() + b"\r\n\r\n"))


HEADERS_COMPLETOS = """
Strict-Transport-Security: max-age=63072000; includeSubDomains
Content-Security-Policy: default-src 'self'; frame-ancestors 'none'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=()
Cross-Origin-Opener-Policy: same-origin
"""


class ValidadoresTests(SimpleTestCase):
    def test_hsts(self):
        self.assertIsNone(hc._validar_hsts("max-age=31536000; includeSubDomains"))
        self.assertIn("corto", hc._validar_hsts("max-age=3600"))
        self.assertIn("max-age", hc._validar_hsts("includeSubDomains"))

    def test_csp(self):
        self.assertIsNone(hc._validar_csp("default-src 'self'"))
        self.assertIsNone(hc._validar_csp("script-src 'self' 'nonce-abc' 'unsafe-inline'"))
        self.assertIn("'unsafe-inline'", hc._validar_csp("default-src 'self' 'unsafe-inline'"))
        self.assertIn("'unsafe-eval'", hc._validar_csp("script-src 'self' 'unsafe-eval'"))
        self.assertIn("comodín", hc._validar_csp("script-src *"))
        self.assertIn("falta", hc._validar_csp("img-src 'self'"))

    def test_otros(self):
        self.assertIsNone(hc._validar_xfo("sameorigin"))
        self.assertIsNotNone(hc._validar_xfo("ALLOW-FROM https://x.com"))
        self.assertIsNone(hc._validar_xcto("nosniff"))
        self.assertIsNotNone(hc._validar_xcto("sniff"))
        self.assertIsNotNone(hc._validar_referrer("no-referrer, unsafe-url"))
        self.assertIsNone(hc._validar_referrer("unsafe-url, strict-origin"))
        self.assertIsNotNone(hc._validar_coop("unsafe-none"))


class EvaluarHeadersTests(SimpleTestCase):
    def test_todos_correctos(self):
        presentes, faltantes = hc._evaluar_headers(_headers(HEADERS_COMPLETOS))
        self.assertEqual(faltantes, [])
        self.assertTrue(all(h["advertencia"] is None for h in presentes))

    def test_frame_ancestors_cubre_x_frame_options(self):
        presentes, faltantes = hc._evaluar_headers(
            _headers("Content-Security-Policy: default-src 'self'; frame-ancestors 'none'"))
        self.assertIn("X-Frame-Options", [h["header"] for h in presentes])
        self.assertNotIn("X-Frame-Options", [h["header"] for h in faltantes])

    def test_header_debil_lleva_advertencia(self):
        presentes, _ = hc._evaluar_headers(_headers("Strict-Transport-Security: max-age=60"))
        hsts = presentes[0]
        self.assertIsNotNone(hsts["advertencia"])
        self.assertTrue(hsts["recomendacion"].startswith("Recomendado:"))


class AdvertenciasTests(SimpleTestCase):
    def test_fugas_de_informacion_y_headers_obsoletos(self):
        adv = hc._advertencias(_headers("""
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/7.4.3
X-XSS-Protection: 1; mode=block
"""), es_https=True)
        self.assertEqual([a["header"] for a in adv], ["Server", "X-Powered-By", "X-XSS-Protection"])

    def test_server_sin_version_y_xxss_cero_no_avisan(self):
        self.assertEqual(hc._advertencias(_headers("Server: nginx\nX-XSS-Protection: 0"), True), [])

    def test_cookies(self):
        adv = hc._advertencias(_headers("""
Set-Cookie: sesion=abc; Path=/
Set-Cookie: segura=1; Secure; HttpOnly; SameSite=Lax
"""), es_https=True)
        self.assertEqual(len(adv), 1)
        self.assertEqual(adv[0]["valor"], "sesion")
        self.assertIn("Secure", adv[0]["detalle"])

    def test_secure_no_se_exige_en_http(self):
        adv = hc._advertencias(_headers("Set-Cookie: a=1; HttpOnly; SameSite=Strict"), es_https=False)
        self.assertEqual(adv, [])


class VerificarHeadersTests(SimpleTestCase):
    """verificar_headers con la red simulada."""

    def _ejecutar(self, headers, url_final="https://ejemplo.com/", ssl_valido=True, redireccion=True):
        ssl_info = {"valido": ssl_valido, "dias_restantes": 90} if ssl_valido else {"valido": False, "error": "x"}
        with mock.patch.object(hc, "resolver_ip_publica", return_value="93.184.216.34"), \
             mock.patch.object(hc, "obtener", return_value=(200, _headers(headers), url_final)), \
             mock.patch.object(hc, "verificar_ssl", return_value=ssl_info), \
             mock.patch.object(hc, "comprobar_redireccion_https", return_value=redireccion):
            return hc.verificar_headers("ejemplo.com")

    def test_sitio_bien_configurado(self):
        r = self._ejecutar(HEADERS_COMPLETOS)
        self.assertEqual(r["resumen"]["puntuacion"], 100)
        self.assertEqual(r["resumen"]["nivel_riesgo"], "BAJO")
        self.assertTrue(r["https"])

    def test_sitio_sin_headers_ni_https(self):
        r = self._ejecutar("Server: x", url_final="http://ejemplo.com/", ssl_valido=False, redireccion=False)
        self.assertEqual(r["resumen"]["puntuacion"], 0)
        self.assertEqual(r["resumen"]["nivel_riesgo"], "ALTO")

    def test_headers_debiles_puntuan_la_mitad(self):
        r = self._ejecutar(HEADERS_COMPLETOS.replace("max-age=63072000", "max-age=60"))
        self.assertEqual(r["resumen"]["debiles"], 1)
        self.assertLess(r["resumen"]["puntuacion"], 100)

    def test_sitio_caido_devuelve_error(self):
        with mock.patch.object(hc, "resolver_ip_publica", return_value="93.184.216.34"), \
             mock.patch.object(hc, "obtener", side_effect=OSError("timeout")):
            self.assertIn("error", hc.verificar_headers("ejemplo.com"))

    def test_metadatos_cloud_bloqueados(self):
        with self.assertRaises(ObjetivoNoPermitido):
            hc.verificar_headers("http://169.254.169.254/latest/meta-data/")

    def test_ssl_a_localhost_bloqueado(self):
        self.assertFalse(hc.verificar_ssl("127.0.0.1")["valido"])
