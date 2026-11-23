"""Comprobaciones de cabeceras HTTP con respuestas simuladas (sin red)."""

from django.test import SimpleTestCase

from scanner.auditoria import motor
from scanner.auditoria.base import Estado, Gravedad
from scanner.auditoria.comprobaciones import cabeceras as cab
from scanner.auditoria.contexto import Contexto

from .utilidades import ClienteFalso

URL = "https://ejemplo.com"

CABECERAS_CORRECTAS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; object-src 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Server": "nginx",
}


def evaluar(clase, cabeceras=None, url_final=None, cuerpo=b""):
    datos = {"cabeceras": cabeceras or {}, "url_final": url_final, "cuerpo": cuerpo}
    return clase().ejecutar(Contexto(URL, ClienteFalso({URL: datos})))


class CasosMixin:
    """Ejecuta una tabla de casos: (cabeceras, estado, gravedad o None, texto en la evidencia)."""

    def comprobar_casos(self, clase, casos, **opciones):
        for cabeceras, estado, gravedad, texto in casos:
            with self.subTest(cabeceras=cabeceras):
                r = evaluar(clase, cabeceras, **opciones)
                self.assertEqual(r.estado, estado, r.evidencia)
                if gravedad is not None:
                    self.assertEqual(r.gravedad, gravedad)
                self.assertIn(texto, r.evidencia)
                self.assertEqual(r.id, clase.id)
                self.assertTrue(r.explicacion and r.recomendacion and r.referencia.startswith("https://"))


class HSTSTests(CasosMixin, SimpleTestCase):
    def test_casos(self):
        H = "Strict-Transport-Security"
        self.comprobar_casos(
            cab.HSTS,
            [
                ({H: "max-age=31536000; includeSubDomains"}, Estado.OK, None, "max-age=31536000"),
                ({H: 'max-age="15552000"'}, Estado.OK, None, "15552000"),
                ({}, Estado.FALLO, Gravedad.MEDIA, "no incluye"),
                ({H: "includeSubDomains"}, Estado.FALLO, Gravedad.MEDIA, "no define max-age"),
                ({H: "max-age=0"}, Estado.FALLO, Gravedad.MEDIA, "desactiva"),
                ({H: "max-age=3600"}, Estado.FALLO, Gravedad.BAJA, "0 días"),
                ({H: "max-age=8640000"}, Estado.FALLO, Gravedad.BAJA, "100 días"),
            ],
        )

    def test_no_aplica_sin_https(self):
        r = evaluar(cab.HSTS, {}, url_final="http://ejemplo.com/")
        self.assertEqual(r.estado, Estado.NO_APLICA)
        self.assertIn("sin HTTPS", r.evidencia)


class CSPTests(CasosMixin, SimpleTestCase):
    def test_casos(self):
        C = "Content-Security-Policy"
        self.comprobar_casos(
            cab.CSP,
            [
                ({C: "default-src 'self'"}, Estado.OK, None, "default-src 'self'"),
                ({C: "script-src 'self' 'nonce-abc' 'unsafe-inline'"}, Estado.OK, None, "nonce"),
                ({C: "script-src 'sha256-xyz' 'unsafe-inline'"}, Estado.OK, None, "sha256"),
                ({}, Estado.FALLO, Gravedad.MEDIA, "no incluye"),
                (
                    {"Content-Security-Policy-Report-Only": "default-src 'self'"},
                    Estado.FALLO,
                    Gravedad.MEDIA,
                    "Report-Only",
                ),
                ({C: "img-src 'self'"}, Estado.FALLO, Gravedad.BAJA, "falta script-src"),
                ({C: "default-src 'self' 'unsafe-inline'"}, Estado.FALLO, Gravedad.BAJA, "'unsafe-inline'"),
                ({C: "script-src 'self' 'unsafe-eval'"}, Estado.FALLO, Gravedad.BAJA, "'unsafe-eval'"),
                ({C: "script-src *"}, Estado.FALLO, Gravedad.BAJA, "cualquier origen"),
                ({C: "script-src https: 'self'"}, Estado.FALLO, Gravedad.BAJA, "cualquier origen"),
                # script-src tiene prioridad sobre default-src.
                ({C: "default-src *; script-src 'self'"}, Estado.OK, None, "script-src"),
            ],
        )

    def test_csp_en_meta(self):
        html = b"""<head><meta http-equiv="Content-Security-Policy" content="default-src 'self'"></head>"""
        r = evaluar(cab.CSP, {"Content-Type": "text/html"}, cuerpo=html)
        self.assertEqual(r.estado, Estado.OK)
        self.assertIn("<meta", r.evidencia)

    def test_problemas_combinados(self):
        problemas = cab.problemas_csp("script-src * 'unsafe-inline' 'unsafe-eval'")
        self.assertEqual(len(problemas), 3)
        self.assertEqual(cab.directivas_csp("A x; a y; b"), {"a": "x", "b": ""})


class XFrameOptionsTests(CasosMixin, SimpleTestCase):
    def test_casos(self):
        self.comprobar_casos(
            cab.XFrameOptions,
            [
                ({"X-Frame-Options": "DENY"}, Estado.OK, None, "DENY"),
                ({"X-Frame-Options": "sameorigin"}, Estado.OK, None, "sameorigin"),
                ({"Content-Security-Policy": "frame-ancestors 'none'"}, Estado.OK, None, "frame-ancestors"),
                ({}, Estado.FALLO, Gravedad.MEDIA, "No hay X-Frame-Options"),
                (
                    {"X-Frame-Options": "ALLOW-FROM https://otra.com"},
                    Estado.FALLO,
                    Gravedad.BAJA,
                    "ALLOW-FROM",
                ),
            ],
        )

    def test_frame_ancestors_en_meta_no_cuenta(self):
        html = b"""<meta http-equiv="Content-Security-Policy" content="frame-ancestors 'none'">"""
        r = evaluar(cab.XFrameOptions, {"Content-Type": "text/html"}, cuerpo=html)
        self.assertEqual(r.estado, Estado.FALLO)


class CabecerasSimplesTests(CasosMixin, SimpleTestCase):
    def test_x_content_type_options(self):
        self.comprobar_casos(
            cab.XContentTypeOptions,
            [
                ({"X-Content-Type-Options": "nosniff"}, Estado.OK, None, "nosniff"),
                ({}, Estado.FALLO, Gravedad.BAJA, "no incluye"),
                ({"X-Content-Type-Options": "nosnif"}, Estado.FALLO, Gravedad.BAJA, "único valor"),
            ],
        )

    def test_referrer_policy(self):
        R = "Referrer-Policy"
        self.comprobar_casos(
            cab.ReferrerPolicy,
            [
                ({R: "no-referrer"}, Estado.OK, None, "no-referrer"),
                ({R: "unsafe-url, strict-origin"}, Estado.OK, None, "strict-origin"),
                ({}, Estado.FALLO, Gravedad.BAJA, "valor por defecto"),
                ({R: "unsafe-url"}, Estado.FALLO, Gravedad.BAJA, "dirección completa"),
                ({R: "origin, no-referrer-when-downgrade"}, Estado.FALLO, Gravedad.BAJA, "no-referrer-when"),
            ],
        )

    def test_permissions_policy(self):
        self.comprobar_casos(
            cab.PermissionsPolicy,
            [
                ({"Permissions-Policy": "camera=()"}, Estado.OK, None, "camera"),
                ({"Feature-Policy": "camera 'none'"}, Estado.FALLO, Gravedad.BAJA, "obsoleta"),
                ({}, Estado.FALLO, Gravedad.BAJA, "no incluye"),
            ],
        )

    def test_coop(self):
        COOP = "Cross-Origin-Opener-Policy"
        self.comprobar_casos(
            cab.COOP,
            [
                ({COOP: "same-origin"}, Estado.OK, None, "same-origin"),
                ({COOP: "same-origin-allow-popups"}, Estado.OK, None, "allow-popups"),
                ({COOP: 'unsafe-none; report-to="x"'}, Estado.FALLO, Gravedad.BAJA, "desactiva"),
                ({}, Estado.FALLO, Gravedad.BAJA, "no incluye"),
            ],
        )

    def test_corp(self):
        P = "Cross-Origin-Resource-Policy"
        self.comprobar_casos(
            cab.CORP,
            [
                ({P: "same-site"}, Estado.OK, None, "same-site"),
                ({P: "cross-origin"}, Estado.OK, None, "cross-origin"),
                ({P: "nadie"}, Estado.FALLO, Gravedad.INFO, "no válido"),
                ({}, Estado.FALLO, Gravedad.INFO, "no incluye"),
            ],
        )


class FugasDeInformacionTests(CasosMixin, SimpleTestCase):
    def test_version_servidor(self):
        self.comprobar_casos(
            cab.VersionServidor,
            [
                ({}, Estado.OK, None, "no envía"),
                ({"Server": "nginx"}, Estado.OK, None, "sin versión"),
                ({"Server": "cloudflare"}, Estado.OK, None, "cloudflare"),
                ({"Server": "nginx/1.18.0 (Ubuntu)"}, Estado.FALLO, Gravedad.BAJA, "nginx/1.18.0"),
                ({"Server": "Apache/2.4.41"}, Estado.FALLO, Gravedad.BAJA, "Apache/2.4.41"),
            ],
        )

    def test_tecnologia_expuesta(self):
        self.comprobar_casos(
            cab.TecnologiaExpuesta,
            [
                ({}, Estado.OK, None, "X-Powered-By"),
                ({"X-Powered-By": "PHP/8.1.2"}, Estado.FALLO, Gravedad.BAJA, "X-Powered-By: PHP/8.1.2"),
                (
                    {"X-AspNet-Version": "4.0.30319", "X-Generator": "Drupal 10"},
                    Estado.FALLO,
                    Gravedad.BAJA,
                    "X-AspNet-Version: 4.0.30319 · X-Generator: Drupal 10",
                ),
            ],
        )

    def test_x_xss_protection(self):
        X = "X-XSS-Protection"
        self.comprobar_casos(
            cab.XXSSProtection,
            [
                ({}, Estado.OK, None, "no está presente"),
                ({X: "0"}, Estado.OK, None, "0"),
                ({X: "1; mode=block"}, Estado.FALLO, Gravedad.INFO, "sigue activado"),
            ],
        )


class AuditoriaDeCabecerasTests(SimpleTestCase):
    """El catálogo de cabeceras completo contra un sitio bien configurado y otro sin protecciones."""

    def _auditar(self, cabeceras):
        from unittest import mock

        cliente = ClienteFalso({URL: {"cabeceras": cabeceras}})
        with mock.patch.object(motor, "resolver_ip_publica", return_value="93.184.216.34"):
            return motor.auditar(URL, cliente=cliente)

    def test_sitio_bien_configurado(self):
        r = self._auditar(CABECERAS_CORRECTAS)
        resultados = r["categorias"][0]["resultados"]
        self.assertEqual([x["id"] for x in resultados if x["estado"] != "ok"], [])
        self.assertEqual((r["nota"], r["resumen"]["nivel_riesgo"]), (10, "BAJO"))

    def test_sitio_sin_protecciones(self):
        r = self._auditar({"Server": "Apache/2.4.41", "X-Powered-By": "PHP/7.4"})
        # 3 medias (HSTS, CSP, XFO), 6 bajas (XCTO, Referrer, Permissions, COOP, Server,
        # X-Powered-By) y CORP como info.
        self.assertEqual(
            r["resumen"]["fallos_por_gravedad"], {"critica": 0, "alta": 0, "media": 3, "baja": 6, "info": 1}
        )
        self.assertEqual((r["nota"], r["resumen"]["nivel_riesgo"]), (4, "ALTO"))
        primero = r["categorias"][0]["resultados"][0]
        self.assertEqual((primero["estado"], primero["gravedad"]), ("fallo", "media"))
