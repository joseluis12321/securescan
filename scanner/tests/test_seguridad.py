"""Protección SSRF, validación de entradas y cliente HTTP seguro."""

import urllib.error
from unittest import mock

from django.test import SimpleTestCase, override_settings

from scanner import seguridad
from scanner.http_seguro import crear_opener, normalizar_url, obtener
from scanner.seguridad import (
    EntradaInvalida,
    ObjetivoNoPermitido,
    crear_conexion_segura,
    resolver_ip_publica,
    validar_puertos,
)

from .utilidades import ServidorHTTPPrueba


def _resolver_que_permite_127(host, puerto=None, _original=seguridad.resolver_ip_publica):
    """Finge que 127.0.0.1 es un sitio público; el resto se valida de verdad."""
    if host == "127.0.0.1":
        return "127.0.0.1"
    return _original(host, puerto)


class ResolverIpPublicaTests(SimpleTestCase):
    INTERNAS = (
        "127.0.0.1",
        "127.1",
        "2130706433",
        "0x7f000001",
        "localhost",
        "0.0.0.0",
        "0",
        "10.0.0.5",
        "172.16.0.1",
        "192.168.1.1",
        "100.64.0.1",
        "169.254.169.254",  # metadatos de AWS/GCP/Azure
        "224.0.0.1",
        "255.255.255.255",
        "::1",
        "::",
        "fe80::1",
        "fc00::1",
        "::ffff:127.0.0.1",  # IPv4 mapeada en IPv6
        "2002:7f00:1::1",  # 6to4 que encapsula 127.0.0.1
    )

    def test_bloquea_direcciones_internas(self):
        for host in self.INTERNAS:
            with self.subTest(host=host), self.assertRaises(ObjetivoNoPermitido):
                resolver_ip_publica(host)

    def test_permite_ips_publicas(self):
        self.assertEqual(resolver_ip_publica("8.8.8.8"), "8.8.8.8")
        self.assertEqual(resolver_ip_publica(" 1.1.1.1 "), "1.1.1.1")
        self.assertEqual(resolver_ip_publica("[2001:4860:4860::8888]"), "2001:4860:4860::8888")

    @override_settings(SECURESCAN_PERMITIR_REDES_PRIVADAS=True)
    def test_redes_privadas_se_pueden_habilitar(self):
        self.assertEqual(resolver_ip_publica("127.0.0.1"), "127.0.0.1")

    def test_hosts_invalidos(self):
        for host in [None, 123, "", "   ", "a" * 300, "host\x00malo"]:
            with self.subTest(host=host), self.assertRaises(EntradaInvalida):
                resolver_ip_publica(host)

    def test_rechaza_si_alguna_ip_es_interna(self):
        """Un dominio con un registro público y otro privado se rechaza entero."""
        infos = [(2, 1, 6, "", ("8.8.8.8", 0)), (2, 1, 6, "", ("10.0.0.1", 0))]
        with mock.patch("socket.getaddrinfo", return_value=infos), self.assertRaises(ObjetivoNoPermitido):
            resolver_ip_publica("mixto.example")

    def test_prefiere_ipv4(self):
        infos = [(10, 1, 6, "", ("2001:4860:4860::8888", 0, 0, 0)), (2, 1, 6, "", ("8.8.8.8", 0))]
        with mock.patch("socket.getaddrinfo", return_value=infos):
            self.assertEqual(resolver_ip_publica("dual.example"), "8.8.8.8")

    def test_conexion_segura_rechaza_ip_interna(self):
        with self.assertRaises(ObjetivoNoPermitido):
            crear_conexion_segura(("127.0.0.1", 80), timeout=1)


class ValidarPuertosTests(SimpleTestCase):
    def test_valida_y_elimina_duplicados(self):
        self.assertEqual(validar_puertos([8000, 9000, 8000]), [8000, 9000])
        self.assertEqual(validar_puertos(None), [])
        self.assertEqual(validar_puertos([1, 65535]), [1, 65535])

    def test_rechaza_valores_invalidos(self):
        for puertos in ["80", [0], [65536], [-1], ["80"], [True], [80.5], [None], list(range(1, 200))]:
            with self.subTest(puertos=puertos), self.assertRaises(EntradaInvalida):
                validar_puertos(puertos)


class NormalizarUrlTests(SimpleTestCase):
    def test_añade_https_por_defecto(self):
        self.assertEqual(normalizar_url("github.com"), ("https://github.com", "github.com", 443))

    def test_puerto_tls(self):
        self.assertEqual(normalizar_url("https://x.com:8443/a")[2], 8443)
        self.assertEqual(normalizar_url("http://x.com:8080/")[2], 443)

    def test_rechaza_urls_peligrosas_o_invalidas(self):
        for url in [
            None,
            "",
            "file:///etc/passwd",
            "ftp://example.com",
            "gopher://x",
            "https://:80",
            "https://x:abc/",
            "https://" + "a" * 3000,
        ]:
            with self.subTest(url=url), self.assertRaises(EntradaInvalida):
                normalizar_url(url)


class ClienteHTTPSeguroTests(SimpleTestCase):
    def test_no_conecta_a_localhost(self):
        with ServidorHTTPPrueba() as srv:
            with self.assertRaises(ObjetivoNoPermitido):
                crear_opener().open(f"http://127.0.0.1:{srv.puerto}/", timeout=2)
            self.assertEqual(srv.rutas, [])

    def test_redireccion_a_red_interna_bloqueada(self):
        """El primer salto se permite (simulado como público); la redirección no."""
        respuestas = {"/": (302, {"Location": "http://localhost:{puerto}/secreto"})}
        with ServidorHTTPPrueba(respuestas) as srv:
            with (
                mock.patch.object(seguridad, "resolver_ip_publica", side_effect=_resolver_que_permite_127),
                self.assertRaises(ObjetivoNoPermitido),
            ):
                obtener(f"http://127.0.0.1:{srv.puerto}/", timeout=2)
            self.assertEqual(srv.rutas, ["/"])

    def test_redireccion_a_otro_esquema_bloqueada(self):
        for destino in ["ftp://127.0.0.1/archivo", "file:///etc/passwd"]:
            respuestas = {"/": (302, {"Location": destino})}
            with self.subTest(destino=destino), ServidorHTTPPrueba(respuestas) as srv:
                with (
                    mock.patch.object(seguridad, "resolver_ip_publica", return_value="127.0.0.1"),
                    self.assertRaises(urllib.error.HTTPError),
                ):
                    obtener(f"http://127.0.0.1:{srv.puerto}/", timeout=2)

    def test_bucle_de_redirecciones_se_corta(self):
        respuestas = {"/": (302, {"Location": "/"})}
        with ServidorHTTPPrueba(respuestas) as srv:
            with (
                mock.patch.object(seguridad, "resolver_ip_publica", return_value="127.0.0.1"),
                self.assertRaises(urllib.error.HTTPError),
            ):
                obtener(f"http://127.0.0.1:{srv.puerto}/", timeout=2)
            self.assertLessEqual(len(srv.rutas), 11)

    def test_respuesta_de_error_devuelve_headers(self):
        respuestas = {"/": (404, {"X-Frame-Options": "DENY"})}
        with ServidorHTTPPrueba(respuestas) as srv:
            with mock.patch.object(seguridad, "resolver_ip_publica", return_value="127.0.0.1"):
                codigo, headers, url_final = obtener(f"http://127.0.0.1:{srv.puerto}/", timeout=2)
        self.assertEqual(codigo, 404)
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertTrue(url_final.startswith("http://127.0.0.1"))
