"""Escáner de puertos: puertos abiertos, banners, SSRF y concurrencia."""

import socket
from unittest import mock

from django.test import SimpleTestCase, override_settings

from scanner import port_scanner
from scanner.port_scanner import ServidorOcupado, _limpiar_banner, escanear_host, escanear_puerto
from scanner.seguridad import EntradaInvalida, ObjetivoNoPermitido

from .utilidades import ServidorTCPPrueba


class EscanerTests(SimpleTestCase):
    def test_localhost_bloqueado_por_defecto(self):
        with self.assertRaises(ObjetivoNoPermitido):
            escanear_host("127.0.0.1")

    def test_puertos_invalidos(self):
        with self.assertRaises(EntradaInvalida):
            escanear_host("8.8.8.8", [70000])

    @override_settings(SECURESCAN_PERMITIR_REDES_PRIVADAS=True)
    def test_detecta_puerto_abierto_y_banner(self):
        with ServidorTCPPrueba(b"SSH-2.0-OpenSSH_9.6\r\n") as srv:
            r = escanear_host("127.0.0.1", [srv.puerto])
        abierto = next(p for p in r["puertos_abiertos"] if p["puerto"] == srv.puerto)
        self.assertEqual(abierto["servicio"], "Personalizado")
        self.assertEqual(abierto["banner"], "SSH-2.0-OpenSSH_9.6")
        self.assertEqual(r["resumen"]["total_verificados"], len(port_scanner.PUERTOS_COMUNES) + 1)

    @override_settings(SECURESCAN_PERMITIR_REDES_PRIVADAS=True)
    def test_servicio_sin_banner(self):
        with ServidorTCPPrueba() as srv:
            puerto, abierto, banner = escanear_puerto("127.0.0.1", srv.puerto)
        self.assertEqual((puerto, abierto), (srv.puerto, True))
        self.assertIsNone(banner)

    def test_puerto_cerrado(self):
        with socket.socket() as s:  # reserva un puerto libre y lo suelta sin escuchar
            s.bind(("127.0.0.1", 0))
            puerto_libre = s.getsockname()[1]
        self.assertEqual(escanear_puerto("127.0.0.1", puerto_libre), (puerto_libre, False, None))

    def test_nivel_de_riesgo(self):
        def falso(ip, puerto):
            return puerto, puerto in (80, 6379), None

        with (
            mock.patch.object(port_scanner, "resolver_ip_publica", return_value="8.8.8.8"),
            mock.patch.object(port_scanner, "escanear_puerto", side_effect=falso),
        ):
            r = escanear_host("ejemplo.com")
        self.assertEqual([p["puerto"] for p in r["puertos_abiertos"]], [80, 6379])
        self.assertEqual(r["puertos_peligrosos"], [6379])
        self.assertEqual(r["resumen"]["nivel_riesgo"], "ALTO")
        self.assertEqual(r["recomendaciones"][0]["servicio"], "Redis")

    def test_servidor_ocupado(self):
        semaforo = mock.Mock(acquire=mock.Mock(return_value=False))
        with (
            mock.patch.object(port_scanner, "resolver_ip_publica", return_value="8.8.8.8"),
            mock.patch.object(port_scanner, "_escaneos_activos", semaforo),
            self.assertRaises(ServidorOcupado),
        ):
            escanear_host("ejemplo.com")

    def test_limpiar_banner(self):
        self.assertEqual(_limpiar_banner(b"220 FTP listo\r\n"), "220 FTP listo")
        self.assertIsNone(_limpiar_banner(b"\x00\x01\xff"))
        self.assertEqual(len(_limpiar_banner(b"A" * 500)), 120)


class ExplicacionPuertosTests(SimpleTestCase):
    def test_todos_los_puertos_comunes_tienen_explicacion(self):
        self.assertEqual(set(port_scanner.EXPLICACION_PUERTOS), set(port_scanner.PUERTOS_COMUNES))
        for puerto in port_scanner.PUERTOS_COMUNES:
            with self.subTest(puerto=puerto):
                info = port_scanner.explicar_puerto(puerto)
                self.assertEqual(set(info), {"que_es", "riesgo", "recomendacion"})
                self.assertTrue(all(len(v) > 20 for v in info.values()))

    def test_puerto_desconocido(self):
        info = port_scanner.explicar_puerto(4444, "Personalizado")
        self.assertIn("Personalizado", info["que_es"])
        self.assertIn("4444", info["que_es"])
        self.assertIn("desconocido", port_scanner.explicar_puerto(4444)["que_es"])
