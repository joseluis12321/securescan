"""Núcleo de la auditoría web: catálogo, puntuación, cliente pasivo, contexto y motor.

Ningún test hace peticiones a Internet: se usan respuestas simuladas o un
servidor local en 127.0.0.1.
"""

from unittest import mock

from django.test import SimpleTestCase

from scanner import seguridad
from scanner.auditoria import motor
from scanner.auditoria.base import (
    CATALOGO,
    MAX_EVIDENCIA,
    Categoria,
    Comprobacion,
    Estado,
    Gravedad,
    Resultado,
    catalogo,
)
from scanner.auditoria.cliente import MAX_BYTES_RESPUESTA, ClienteAuditoria, LimiteAuditoria
from scanner.auditoria.contexto import Contexto
from scanner.auditoria.puntuacion import calcular_nota, nivel_riesgo
from scanner.http_seguro import USER_AGENT, solicitar
from scanner.seguridad import EntradaInvalida, ObjetivoNoPermitido, ServidorOcupado

from .utilidades import ClienteFalso, ServidorHTTPPrueba, cabeceras

URL = "https://ejemplo.com"


def _comprobacion(id_, categoria=Categoria.CABECERAS, gravedad=Gravedad.MEDIA, accion=None):
    """Crea una comprobación de prueba sin registrarla en el catálogo real."""

    class Prueba(Comprobacion, registrar=False):
        def ejecutar(self, ctx):
            return accion(self, ctx)

    Prueba.id, Prueba.categoria, Prueba.gravedad = id_, categoria, gravedad
    Prueba.titulo, Prueba.explicacion, Prueba.recomendacion = f"Título {id_}", "Explicación", "Recomendación"
    Prueba.referencia = "https://owasp.org/"
    return Prueba()


def _resultado(estado, gravedad):
    return Resultado("x", Categoria.CABECERAS, "t", gravedad, estado, "e", "x", "r", "https://owasp.org/")


class Reloj:
    """Reloj simulado: dormir() avanza el tiempo sin esperar de verdad."""

    def __init__(self):
        self.ahora = 1000.0
        self.esperas = []

    def __call__(self):
        return self.ahora

    def dormir(self, segundos):
        self.esperas.append(round(segundos, 3))
        self.ahora += segundos


class CatalogoTests(SimpleTestCase):
    def test_las_comprobaciones_se_registran_solas(self):
        ids = [c.id for c in catalogo()]
        self.assertIn("cabeceras.hsts", ids)
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(isinstance(c, Comprobacion) for c in catalogo()))

    def test_catalogo_ordenado_por_categoria(self):
        orden = list(Categoria)
        posiciones = [orden.index(c.categoria) for c in catalogo()]
        self.assertEqual(posiciones, sorted(posiciones))

    def test_registro_valida_los_atributos(self):
        with self.assertRaisesRegex(TypeError, "faltan"):

            class SinTitulo(Comprobacion):
                id = "prueba.sin_titulo"
                categoria = Categoria.CABECERAS
                gravedad = Gravedad.BAJA

        with self.assertRaisesRegex(TypeError, "gravedad"):

            class GravedadTexto(Comprobacion):
                id, titulo, explicacion, recomendacion, referencia = "prueba.g", "t", "e", "r", "https://x"
                categoria = Categoria.CABECERAS
                gravedad = "alta"

        with self.assertRaisesRegex(TypeError, "categoría"):

            class SinCategoria(Comprobacion):
                id, titulo, explicacion, recomendacion, referencia = "prueba.c", "t", "e", "r", "https://x"
                gravedad = Gravedad.BAJA

        self.assertNotIn("prueba.sin_titulo", CATALOGO)

    def test_identificador_duplicado(self):
        with self.assertRaisesRegex(ValueError, "duplicado"):

            class OtraHSTS(Comprobacion):
                id, titulo, explicacion, recomendacion, referencia = (
                    "cabeceras.hsts",
                    "t",
                    "e",
                    "r",
                    "https://x",
                )
                categoria = Categoria.CABECERAS
                gravedad = Gravedad.BAJA

    def test_resultados_y_evidencia_recortada(self):
        c = _comprobacion("prueba.r", accion=None)
        r = c.fallo("x" * 5000, gravedad=Gravedad.ALTA, recomendacion="Otra")
        self.assertEqual((r.estado, r.gravedad, r.recomendacion), (Estado.FALLO, Gravedad.ALTA, "Otra"))
        self.assertEqual(len(r.evidencia), MAX_EVIDENCIA)
        self.assertEqual(c.fallo("a").gravedad, Gravedad.MEDIA)
        self.assertEqual(c.ok("línea 1\nlínea   2").evidencia, "línea 1 línea 2")
        d = c.no_aplica("motivo").como_dict()
        self.assertEqual((d["estado"], d["categoria"], d["gravedad"]), ("no_aplica", "cabeceras", "media"))
        self.assertEqual(set(d), set(Resultado.__dataclass_fields__))

    def test_etiquetas(self):
        self.assertEqual(Gravedad.CRITICA.etiqueta, "Crítica")
        self.assertEqual(Estado.NO_APLICA.etiqueta, "No aplica")
        self.assertEqual(Categoria.DNS.nombre, "DNS y correo")
        self.assertLess(Gravedad.BAJA.peso, Gravedad.CRITICA.peso)

    def test_ejecutar_es_abstracto(self):
        class Base(Comprobacion, registrar=False):
            pass

        with self.assertRaises(NotImplementedError):
            Base().ejecutar(None)


class PuntuacionTests(SimpleTestCase):
    def test_sin_fallos_es_10(self):
        resultados = [_resultado(Estado.OK, Gravedad.CRITICA), _resultado(Estado.NO_APLICA, Gravedad.ALTA)]
        self.assertEqual(calcular_nota(resultados), 10)
        self.assertEqual(calcular_nota([]), 10)

    def test_penalizaciones_por_gravedad(self):
        fallos = [
            _resultado(Estado.FALLO, Gravedad.MEDIA),
            _resultado(Estado.FALLO, Gravedad.BAJA),
            _resultado(Estado.FALLO, Gravedad.INFO),
        ]
        self.assertEqual(calcular_nota(fallos), 8.5)

    def test_topes_por_fallo_alto_y_critico(self):
        self.assertEqual(calcular_nota([_resultado(Estado.FALLO, Gravedad.ALTA)]), 7)
        self.assertEqual(calcular_nota([_resultado(Estado.FALLO, Gravedad.CRITICA)]), 4)

    def test_nota_minima_1(self):
        self.assertEqual(calcular_nota([_resultado(Estado.FALLO, Gravedad.CRITICA)] * 5), 1)

    def test_nivel_de_riesgo(self):
        self.assertEqual(
            [nivel_riesgo(n) for n in (10, 8, 7.9, 5, 4.9, 1)], ["BAJO"] * 2 + ["MEDIO"] * 2 + ["ALTO"] * 2
        )


class ClienteAuditoriaTests(SimpleTestCase):
    def _cliente(self, **opciones):
        reloj = Reloj()
        transporte = mock.Mock(return_value=(200, cabeceras({"A": "b"}), URL + "/final", b"cuerpo"))
        cliente = ClienteAuditoria(transporte=transporte, reloj=reloj, dormir=reloj.dormir, **opciones)
        return cliente, transporte, reloj

    def test_solo_get_y_head(self):
        cliente, transporte, _ = self._cliente()
        for metodo in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS", "get"):
            with self.subTest(metodo=metodo), self.assertRaisesRegex(ValueError, "pasiva"):
                cliente.peticion(metodo, URL)
        transporte.assert_not_called()

    def test_solo_cabeceras_permitidas(self):
        cliente, transporte, _ = self._cliente()
        for extra in ({"Cookie": "a=1"}, {"Authorization": "Basic x"}, {"X-Forwarded-For": "1.1.1.1"}):
            with self.subTest(extra=extra), self.assertRaisesRegex(ValueError, "no permitidas"):
                cliente.get(URL, cabeceras=extra)
        transporte.assert_not_called()
        cliente.get(URL, cabeceras={"Range": "bytes=0-511"})
        self.assertEqual(transporte.call_args.kwargs["cabeceras"], {"Range": "bytes=0-511"})

    def test_limite_de_peticiones_por_segundo(self):
        cliente, _, reloj = self._cliente(peticiones_por_segundo=5)
        for _ in range(4):
            cliente.get(URL)
        self.assertEqual(reloj.esperas, [0.2, 0.2, 0.2])

    def test_maximo_de_peticiones(self):
        cliente, transporte, _ = self._cliente(max_peticiones=3)
        for _ in range(3):
            cliente.head(URL)
        with self.assertRaisesRegex(LimiteAuditoria, "máximo de 3"):
            cliente.head(URL)
        self.assertEqual((transporte.call_count, cliente.peticiones), (3, 3))

    def test_presupuesto_de_tiempo(self):
        cliente, transporte, reloj = self._cliente(presupuesto=10, timeout=5)
        cliente.get(URL)
        self.assertEqual(transporte.call_args.kwargs["timeout"], 5)
        reloj.ahora += 8  # quedan 2 s: el tiempo de espera se ajusta
        cliente.get(URL)
        self.assertAlmostEqual(transporte.call_args.kwargs["timeout"], 2, places=1)
        reloj.ahora += 5
        self.assertTrue(cliente.tiempo_agotado())
        with self.assertRaisesRegex(LimiteAuditoria, "tiempo"):
            cliente.get(URL)

    def test_parametros_y_respuesta(self):
        cliente, transporte, _ = self._cliente()
        r = cliente.get(URL, max_bytes=10**9, seguir_redirecciones=False)
        opciones = transporte.call_args.kwargs
        self.assertEqual(opciones["metodo"], "GET")
        self.assertEqual(opciones["max_bytes"], MAX_BYTES_RESPUESTA)
        self.assertFalse(opciones["seguir_redirecciones"])
        self.assertEqual((r.codigo, r.url, r.url_final, r.cuerpo), (200, URL, URL + "/final", b"cuerpo"))
        cliente.get(URL, max_bytes=-5)
        self.assertEqual(transporte.call_args.kwargs["max_bytes"], 0)

    def test_texto_respeta_el_charset(self):
        cliente, transporte, _ = self._cliente()
        for tipo, cuerpo, esperado in (
            ("text/html; charset=iso-8859-1", "canción".encode("latin-1"), "canción"),
            ("text/html", "canción".encode(), "canción"),
            ("text/html; charset=desconocido", b"abc", "abc"),
        ):
            transporte.return_value = (200, cabeceras({"Content-Type": tipo}), URL, cuerpo)
            self.assertEqual(cliente.get(URL).texto, esperado)


class ContextoTests(SimpleTestCase):
    def _ctx(self, datos):
        return Contexto("ejemplo.com", ClienteFalso({URL: datos}))

    def test_respuesta_principal_una_sola_vez(self):
        ctx = self._ctx({"cabeceras": {"Server": "nginx"}})
        self.assertEqual(ctx.cabecera("Server"), "nginx")
        self.assertEqual(ctx.cabecera("server"), "nginx")
        self.assertIsNone(ctx.cabecera("X-No-Existe"))
        self.assertEqual(ctx.cliente.pedidas, [("GET", URL)])
        self.assertEqual((ctx.host, ctx.puerto_tls, ctx.es_https), ("ejemplo.com", 443, True))

    def test_cabeceras_repetidas(self):
        ctx = self._ctx({"cabeceras": {"Set-Cookie": ["a=1", "b=2"], "Vary": ["Accept", "Cookie"]}})
        self.assertEqual(ctx.cabeceras("Set-Cookie"), ["a=1", "b=2"])
        self.assertEqual(ctx.cabecera("Vary"), "Accept, Cookie")

    def test_redireccion_a_http(self):
        self.assertFalse(self._ctx({"url_final": "http://ejemplo.com/"}).es_https)

    def test_csp_en_meta_solo_en_html(self):
        html = (
            b"<html><head><meta http-equiv='Content-Security-Policy' content=\"default-src 'self'\"></head>"
        )
        ctx = self._ctx({"cabeceras": {"Content-Type": "text/html; charset=utf-8"}, "cuerpo": html})
        self.assertEqual(ctx.csp_meta, "default-src 'self'")
        ctx = self._ctx({"cabeceras": {"Content-Type": "application/json"}, "cuerpo": html})
        self.assertEqual((ctx.html, ctx.csp_meta), ("", None))
        ctx = self._ctx({"cabeceras": {"Content-Type": "text/html"}, "cuerpo": b"<meta http-equiv=refresh>"})
        self.assertIsNone(ctx.csp_meta)


class MotorTests(SimpleTestCase):
    def setUp(self):
        resolver = mock.patch.object(motor, "resolver_ip_publica", return_value="93.184.216.34")
        resolver.start()
        self.addCleanup(resolver.stop)

    def _auditar(self, comprobaciones, cliente=None):
        cliente = cliente or ClienteFalso({URL: {"cabeceras": {"Server": "nginx"}}})
        return motor.auditar("ejemplo.com", cliente=cliente, comprobaciones=comprobaciones)

    def test_resultado_completo(self):
        comprobaciones = [
            _comprobacion("p.ok", accion=lambda s, ctx: s.ok(ctx.cabecera("Server"))),
            _comprobacion("p.fallo_baja", gravedad=Gravedad.BAJA, accion=lambda s, ctx: s.fallo("mal")),
            _comprobacion("p.na", accion=lambda s, ctx: s.no_aplica("no")),
            _comprobacion(
                "p.alta",
                categoria=Categoria.TLS,
                gravedad=Gravedad.ALTA,
                accion=lambda s, ctx: s.fallo("mal"),
            ),
        ]
        r = self._auditar(comprobaciones)
        self.assertEqual((r["url"], r["url_final"], r["codigo_estado"]), (URL, URL, 200))
        # 10 − 0,5 (baja) − 2 (alta) = 7,5, limitado a 7 por el fallo alto.
        self.assertEqual((r["nota"], r["resumen"]["nivel_riesgo"]), (7, "MEDIO"))
        self.assertEqual(
            {k: r["resumen"][k] for k in ("total", "ok", "fallos", "no_aplica")},
            {"total": 4, "ok": 1, "fallos": 2, "no_aplica": 1},
        )
        self.assertEqual(
            r["resumen"]["fallos_por_gravedad"], {"critica": 0, "alta": 1, "media": 0, "baja": 1, "info": 0}
        )
        self.assertEqual([c["id"] for c in r["categorias"]], ["cabeceras", "tls"])
        cabeceras_ = r["categorias"][0]
        self.assertEqual((cabeceras_["nombre"], cabeceras_["fallos"]), ("Cabeceras HTTP", 1))
        # Primero los fallos, después los correctos y al final los que no aplican.
        self.assertEqual([x["id"] for x in cabeceras_["resultados"]], ["p.fallo_baja", "p.ok", "p.na"])
        self.assertEqual(cabeceras_["resultados"][1]["evidencia"], "nginx")
        self.assertEqual(r["peticiones"], 1)

    def test_fallos_ordenados_por_gravedad(self):
        comprobaciones = [
            _comprobacion(f"p.{g}", gravedad=g, accion=lambda s, ctx: s.fallo("x"))
            for g in (Gravedad.BAJA, Gravedad.CRITICA, Gravedad.MEDIA)
        ]
        ids = [x["id"] for x in self._auditar(comprobaciones)["categorias"][0]["resultados"]]
        self.assertEqual(ids, ["p.critica", "p.media", "p.baja"])

    def test_un_error_no_detiene_la_auditoria(self):
        def explota(s, ctx):
            raise RuntimeError("detalle interno")

        def red(s, ctx):
            raise TimeoutError("timed out")

        def ssrf(s, ctx):
            raise ObjetivoNoPermitido("Objetivo no permitido: 10.0.0.1")

        def limite(s, ctx):
            raise LimiteAuditoria("se alcanzó el máximo de 60 peticiones")

        comprobaciones = [
            _comprobacion("p.explota", accion=explota),
            _comprobacion("p.red", accion=red),
            _comprobacion("p.ssrf", accion=ssrf),
            _comprobacion("p.limite", accion=limite),
            _comprobacion("p.nada", accion=lambda s, ctx: None),
            _comprobacion("p.ok", accion=lambda s, ctx: s.ok("bien")),
        ]
        with self.assertLogs("scanner.auditoria.motor", level="WARNING") as logs:
            r = self._auditar(comprobaciones)
        evidencias = {x["id"]: (x["estado"], x["evidencia"]) for x in r["categorias"][0]["resultados"]}
        self.assertEqual(evidencias["p.ok"], ("ok", "bien"))
        self.assertEqual(
            evidencias["p.explota"], ("no_aplica", "No se pudo comprobar: error interno de SecureScan")
        )
        self.assertIn("tardó demasiado", evidencias["p.red"][1])
        self.assertIn("10.0.0.1", evidencias["p.ssrf"][1])
        self.assertIn("60 peticiones", evidencias["p.limite"][1])
        self.assertEqual(evidencias["p.nada"][0], "no_aplica")
        self.assertNotIn("detalle interno", str(r))  # el detalle solo va al log
        self.assertTrue(any("detalle interno" in linea for linea in logs.output))
        self.assertEqual(r["nota"], 10)  # lo que no se pudo comprobar no resta

    def test_tiempo_agotado(self):
        cliente = ClienteFalso({URL: {}})
        llamada = mock.Mock()
        comprobacion = _comprobacion("p.tarde", accion=llamada)
        cliente.agotado = True
        r = self._auditar([comprobacion], cliente=cliente)
        llamada.assert_not_called()
        self.assertIn("agotó el tiempo", r["categorias"][0]["resultados"][0]["evidencia"])

    def test_sitio_que_no_responde(self):
        cliente = ClienteFalso({URL: ConnectionRefusedError()})
        llamada = mock.Mock()
        r = self._auditar([_comprobacion("p.x", accion=llamada)], cliente=cliente)
        self.assertEqual(r, {"error": f"No se pudo conectar con {URL}: el servidor rechazó la conexión"})
        llamada.assert_not_called()

    def test_redireccion_a_red_interna(self):
        cliente = ClienteFalso({URL: ObjetivoNoPermitido("Objetivo no permitido")})
        with self.assertRaises(ObjetivoNoPermitido):
            self._auditar([], cliente=cliente)

    def test_valida_la_url_y_el_destino(self):
        with self.assertRaises(EntradaInvalida):
            motor.auditar("ftp://ejemplo.com")
        with (
            mock.patch.object(motor, "resolver_ip_publica", side_effect=ObjetivoNoPermitido("interna")),
            self.assertRaises(ObjetivoNoPermitido),
        ):
            motor.auditar("http://169.254.169.254/")

    def test_servidor_ocupado(self):
        with mock.patch.object(motor, "_auditorias_activas") as semaforo:
            semaforo.acquire.return_value = False
            with self.assertRaises(ServidorOcupado):
                self._auditar([])
            semaforo.release.assert_not_called()

    def test_usa_el_catalogo_completo_por_defecto(self):
        r = motor.auditar("ejemplo.com", cliente=ClienteFalso({URL: {}}))
        total = sum(len(c["resultados"]) for c in r["categorias"])
        self.assertEqual(total, len(CATALOGO))

    def test_describir_error(self):
        import socket
        import ssl
        import urllib.error

        casos = [
            (urllib.error.URLError(TimeoutError()), "tardó demasiado"),
            (ConnectionResetError(), "cortó la conexión"),
            (ssl.SSLError(1, "fallo"), "TLS"),
            (socket.gaierror(), "resolver"),
            (OSError("otra cosa"), "otra cosa"),
            (urllib.error.URLError("texto"), "texto"),
        ]
        for error, texto in casos:
            with self.subTest(error=error):
                self.assertIn(texto, motor.describir_error(error))


class SolicitarTests(SimpleTestCase):
    """http_seguro.solicitar contra un servidor local (127.0.0.1, sin Internet)."""

    def setUp(self):
        permitir = mock.patch.object(seguridad, "resolver_ip_publica", return_value="127.0.0.1")
        permitir.start()
        self.addCleanup(permitir.stop)

    def test_head_no_lee_cuerpo(self):
        with ServidorHTTPPrueba({"/": (200, {"X-A": "1"}, b"contenido")}) as srv:
            codigo, headers, _url, cuerpo = solicitar(
                f"http://127.0.0.1:{srv.puerto}/", metodo="HEAD", timeout=2
            )
        self.assertEqual((codigo, headers["X-A"], cuerpo), (200, "1", b""))
        self.assertEqual(srv.peticiones, [("HEAD", "/")])

    def test_lectura_limitada_y_user_agent(self):
        with ServidorHTTPPrueba({"/": (200, {}, b"0123456789" * 100)}) as srv:
            _c, _h, _u, cuerpo = solicitar(
                f"http://127.0.0.1:{srv.puerto}/", max_bytes=15, timeout=2, cabeceras={"User-Agent": "otro"}
            )
        self.assertEqual(cuerpo, b"012345678901234")
        # El User-Agent de SecureScan no se puede sustituir.
        self.assertEqual(srv.cabeceras_recibidas[0]["User-Agent"], USER_AGENT)

    def test_sin_seguir_redirecciones(self):
        respuestas = {"/": (301, {"Location": "/destino"}), "/destino": (200, {})}
        with ServidorHTTPPrueba(respuestas) as srv:
            codigo, headers, url, _ = solicitar(
                f"http://127.0.0.1:{srv.puerto}/", seguir_redirecciones=False, timeout=2
            )
        self.assertEqual((codigo, headers["Location"]), (301, "/destino"))
        self.assertEqual(srv.rutas, ["/"])
        self.assertTrue(url.endswith(f":{srv.puerto}/"))

    def test_error_devuelve_cuerpo_limitado(self):
        with ServidorHTTPPrueba({"/": (404, {}, b"no existe")}) as srv:
            codigo, _h, _u, cuerpo = solicitar(f"http://127.0.0.1:{srv.puerto}/", max_bytes=2, timeout=2)
        self.assertEqual((codigo, cuerpo), (404, b"no"))

    def test_metodo_no_permitido(self):
        with self.assertRaises(ValueError):
            solicitar("http://127.0.0.1/", metodo="POST")
