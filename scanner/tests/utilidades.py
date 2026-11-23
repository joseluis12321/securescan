"""Utilidades compartidas por los tests. No hacen peticiones a Internet."""

import contextlib
import http.client
import http.server
import io
import socket
import threading

from scanner.auditoria.cliente import Respuesta


class ServidorHTTPPrueba:
    """Servidor HTTP mínimo en 127.0.0.1 que registra las peticiones recibidas.

    respuestas: {ruta: (código, {header: valor})} o (código, {header: valor}, cuerpo).
    Las rutas no listadas devuelven 200. `rutas` guarda las rutas pedidas,
    `peticiones` los pares (método, ruta) y `cabeceras_recibidas` las cabeceras
    de cada petición.
    """

    def __init__(self, respuestas=None):
        rutas = self.rutas = []
        peticiones = self.peticiones = []
        recibidas = self.cabeceras_recibidas = []
        respuestas = respuestas or {}

        class Manejador(http.server.BaseHTTPRequestHandler):
            def _responder(self, con_cuerpo):
                rutas.append(self.path)
                peticiones.append((self.command, self.path))
                recibidas.append(dict(self.headers))
                codigo, headers, *resto = respuestas.get(self.path, (200, {}))
                cuerpo = resto[0] if resto else b""
                self.send_response(codigo)
                for k, v in headers.items():
                    for valor in v if isinstance(v, list) else [v]:
                        self.send_header(k, valor.format(puerto=self.server.server_port))
                if cuerpo:
                    self.send_header("Content-Length", str(len(cuerpo)))
                self.end_headers()
                if con_cuerpo and cuerpo:
                    self.wfile.write(cuerpo)

            def do_GET(self):
                self._responder(con_cuerpo=True)

            def do_HEAD(self):
                self._responder(con_cuerpo=False)

            def log_message(self, *args):
                pass

        self.servidor = http.server.HTTPServer(("127.0.0.1", 0), Manejador)
        self.puerto = self.servidor.server_port
        threading.Thread(target=self.servidor.serve_forever, daemon=True).start()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.servidor.shutdown()
        self.servidor.server_close()


class ServidorTCPPrueba:
    """Servidor TCP en 127.0.0.1 que envía `banner` al aceptar cada conexión."""

    def __init__(self, banner=b""):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen()
        self.puerto = self.sock.getsockname()[1]
        self._banner = banner
        self._activo = True
        threading.Thread(target=self._aceptar, daemon=True).start()

    def _aceptar(self):
        while self._activo:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                if self._banner:
                    conn.sendall(self._banner)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._activo = False
        with contextlib.suppress(OSError):
            self.sock.shutdown(socket.SHUT_RDWR)  # despierta al hilo bloqueado en accept()
        self.sock.close()


def cabeceras(valores=None) -> http.client.HTTPMessage:
    """HTTPMessage a partir de {nombre: valor | [valores]}, como las que devuelve http.client."""
    lineas = []
    for nombre, valor in (valores or {}).items():
        for v in valor if isinstance(valor, list) else [valor]:
            lineas.append(f"{nombre}: {v}")
    texto = "\r\n".join(lineas) + "\r\n\r\n"
    return http.client.parse_headers(io.BytesIO(texto.encode("latin-1")))


class ClienteFalso:
    """Sustituye a ClienteAuditoria en los tests: responde sin usar la red.

    respuestas: {url: dict(codigo=200, cabeceras={...}, cuerpo=b"", url_final=None)}
    o {url: excepción}. Las URLs no listadas devuelven 404. `pedidas` guarda los
    pares (método, url).
    """

    def __init__(self, respuestas=None):
        self.respuestas = respuestas or {}
        self.pedidas = []
        self.peticiones = 0
        self.agotado = False

    def tiempo_agotado(self):
        return self.agotado

    def get(self, url, **opciones):
        return self.peticion("GET", url, **opciones)

    def head(self, url, **opciones):
        return self.peticion("HEAD", url, **opciones)

    def peticion(self, metodo, url, **_opciones):
        self.pedidas.append((metodo, url))
        self.peticiones += 1
        datos = self.respuestas.get(url, {"codigo": 404})
        if isinstance(datos, Exception):
            raise datos
        return Respuesta(
            codigo=datos.get("codigo", 200),
            cabeceras=cabeceras(datos.get("cabeceras")),
            url=url,
            url_final=datos.get("url_final") or url,
            cuerpo=b"" if metodo == "HEAD" else datos.get("cuerpo", b""),
        )
