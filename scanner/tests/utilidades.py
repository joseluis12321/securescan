"""Utilidades compartidas por los tests. No hacen peticiones a Internet."""

import http.server
import socket
import threading


class ServidorHTTPPrueba:
    """Servidor HTTP mínimo en 127.0.0.1 que registra las rutas pedidas.

    respuestas: {ruta: (código, {header: valor})}. Las rutas no listadas devuelven 200.
    """

    def __init__(self, respuestas=None):
        rutas = self.rutas = []
        respuestas = respuestas or {}

        class Manejador(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                rutas.append(self.path)
                codigo, headers = respuestas.get(self.path, (200, {}))
                self.send_response(codigo)
                for k, v in headers.items():
                    for valor in v if isinstance(v, list) else [v]:
                        self.send_header(k, valor.format(puerto=self.server.server_port))
                self.end_headers()

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
        try:
            self.sock.shutdown(socket.SHUT_RDWR)  # despierta al hilo bloqueado en accept()
        except OSError:
            pass
        self.sock.close()
