"""Analizador de logs de servidor.

Formatos reconocidos: Apache/Nginx (common/combined), auth.log/SSH, syslog y
cualquier log con marcas de tiempo ISO-8601. Las líneas se procesan una a una,
así que se pueden analizar archivos grandes sin cargarlos enteros en memoria.
"""

import ipaddress
import re
from collections import Counter
from collections.abc import Iterable
from urllib.parse import unquote_plus

# Las líneas reales de log rara vez superan unos cientos de caracteres. Recortar
# evita que una línea gigante dispare un ReDoS en las expresiones regulares.
MAX_LONGITUD_LINEA = 8192
MAX_DETALLES = 5  # ejemplos guardados por cada tipo de amenaza
MAX_IPS_REPORTADAS = 50

UMBRAL_FUERZA_BRUTA = 5  # logins fallidos desde una misma IP
UMBRAL_LOGIN_SOSPECHOSO = 3
UMBRAL_404 = 10  # 404 totales para considerarlo escaneo de rutas
UMBRAL_404_ALTO = 50
UMBRAL_EVENTOS_IP_ALTO = 5  # peticiones maliciosas desde una misma IP
# Una IP sin ataques solo se marca por volumen si supera ambos umbrales.
UMBRAL_VOLUMEN_IP = 20
UMBRAL_VOLUMEN_PROPORCION = 0.10

ORDEN_NIVEL = {"ALTO": 0, "MEDIO": 1, "BAJO": 2}

HERRAMIENTAS = [
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "dirbuster",
    "gobuster",
    "dirb",
    "dirsearch",
    "feroxbuster",
    "hydra",
    "metasploit",
    "burpsuite",
    "acunetix",
    "nessus",
    "openvas",
    "zgrab",
    "nuclei",
    "wfuzz",
    "ffuf",
    "wpscan",
    "whatweb",
    "arachni",
    "w3af",
    "commix",
    "xsstrike",
    "zmeu",
    "jaeles",
    "netsparker",
    "qualys",
]


def _compilar(patrones):
    return re.compile("|".join(f"(?:{p})" for p in patrones), re.IGNORECASE)


# (clave, descripción, nivel, prefiltro, patrón). Se aplican sobre la línea
# decodificada y en minúsculas. El prefiltro son subcadenas baratas de buscar:
# la regex solo se ejecuta si aparece alguna (acelera mucho los logs grandes).
CATEGORIAS = [
    (
        "sqli",
        "Posible SQL Injection detectado",
        "ALTO",
        (
            "select",
            "insert",
            "drop",
            "truncate",
            "sleep",
            "benchmark",
            "waitfor",
            "information_schema",
            "'",
            " or ",
            " and ",
        ),
        _compilar(
            [
                r"\bunion\b.{0,100}?\bselect\b",
                r"\bselect\b.{0,100}?\bfrom\b",
                r"\binsert\b.{0,60}?\binto\b",
                r"\b(?:drop|truncate)\s+table\b",
                r"'\s*(?:or|and)\s+'?\w+'?\s*=\s*'?\w+",
                r"\b(?:or|and)\s+\d+\s*=\s*\d+",
                r"\b(?:sleep|benchmark|pg_sleep)\s*\(",
                r"\bwaitfor\s+delay\b",
                r"information_schema",
                r"'\s*(?:--|#|/\*)",
            ]
        ),
    ),
    (
        "xss",
        "Posible ataque XSS detectado",
        "ALTO",
        (
            "<",
            "javascript",
            "alert",
            "prompt",
            "confirm",
            "document.",
            "onerror",
            "onload",
            "onmouseover",
            "onfocus",
            "onclick",
            "ontoggle",
            "onbegin",
        ),
        _compilar(
            [
                r"<\s*/?\s*script",
                r"javascript\s*:",
                r"\bon(?:error|load|mouseover|focus|click|toggle|begin)\s*=",
                r"\b(?:alert|prompt|confirm)\s*\(",
                r"document\.(?:cookie|domain|write)",
                r"<\s*(?:iframe|svg|img|object|embed)\b",
            ]
        ),
    ),
    (
        "traversal",
        "Intento de Path Traversal",
        "ALTO",
        ("..", "/etc/", ".ini", "/proc/"),
        _compilar(
            [
                r"\.\.[/\\]",
                r"/etc/(?:passwd|shadow|hosts)\b",
                r"\b(?:win|boot)\.ini\b",
                r"/proc/self/",
            ]
        ),
    ),
    (
        "rce",
        "Posible inyección de comandos (RCE)",
        "ALTO",
        (";", "|", "`", "$(", "/bin/", "cmd.exe", "powershell"),
        _compilar(
            [
                r"[;|`]\s*(?:cat|wget|curl|bash|sh|nc|ncat|python\d?|perl|id|whoami|uname)\b",
                r"\$\(\s*\w+",
                r"/bin/(?:ba)?sh\b",
                r"\b(?:cmd\.exe|powershell)\b",
            ]
        ),
    ),
    (
        "log4shell",
        "Intento de explotación Log4Shell (JNDI)",
        "ALTO",
        ("${",),
        _compilar(
            [
                r"\$\{\s*(?:jndi|\$\{|lower:|upper:|env:|::-)",
            ]
        ),
    ),
    (
        "sensibles",
        "Búsqueda de archivos sensibles",
        "MEDIO",
        (
            "/.",
            "wp-",
            "web.config",
            "phpinfo",
            "server-status",
            "phpmyadmin",
            "pma",
            "adminer",
            ".bak",
            ".old",
            ".sql",
            ".swp",
        ),
        _compilar(
            [
                r"/\.(?:env|git|svn|hg|htaccess|htpasswd|ds_store|aws|ssh)\b",
                r"/(?:wp-config\.php|web\.config|phpinfo\.php|server-status|wp-login\.php)",
                r"/(?:phpmyadmin|pma|adminer)\b",
                r"\.(?:bak|old|sql|swp)(?=[?\s\"]|$)",
            ]
        ),
    ),
]

RE_HERRAMIENTA = re.compile(r"\b(" + "|".join(map(re.escape, HERRAMIENTAS)) + r")\b", re.I)
PREFILTRO_LOGIN = ("fail", "invalid user", "incorrect", "maximum auth")
RE_LOGIN_FALLIDO = re.compile(
    r"failed password|authentication failure|invalid user|failed login|login incorrect"
    r"|failed publickey|maximum authentication attempts",
    re.IGNORECASE,
)
RE_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
RE_ESTADO_HTTP = re.compile(r'"\s(\d{3})\s')
RE_HORAS = [
    re.compile(r"\d{2}/\w+/\d{4}:(\d{2}):\d{2}:\d{2}"),  # Apache/Nginx
    re.compile(r"\d{4}-\d{2}-\d{2}[T ](\d{2}):\d{2}:\d{2}"),  # ISO-8601
    re.compile(r"^\w{3}\s+\d{1,2}\s(\d{2}):\d{2}:\d{2}"),  # syslog
]


def _ip_cliente(linea: str) -> str | None:
    """Primera IPv4 válida de la línea (cliente en access.log, origen en auth.log)."""
    for m in RE_IPV4.finditer(linea):
        candidata = m.group()
        if all(int(octeto) <= 255 for octeto in candidata.split(".")):
            return str(ipaddress.IPv4Address(candidata))  # normaliza ceros a la izquierda
    return None


def _user_agent(linea: str) -> str:
    """Último campo entre comillas (User-Agent en formato combined) o la línea entera."""
    if linea.endswith('"'):
        partes = linea.rsplit('"', 2)
        if len(partes) == 3:
            return partes[1]
    return linea


def _hora(linea: str) -> str | None:
    for patron in RE_HORAS:
        m = patron.search(linea)
        if m and int(m.group(1)) < 24:
            return m.group(1)
    return None


def _decodificar(linea: str) -> str:
    """Deshace la codificación URL (dos veces, para cubrir %252e y similares)."""
    return unquote_plus(unquote_plus(linea))


class _Hallazgo:
    """Cuenta todas las ocurrencias pero guarda solo unos pocos ejemplos."""

    __slots__ = ("cantidad", "detalle")

    def __init__(self):
        self.cantidad = 0
        self.detalle = []

    def agregar(self, numero, linea, **extra):
        self.cantidad += 1
        if len(self.detalle) < MAX_DETALLES:
            self.detalle.append({"linea": numero, "contenido": linea, **extra})


def analizar_logs(contenido: str | Iterable[str]) -> dict:
    """Analiza un log. `contenido` puede ser un str o un iterable de líneas."""
    lineas = contenido.splitlines() if isinstance(contenido, str) else contenido

    total_lineas = 0
    apariciones_ip = Counter()
    eventos_ip = Counter()  # peticiones maliciosas por IP
    fallos_login_ip = Counter()
    actividad_horas = Counter()
    hallazgos = {categoria[0]: _Hallazgo() for categoria in CATEGORIAS}
    herramientas = _Hallazgo()
    logins = _Hallazgo()
    errores_404 = _Hallazgo()
    errores_5xx = _Hallazgo()

    for numero, bruta in enumerate(lineas, 1):
        total_lineas = numero
        linea = bruta[:MAX_LONGITUD_LINEA].strip()
        if not linea:
            continue

        ip = _ip_cliente(linea)
        if ip:
            apariciones_ip[ip] += 1

        hora = _hora(linea)
        if hora:
            actividad_horas[hora] += 1

        maliciosa = False
        bajo = _decodificar(linea).lower()
        for clave, _desc, _nivel, prefiltro, patron in CATEGORIAS:
            if any(k in bajo for k in prefiltro) and patron.search(bajo):
                hallazgos[clave].agregar(numero, linea)
                maliciosa = True

        m = RE_HERRAMIENTA.search(_user_agent(linea))
        if m:
            herramientas.agregar(numero, linea, herramienta=m.group(1).lower())
            maliciosa = True

        bajo_original = linea.lower()
        if any(k in bajo_original for k in PREFILTRO_LOGIN) and RE_LOGIN_FALLIDO.search(linea):
            logins.agregar(numero, linea)
            if ip:
                fallos_login_ip[ip] += 1

        m = RE_ESTADO_HTTP.search(linea)
        if m:
            estado = int(m.group(1))
            if estado == 404:
                errores_404.agregar(numero, linea)
            elif 500 <= estado <= 599:
                errores_5xx.agregar(numero, linea)

        if maliciosa and ip:
            eventos_ip[ip] += 1

    amenazas = []

    def agregar_amenaza(tipo, hallazgo, nivel):
        if hallazgo.cantidad:
            amenazas.append(
                {
                    "tipo": tipo,
                    "cantidad": hallazgo.cantidad,
                    "detalle": hallazgo.detalle,
                    "nivel": nivel,
                }
            )

    atacantes = sorted(
        ((ip, n) for ip, n in fallos_login_ip.items() if n >= UMBRAL_FUERZA_BRUTA),
        key=lambda x: -x[1],
    )
    nivel_login = "ALTO" if atacantes or logins.cantidad > 10 else "MEDIO"
    agregar_amenaza("Intentos de login fallidos", logins, nivel_login)
    if atacantes:
        amenazas.append(
            {
                "tipo": "Ataque de fuerza bruta (por IP)",
                "cantidad": len(atacantes),
                "detalle": [
                    {"linea": None, "contenido": f"{ip} — {n} intentos fallidos"}
                    for ip, n in atacantes[:MAX_DETALLES]
                ],
                "nivel": "ALTO",
            }
        )

    for clave, desc, nivel, _prefiltro, _patron in CATEGORIAS:
        agregar_amenaza(desc, hallazgos[clave], nivel)
    agregar_amenaza("Herramienta de hacking detectada en User-Agent", herramientas, "ALTO")
    if errores_404.cantidad >= UMBRAL_404:
        nivel_404 = "ALTO" if errores_404.cantidad >= UMBRAL_404_ALTO else "MEDIO"
        agregar_amenaza("Errores 404 excesivos (posible escaneo de rutas)", errores_404, nivel_404)
    agregar_amenaza("Errores internos del servidor (5xx)", errores_5xx, "BAJO")

    amenazas.sort(key=lambda a: (ORDEN_NIVEL[a["nivel"]], -a["cantidad"]))

    ips_sospechosas = _ips_sospechosas(apariciones_ip, eventos_ip, fallos_login_ip, total_lineas)

    resultados = {
        "total_lineas": total_lineas,
        "amenazas": amenazas,
        "ips_sospechosas": ips_sospechosas[:MAX_IPS_REPORTADAS],
        "actividad_por_hora": dict(sorted(actividad_horas.items())),
    }
    resultados["resumen"] = {
        "total_lineas": total_lineas,
        "total_amenazas": len(amenazas),
        "ips_sospechosas": len(ips_sospechosas),
        "nivel_riesgo": calcular_nivel_riesgo(amenazas, ips_sospechosas),
    }
    return resultados


def _ips_sospechosas(apariciones, eventos, fallos, total_lineas):
    sospechosas = []
    for ip, n in apariciones.items():
        ev, fl = eventos[ip], fallos[ip]
        por_volumen = n >= UMBRAL_VOLUMEN_IP and n >= total_lineas * UMBRAL_VOLUMEN_PROPORCION
        if ev >= UMBRAL_EVENTOS_IP_ALTO or fl >= UMBRAL_FUERZA_BRUTA:
            nivel = "ALTO"
        elif ev or fl >= UMBRAL_LOGIN_SOSPECHOSO or por_volumen:
            nivel = "MEDIO"
        else:
            continue
        sospechosas.append(
            {
                "ip": ip,
                "apariciones": n,
                "eventos_maliciosos": ev,
                "fallos_login": fl,
                "nivel": nivel,
            }
        )
    sospechosas.sort(
        key=lambda x: (
            ORDEN_NIVEL[x["nivel"]],
            -(x["eventos_maliciosos"] + x["fallos_login"]),
            -x["apariciones"],
        )
    )
    return sospechosas


def calcular_nivel_riesgo(amenazas, ips_sospechosas):
    if any(a["nivel"] == "ALTO" for a in amenazas) or any(ip["nivel"] == "ALTO" for ip in ips_sospechosas):
        return "ALTO"
    if amenazas or ips_sospechosas:
        return "MEDIO"
    return "BAJO"
