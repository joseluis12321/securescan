"""Verificador de headers de seguridad HTTP, certificado TLS y redirección a HTTPS."""

import datetime
import http.client
import re
import socket
import ssl

from .http_seguro import normalizar_url, obtener
from .seguridad import EntradaInvalida, resolver_ip_publica

PESOS = {"ALTO": 3, "MEDIO": 2, "BAJO": 1}
HSTS_MIN_SEGUNDOS = 60 * 60 * 24 * 180  # 6 meses
MAX_HEADERS_GUARDADOS = 100
MAX_LONGITUD_VALOR = 2000
MAX_ADVERTENCIAS_COOKIES = 10


# ---------------------------------------------------------------------------
# Validación del valor de cada header (None = correcto; str = problema)
# ---------------------------------------------------------------------------


def _validar_hsts(valor: str) -> str | None:
    m = re.search(r'max-age\s*=\s*"?(\d+)', valor, re.IGNORECASE)
    if not m:
        return "No define max-age"
    if int(m.group(1)) < HSTS_MIN_SEGUNDOS:
        return f"max-age demasiado corto ({m.group(1)} s); se recomienda al menos 6 meses"
    return None


def _directivas_csp(valor: str) -> dict[str, str]:
    directivas = {}
    for parte in valor.lower().split(";"):
        tokens = parte.split()
        if tokens:
            directivas.setdefault(tokens[0], " ".join(tokens[1:]))
    return directivas


def _validar_csp(valor: str) -> str | None:
    directivas = _directivas_csp(valor)
    scripts = directivas.get("script-src", directivas.get("default-src"))
    if scripts is None:
        return "No restringe los scripts (falta script-src o default-src)"
    problemas = []
    usa_nonce_o_hash = "'nonce-" in scripts or "'sha256-" in scripts or "'sha384-" in scripts
    if "'unsafe-inline'" in scripts and not usa_nonce_o_hash:
        problemas.append("'unsafe-inline'")
    if "'unsafe-eval'" in scripts:
        problemas.append("'unsafe-eval'")
    if re.search(r"(?:^|\s)(?:\*|https?:|data:)(?:\s|$)", scripts):
        problemas.append("orígenes comodín (*, https:, data:)")
    if problemas:
        return "Permite scripts inseguros: " + ", ".join(problemas)
    return None


def _validar_xfo(valor: str) -> str | None:
    if valor.strip().upper() not in ("DENY", "SAMEORIGIN"):
        return "Valor no válido (ALLOW-FROM está obsoleto): usar DENY o SAMEORIGIN"
    return None


def _validar_xcto(valor: str) -> str | None:
    return None if valor.strip().lower() == "nosniff" else "El único valor válido es nosniff"


def _validar_referrer(valor: str) -> str | None:
    ultima = valor.split(",")[-1].strip().lower()
    if ultima in ("unsafe-url", "no-referrer-when-downgrade"):
        return f"'{ultima}' envía la URL completa a otros sitios"
    return None


def _validar_coop(valor: str) -> str | None:
    if valor.strip().lower() == "unsafe-none":
        return "'unsafe-none' desactiva el aislamiento"
    return None


HEADERS_SEGURIDAD = {
    "Strict-Transport-Security": {
        "descripcion": "Obliga a usar HTTPS y evita ataques de downgrade",
        "nivel": "ALTO",
        "recomendacion": "Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "validar": _validar_hsts,
    },
    "Content-Security-Policy": {
        "descripcion": "Mitiga XSS limitando de dónde se cargan scripts y recursos",
        "nivel": "ALTO",
        "recomendacion": "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'",
        "validar": _validar_csp,
    },
    "X-Frame-Options": {
        "descripcion": "Previene clickjacking impidiendo cargar la página en iframes",
        "nivel": "MEDIO",
        "recomendacion": "X-Frame-Options: DENY (o CSP frame-ancestors 'none')",
        "validar": _validar_xfo,
    },
    "X-Content-Type-Options": {
        "descripcion": "Evita que el navegador adivine el tipo MIME (MIME sniffing)",
        "nivel": "MEDIO",
        "recomendacion": "X-Content-Type-Options: nosniff",
        "validar": _validar_xcto,
    },
    "Referrer-Policy": {
        "descripcion": "Controla qué información se envía en el header Referer",
        "nivel": "BAJO",
        "recomendacion": "Referrer-Policy: strict-origin-when-cross-origin",
        "validar": _validar_referrer,
    },
    "Permissions-Policy": {
        "descripcion": "Restringe el acceso a APIs del navegador (cámara, micrófono...)",
        "nivel": "BAJO",
        "recomendacion": "Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "validar": None,
    },
    "Cross-Origin-Opener-Policy": {
        "descripcion": "Aísla la ventana de otros orígenes (mitiga ataques tipo XS-Leaks)",
        "nivel": "BAJO",
        "recomendacion": "Cross-Origin-Opener-Policy: same-origin",
        "validar": _validar_coop,
    },
}

HEADERS_QUE_REVELAN_TECNOLOGIA = ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator")


# ---------------------------------------------------------------------------
# Comprobaciones
# ---------------------------------------------------------------------------


def verificar_ssl(host: str, puerto: int = 443) -> dict:
    try:
        ip = resolver_ip_publica(host, puerto)
        ctx = ssl.create_default_context()
        with (
            socket.create_connection((ip, puerto), timeout=5) as sock,
            ctx.wrap_socket(sock, server_hostname=host) as conn,
        ):
            cert = conn.getpeercert()
            version_tls = conn.version()
            cifrado = conn.cipher()
        fecha_exp = datetime.datetime.fromtimestamp(
            ssl.cert_time_to_seconds(cert["notAfter"]), tz=datetime.UTC
        )
        dias_restantes = (fecha_exp - datetime.datetime.now(datetime.UTC)).days
        return {
            "valido": True,
            "expira": fecha_exp.strftime("%d/%m/%Y"),
            "dias_restantes": dias_restantes,
            "nivel": "ALTO" if dias_restantes < 15 else "MEDIO" if dias_restantes < 30 else "BAJO",
            "version_tls": version_tls,
            "cifrado": cifrado[0] if cifrado else None,
            "sujeto": dict(x[0] for x in cert.get("subject", [])),
            "emisor": dict(x[0] for x in cert.get("issuer", [])),
            "dominios": [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"][:10],
        }
    except ssl.SSLCertVerificationError as e:
        return {"valido": False, "error": f"Certificado no válido: {e.verify_message or e}"}
    except (OSError, KeyError, ValueError) as e:  # incluye SSLError y EntradaInvalida
        return {"valido": False, "error": str(e) or e.__class__.__name__}


def comprobar_redireccion_https(host: str) -> bool | None:
    """True si http:// redirige a https://, False si no, None si el puerto 80 no responde."""
    destino = f"[{host}]" if ":" in host else host
    try:
        _codigo, _headers, url_final = obtener(f"http://{destino}/", timeout=5)
    except EntradaInvalida:
        raise
    except (OSError, http.client.HTTPException, ValueError):
        return None
    return url_final.startswith("https://")


def _advertencias(headers, es_https: bool) -> list[dict]:
    advertencias = []

    servidor = headers.get("Server")
    if servidor and re.search(r"\d", servidor):
        advertencias.append(
            {
                "tipo": "Fuga de información",
                "header": "Server",
                "valor": servidor,
                "detalle": "Revela la versión del software del servidor",
                "recomendacion": (
                    "Ocultar la versión (ServerTokens Prod en Apache, server_tokens off en Nginx)"
                ),
            }
        )
    for nombre in HEADERS_QUE_REVELAN_TECNOLOGIA:
        valor = headers.get(nombre)
        if valor:
            advertencias.append(
                {
                    "tipo": "Fuga de información",
                    "header": nombre,
                    "valor": valor,
                    "detalle": "Revela la tecnología usada por el servidor",
                    "recomendacion": f"Eliminar el header {nombre}",
                }
            )

    xxss = headers.get("X-XSS-Protection")
    if xxss and xxss.strip() != "0":
        advertencias.append(
            {
                "tipo": "Header obsoleto",
                "header": "X-XSS-Protection",
                "valor": xxss,
                "detalle": "El filtro XSS de los navegadores está retirado y puede introducir fallos",
                "recomendacion": "Usar X-XSS-Protection: 0 (o eliminarlo) y confiar en una CSP",
            }
        )

    cookies = headers.get_all("Set-Cookie") or []
    for cookie in cookies[:MAX_ADVERTENCIAS_COOKIES]:
        nombre = cookie.split("=", 1)[0].strip()
        atributos = {a.strip().split("=")[0].lower() for a in cookie.split(";")[1:]}
        faltan = [
            attr
            for attr, aplica in (("Secure", es_https), ("HttpOnly", True), ("SameSite", True))
            if aplica and attr.lower() not in atributos
        ]
        if faltan:
            advertencias.append(
                {
                    "tipo": "Cookie sin protección",
                    "header": "Set-Cookie",
                    "valor": nombre,
                    "detalle": "Le falta: " + ", ".join(faltan),
                    "recomendacion": "Añadir " + "; ".join(faltan) + " a la cookie",
                }
            )
    return advertencias


def _evaluar_headers(headers) -> tuple[list[dict], list[dict]]:
    presentes, faltantes = [], []
    csp = headers.get("Content-Security-Policy", "")
    for nombre, info in HEADERS_SEGURIDAD.items():
        valor = headers.get(nombre)
        if valor is None and nombre == "X-Frame-Options" and "frame-ancestors" in _directivas_csp(csp):
            valor = "(cubierto por CSP frame-ancestors)"
            advertencia = None
        elif valor is None:
            faltantes.append(
                {
                    "header": nombre,
                    "descripcion": info["descripcion"],
                    "nivel": info["nivel"],
                    "recomendacion": "Agregar: " + info["recomendacion"],
                }
            )
            continue
        else:
            advertencia = info["validar"](valor) if info["validar"] else None
        presentes.append(
            {
                "header": nombre,
                "valor": valor[:MAX_LONGITUD_VALOR],
                "descripcion": info["descripcion"],
                "nivel": info["nivel"],
                "advertencia": advertencia,
                "recomendacion": ("Recomendado: " + info["recomendacion"]) if advertencia else None,
            }
        )
    return presentes, faltantes


def verificar_headers(url: str) -> dict:
    """Analiza los headers de seguridad, el certificado TLS y la redirección HTTPS.

    Lanza EntradaInvalida/ObjetivoNoPermitido si la URL no es válida o apunta
    (directamente o mediante redirecciones) a una red interna. Si el sitio no
    responde devuelve {"error": ...}.
    """
    url, host, puerto_tls = normalizar_url(url)
    resolver_ip_publica(host)  # error claro antes de conectar

    try:
        codigo, headers, url_final = obtener(url)
    except EntradaInvalida:
        raise
    except (OSError, http.client.HTTPException, ValueError) as e:
        return {"error": f"No se pudo conectar con {url}: {e}"}

    es_https = url_final.startswith("https://")
    presentes, faltantes = _evaluar_headers(headers)
    advertencias = _advertencias(headers, es_https)
    ssl_info = verificar_ssl(host, puerto_tls)
    redireccion = comprobar_redireccion_https(host)

    peso_total = sum(PESOS[h["nivel"]] for h in HEADERS_SEGURIDAD.values())
    obtenido = sum(PESOS[h["nivel"]] * (0.5 if h["advertencia"] else 1) for h in presentes)
    puntuacion = round(100 * obtenido / peso_total)

    problemas_graves = (
        sum(1 for h in faltantes if h["nivel"] == "ALTO")
        + (not es_https)
        + (redireccion is False)
        + (not ssl_info.get("valido"))
    )
    if problemas_graves >= 2:
        nivel = "ALTO"
    elif problemas_graves == 1 or puntuacion < 60:
        nivel = "MEDIO"
    else:
        nivel = "BAJO"

    todos = {}
    for k, v in list(headers.items())[:MAX_HEADERS_GUARDADOS]:
        todos[k] = v[:MAX_LONGITUD_VALOR]

    return {
        "url": url,
        "url_final": url_final,
        "codigo_estado": codigo,
        "https": es_https,
        "redireccion_https": redireccion,
        "headers_presentes": presentes,
        "headers_faltantes": faltantes,
        "advertencias": advertencias,
        "todos_headers": todos,
        "ssl_info": ssl_info,
        "resumen": {
            "puntuacion": puntuacion,
            "presentes": len(presentes),
            "faltantes": len(faltantes),
            "debiles": sum(1 for h in presentes if h["advertencia"]),
            "advertencias": len(advertencias),
            "total": len(HEADERS_SEGURIDAD),
            "nivel_riesgo": nivel,
        },
    }
