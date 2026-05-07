import urllib.request
import ssl
import socket
import datetime

HEADERS_SEGURIDAD = {
    "Strict-Transport-Security": {
        "descripcion": "Fuerza conexiones HTTPS y previene downgrade attacks",
        "nivel": "ALTO",
        "recomendacion": "Agregar: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    },
    "Content-Security-Policy": {
        "descripcion": "Previene ataques XSS definiendo fuentes de contenido permitidas",
        "nivel": "ALTO",
        "recomendacion": "Agregar: Content-Security-Policy: default-src self"
    },
    "X-Frame-Options": {
        "descripcion": "Previene ataques de clickjacking bloqueando iframes",
        "nivel": "MEDIO",
        "recomendacion": "Agregar: X-Frame-Options: DENY o SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "descripcion": "Previene MIME type sniffing en el navegador",
        "nivel": "MEDIO",
        "recomendacion": "Agregar: X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "descripcion": "Controla que informacion se envia como referrer",
        "nivel": "BAJO",
        "recomendacion": "Agregar: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "descripcion": "Controla el acceso a APIs del navegador como camara y microfono",
        "nivel": "BAJO",
        "recomendacion": "Agregar: Permissions-Policy: camera=(), microphone=(), geolocation=()"
    },
    "X-XSS-Protection": {
        "descripcion": "Activa el filtro XSS integrado del navegador",
        "nivel": "MEDIO",
        "recomendacion": "Agregar: X-XSS-Protection: 1; mode=block"
    },
    "Cache-Control": {
        "descripcion": "Controla el cacheo de informacion sensible",
        "nivel": "BAJO",
        "recomendacion": "Agregar: Cache-Control: no-store para paginas con datos sensibles"
    }
}

def verificar_ssl(host):
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=host)
        conn.settimeout(5)
        conn.connect((host, 443))
        cert = conn.getpeercert()
        conn.close()
        fecha_str = cert["notAfter"]
        fecha_exp = datetime.datetime.strptime(fecha_str, "%b %d %H:%M:%S %Y %Z")
        dias_restantes = (fecha_exp - datetime.datetime.utcnow()).days
        return {
            "valido": True,
            "expira": fecha_exp.strftime("%d/%m/%Y"),
            "dias_restantes": dias_restantes,
            "nivel": "ALTO" if dias_restantes < 15 else "MEDIO" if dias_restantes < 30 else "BAJO",
            "sujeto": dict(x[0] for x in cert.get("subject", [])),
            "emisor": dict(x[0] for x in cert.get("issuer", []))
        }
    except Exception as e:
        return {"valido": False, "error": str(e)}

def verificar_headers(url):
    if not url.startswith("http"):
        url = "https://" + url

    resultado = {
        "url": url,
        "headers_presentes": [],
        "headers_faltantes": [],
        "todos_headers": {},
        "ssl_info": {},
        "resumen": {}
    }

    try:
        host = url.replace("https://", "").replace("http://", "").split("/")[0]
        resultado["ssl_info"] = verificar_ssl(host)
    except:
        resultado["ssl_info"] = {"valido": False, "error": "No se pudo verificar SSL"}

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "SecureScan/2.0"})
        response = urllib.request.urlopen(req, timeout=8, context=ctx)
        headers_reales = dict(response.headers)
        resultado["todos_headers"] = headers_reales
        resultado["codigo_estado"] = response.status

        redir_url = response.geturl()
        resultado["redireccion_https"] = redir_url.startswith("https://")
    except Exception as e:
        return {"error": str(e)}

    for header, info in HEADERS_SEGURIDAD.items():
        encontrado = any(h.lower() == header.lower() for h in headers_reales)
        if encontrado:
            valor = next(v for k, v in headers_reales.items() if k.lower() == header.lower())
            resultado["headers_presentes"].append({
                "header": header,
                "valor": valor,
                "descripcion": info["descripcion"],
                "nivel": info["nivel"]
            })
        else:
            resultado["headers_faltantes"].append({
                "header": header,
                "descripcion": info["descripcion"],
                "nivel": info["nivel"],
                "recomendacion": info["recomendacion"]
            })

    total = len(HEADERS_SEGURIDAD)
    presentes = len(resultado["headers_presentes"])
    puntuacion = int((presentes / total) * 100)
    faltantes_altos = sum(1 for h in resultado["headers_faltantes"] if h["nivel"] == "ALTO")

    resultado["resumen"] = {
        "puntuacion": puntuacion,
        "presentes": presentes,
        "faltantes": len(resultado["headers_faltantes"]),
        "total": total,
        "nivel_riesgo": "ALTO" if faltantes_altos >= 2 else "MEDIO" if faltantes_altos == 1 else "BAJO"
    }

    return resultado
