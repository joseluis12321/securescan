"""Cabeceras HTTP de seguridad y fugas de información en las cabeceras."""

import re

from ..base import Categoria, Comprobacion, Gravedad

GUIA_CABECERAS = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
HSTS_MIN_SEGUNDOS = 60 * 60 * 24 * 180  # 6 meses
CABECERAS_DE_TECNOLOGIA = ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator")


def directivas_csp(politica: str) -> dict[str, str]:
    """{directiva: valores} de una política CSP. Si una directiva se repite, vale la primera."""
    directivas = {}
    for parte in politica.lower().split(";"):
        tokens = parte.split()
        if tokens:
            directivas.setdefault(tokens[0], " ".join(tokens[1:]))
    return directivas


def problemas_csp(politica: str) -> list[str]:
    """Debilidades de la política respecto a los scripts (lista vacía si es sólida)."""
    directivas = directivas_csp(politica)
    scripts = directivas.get("script-src", directivas.get("default-src"))
    if scripts is None:
        return ["no restringe los scripts (falta script-src o default-src)"]
    problemas = []
    usa_nonce_o_hash = any(f"'{p}-" in scripts for p in ("nonce", "sha256", "sha384", "sha512"))
    if "'unsafe-inline'" in scripts and not usa_nonce_o_hash:
        problemas.append("permite scripts en línea ('unsafe-inline')")
    if "'unsafe-eval'" in scripts:
        problemas.append("permite eval ('unsafe-eval')")
    if re.search(r"(?:^|\s)(?:\*|https?:|data:)(?:\s|$)", scripts):
        problemas.append("permite scripts de cualquier origen (*, https: o data:)")
    return problemas


class ComprobacionDeCabeceras(Comprobacion, registrar=False):
    categoria = Categoria.CABECERAS


class HSTS(ComprobacionDeCabeceras):
    id = "cabeceras.hsts"
    titulo = "HSTS: obligar a usar siempre HTTPS"
    gravedad = Gravedad.MEDIA
    explicacion = (
        "HSTS le indica al navegador que este sitio solo debe visitarse de forma segura (HTTPS). "
        "Sin esta cabecera, alguien conectado a la misma red, por ejemplo una wifi pública, puede "
        "interceptar la primera visita, que se hace sin cifrar, y llevar al usuario a una copia falsa "
        "del sitio."
    )
    recomendacion = (
        "Añade en las respuestas HTTPS «Strict-Transport-Security: max-age=31536000; includeSubDomains». "
        'En Nginx: add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;'
    )
    referencia = (
        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"
    )

    def ejecutar(self, ctx):
        if not ctx.es_https:
            return self.no_aplica(
                f"La página se sirve sin HTTPS ({ctx.url_final}); HSTS solo funciona en HTTPS"
            )
        valor = ctx.cabecera("Strict-Transport-Security")
        if valor is None:
            return self.fallo("La respuesta HTTPS no incluye la cabecera Strict-Transport-Security")
        m = re.search(r'max-age\s*=\s*"?(\d+)', valor, re.IGNORECASE)
        if not m:
            return self.fallo(f"La cabecera no define max-age: Strict-Transport-Security: {valor}")
        segundos = int(m.group(1))
        if segundos == 0:
            return self.fallo(f"max-age=0 desactiva HSTS: Strict-Transport-Security: {valor}")
        if segundos < HSTS_MIN_SEGUNDOS:
            return self.fallo(
                f"max-age={segundos} s ({segundos // 86400} días) es demasiado corto; "
                "se recomiendan al menos 180 días (mejor 1 año)",
                gravedad=Gravedad.BAJA,
            )
        return self.ok(f"Strict-Transport-Security: {valor}")


class CSP(ComprobacionDeCabeceras):
    id = "cabeceras.csp"
    titulo = "Política de seguridad de contenido (CSP)"
    gravedad = Gravedad.MEDIA
    explicacion = (
        "La CSP le dice al navegador de dónde puede cargar scripts, estilos e imágenes. Es la mejor defensa "
        "contra el cross-site scripting (XSS): aunque un atacante consiga meter código en la página, "
        "el navegador se niega a ejecutarlo."
    )
    recomendacion = (
        "Define una política que solo permita tus propios recursos, por ejemplo "
        "«Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; "
        "frame-ancestors 'none'». Evita 'unsafe-inline' y 'unsafe-eval'; si necesitas scripts "
        "en línea, usa nonces o hashes."
    )
    referencia = "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"

    def ejecutar(self, ctx):
        politica = ctx.cabecera("Content-Security-Policy")
        origen = "Content-Security-Policy"
        if politica is None and ctx.csp_meta:
            politica, origen = ctx.csp_meta, "CSP en <meta http-equiv>"
        if politica is None:
            if ctx.cabecera("Content-Security-Policy-Report-Only"):
                return self.fallo(
                    "Solo hay Content-Security-Policy-Report-Only: la política se vigila pero no se aplica"
                )
            return self.fallo("La respuesta no incluye la cabecera Content-Security-Policy")
        problemas = problemas_csp(politica)
        if problemas:
            return self.fallo(
                f"La política {'; '.join(problemas)}. {origen}: {politica}", gravedad=Gravedad.BAJA
            )
        return self.ok(f"{origen}: {politica}")


class XFrameOptions(ComprobacionDeCabeceras):
    id = "cabeceras.x_frame_options"
    titulo = "Protección contra clickjacking (X-Frame-Options)"
    gravedad = Gravedad.MEDIA
    explicacion = (
        "Sin esta protección, otra web puede mostrar tu sitio dentro de un marco invisible y engañar al "
        "usuario para que pulse botones de tu página (por ejemplo, confirmar un pago o cambiar su "
        "contraseña) "
        "sin darse cuenta. Este engaño se llama clickjacking."
    )
    recomendacion = (
        "Añade «X-Frame-Options: DENY» (o SAMEORIGIN si tu propio sitio usa marcos) o, mejor aún, "
        "la directiva «frame-ancestors 'none'» en la Content-Security-Policy."
    )
    referencia = "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"

    def ejecutar(self, ctx):
        # frame-ancestors no tiene efecto en una CSP definida con <meta>: solo cuenta la cabecera.
        csp = directivas_csp(ctx.cabecera("Content-Security-Policy") or "")
        if "frame-ancestors" in csp:
            return self.ok(f"Protegido por la CSP: frame-ancestors {csp['frame-ancestors']}")
        valor = ctx.cabecera("X-Frame-Options")
        if valor is None:
            return self.fallo("No hay X-Frame-Options ni la directiva frame-ancestors en la CSP")
        if valor.strip().upper() not in ("DENY", "SAMEORIGIN"):
            return self.fallo(
                f"Valor no válido u obsoleto (ALLOW-FROM ya no funciona): X-Frame-Options: {valor}",
                gravedad=Gravedad.BAJA,
            )
        return self.ok(f"X-Frame-Options: {valor}")


class XContentTypeOptions(ComprobacionDeCabeceras):
    id = "cabeceras.x_content_type_options"
    titulo = "Evitar que el navegador adivine el tipo de archivo"
    gravedad = Gravedad.BAJA
    explicacion = (
        "Algunos navegadores intentan adivinar qué tipo de archivo reciben aunque el servidor diga otra "
        "cosa. "
        "Un atacante puede aprovecharlo para que un archivo subido, como una imagen, se ejecute como código. "
        "La cabecera X-Content-Type-Options: nosniff desactiva ese comportamiento."
    )
    recomendacion = "Añade «X-Content-Type-Options: nosniff» en todas las respuestas."
    referencia = f"{GUIA_CABECERAS}#x-content-type-options"

    def ejecutar(self, ctx):
        valor = ctx.cabecera("X-Content-Type-Options")
        if valor is None:
            return self.fallo("La respuesta no incluye la cabecera X-Content-Type-Options")
        if valor.strip().lower() != "nosniff":
            return self.fallo(f"El único valor válido es nosniff: X-Content-Type-Options: {valor}")
        return self.ok(f"X-Content-Type-Options: {valor}")


class ReferrerPolicy(ComprobacionDeCabeceras):
    id = "cabeceras.referrer_policy"
    titulo = "Control de la información enviada a otras webs (Referrer-Policy)"
    gravedad = Gravedad.BAJA
    explicacion = (
        "Cuando un usuario pulsa un enlace hacia otra web, el navegador le dice a esa web desde qué página "
        "venía. Si la dirección contiene datos privados (un identificador, un código de acceso, una "
        "búsqueda), "
        "esos datos acaban en manos de terceros. Referrer-Policy limita esa información."
    )
    recomendacion = (
        "Añade «Referrer-Policy: strict-origin-when-cross-origin» (o no-referrer si no necesitas esa "
        "información)."
    )
    referencia = f"{GUIA_CABECERAS}#referrer-policy"

    def ejecutar(self, ctx):
        valor = ctx.cabecera("Referrer-Policy")
        if valor is None:
            return self.fallo(
                "La respuesta no incluye Referrer-Policy (se usa el valor por defecto del navegador)"
            )
        # Con varios valores, el navegador aplica el último que entiende.
        ultima = valor.split(",")[-1].strip().lower()
        if ultima in ("unsafe-url", "no-referrer-when-downgrade"):
            return self.fallo(
                f"'{ultima}' envía la dirección completa a otras webs: Referrer-Policy: {valor}"
            )
        return self.ok(f"Referrer-Policy: {valor}")


class PermissionsPolicy(ComprobacionDeCabeceras):
    id = "cabeceras.permissions_policy"
    titulo = "Limitar el acceso a cámara, micrófono y ubicación (Permissions-Policy)"
    gravedad = Gravedad.BAJA
    explicacion = (
        "Permite decidir qué funciones del navegador puede usar la página: cámara, micrófono, ubicación, "
        "pagos… Si no se limitan, un script de terceros o código inyectado podría intentar usarlas."
    )
    recomendacion = (
        "Añade «Permissions-Policy: camera=(), microphone=(), geolocation=()» y desactiva cualquier otra "
        "función que tu sitio no necesite."
    )
    referencia = f"{GUIA_CABECERAS}#permissions-policy-formerly-feature-policy"

    def ejecutar(self, ctx):
        valor = ctx.cabecera("Permissions-Policy")
        if valor is not None:
            return self.ok(f"Permissions-Policy: {valor}")
        antigua = ctx.cabecera("Feature-Policy")
        if antigua is not None:
            return self.fallo(f"Solo se usa Feature-Policy, la versión antigua y obsoleta: {antigua}")
        return self.fallo("La respuesta no incluye la cabecera Permissions-Policy")


class COOP(ComprobacionDeCabeceras):
    id = "cabeceras.coop"
    titulo = "Aislamiento de la ventana (Cross-Origin-Opener-Policy)"
    gravedad = Gravedad.BAJA
    explicacion = (
        "Aísla la pestaña de tu sitio de las ventanas de otras webs que la abren o que ella abre. Así una "
        "página maliciosa no puede manipular tu sitio ni deducir información a través de la ventana "
        "(ataques llamados XS-Leaks)."
    )
    recomendacion = (
        "Añade «Cross-Origin-Opener-Policy: same-origin» (o same-origin-allow-popups si usas ventanas "
        "emergentes para iniciar sesión o pagar)."
    )
    referencia = f"{GUIA_CABECERAS}#cross-origin-opener-policy-coop"

    def ejecutar(self, ctx):
        valor = ctx.cabecera("Cross-Origin-Opener-Policy")
        if valor is None:
            return self.fallo("La respuesta no incluye la cabecera Cross-Origin-Opener-Policy")
        if valor.split(";")[0].strip().lower() == "unsafe-none":
            return self.fallo(f"'unsafe-none' desactiva el aislamiento: Cross-Origin-Opener-Policy: {valor}")
        return self.ok(f"Cross-Origin-Opener-Policy: {valor}")


class CORP(ComprobacionDeCabeceras):
    id = "cabeceras.corp"
    titulo = "Quién puede incrustar tus recursos (Cross-Origin-Resource-Policy)"
    gravedad = Gravedad.INFO
    explicacion = (
        "Indica si otras webs pueden cargar los recursos de tu sitio (imágenes, scripts, documentos). "
        "Ayuda a protegerse de ataques que leen datos de otras webs aprovechando fallos de los procesadores, "
        "como Spectre."
    )
    recomendacion = (
        "Añade «Cross-Origin-Resource-Policy: same-origin» (o same-site). Usa cross-origin solo en recursos "
        "pensados para ser públicos, como los de una CDN."
    )
    referencia = f"{GUIA_CABECERAS}#cross-origin-resource-policy-corp"

    def ejecutar(self, ctx):
        valor = ctx.cabecera("Cross-Origin-Resource-Policy")
        if valor is None:
            return self.fallo("La respuesta no incluye la cabecera Cross-Origin-Resource-Policy")
        if valor.strip().lower() not in ("same-origin", "same-site", "cross-origin"):
            return self.fallo(f"Valor no válido: Cross-Origin-Resource-Policy: {valor}")
        return self.ok(f"Cross-Origin-Resource-Policy: {valor}")


class VersionServidor(ComprobacionDeCabeceras):
    id = "cabeceras.version_servidor"
    titulo = "El servidor revela su versión (cabecera Server)"
    gravedad = Gravedad.BAJA
    explicacion = (
        "La cabecera Server indica qué programa usa el servidor web. Si además muestra la versión exacta, "
        "un atacante puede buscar directamente fallos conocidos de esa versión sin tener que probar nada."
    )
    recomendacion = (
        "Oculta la versión: «server_tokens off;» en Nginx, «ServerTokens Prod» y «ServerSignature Off» en "
        "Apache, o «removeServerHeader» en IIS."
    )
    referencia = (
        "https://owasp.org/www-project-web-security-testing-guide/stable/"
        "4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"
    )

    def ejecutar(self, ctx):
        valor = ctx.cabecera("Server")
        if valor is None:
            return self.ok("El servidor no envía la cabecera Server")
        if re.search(r"\d", valor):
            return self.fallo(f"Server: {valor}")
        return self.ok(f"Server: {valor} (sin versión)")


class TecnologiaExpuesta(ComprobacionDeCabeceras):
    id = "cabeceras.tecnologia_expuesta"
    titulo = "Cabeceras que revelan la tecnología del sitio (X-Powered-By…)"
    gravedad = Gravedad.BAJA
    explicacion = (
        "Cabeceras como X-Powered-By anuncian el lenguaje o la plataforma con la que está hecho el sitio "
        "(PHP, ASP.NET…) y a menudo su versión. No aportan nada a los visitantes y le ahorran trabajo a un "
        "atacante."
    )
    recomendacion = (
        "Elimina estas cabeceras: «expose_php = Off» en php.ini, «Header unset X-Powered-By» en Apache o "
        "«enableVersionHeader=false» en ASP.NET."
    )
    referencia = f"{GUIA_CABECERAS}#x-powered-by"

    def ejecutar(self, ctx):
        expuestas = [
            f"{n}: {ctx.cabecera(n)}" for n in CABECERAS_DE_TECNOLOGIA if ctx.cabecera(n) is not None
        ]
        if expuestas:
            return self.fallo(" · ".join(expuestas))
        return self.ok("No se envía ninguna de: " + ", ".join(CABECERAS_DE_TECNOLOGIA))


class XXSSProtection(ComprobacionDeCabeceras):
    id = "cabeceras.x_xss_protection"
    titulo = "Filtro XSS antiguo (X-XSS-Protection)"
    gravedad = Gravedad.INFO
    explicacion = (
        "Es una cabecera antigua que activaba un filtro contra XSS en navegadores viejos. Los navegadores "
        "actuales lo han retirado y en algunos el propio filtro podía usarse para provocar fallos. Hoy se "
        "recomienda desactivarlo y confiar en la CSP."
    )
    recomendacion = (
        "Usa «X-XSS-Protection: 0» o elimina la cabecera, y protege el sitio con una Content-Security-Policy."
    )
    referencia = f"{GUIA_CABECERAS}#x-xss-protection"

    def ejecutar(self, ctx):
        valor = ctx.cabecera("X-XSS-Protection")
        if valor is None:
            return self.ok("La cabecera no está presente")
        if valor.strip() != "0":
            return self.fallo(f"El filtro sigue activado: X-XSS-Protection: {valor}")
        return self.ok(f"X-XSS-Protection: {valor}")
