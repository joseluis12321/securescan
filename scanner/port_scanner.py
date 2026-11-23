"""Escáner de puertos TCP con identificación pasiva de servicios (banners)."""

import concurrent.futures
import socket
import string
import threading

from django.conf import settings

from .seguridad import ServidorOcupado, resolver_ip_publica, validar_puertos

TIMEOUT_CONEXION = 1.0
TIMEOUT_BANNER = 1.5
MAX_LONGITUD_BANNER = 120
MAX_HILOS = 100

PUERTOS_COMUNES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "Jupyter",
    9200: "Elasticsearch",
    27017: "MongoDB",
    11211: "Memcached",
}

PUERTOS_PELIGROSOS = {
    21: "FTP transmite credenciales en texto plano. Usar SFTP en su lugar.",
    23: "Telnet es inseguro, reemplazar con SSH.",
    445: "SMB expuesto puede ser vulnerable a EternalBlue/WannaCry.",
    1433: "Base de datos MSSQL expuesta publicamente es un riesgo critico.",
    1521: "Base de datos Oracle expuesta publicamente.",
    3306: "MySQL no deberia estar expuesto publicamente.",
    3389: "RDP es objetivo frecuente de ataques de fuerza bruta.",
    5900: "VNC sin cifrado expone el escritorio remoto.",
    6379: "Redis sin autenticacion permite acceso total a los datos.",
    8888: "Jupyter Notebook puede permitir ejecucion de codigo remoto.",
    9200: "Elasticsearch expuesto puede filtrar todos los datos.",
    27017: "MongoDB sin autenticacion permite acceso total.",
    11211: "Memcached puede ser usado para ataques DDoS de amplificacion.",
}

# Explicación de cada servicio para alguien no técnico: (qué es, riesgo, recomendación).
EXPLICACION_PUERTOS = {
    21: (
        "FTP: un servicio antiguo para subir y descargar archivos.",
        "Envía usuarios, contraseñas y archivos sin cifrar: cualquiera en el camino puede leerlos.",
        "Sustitúyelo por SFTP (incluido en SSH) o FTPS, y cierra el puerto 21 si no lo usas.",
    ),
    22: (
        "SSH: acceso remoto a la línea de comandos del servidor.",
        "Es seguro si está bien configurado, pero recibe intentos constantes de adivinar contraseñas.",
        "Usa claves en lugar de contraseñas, desactiva el acceso directo de root y limita el acceso por IP "
        "o con una herramienta como fail2ban.",
    ),
    23: (
        "Telnet: acceso remoto antiguo a la línea de comandos.",
        "Todo viaja sin cifrar, incluida la contraseña: es fácil de espiar y de atacar.",
        "Desactívalo y usa SSH en su lugar.",
    ),
    25: (
        "SMTP: el servicio que envía y recibe correo electrónico.",
        "Si está mal configurado puede usarse para enviar spam en tu nombre (relay abierto).",
        "Si el servidor no gestiona correo, ciérralo. Si lo gestiona, exige autenticación y cifrado "
        "(STARTTLS).",
    ),
    53: (
        "DNS: traduce nombres de dominio a direcciones IP.",
        "Un DNS abierto a cualquiera puede usarse para ataques de denegación de servicio por amplificación.",
        "Si no es un servidor DNS público, ciérralo o responde solo a tu red; desactiva la recursión "
        "abierta.",
    ),
    80: (
        "HTTP: la versión sin cifrar de una web.",
        "Lo que se envía por HTTP (formularios, sesiones) puede leerse o modificarse por el camino.",
        "Mantenlo solo para redirigir a HTTPS (puerto 443).",
    ),
    110: (
        "POP3: descarga de correo electrónico.",
        "Sin cifrado, las contraseñas y los correos viajan en texto plano.",
        "Usa POP3S (puerto 995) y cierra el 110, o desactívalo si no se usa.",
    ),
    143: (
        "IMAP: acceso al buzón de correo.",
        "Sin cifrado, las contraseñas y los correos viajan en texto plano.",
        "Usa IMAPS (puerto 993) y cierra el 143, o desactívalo si no se usa.",
    ),
    443: (
        "HTTPS: la versión cifrada de una web.",
        "Es el puerto normal de un sitio web; el riesgo depende de la aplicación y de su configuración TLS.",
        "Mantén el certificado al día y revisa la configuración con la auditoría web de SecureScan.",
    ),
    445: (
        "SMB: carpetas e impresoras compartidas de Windows.",
        "Ha tenido fallos muy graves (WannaCry se propagó por aquí) y nunca debería verse desde Internet.",
        "Ciérralo en el cortafuegos de Internet y usa una VPN para compartir archivos a distancia.",
    ),
    1433: (
        "Microsoft SQL Server: una base de datos.",
        "Una base de datos accesible desde Internet puede sufrir robos de datos e intentos de contraseña.",
        "Ciérralo al exterior; permite solo las conexiones de tus servidores de aplicación o usa una VPN.",
    ),
    1521: (
        "Oracle Database: una base de datos.",
        "Una base de datos accesible desde Internet puede sufrir robos de datos e intentos de contraseña.",
        "Ciérralo al exterior; permite solo las conexiones de tus servidores de aplicación o usa una VPN.",
    ),
    3306: (
        "MySQL / MariaDB: una base de datos.",
        "Una base de datos accesible desde Internet puede sufrir robos de datos e intentos de contraseña.",
        "Haz que escuche solo en la red interna (bind-address) y bloquea el puerto en el cortafuegos.",
    ),
    3389: (
        "RDP: escritorio remoto de Windows.",
        "Es uno de los objetivos favoritos para adivinar contraseñas y para entrar con ransomware.",
        "No lo publiques en Internet: accede a través de una VPN y activa la autenticación a nivel de "
        "red (NLA).",
    ),
    5432: (
        "PostgreSQL: una base de datos.",
        "Una base de datos accesible desde Internet puede sufrir robos de datos e intentos de contraseña.",
        "Configura listen_addresses y pg_hba.conf para aceptar solo tu red y bloquea el puerto al exterior.",
    ),
    5900: (
        "VNC: control remoto del escritorio.",
        "Muchas instalaciones no cifran la conexión o usan contraseñas débiles: da control total del equipo.",
        "No lo publiques en Internet; úsalo a través de SSH o de una VPN.",
    ),
    6379: (
        "Redis: una base de datos en memoria.",
        "Por defecto no pide contraseña: quien llegue a él puede leer, borrar datos o tomar el servidor.",
        "Haz que escuche solo en 127.0.0.1 o en la red interna, activa la contraseña (requirepass) y "
        "bloquea el puerto al exterior.",
    ),
    8080: (
        "HTTP alternativo: suele ser una web, un panel de administración o un servidor de desarrollo.",
        "Muchas veces es un servicio de pruebas olvidado o un panel que no debería ser público.",
        "Comprueba qué sirve; si no tiene que ser público, ciérralo o protégelo con contraseña y HTTPS.",
    ),
    8443: (
        "HTTPS alternativo: suele ser un panel de administración o una segunda web.",
        "Los paneles de administración expuestos son un objetivo habitual de ataques.",
        "Limita el acceso por IP o VPN y mantén el software del panel actualizado.",
    ),
    8888: (
        "Jupyter Notebook u otra herramienta de desarrollo.",
        "Jupyter permite ejecutar código en el servidor: si está expuesto, cualquiera podría controlarlo.",
        "No lo publiques en Internet; accede mediante un túnel SSH y protégelo con contraseña o token.",
    ),
    9200: (
        "Elasticsearch: un motor de búsqueda y almacenamiento de datos.",
        "Expuesto sin autenticación ha provocado filtraciones de millones de registros.",
        "Activa la seguridad (usuarios y TLS) y bloquea el puerto al exterior.",
    ),
    27017: (
        "MongoDB: una base de datos.",
        "Las instalaciones sin autenticación expuestas a Internet han sido borradas y secuestradas en masa.",
        "Activa la autenticación, haz que escuche solo en la red interna y bloquea el puerto al exterior.",
    ),
    11211: (
        "Memcached: una caché en memoria.",
        "No tiene autenticación y se ha usado para ataques de denegación de servicio enormes.",
        "Haz que escuche solo en 127.0.0.1 o en la red interna y bloquea el puerto al exterior.",
    ),
}


def explicar_puerto(puerto: int, servicio: str = "") -> dict:
    """{"que_es", "riesgo", "recomendacion"} de un puerto, con un texto genérico para los desconocidos."""
    if puerto in EXPLICACION_PUERTOS:
        que_es, riesgo, recomendacion = EXPLICACION_PUERTOS[puerto]
    else:
        que_es = f"Servicio {servicio or 'desconocido'} escuchando en el puerto {puerto}."
        riesgo = (
            "Cada puerto abierto es una puerta de entrada más: si el programa que lo usa no está "
            "actualizado o está mal configurado, puede ser atacado."
        )
        recomendacion = (
            "Comprueba qué programa usa este puerto. Si no hace falta acceder desde Internet, ciérralo o "
            "limítalo en el cortafuegos a las IPs que lo necesiten."
        )
    return {"que_es": que_es, "riesgo": riesgo, "recomendacion": recomendacion}


# Limita los escaneos simultáneos en el proceso para no agotar hilos y sockets.
_escaneos_activos = threading.BoundedSemaphore(getattr(settings, "SECURESCAN_MAX_ESCANEOS_SIMULTANEOS", 4))

_IMPRIMIBLES = set(string.printable) - set("\x0b\x0c")


def _limpiar_banner(datos: bytes) -> str | None:
    texto = datos.decode("latin-1")
    texto = "".join(c if c in _IMPRIMIBLES else " " for c in texto)
    texto = " ".join(texto.split())[:MAX_LONGITUD_BANNER]
    return texto or None


def escanear_puerto(ip: str, puerto: int, timeout: float = TIMEOUT_CONEXION):
    """Devuelve (puerto, abierto, banner). Solo escucha: nunca envía datos."""
    try:
        with socket.create_connection((ip, puerto), timeout=timeout) as sock:
            sock.settimeout(TIMEOUT_BANNER)
            try:
                banner = _limpiar_banner(sock.recv(256))
            except OSError:
                banner = None  # el servicio no habla primero (HTTP, Redis...)
            return puerto, True, banner
    except OSError:
        return puerto, False, None


def escanear_host(host: str, puertos_extra=None) -> dict:
    """Escanea los puertos comunes (y extra) de `host`.

    Lanza EntradaInvalida/ObjetivoNoPermitido si el host o los puertos no son
    válidos o si el host resuelve a una red interna (protección SSRF), y
    ServidorOcupado si ya hay demasiados escaneos en curso.
    """
    puertos_extra = validar_puertos(puertos_extra)
    ip = resolver_ip_publica(host)

    puertos_a_escanear = dict(PUERTOS_COMUNES)
    for p in puertos_extra:
        puertos_a_escanear.setdefault(p, "Personalizado")

    if not _escaneos_activos.acquire(timeout=10):
        raise ServidorOcupado("El servidor está ocupado con otros escaneos. Inténtalo en unos segundos.")
    try:
        hilos = min(MAX_HILOS, len(puertos_a_escanear))
        with concurrent.futures.ThreadPoolExecutor(max_workers=hilos) as executor:
            resultados_puertos = list(executor.map(lambda p: escanear_puerto(ip, p), puertos_a_escanear))
    finally:
        _escaneos_activos.release()

    abiertos, recomendaciones = [], []
    for puerto, abierto, banner in sorted(resultados_puertos):
        if not abierto:
            continue
        servicio = puertos_a_escanear[puerto]
        peligroso = puerto in PUERTOS_PELIGROSOS
        entrada = {"puerto": puerto, "servicio": servicio, "peligroso": peligroso, "banner": banner}
        if peligroso:
            entrada["recomendacion"] = PUERTOS_PELIGROSOS[puerto]
            recomendaciones.append(
                {
                    "puerto": puerto,
                    "servicio": servicio,
                    "recomendacion": PUERTOS_PELIGROSOS[puerto],
                }
            )
        abiertos.append(entrada)

    peligrosos = [p["puerto"] for p in abiertos if p["peligroso"]]
    return {
        "host": host,
        "ip": ip,
        "puertos_abiertos": abiertos,
        "puertos_peligrosos": peligrosos,
        "recomendaciones": recomendaciones,
        "resumen": {
            "total_abiertos": len(abiertos),
            "total_peligrosos": len(peligrosos),
            "total_verificados": len(puertos_a_escanear),
            "nivel_riesgo": "ALTO" if peligrosos else ("MEDIO" if abiertos else "BAJO"),
        },
    }
