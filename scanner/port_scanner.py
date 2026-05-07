import socket
import concurrent.futures

PUERTOS_COMUNES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "Jupyter", 9200: "Elasticsearch",
    27017: "MongoDB", 11211: "Memcached"
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
    11211: "Memcached puede ser usado para ataques DDoS de amplificacion."
}

def escanear_puerto(host, puerto, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        resultado = sock.connect_ex((host, puerto))
        sock.close()
        return puerto, resultado == 0
    except:
        return puerto, False

def escanear_host(host, puertos_extra=None):
    resultados = {
        "host": host,
        "puertos_abiertos": [],
        "puertos_peligrosos": [],
        "recomendaciones": [],
        "resumen": {}
    }

    try:
        ip = socket.gethostbyname(host)
        resultados["ip"] = ip
    except:
        return {"error": f"No se pudo resolver el host: {host}"}

    puertos_a_escanear = dict(PUERTOS_COMUNES)
    if puertos_extra:
        for p in puertos_extra:
            if p not in puertos_a_escanear:
                puertos_a_escanear[p] = "Personalizado"

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(escanear_puerto, ip, p): p for p in puertos_a_escanear}
        for future in concurrent.futures.as_completed(futures):
            puerto, abierto = future.result()
            if abierto:
                servicio = puertos_a_escanear[puerto]
                peligroso = puerto in PUERTOS_PELIGROSOS
                entry = {
                    "puerto": puerto,
                    "servicio": servicio,
                    "peligroso": peligroso
                }
                if peligroso:
                    entry["recomendacion"] = PUERTOS_PELIGROSOS[puerto]
                    resultados["puertos_peligrosos"].append(puerto)
                    resultados["recomendaciones"].append({
                        "puerto": puerto,
                        "servicio": servicio,
                        "recomendacion": PUERTOS_PELIGROSOS[puerto]
                    })
                resultados["puertos_abiertos"].append(entry)

    resultados["puertos_abiertos"].sort(key=lambda x: x["puerto"])
    total = len(puertos_a_escanear)
    resultados["resumen"] = {
        "total_abiertos": len(resultados["puertos_abiertos"]),
        "total_peligrosos": len(resultados["puertos_peligrosos"]),
        "total_verificados": total,
        "nivel_riesgo": "ALTO" if resultados["puertos_peligrosos"] else ("MEDIO" if resultados["puertos_abiertos"] else "BAJO")
    }

    return resultados
