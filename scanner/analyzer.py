import re
from collections import Counter, defaultdict

USERAGENTS_MALICIOSOS = [
    'sqlmap', 'nikto', 'nmap', 'masscan', 'dirbuster', 'gobuster',
    'hydra', 'metasploit', 'burpsuite', 'acunetix', 'nessus', 'openvas',
    'zgrab', 'nuclei', 'wfuzz', 'ffuf', 'dirb', 'scanner'
]

PATRONES_SQLI = [
    r'(union.*select|select.*from|insert.*into|drop.*table)',
    r'(1=1|1 =1|1= 1)',
    r'(sleep\(|benchmark\(|waitfor|pg_sleep)',
    r'(%27|%22|%2d%2d)',
]

PATRONES_XSS = [
    r'(<script|</script|javascript:|onerror=|onload=)',
    r'(alert\(|document\.cookie|window\.location)',
]

PATRONES_TRAVERSAL = [
    r'(\.\./|\.\.\\|%2e%2e%2f|%252e%252e)',
]

def analizar_logs(contenido):
    lineas = contenido.splitlines()
    resultados = {
        'total_lineas': len(lineas),
        'amenazas': [],
        'ips_sospechosas': [],
        'resumen': {},
        'actividad_por_hora': {}
    }

    patron_ip = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    patron_error_login = r'(Failed password|authentication failure|Invalid user|failed login|Login incorrect)'
    patron_hora = r'\d{2}/\w+/\d{4}:(\d{2}):\d{2}:\d{2}'

    ips_counter = Counter()
    errores_login = []
    errores_404 = []
    errores_500 = []
    sqli_detectado = []
    xss_detectado = []
    traversal_detectado = []
    ua_maliciosos = []
    actividad_horas = Counter()

    for numero, linea in enumerate(lineas, 1):
        ips_encontradas = re.findall(patron_ip, linea)
        for ip in ips_encontradas:
            ips_counter[ip] += 1

        hora_match = re.search(patron_hora, linea)
        if hora_match:
            hora = hora_match.group(1)
            actividad_horas[hora] += 1

        if re.search(patron_error_login, linea, re.IGNORECASE):
            errores_login.append({'linea': numero, 'contenido': linea.strip()})

        if '" 404 ' in linea:
            errores_404.append({'linea': numero, 'contenido': linea.strip()})

        if '" 500 ' in linea:
            errores_500.append({'linea': numero, 'contenido': linea.strip()})

        for patron in PATRONES_SQLI:
            if re.search(patron, linea, re.IGNORECASE):
                sqli_detectado.append({'linea': numero, 'contenido': linea.strip()})
                break

        for patron in PATRONES_XSS:
            if re.search(patron, linea, re.IGNORECASE):
                xss_detectado.append({'linea': numero, 'contenido': linea.strip()})
                break

        for patron in PATRONES_TRAVERSAL:
            if re.search(patron, linea, re.IGNORECASE):
                traversal_detectado.append({'linea': numero, 'contenido': linea.strip()})
                break

        linea_lower = linea.lower()
        for ua in USERAGENTS_MALICIOSOS:
            if ua in linea_lower:
                ua_maliciosos.append({'linea': numero, 'contenido': linea.strip(), 'herramienta': ua})
                break

    for ip, cantidad in ips_counter.items():
        if cantidad > 10:
            resultados['ips_sospechosas'].append({
                'ip': ip,
                'apariciones': cantidad,
                'nivel': 'ALTO' if cantidad > 50 else 'MEDIO'
            })

    if errores_login:
        resultados['amenazas'].append({
            'tipo': 'Intentos de login fallidos',
            'cantidad': len(errores_login),
            'detalle': errores_login[:5],
            'nivel': 'ALTO' if len(errores_login) > 10 else 'MEDIO'
        })

    if sqli_detectado:
        resultados['amenazas'].append({
            'tipo': 'Posible SQL Injection detectado',
            'cantidad': len(sqli_detectado),
            'detalle': sqli_detectado[:5],
            'nivel': 'ALTO'
        })

    if xss_detectado:
        resultados['amenazas'].append({
            'tipo': 'Posible ataque XSS detectado',
            'cantidad': len(xss_detectado),
            'detalle': xss_detectado[:5],
            'nivel': 'ALTO'
        })

    if traversal_detectado:
        resultados['amenazas'].append({
            'tipo': 'Intento de Path Traversal',
            'cantidad': len(traversal_detectado),
            'detalle': traversal_detectado[:5],
            'nivel': 'ALTO'
        })

    if ua_maliciosos:
        resultados['amenazas'].append({
            'tipo': 'Herramienta de hacking detectada en User-Agent',
            'cantidad': len(ua_maliciosos),
            'detalle': ua_maliciosos[:5],
            'nivel': 'ALTO'
        })

    if errores_404:
        resultados['amenazas'].append({
            'tipo': 'Errores 404 excesivos (posible escaneo de rutas)',
            'cantidad': len(errores_404),
            'detalle': errores_404[:5],
            'nivel': 'MEDIO' if len(errores_404) < 20 else 'ALTO'
        })

    if errores_500:
        resultados['amenazas'].append({
            'tipo': 'Errores internos del servidor',
            'cantidad': len(errores_500),
            'detalle': errores_500[:5],
            'nivel': 'BAJO'
        })

    resultados['actividad_por_hora'] = dict(sorted(actividad_horas.items()))
    resultados['resumen'] = {
        'total_lineas': len(lineas),
        'total_amenazas': len(resultados['amenazas']),
        'ips_sospechosas': len(resultados['ips_sospechosas']),
        'nivel_riesgo': calcular_nivel_riesgo(resultados)
    }

    return resultados


def calcular_nivel_riesgo(resultados):
    amenazas_altas = sum(1 for a in resultados['amenazas'] if a.get('nivel') == 'ALTO')
    if amenazas_altas > 0 or len(resultados['ips_sospechosas']) > 3:
        return 'ALTO'
    elif len(resultados['amenazas']) > 0:
        return 'MEDIO'
    else:
        return 'BAJO'
