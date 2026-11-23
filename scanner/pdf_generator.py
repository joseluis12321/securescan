"""Generación de reportes PDF profesionales con ReportLab.

Todo texto dinámico pasa por `_e()` antes de entrar en un Paragraph: ReportLab
interpreta etiquetas como <b>, <font> o <img src>, y sin escapar un log
malicioso podría inyectar contenido o hacer que el servidor descargue URLs.
"""

import datetime
import io
from html import escape

from django.utils import timezone
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from .port_scanner import explicar_puerto

AZUL = colors.HexColor('#1a56db')
ROJO = colors.HexColor('#e02424')
ROJO_OSCURO = colors.HexColor('#9b1c1c')
VERDE = colors.HexColor('#057a55')
NARANJA = colors.HexColor('#d97706')
NEGRO = colors.HexColor('#111827')
GRIS_OSC = colors.HexColor('#374151')
GRIS_MED = colors.HexColor('#6b7280')
GRIS_BORDE = colors.HexColor('#d1d5db')
GRIS_FONDO = colors.HexColor('#f9fafb')
BLANCO = colors.white

ANCHO_UTIL = 7 * inch
NOMBRES = {
    'logs': 'Análisis de Logs',
    'puertos': 'Escaneo de Puertos',
    'headers': 'Verificación de Headers HTTP',
    'web': 'Auditoría Web',
}

# Auditoría web: textos y colores de gravedad y estado (nunca se usa texto libre como clave).
GRAVEDADES = {
    'critica': ('Crítica', ROJO_OSCURO),
    'alta': ('Alta', ROJO),
    'media': ('Media', NARANJA),
    'baja': ('Baja', AZUL),
    'info': ('Info', GRIS_MED),
}
ESTADOS = {'fallo': 'FALLO', 'ok': 'OK', 'no_aplica': 'NO APLICA'}

ESTILOS = {
    'titulo': ParagraphStyle(
        'titulo',
        fontSize=26,
        textColor=AZUL,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold',
        spaceAfter=16,
        leading=30,
    ),
    'sub': ParagraphStyle('sub', fontSize=11, textColor=GRIS_MED, alignment=TA_CENTER, spaceAfter=20),
    # keepWithNext: un título nunca se queda solo al final de una página.
    'seccion': ParagraphStyle(
        'seccion',
        fontSize=13,
        textColor=AZUL,
        fontName='Helvetica-Bold',
        spaceBefore=16,
        spaceAfter=8,
        keepWithNext=1,
    ),
    'normal': ParagraphStyle('normal', fontSize=10, textColor=NEGRO, spaceAfter=5, leading=14),
    'codigo': ParagraphStyle(
        'codigo', fontSize=8, textColor=GRIS_OSC, fontName='Courier', spaceAfter=3, leading=11, leftIndent=12
    ),
    'celda': ParagraphStyle('celda', fontSize=9, textColor=NEGRO, leading=11),
    'celda_cab': ParagraphStyle(
        'celda_cab', fontSize=9, textColor=BLANCO, leading=11, fontName='Helvetica-Bold'
    ),
    'detalle': ParagraphStyle(
        'detalle', fontSize=9, textColor=GRIS_OSC, spaceAfter=8, leftIndent=12, leading=12
    ),
    'campo': ParagraphStyle('campo', fontSize=9, textColor=GRIS_OSC, spaceAfter=3, leftIndent=12, leading=12),
    'nota': ParagraphStyle('nota', fontSize=8, textColor=GRIS_MED, spaceAfter=6, leading=11),
}


def _e(valor) -> str:
    """Escapa texto para Paragraph."""
    return escape(str(valor if valor is not None else ''), quote=False)


def _nivel(valor) -> str:
    """Normaliza el nivel a ALTO/MEDIO/BAJO (los análisis antiguos incluían emojis)."""
    texto = str(valor or '').upper()
    for nivel in ('ALTO', 'MEDIO', 'BAJO'):
        if nivel in texto:
            return nivel
    return 'BAJO'


def _color_nivel(nivel) -> colors.Color:
    return {'ALTO': ROJO, 'MEDIO': NARANJA}.get(_nivel(nivel), VERDE)


def _parrafo_con_color(texto: str, color, negrita=True, tam=10) -> Paragraph:
    return Paragraph(
        texto,
        ParagraphStyle(
            'c',
            fontSize=tam,
            textColor=color,
            spaceAfter=3,
            fontName='Helvetica-Bold' if negrita else 'Helvetica',
        ),
    )


def _tabla(filas, proporciones, colores_celda=()):
    """Tabla con cabecera azul. Las celdas son Paragraph para que el texto largo haga salto de línea.

    colores_celda: [(columna, fila, color)] para resaltar celdas en negrita.
    """
    anchos = [ANCHO_UTIL * p for p in proporciones]
    datos = []
    for i, fila in enumerate(filas):
        estilo = ESTILOS['celda_cab'] if i == 0 else ESTILOS['celda']
        datos.append([Paragraph(_e(c), estilo) for c in fila])
    for col, fila, color in colores_celda:
        texto = _e(filas[fila][col])
        datos[fila][col] = Paragraph(
            f'<b>{texto}</b>', ParagraphStyle('resaltada', parent=ESTILOS['celda'], textColor=color)
        )

    t = Table(datos, colWidths=anchos, repeatRows=1)
    t.setStyle(
        TableStyle(
            [
                ('BACKGROUND', (0, 0), (-1, 0), AZUL),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [BLANCO, GRIS_FONDO]),
                ('GRID', (0, 0), (-1, -1), 0.5, GRIS_BORDE),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('LEFTPADDING', (0, 0), (-1, -1), 8),
                ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ]
        )
    )
    return t


def _pie_de_pagina(canvas, doc):
    canvas.saveState()
    canvas.setFont('Helvetica', 8)
    canvas.setFillColor(GRIS_MED)
    canvas.drawString(0.75 * inch, 0.5 * inch, 'SecureScan — Reporte de ciberseguridad defensiva')
    canvas.drawRightString(letter[0] - 0.75 * inch, 0.5 * inch, f'Página {doc.page}')
    canvas.restoreState()


def generar_reporte_pdf(tipo, datos, url_o_host='', fecha=None) -> io.BytesIO:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.85 * inch,
        title=f'SecureScan — {NOMBRES.get(tipo, tipo)}',
        author='SecureScan',
    )
    fecha = timezone.localtime(fecha) if fecha else datetime.datetime.now()
    datos = datos if isinstance(datos, dict) else {}
    nombre = NOMBRES.get(tipo, tipo)

    story = [
        Paragraph('SecureScan', ESTILOS['titulo']),
        Paragraph('Herramienta de Ciberseguridad Defensiva', ESTILOS['sub']),
        HRFlowable(width='100%', thickness=2, color=AZUL),
        Spacer(1, 14),
        Paragraph(_e(nombre), ESTILOS['seccion']),
        _tabla(
            [
                ['Campo', 'Valor'],
                ['Fecha del análisis', fecha.strftime('%d/%m/%Y %H:%M:%S')],
                ['Tipo de análisis', nombre],
                ['Objetivo', url_o_host or 'Archivo de logs'],
            ],
            [0.35, 0.65],
        ),
        Spacer(1, 14),
        HRFlowable(width='100%', thickness=0.5, color=GRIS_BORDE),
        Spacer(1, 10),
    ]

    secciones = {'logs': _logs, 'puertos': _puertos, 'headers': _headers, 'web': _web}
    secciones.get(tipo, lambda *_: None)(story, datos)

    story += [
        Spacer(1, 24),
        HRFlowable(width='100%', thickness=0.5, color=GRIS_BORDE),
        Spacer(1, 6),
        Paragraph('Uso exclusivo en sistemas propios o con autorización explícita.', ESTILOS['sub']),
    ]
    doc.build(story, onFirstPage=_pie_de_pagina, onLaterPages=_pie_de_pagina)
    buffer.seek(0)
    return buffer


def _resumen(story, filas):
    """Tabla de resumen cuya segunda fila es el nivel de riesgo (coloreado)."""
    story.append(_tabla(filas, [0.45, 0.55], [(1, 1, _color_nivel(filas[1][1]))]))
    story.append(Spacer(1, 10))


def _logs(story, datos):
    resumen = datos.get('resumen', {})
    story.append(Paragraph('Resumen Ejecutivo', ESTILOS['seccion']))
    _resumen(
        story,
        [
            ['Indicador', 'Valor'],
            ['Nivel de riesgo', _nivel(resumen.get('nivel_riesgo'))],
            ['Líneas analizadas', resumen.get('total_lineas', 0)],
            ['Amenazas detectadas', resumen.get('total_amenazas', 0)],
            ['IPs sospechosas', resumen.get('ips_sospechosas', 0)],
        ],
    )

    amenazas = datos.get('amenazas', [])
    if amenazas:
        story.append(Paragraph('Amenazas Detectadas', ESTILOS['seccion']))
        for a in amenazas:
            story.append(
                _parrafo_con_color(
                    f"[{_e(_nivel(a.get('nivel')))}]  {_e(a.get('tipo'))}  —  "
                    f"{_e(a.get('cantidad'))} ocurrencias",
                    _color_nivel(a.get('nivel')),
                )
            )
            for d in a.get('detalle', [])[:3]:
                contenido = _e(str(d.get('contenido', ''))[:160])
                prefijo = f"Línea {_e(d.get('linea'))}: " if d.get('linea') else ''
                story.append(Paragraph(prefijo + contenido, ESTILOS['codigo']))
            story.append(Spacer(1, 5))

    ips = datos.get('ips_sospechosas', [])
    if ips:
        story.append(Paragraph('IPs Sospechosas', ESTILOS['seccion']))
        filas = [['IP', 'Apariciones', 'Peticiones maliciosas', 'Logins fallidos', 'Nivel']]
        for ip in ips:
            filas.append(
                [
                    ip.get('ip', ''),
                    ip.get('apariciones', 0),
                    ip.get('eventos_maliciosos', '-'),
                    ip.get('fallos_login', '-'),
                    _nivel(ip.get('nivel')),
                ]
            )
        story.append(
            _tabla(
                filas,
                [0.26, 0.16, 0.22, 0.18, 0.18],
                [(4, i, _color_nivel(f[4])) for i, f in enumerate(filas) if i],
            )
        )


def _puertos(story, datos):
    resumen = datos.get('resumen', {})
    story.append(Paragraph('Resumen del Escaneo', ESTILOS['seccion']))
    _resumen(
        story,
        [
            ['Indicador', 'Valor'],
            ['Nivel de riesgo', _nivel(resumen.get('nivel_riesgo'))],
            ['Host', f"{datos.get('host', '')}  ({datos.get('ip', '')})"],
            ['Puertos verificados', resumen.get('total_verificados', 0)],
            ['Puertos abiertos', resumen.get('total_abiertos', 0)],
            ['Puertos peligrosos', resumen.get('total_peligrosos', 0)],
        ],
    )

    puertos = datos.get('puertos_abiertos', [])
    if puertos:
        story.append(Paragraph('Puertos Abiertos', ESTILOS['seccion']))
        filas = [['Puerto', 'Servicio', 'Banner', 'Estado']]
        for p in puertos:
            filas.append(
                [
                    f":{p.get('puerto')}",
                    p.get('servicio', ''),
                    p.get('banner') or '—',
                    'RIESGO' if p.get('peligroso') else 'OK',
                ]
            )
        story.append(
            _tabla(
                filas,
                [0.13, 0.2, 0.52, 0.15],
                [(3, i, ROJO if f[3] == 'RIESGO' else VERDE) for i, f in enumerate(filas) if i],
            )
        )
        story.append(Spacer(1, 10))

        _seccion_con_bloques(story, 'Detalle por Puerto', [_detalle_puerto(p) for p in puertos])


def _seccion_con_bloques(story, titulo: str, bloques: list[list]):
    """Añade un título y bloques que no se parten entre páginas.

    El título va dentro del primer bloque: keepWithNext no funciona cuando lo
    siguiente es un KeepTogether, y el título se quedaría solo al final de una página.
    """
    encabezado = Paragraph(_e(titulo), ESTILOS['seccion'])
    if not bloques:
        story.append(encabezado)
        return
    bloques[0].insert(0, encabezado)
    story.extend(KeepTogether(bloque) for bloque in bloques)


def _campo(etiqueta: str, texto) -> Paragraph:
    return Paragraph(f'<b>{_e(etiqueta)}:</b> {_e(texto)}', ESTILOS['campo'])


def _detalle_puerto(p: dict) -> list:
    """Qué es el servicio, su riesgo y la recomendación. Se calcula al generar el PDF,
    así también funciona con escaneos guardados antes de existir estas explicaciones."""
    try:
        numero = int(p.get('puerto'))
    except (TypeError, ValueError):
        numero = 0
    info = explicar_puerto(numero, str(p.get('servicio') or ''))
    peligroso = bool(p.get('peligroso'))
    estado = 'RIESGO' if peligroso else 'ABIERTO'
    bloque = [
        _parrafo_con_color(
            f"Puerto :{_e(p.get('puerto'))}  —  {_e(p.get('servicio'))}  [{estado}]",
            ROJO if peligroso else AZUL,
        ),
        _campo('Qué es', info['que_es']),
        _campo('Riesgo', info['riesgo']),
        _campo('Recomendación', info['recomendacion']),
    ]
    if p.get('banner'):
        bloque.append(_campo('Servicio identificado (banner)', p['banner']))
    bloque.append(Spacer(1, 8))
    return bloque


def _texto_redireccion(valor) -> str:
    if valor is None:
        return 'No aplica (HTTP no disponible)'
    return 'Sí' if valor else 'No'


def _headers(story, datos):
    resumen = datos.get('resumen', {})
    story.append(Paragraph('Resumen de Seguridad', ESTILOS['seccion']))
    _resumen(
        story,
        [
            ['Indicador', 'Valor'],
            ['Nivel de riesgo', _nivel(resumen.get('nivel_riesgo'))],
            ['URL analizada', datos.get('url', '')],
            ['Código de estado', datos.get('codigo_estado', '—')],
            ['Puntuación', f"{resumen.get('puntuacion', 0)} / 100"],
            ['Headers presentes', resumen.get('presentes', 0)],
            ['Headers faltantes', resumen.get('faltantes', 0)],
            ['Redirección HTTP → HTTPS', _texto_redireccion(datos.get('redireccion_https'))],
        ],
    )

    ssl = datos.get('ssl_info', {})
    if ssl:
        story.append(Paragraph('Certificado TLS', ESTILOS['seccion']))
        if ssl.get('valido'):
            dias = ssl.get('dias_restantes', 0)
            filas = [
                ['Campo', 'Valor'],
                ['Estado', 'Válido'],
                ['Expira', ssl.get('expira', 'N/A')],
                ['Días restantes', dias],
                ['Versión TLS', ssl.get('version_tls') or '—'],
                ['Cifrado', ssl.get('cifrado') or '—'],
                ['Emisor', (ssl.get('emisor') or {}).get('organizationName', '—')],
            ]
            color = ROJO if dias < 15 else NARANJA if dias < 30 else VERDE
            story.append(_tabla(filas, [0.35, 0.65], [(1, 3, color)]))
        else:
            story.append(
                _parrafo_con_color(f"TLS no disponible: {_e(ssl.get('error', 'N/A'))}", ROJO, negrita=False)
            )
        story.append(Spacer(1, 8))

    presentes = datos.get('headers_presentes', [])
    if presentes:
        story.append(Paragraph('Headers Presentes', ESTILOS['seccion']))
        filas = [['Header', 'Estado', 'Observación']]
        for h in presentes:
            filas.append(
                [
                    h.get('header', ''),
                    'MEJORABLE' if h.get('advertencia') else 'OK',
                    h.get('advertencia') or h.get('descripcion', ''),
                ]
            )
        story.append(
            _tabla(
                filas,
                [0.32, 0.16, 0.52],
                [(1, i, NARANJA if f[1] == 'MEJORABLE' else VERDE) for i, f in enumerate(filas) if i],
            )
        )
        story.append(Spacer(1, 10))

    faltantes = datos.get('headers_faltantes', [])
    if faltantes:
        story.append(Paragraph('Headers Faltantes y Recomendaciones', ESTILOS['seccion']))
        filas = [['Header', 'Nivel', 'Recomendación']]
        for h in faltantes:
            filas.append([h.get('header', ''), _nivel(h.get('nivel')), h.get('recomendacion', '')])
        story.append(
            _tabla(filas, [0.3, 0.12, 0.58], [(1, i, _color_nivel(f[1])) for i, f in enumerate(filas) if i])
        )
        story.append(Spacer(1, 10))

    advertencias = datos.get('advertencias', [])
    if advertencias:
        story.append(Paragraph('Otras Advertencias', ESTILOS['seccion']))
        filas = [['Tipo', 'Header', 'Detalle', 'Recomendación']]
        for a in advertencias:
            filas.append(
                [
                    a.get('tipo', ''),
                    f"{a.get('header', '')}: {a.get('valor', '')}",
                    a.get('detalle', ''),
                    a.get('recomendacion', ''),
                ]
            )
        story.append(_tabla(filas, [0.18, 0.27, 0.27, 0.28]))


def _numero(valor, por_defecto=0.0) -> float:
    try:
        return float(valor)
    except (TypeError, ValueError):
        return por_defecto


def _formatear_nota(nota: float) -> str:
    return f'{nota:.1f}'.replace('.', ',')


def _comprobacion(c: dict) -> list:
    estado = c.get('estado') if c.get('estado') in ESTADOS else 'no_aplica'
    nombre_gravedad, color_gravedad = GRAVEDADES.get(c.get('gravedad'), GRAVEDADES['info'])
    if estado == 'fallo':
        etiqueta, color = f'FALLO · {nombre_gravedad}', color_gravedad
    else:
        etiqueta, color = ESTADOS[estado], VERDE if estado == 'ok' else GRIS_MED

    bloque = [
        _parrafo_con_color(f'[{_e(etiqueta)}]  {_e(c.get("titulo"))}', color),
        _campo('Qué significa', c.get('explicacion', '')),
        _campo('Evidencia', c.get('evidencia', '')),
        _campo('Recomendación', c.get('recomendacion', '')),
    ]
    referencia = str(c.get('referencia') or '')
    if referencia.startswith('https://'):
        enlace = escape(referencia, quote=True)
        bloque.append(
            Paragraph(
                f'<b>Referencia:</b> <a href="{enlace}" color="#1a56db">{_e(referencia)}</a>',
                ESTILOS['campo'],
            )
        )
    bloque.append(Spacer(1, 8))
    return bloque


def _web(story, datos):
    resumen = datos.get('resumen', {})
    nota = max(1.0, min(10.0, _numero(datos.get('nota', resumen.get('nota')), 1.0)))
    por_gravedad = resumen.get('fallos_por_gravedad', {})
    texto_gravedad = ' · '.join(
        f'{nombre}: {int(_numero(por_gravedad.get(clave)))}' for clave, (nombre, _c) in GRAVEDADES.items()
    )

    story.append(Paragraph('Resumen de la Auditoría', ESTILOS['seccion']))
    _resumen(
        story,
        [
            ['Indicador', 'Valor'],
            ['Nivel de riesgo', _nivel(resumen.get('nivel_riesgo'))],
            ['Nota global', f'{_formatear_nota(nota)} / 10'],
            ['URL analizada', datos.get('url', '')],
            ['URL final (tras redirecciones)', datos.get('url_final', '—')],
            ['Código de estado', datos.get('codigo_estado', '—')],
            [
                'Comprobaciones',
                f"{int(_numero(resumen.get('total')))} en total: "
                f"{int(_numero(resumen.get('ok')))} correctas, "
                f"{int(_numero(resumen.get('fallos')))} con fallos, "
                f"{int(_numero(resumen.get('no_aplica')))} no aplican",
            ],
            ['Fallos por gravedad', texto_gravedad],
        ],
    )
    peticiones = int(_numero(datos.get('peticiones')))
    hechas = (
        'se hizo 1 petición normal' if peticiones == 1 else f'se hicieron {peticiones} peticiones normales'
    )
    story.append(
        Paragraph(
            'La nota parte de 10 y cada fallo resta según su gravedad (crítica 4, alta 2, media 1, baja 0,5, '
            'info 0). Con algún fallo crítico la nota máxima es 4, y con alguno alto, 7. Todas las '
            f'comprobaciones son pasivas: {hechas} al sitio, sin ataques ni pruebas que puedan dañarlo.',
            ESTILOS['nota'],
        )
    )

    for categoria in datos.get('categorias', []):
        bloques = [_comprobacion(c) for c in categoria.get('resultados', [])]
        _seccion_con_bloques(story, categoria.get('nombre', ''), bloques)
