from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import io
import datetime
from xml.sax.saxutils import escape

from django.utils import timezone

# Paleta limpia — fondo blanco, texto negro, acentos azul/rojo/verde
AZUL       = colors.HexColor('#1a56db')
ROJO       = colors.HexColor('#e02424')
VERDE      = colors.HexColor('#057a55')
NARANJA    = colors.HexColor('#d97706')
NEGRO      = colors.HexColor('#111827')
GRIS_OSC   = colors.HexColor('#374151')
GRIS_MED   = colors.HexColor('#6b7280')
GRIS_BORDE = colors.HexColor('#d1d5db')
GRIS_FONDO = colors.HexColor('#f9fafb')
BLANCO     = colors.white

def _estilo_titulo():
    return ParagraphStyle('titulo', fontSize=26, textColor=AZUL,
        alignment=TA_CENTER, fontName='Helvetica-Bold', spaceAfter=16)

def _estilo_sub():
    return ParagraphStyle('sub', fontSize=11, textColor=GRIS_MED,
        alignment=TA_CENTER, spaceAfter=20)

def _estilo_seccion():
    return ParagraphStyle('sec', fontSize=13, textColor=AZUL,
        fontName='Helvetica-Bold', spaceBefore=16, spaceAfter=8)

def _estilo_normal():
    return ParagraphStyle('nor', fontSize=10, textColor=NEGRO,
        spaceAfter=5, leading=15)

def _estilo_codigo():
    return ParagraphStyle('cod', fontSize=8, textColor=GRIS_OSC,
        fontName='Courier', spaceAfter=3, leading=12)

def _e(valor):
    """Escapa texto para Paragraph: ReportLab interpreta <b>, <font>, etc."""
    return escape(str(valor if valor is not None else ''))

def _color_nivel(nivel):
    n = str(nivel).upper()
    if 'ALTO' in n:   return ROJO
    if 'MEDIO' in n:  return NARANJA
    return VERDE

def _tabla_base(data, col_widths):
    t = Table(data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ('BACKGROUND',   (0, 0), (-1, 0), AZUL),
        ('TEXTCOLOR',    (0, 0), (-1, 0), BLANCO),
        ('FONTNAME',     (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE',     (0, 0), (-1,-1), 9),
        ('BACKGROUND',   (0, 1), (-1,-1), BLANCO),
        ('ROWBACKGROUND',(0, 1), (-1,-1), [BLANCO, GRIS_FONDO]),
        ('TEXTCOLOR',    (0, 1), (-1,-1), NEGRO),
        ('GRID',         (0, 0), (-1,-1), 0.5, GRIS_BORDE),
        ('BOTTOMPADDING',(0, 0), (-1,-1), 7),
        ('TOPPADDING',   (0, 0), (-1,-1), 7),
        ('LEFTPADDING',  (0, 0), (-1,-1), 10),
        ('RIGHTPADDING', (0, 0), (-1,-1), 10),
    ]))
    return t

def generar_reporte_pdf(tipo, datos, url_o_host='', fecha=None):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter,
        rightMargin=0.75*inch, leftMargin=0.75*inch,
        topMargin=0.75*inch, bottomMargin=0.75*inch)

    ss  = _estilo_seccion()
    ns  = _estilo_normal()
    cs  = _estilo_codigo()
    tit = _estilo_titulo()
    sub = _estilo_sub()
    story = []

    nombres = {
        'logs':    'Analisis de Logs',
        'puertos': 'Escaneo de Puertos',
        'headers': 'Verificacion de Headers HTTP'
    }
    fecha = timezone.localtime(fecha) if fecha else datetime.datetime.now()
    now = fecha.strftime('%d/%m/%Y %H:%M:%S')

    # Encabezado
    story.append(Paragraph('SecureScan', tit))
    story.append(Paragraph('Herramienta de Ciberseguridad Defensiva', sub))
    story.append(HRFlowable(width='100%', thickness=2, color=AZUL))
    story.append(Spacer(1, 14))

    # Metadatos
    story.append(Paragraph(_e(nombres.get(tipo, tipo)), ss))
    meta = _tabla_base(
        [['Campo', 'Valor'],
         ['Fecha', now],
         ['Tipo de analisis', nombres.get(tipo, tipo)],
         ['Objetivo', url_o_host or 'Archivo de logs']],
        [2.5*inch, 4.2*inch]
    )
    story.append(meta)
    story.append(Spacer(1, 14))
    story.append(HRFlowable(width='100%', thickness=0.5, color=GRIS_BORDE))
    story.append(Spacer(1, 10))

    if tipo == 'logs':
        _logs(story, datos, ss, ns, cs)
    elif tipo == 'puertos':
        _puertos(story, datos, ss, ns)
    elif tipo == 'headers':
        _headers(story, datos, ss, ns)

    story.append(Spacer(1, 24))
    story.append(HRFlowable(width='100%', thickness=0.5, color=GRIS_BORDE))
    story.append(Spacer(1, 6))
    story.append(Paragraph('Generado por SecureScan — Herramienta de ciberseguridad defensiva', sub))

    doc.build(story)
    buffer.seek(0)
    return buffer


def _logs(story, datos, ss, ns, cs):
    resumen = datos.get('resumen', {})
    nivel   = str(resumen.get('nivel_riesgo', 'BAJO')).upper()
    col_niv = _color_nivel(nivel)

    story.append(Paragraph('Resumen Ejecutivo', ss))
    t = _tabla_base(
        [['Indicador', 'Valor'],
         ['Nivel de riesgo',     nivel],
         ['Lineas analizadas',   str(resumen.get('total_lineas', 0))],
         ['Amenazas detectadas', str(resumen.get('total_amenazas', 0))],
         ['IPs sospechosas',     str(resumen.get('ips_sospechosas', 0))]],
        [3*inch, 3.7*inch]
    )
    # Colorear fila de nivel
    t.setStyle(TableStyle([
        ('TEXTCOLOR', (1, 1), (1, 1), col_niv),
        ('FONTNAME',  (1, 1), (1, 1), 'Helvetica-Bold'),
    ]))
    story.append(t)
    story.append(Spacer(1, 10))

    amenazas = datos.get('amenazas', [])
    if amenazas:
        story.append(Paragraph('Amenazas Detectadas', ss))
        for a in amenazas:
            col = _color_nivel(a.get('nivel', 'BAJO'))
            etiqueta = ParagraphStyle('ae', fontSize=10, textColor=col,
                fontName='Helvetica-Bold', spaceAfter=3)
            story.append(Paragraph(
                f"[{_e(a.get('nivel'))}]  {_e(a.get('tipo'))}  —  {_e(a.get('cantidad'))} ocurrencias",
                etiqueta))
            for d in a.get('detalle', [])[:3]:
                story.append(Paragraph(
                    f"    Linea {_e(d.get('linea'))}: {_e(str(d.get('contenido',''))[:110])}",
                    cs))
            story.append(Spacer(1, 5))

    ips = datos.get('ips_sospechosas', [])
    if ips:
        story.append(Paragraph('IPs Sospechosas', ss))
        rows = [['IP', 'Apariciones', 'Nivel']]
        for ip in ips:
            rows.append([ip.get('ip',''), str(ip.get('apariciones',0)), ip.get('nivel','')])
        story.append(_tabla_base(rows, [3*inch, 2*inch, 1.7*inch]))


def _puertos(story, datos, ss, ns):
    resumen = datos.get('resumen', {})
    nivel   = str(resumen.get('nivel_riesgo', 'BAJO')).upper()

    story.append(Paragraph('Resumen del Escaneo', ss))
    t = _tabla_base(
        [['Indicador', 'Valor'],
         ['Nivel de riesgo',   nivel],
         ['Host',              f"{datos.get('host','')}  ({datos.get('ip','')})"],
         ['Puertos verificados', str(resumen.get('total_verificados', 0))],
         ['Puertos abiertos',    str(resumen.get('total_abiertos', 0))],
         ['Puertos peligrosos',  str(resumen.get('total_peligrosos', 0))]],
        [3*inch, 3.7*inch]
    )
    t.setStyle(TableStyle([
        ('TEXTCOLOR', (1, 1), (1, 1), _color_nivel(nivel)),
        ('FONTNAME',  (1, 1), (1, 1), 'Helvetica-Bold'),
    ]))
    story.append(t)
    story.append(Spacer(1, 10))

    puertos = datos.get('puertos_abiertos', [])
    if puertos:
        story.append(Paragraph('Puertos Abiertos', ss))
        rows = [['Puerto', 'Servicio', 'Estado']]
        for p in puertos:
            estado = 'RIESGO' if p.get('peligroso') else 'OK'
            rows.append([f":{p.get('puerto')}", p.get('servicio',''), estado])
        t2 = _tabla_base(rows, [1.5*inch, 3.2*inch, 2*inch])
        # Colorear columna Estado
        for i, p in enumerate(puertos, start=1):
            col = ROJO if p.get('peligroso') else VERDE
            t2.setStyle(TableStyle([('TEXTCOLOR', (2, i), (2, i), col),
                                    ('FONTNAME',  (2, i), (2, i), 'Helvetica-Bold')]))
        story.append(t2)
        story.append(Spacer(1, 10))

    recs = datos.get('recomendaciones', [])
    if recs:
        story.append(Paragraph('Recomendaciones de Seguridad', ss))
        for r in recs:
            story.append(Paragraph(
                f"Puerto :{_e(r.get('puerto'))}  —  {_e(r.get('servicio'))}",
                ParagraphStyle('rh', fontSize=10, textColor=ROJO,
                    fontName='Helvetica-Bold', spaceAfter=2)))
            story.append(Paragraph(
                f"    {_e(r.get('recomendacion',''))}",
                ParagraphStyle('rd', fontSize=9, textColor=GRIS_OSC, spaceAfter=8)))


def _headers(story, datos, ss, ns):
    resumen = datos.get('resumen', {})
    nivel   = str(resumen.get('nivel_riesgo', 'BAJO')).upper()
    pts     = resumen.get('puntuacion', 0)

    story.append(Paragraph('Resumen de Seguridad', ss))
    t = _tabla_base(
        [['Indicador', 'Valor'],
         ['Nivel de riesgo',      nivel],
         ['URL analizada',        datos.get('url','')],
         ['Puntuacion',           f"{pts} / 100"],
         ['Headers presentes',    str(resumen.get('presentes', 0))],
         ['Headers faltantes',    str(resumen.get('faltantes', 0))],
         ['Redireccion HTTPS',    'Si' if datos.get('redireccion_https') else 'No']],
        [3*inch, 3.7*inch]
    )
    t.setStyle(TableStyle([
        ('TEXTCOLOR', (1, 1), (1, 1), _color_nivel(nivel)),
        ('FONTNAME',  (1, 1), (1, 1), 'Helvetica-Bold'),
    ]))
    story.append(t)
    story.append(Spacer(1, 10))

    ssl = datos.get('ssl_info', {})
    if ssl:
        story.append(Paragraph('Certificado SSL', ss))
        if ssl.get('valido'):
            dias = ssl.get('dias_restantes', 0)
            col_ssl = ROJO if dias < 15 else NARANJA if dias < 30 else VERDE
            rows = [['Campo', 'Valor'],
                    ['Estado', 'Valido'],
                    ['Expira', ssl.get('expira', 'N/A')],
                    ['Dias restantes', str(dias)]]
            t2 = _tabla_base(rows, [3*inch, 3.7*inch])
            t2.setStyle(TableStyle([
                ('TEXTCOLOR', (1, 3), (1, 3), col_ssl),
                ('FONTNAME',  (1, 3), (1, 3), 'Helvetica-Bold'),
            ]))
            story.append(t2)
        else:
            story.append(Paragraph(
                f"SSL no disponible: {_e(ssl.get('error','N/A'))}",
                ParagraphStyle('se', fontSize=10, textColor=ROJO, spaceAfter=6)))
        story.append(Spacer(1, 8))

    presentes = datos.get('headers_presentes', [])
    if presentes:
        story.append(Paragraph('Headers Presentes', ss))
        rows = [['Header', 'Descripcion']]
        for h in presentes:
            rows.append([h.get('header',''), h.get('descripcion','')])
        t3 = _tabla_base(rows, [2.5*inch, 4.2*inch])
        # Verde en columna header
        for i in range(1, len(presentes)+1):
            t3.setStyle(TableStyle([('TEXTCOLOR', (0, i), (0, i), VERDE),
                                    ('FONTNAME',  (0, i), (0, i), 'Helvetica-Bold')]))
        story.append(t3)
        story.append(Spacer(1, 10))

    faltantes = datos.get('headers_faltantes', [])
    if faltantes:
        story.append(Paragraph('Headers Faltantes y Recomendaciones', ss))
        rows = [['Header', 'Nivel', 'Recomendacion']]
        for h in faltantes:
            rows.append([h.get('header',''), h.get('nivel',''), h.get('recomendacion','')])
        t4 = _tabla_base(rows, [1.8*inch, 0.9*inch, 4*inch])
        for i, h in enumerate(faltantes, start=1):
            col = _color_nivel(h.get('nivel',''))
            t4.setStyle(TableStyle([('TEXTCOLOR', (0, i), (1, i), col),
                                    ('FONTNAME',  (0, i), (1, i), 'Helvetica-Bold')]))
        story.append(t4)
