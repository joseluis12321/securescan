/* SecureScan — interfaz web.
 *
 * Seguridad: todo el HTML se construye con la plantilla etiquetada html`...`,
 * que escapa por defecto cada valor interpolado. Solo los fragmentos creados
 * con html`...` se insertan sin escapar, así que el XSS queda descartado por
 * construcción. No hay JS inline ni atributos style: la CSP lo prohíbe.
 */
'use strict';

const SecureScan = (() => {
    // ---------------------------------------------------------------------
    // Plantillas HTML seguras
    // ---------------------------------------------------------------------
    class HtmlSeguro {
        constructor(texto) { this.texto = texto; }
        toString() { return this.texto; }
    }

    const ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
    const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ESCAPES[c]);

    function convertir(v) {
        if (v instanceof HtmlSeguro) return v.texto;
        if (Array.isArray(v)) return v.map(convertir).join('');
        if (v === false || v === null || v === undefined) return '';
        return esc(v);
    }

    function html(partes, ...valores) {
        let salida = partes[0];
        valores.forEach((v, i) => { salida += convertir(v) + partes[i + 1]; });
        return new HtmlSeguro(salida);
    }

    const num = (v) => { const n = Number(v); return Number.isFinite(n) ? n : 0; };
    // Normaliza el nivel a un valor conocido: nunca se usa texto libre como clase CSS.
    const nivel = (v) => { const t = String(v ?? ''); return t.includes('ALTO') ? 'ALTO' : t.includes('MEDIO') ? 'MEDIO' : 'BAJO'; };
    const $ = (id) => document.getElementById(id);

    /** Inserta HTML seguro y aplica las dimensiones dinámicas (vía CSSOM, permitido por la CSP). */
    function pintar(elemento, contenido) {
        elemento.innerHTML = convertir(contenido);
        elemento.querySelectorAll('[data-alto]').forEach((e) => { e.style.height = `${num(e.dataset.alto)}px`; });
        elemento.querySelectorAll('[data-ancho]').forEach((e) => { e.style.width = `${num(e.dataset.ancho)}%`; });
        elemento.hidden = false;
    }

    // ---------------------------------------------------------------------
    // Componentes
    // ---------------------------------------------------------------------
    const bannerNivel = (icono, etiqueta, valorNivel, extra = '') => html`
        <div class="nivel-banner nivel-${nivel(valorNivel)}">
            <div class="icono">${icono}</div>
            <div class="cuerpo">
                <div class="nivel-label">${etiqueta}</div>
                <div class="nivel-texto">${nivel(valorNivel)}</div>
                ${extra}
            </div>
        </div>`;

    const stat = (valor, etiqueta, clase = '') => html`
        <div class="stat-card"><div class="stat-n ${clase}">${num(valor)}</div><div class="stat-l">${etiqueta}</div></div>`;

    const badge = (texto, clase) => html`<span class="badge-n badge-${clase}">${texto}</span>`;

    const item = ({ titulo, badgeHtml = '', cuerpo = '', borde = '' }) => html`
        <div class="item ${borde}">
            <div class="item-header"><span class="item-titulo">${titulo}</span>${badgeHtml}</div>
            ${cuerpo}
        </div>`;

    const vacio = (texto, clase = 'ok') => html`<div class="no-data ${clase}">${texto}</div>`;
    const seccion = (titulo) => html`<div class="sec-titulo">${titulo}</div>`;

    // ---------------------------------------------------------------------
    // Renderizado de resultados
    // ---------------------------------------------------------------------
    function graficaHoras(horas) {
        const valores = Object.values(horas).map(num);
        const max = Math.max(...valores, 0);
        const barras = [];
        for (let h = 0; h < 24; h++) {
            const hs = String(h).padStart(2, '0');
            const v = num(horas[hs]);
            const alto = max > 0 ? Math.max(4, Math.round((v / max) * 56)) : 4;
            const clase = v > max * 0.7 ? 'alto' : v > max * 0.4 ? 'medio' : '';
            barras.push(html`
                <div class="hora-bar-wrap">
                    <div class="hora-bar ${clase}" data-alto="${alto}" title="${hs}:00 - ${v} eventos"></div>
                    <div class="hora-label">${h % 6 === 0 ? hs : ''}</div>
                </div>`);
        }
        return html`${seccion('📈 Actividad por hora')}<div class="grafica"><div class="hora-chart">${barras}</div></div>`;
    }

    function renderLogs(r) {
        const res = r.resumen || {};
        const horas = r.actividad_por_hora || {};
        const amenazas = r.amenazas || [];
        const ips = r.ips_sospechosas || [];

        return html`
            ${bannerNivel('🛡', 'Nivel de riesgo detectado', res.nivel_riesgo)}
            <div class="stats-grid">
                ${stat(res.total_lineas, 'Líneas analizadas')}
                ${stat(res.total_amenazas, 'Amenazas', num(res.total_amenazas) > 0 ? 'txt-ALTO' : 'txt-BAJO')}
                ${stat(res.ips_sospechosas, 'IPs sospechosas', num(res.ips_sospechosas) > 0 ? 'txt-MEDIO' : 'txt-BAJO')}
                ${stat(Object.keys(horas).length, 'Horas con actividad', 'txt-gris')}
            </div>
            ${Object.keys(horas).length > 0 && graficaHoras(horas)}
            ${seccion('🚨 Amenazas encontradas')}
            ${amenazas.length === 0 ? vacio('✓ No se detectaron amenazas') : amenazas.map((a) => item({
                titulo: a.tipo,
                badgeHtml: badge(nivel(a.nivel), nivel(a.nivel)),
                cuerpo: html`
                    <div class="item-desc">${num(a.cantidad)} ocurrencias detectadas</div>
                    <div class="item-detalle">${(a.detalle || []).map((d) =>
                        html`${d.linea ? `Línea ${num(d.linea)}: ` : ''}${d.contenido}\n`)}</div>`,
            }))}
            ${ips.length > 0 && html`
                ${seccion('🌎 IPs sospechosas')}
                ${ips.map((ip) => item({
                    titulo: html`<span class="mono">${ip.ip}</span>`,
                    badgeHtml: badge(nivel(ip.nivel), nivel(ip.nivel)),
                    cuerpo: html`<div class="item-desc">${num(ip.apariciones)} apariciones ·
                        ${num(ip.eventos_maliciosos)} peticiones maliciosas · ${num(ip.fallos_login)} logins fallidos</div>`,
                }))}`}`;
    }

    function renderPuertos(r) {
        const res = r.resumen || {};
        const abiertos = r.puertos_abiertos || [];
        const recs = r.recomendaciones || [];

        return html`
            ${bannerNivel('🔌', `Escaneo — ${r.host} (${r.ip})`, res.nivel_riesgo)}
            <div class="stats-grid stats-grid-3">
                ${stat(res.total_verificados, 'Verificados')}
                ${stat(res.total_abiertos, 'Abiertos', num(res.total_abiertos) > 0 ? 'txt-MEDIO' : 'txt-BAJO')}
                ${stat(res.total_peligrosos, 'Peligrosos', num(res.total_peligrosos) > 0 ? 'txt-ALTO' : 'txt-BAJO')}
            </div>
            ${seccion('🔴 Puertos abiertos')}
            ${abiertos.length === 0 ? vacio('✓ Sin puertos abiertos') : html`
                <div class="puertos-grid">${abiertos.map((p) => html`
                    <div class="puerto ${p.peligroso ? 'puerto-mal' : 'puerto-ok'}">
                        <div>
                            <div class="p-num">:${num(p.puerto)}</div>
                            <div class="p-svc">${p.servicio}</div>
                            ${p.banner && html`<div class="p-banner" title="${p.banner}">${p.banner}</div>`}
                        </div>
                        ${p.peligroso ? html`<span class="tag tag-mal">RIESGO</span>` : html`<span class="tag tag-ok">OK</span>`}
                    </div>`)}
                </div>`}
            ${recs.length > 0 && html`
                ${seccion('⚠ Recomendaciones')}
                ${recs.map((rec) => item({
                    titulo: `Puerto :${num(rec.puerto)} — ${rec.servicio}`,
                    badgeHtml: badge('RIESGO', 'ALTO'),
                    cuerpo: html`<div class="item-rec">💡 ${rec.recomendacion}</div>`,
                }))}`}`;
    }

    function renderSsl(ssl) {
        if (!ssl) return '';
        if (!ssl.valido) {
            return html`${seccion('🔐 Certificado TLS')}${item({
                titulo: '✗ TLS no disponible o certificado no válido', borde: 'borde-mal',
                badgeHtml: badge('ALTO', 'ALTO'),
                cuerpo: html`<div class="item-desc">${ssl.error || 'No se pudo verificar'}</div>`,
            })}`;
        }
        const dias = num(ssl.dias_restantes);
        const campo = (k, v) => html`<div class="ssl-item"><div class="k">${k}</div><div class="v">${v}</div></div>`;
        return html`${seccion('🔐 Certificado TLS')}${item({
            titulo: '✓ Certificado válido', borde: 'borde-ok',
            badgeHtml: dias < 30 ? badge('EXPIRA PRONTO', 'MEDIO') : badge('VIGENTE', 'BAJO'),
            cuerpo: html`<div class="ssl-grid">
                ${campo('Expira', ssl.expira)}${campo('Días restantes', `${dias} días`)}
                ${campo('Versión TLS', ssl.version_tls || '—')}${campo('Emisor', (ssl.emisor || {}).organizationName || '—')}
            </div>`,
        })}`;
    }

    function renderRedireccion(valor) {
        const textos = {
            true: '✓ HTTP redirige a HTTPS correctamente',
            false: '✗ HTTP no redirige a HTTPS',
            null: '✓ HTTP (puerto 80) no disponible: solo HTTPS',
        };
        const ok = valor !== false;
        return html`${seccion('🔗 Redirección HTTPS')}${item({
            titulo: textos[String(valor ?? null)] || textos.null,
            borde: ok ? 'borde-ok' : 'borde-mal',
            badgeHtml: ok ? badge('OK', 'BAJO') : badge('RIESGO', 'ALTO'),
        })}`;
    }

    function renderHeaders(r) {
        const res = r.resumen || {};
        const pts = Math.max(0, Math.min(100, num(res.puntuacion)));
        const presentes = r.headers_presentes || [];
        const faltantes = r.headers_faltantes || [];
        const advertencias = r.advertencias || [];
        const recortar = (v) => { const t = String(v ?? ''); return t.length > 120 ? `${t.slice(0, 120)}…` : t; };

        const barra = html`
            <div class="bar-wrap"><div class="bar-fill bar-${nivel(res.nivel_riesgo)}" data-ancho="${pts}"></div></div>
            <div class="puntuacion-texto">Puntuación: ${pts}/100 — ${num(res.presentes)} de ${num(res.total)} headers</div>`;

        return html`
            ${bannerNivel('🔒', `Análisis — ${r.url}`, res.nivel_riesgo, barra)}
            <div class="stats-grid stats-grid-3">
                ${stat(res.presentes, 'Presentes', 'txt-BAJO')}
                ${stat(res.faltantes, 'Faltantes', 'txt-ALTO')}
                ${stat(pts, 'Puntuación')}
            </div>
            ${renderSsl(r.ssl_info)}
            ${renderRedireccion(r.redireccion_https)}
            ${presentes.length > 0 && html`
                ${seccion('✓ Headers presentes')}
                ${presentes.map((h) => item({
                    titulo: h.header, borde: h.advertencia ? 'borde-aviso' : 'borde-ok',
                    badgeHtml: h.advertencia ? badge('MEJORABLE', 'WARN') : badge('OK', 'OK'),
                    cuerpo: html`
                        <div class="item-desc">${h.descripcion}</div>
                        <div class="item-valor">${recortar(h.valor)}</div>
                        ${h.advertencia && html`<div class="item-rec">⚠ ${h.advertencia}<br>💡 ${h.recomendacion}</div>`}`,
                }))}`}
            ${faltantes.length > 0 && html`
                ${seccion('✗ Headers faltantes')}
                ${faltantes.map((h) => item({
                    titulo: h.header, borde: 'borde-mal',
                    badgeHtml: badge(nivel(h.nivel), nivel(h.nivel)),
                    cuerpo: html`<div class="item-desc">${h.descripcion}</div><div class="item-rec">💡 ${h.recomendacion}</div>`,
                }))}`}
            ${advertencias.length > 0 && html`
                ${seccion('⚠ Otras advertencias')}
                ${advertencias.map((a) => item({
                    titulo: `${a.tipo} — ${a.header}`, borde: 'borde-aviso',
                    badgeHtml: badge('AVISO', 'WARN'),
                    cuerpo: html`<div class="item-valor">${a.valor}</div><div class="item-desc">${a.detalle}</div>
                        <div class="item-rec">💡 ${a.recomendacion}</div>`,
                }))}`}`;
    }

    const RENDER = { logs: renderLogs, puertos: renderPuertos, headers: renderHeaders };

    // ---------------------------------------------------------------------
    // Comunicación con el servidor
    // ---------------------------------------------------------------------
    function leerConfig() {
        const nodo = $('config-securescan');
        return nodo ? JSON.parse(nodo.textContent) : {};
    }

    const CONFIG = leerConfig();
    const CSRF = document.querySelector('meta[name="csrf-token"]')?.content || '';

    async function peticion(url, opciones = {}) {
        const respuesta = await fetch(url, {
            credentials: 'same-origin',
            ...opciones,
            headers: { 'X-CSRFToken': CSRF, ...(opciones.headers || {}) },
        });
        if (respuesta.status === 401) {
            window.location.href = `${CONFIG.urls.login}?next=${encodeURIComponent(window.location.pathname)}`;
            throw new Error('Sesión caducada');
        }
        const tipo = respuesta.headers.get('Content-Type') || '';
        if (!tipo.includes('application/json')) {
            throw new Error(respuesta.status === 403
                ? 'Petición rechazada (CSRF). Recarga la página.'
                : `Error del servidor (${respuesta.status})`);
        }
        const datos = await respuesta.json();
        if (!respuesta.ok || !datos.success) throw new Error(datos.error || `Error ${respuesta.status}`);
        return datos;
    }

    const postJSON = (url, cuerpo) => peticion(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(cuerpo),
    });

    const urlDe = (plantilla, id) => plantilla.replace('/0/', `/${encodeURIComponent(id)}/`);

    function accionesResultado(id) {
        return html`
            <a class="btn btn-pdf" href="${urlDe(CONFIG.urls.pdf, id)}">📄 Exportar PDF</a>
            <a class="btn btn-blue" href="${urlDe(CONFIG.urls.json, id)}">{} Exportar JSON</a>
            <a class="btn btn-gris" href="${urlDe(CONFIG.urls.detalle, id)}">Ver en el historial</a>`;
    }

    /** Flujo común: mostrar carga, llamar al servidor y pintar el resultado o el error. */
    async function ejecutar(tipo, accion) {
        const loader = $(`loader-${tipo}`);
        const resultado = $(`result-${tipo}`);
        const acciones = $(`acciones-${tipo}`);
        loader.hidden = false;
        resultado.hidden = true;
        acciones.hidden = true;
        try {
            const datos = await accion();
            pintar(resultado, RENDER[tipo](datos.resultado));
            pintar(acciones, accionesResultado(datos.id));
        } catch (error) {
            pintar(resultado, vacio(`Error: ${error.message}`, 'error'));
        } finally {
            loader.hidden = true;
        }
    }

    // ---------------------------------------------------------------------
    // Página principal
    // ---------------------------------------------------------------------
    function iniciarPestanas() {
        document.querySelectorAll('[data-tab]').forEach((boton) => {
            boton.addEventListener('click', () => {
                document.querySelectorAll('.tab').forEach((t) => {
                    t.classList.remove('active');
                    t.setAttribute('aria-selected', 'false');
                });
                document.querySelectorAll('.panel').forEach((p) => p.classList.remove('active'));
                boton.classList.add('active');
                boton.setAttribute('aria-selected', 'true');
                $(`panel-${boton.dataset.tab}`).classList.add('active');
            });
        });
    }

    function iniciarLogs() {
        const input = $('archivo_log');
        const zona = $('dropZone');
        const estado = $('fileOk');
        const boton = $('btnAnalizar');
        const maxBytes = num(CONFIG.maxLogMb) * 1024 * 1024;

        $('btnSeleccionar').addEventListener('click', (e) => { e.stopPropagation(); input.click(); });
        zona.addEventListener('click', () => input.click());
        zona.addEventListener('dragover', (e) => { e.preventDefault(); zona.classList.add('arrastrando'); });
        zona.addEventListener('dragleave', () => zona.classList.remove('arrastrando'));
        zona.addEventListener('drop', (e) => {
            e.preventDefault();
            zona.classList.remove('arrastrando');
            if (e.dataTransfer.files.length > 0) {
                input.files = e.dataTransfer.files;
                input.dispatchEvent(new Event('change'));
            }
        });
        input.addEventListener('change', () => {
            const archivo = input.files[0];
            if (!archivo) return;
            estado.textContent = `Listo: ${archivo.name} (${(archivo.size / 1024).toFixed(1)} KB)`;
            estado.hidden = false;
            boton.hidden = false;
        });
        boton.addEventListener('click', async (e) => {
            e.stopPropagation();
            const archivo = input.files[0];
            if (!archivo) return;
            if (archivo.size > maxBytes) {
                pintar($('result-logs'), vacio(`Error: el archivo supera el tamaño máximo de ${num(CONFIG.maxLogMb)} MB`, 'error'));
                return;
            }
            boton.disabled = true;
            const datos = new FormData();
            datos.append('archivo_log', archivo);
            await ejecutar('logs', () => peticion(CONFIG.urls.analizar, { method: 'POST', body: datos }));
            boton.disabled = false;
        });
    }

    function iniciarFormularios() {
        $('form-puertos').addEventListener('submit', (e) => {
            e.preventDefault();
            const host = $('inputHost').value.trim();
            const extra = $('inputPuertosExtra').value.trim();
            const puertos = extra ? extra.split(',').map((p) => parseInt(p.trim(), 10)).filter((p) => !Number.isNaN(p)) : [];
            if (!host) return;
            const autorizado = $('autorizadoPuertos').checked;
            ejecutar('puertos', () => postJSON(CONFIG.urls.escanear, { host, puertos_extra: puertos, autorizado }));
        });
        $('form-headers').addEventListener('submit', (e) => {
            e.preventDefault();
            const url = $('inputUrl').value.trim();
            if (!url) return;
            const autorizado = $('autorizadoHeaders').checked;
            ejecutar('headers', () => postJSON(CONFIG.urls.headers, { url, autorizado }));
        });
    }

    // ---------------------------------------------------------------------
    // Página de detalle de un análisis guardado
    // ---------------------------------------------------------------------
    function iniciarDetalle() {
        const nodo = $('datos-analisis');
        const destino = $('resultado-detalle');
        if (!nodo || !destino) return;
        const { tipo, resultado } = JSON.parse(nodo.textContent);
        const render = RENDER[tipo];
        pintar(destino, render ? render(resultado || {}) : vacio('Tipo de análisis desconocido', 'error'));
    }

    /** Formularios con data-confirmar piden confirmación antes de enviarse. */
    function iniciarConfirmaciones() {
        document.querySelectorAll('form[data-confirmar]').forEach((form) => {
            form.addEventListener('submit', (e) => {
                if (!window.confirm(form.dataset.confirmar)) e.preventDefault();
            });
        });
    }

    function iniciar() {
        if ($('panel-logs')) {
            iniciarPestanas();
            iniciarLogs();
            iniciarFormularios();
        }
        iniciarDetalle();
        iniciarConfirmaciones();
    }

    document.addEventListener('DOMContentLoaded', iniciar);

    return { html, esc, pintar, RENDER };
})();
