#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Privacy Scanner -- HTML Report Generator

Generates a self-contained, offline-capable HTML report with:
  - Palantir Gotham-inspired intelligence briefing UI
  - i18n support (pt/en/es) with live language switcher
  - Interactive device rows with expand/collapse
  - Risk-level color coding and distribution visualization
  - Print-friendly mode
  - Copy-to-clipboard for IP/MAC addresses

Usage:
    python3 report_html.py \\
        --classifications /tmp/scan/classifications.txt \\
        --summary /tmp/scan/summary_counts.txt \\
        --output ./report.html \\
        --subnet "192.168.1.0/24" \\
        --interface "wlan0" \\
        --gateway "192.168.1.1" \\
        --scanner-ip "192.168.1.5" \\
        --duration "45" \\
        --mode "Full" \\
        --lang "pt"
"""

import argparse
import html
import os
import sys
from datetime import datetime


def parse_args():
    p = argparse.ArgumentParser(
        description="Generate HTML report for privacy surveillance scan"
    )
    p.add_argument("--classifications", required=True,
                   help="Path to classifications.txt (pipe-delimited)")
    p.add_argument("--summary", required=True,
                   help="Path to summary_counts.txt")
    p.add_argument("--output", required=True,
                   help="Output HTML file path")
    p.add_argument("--subnet", default="unknown")
    p.add_argument("--interface", default="unknown")
    p.add_argument("--gateway", default="unknown")
    p.add_argument("--scanner-ip", default="unknown")
    p.add_argument("--duration", default="0")
    p.add_argument("--mode", default="Full")
    p.add_argument("--lang", default="pt", choices=["pt", "en", "es"])
    return p.parse_args()


def load_devices(path):
    devices = []
    if not os.path.exists(path):
        return devices
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split("|", 7)
            if len(parts) >= 8:
                devices.append({
                    "risk": parts[0],
                    "ip": parts[1],
                    "mac": parts[2],
                    "manufacturer": parts[3],
                    "device_type": parts[4],
                    "ports": parts[5],
                    "evidence": parts[6],
                    "recommendation": parts[7],
                })
    return devices


def load_counts(path):
    counts = {"CRITICAL": 0, "HIGH": 0, "MODERATE": 0, "LOW": 0, "INFO": 0}
    if not os.path.exists(path):
        return counts
    with open(path, "r", encoding="utf-8") as f:
        parts = f.read().strip().split("|")
        if len(parts) == 5:
            keys = ["CRITICAL", "HIGH", "MODERATE", "LOW", "INFO"]
            for i, k in enumerate(keys):
                try:
                    counts[k] = int(parts[i])
                except ValueError:
                    counts[k] = 0
    return counts


def esc(s):
    """HTML-escape user data."""
    return html.escape(str(s)) if s else ""


# ---------------------------------------------------------------------------
# i18n dictionary -- every UI string in 3 languages
# Note: all values are plain text only (no HTML). HTML structure for bold
# emphasis in action steps is handled in the DOM, not in translations.
# ---------------------------------------------------------------------------
I18N = {
    # -- Page chrome
    "page_title": {
        "pt": "Relatório de Varredura de Vigilância",
        "en": "Surveillance Scan Report",
        "es": "Informe de Escaneo de Vigilancia",
    },
    "subtitle": {
        "pt": "Auditoria defensiva de privacidade \u2014 varredura WiFi para câmeras ocultas e dispositivos de gravação",
        "en": "Defensive privacy audit \u2014 WiFi network scan for hidden cameras and recording devices",
        "es": "Auditor\u00eda defensiva de privacidad \u2014 escaneo WiFi para c\u00e1maras ocultas y dispositivos de grabaci\u00f3n",
    },

    # -- Metadata labels
    "meta_date": {"pt": "Data", "en": "Date", "es": "Fecha"},
    "meta_network": {"pt": "Rede", "en": "Network", "es": "Red"},
    "meta_interface": {"pt": "Interface", "en": "Interface", "es": "Interfaz"},
    "meta_gateway": {"pt": "Gateway", "en": "Gateway", "es": "Gateway"},
    "meta_scanner_ip": {"pt": "IP do Scanner", "en": "Scanner IP", "es": "IP del Esc\u00e1ner"},
    "meta_duration": {"pt": "Duração", "en": "Duration", "es": "Duración"},
    "meta_mode": {"pt": "Modo", "en": "Mode", "es": "Modo"},

    # -- Risk level names
    "risk_CRITICAL": {"pt": "Crítico", "en": "Critical", "es": "Crítico"},
    "risk_HIGH": {"pt": "Alto", "en": "High", "es": "Alto"},
    "risk_MODERATE": {"pt": "Moderado", "en": "Moderate", "es": "Moderado"},
    "risk_LOW": {"pt": "Baixo", "en": "Low", "es": "Bajo"},
    "risk_INFO": {"pt": "Info", "en": "Info", "es": "Info"},

    # -- Risk summary section
    "risk_summary_title": {"pt": "Resumo de Riscos", "en": "Risk Summary", "es": "Resumen de Riesgos"},

    # -- Banner texts
    "banner_danger": {
        "pt": "DISPOSITIVOS DE VIGILÂNCIA PROVAVELMENTE PRESENTES",
        "en": "SURVEILLANCE DEVICES LIKELY PRESENT",
        "es": "DISPOSITIVOS DE VIGILANCIA PROBABLEMENTE PRESENTES",
    },
    "banner_warning": {
        "pt": "DISPOSITIVOS SUSPEITOS DETECTADOS",
        "en": "SUSPICIOUS DEVICES DETECTED",
        "es": "DISPOSITIVOS SOSPECHOSOS DETECTADOS",
    },
    "banner_safe": {
        "pt": "Nenhum dispositivo de vigilância confirmado",
        "en": "No confirmed surveillance devices found",
        "es": "No se encontraron dispositivos de vigilancia confirmados",
    },

    # -- Device detail labels
    "detail_mac": {"pt": "Endereço MAC", "en": "MAC Address", "es": "Dirección MAC"},
    "detail_manufacturer": {"pt": "Fabricante", "en": "Manufacturer", "es": "Fabricante"},
    "detail_type": {"pt": "Tipo", "en": "Type", "es": "Tipo"},
    "detail_ports": {"pt": "Portas Abertas", "en": "Open Ports", "es": "Puertos Abiertos"},
    "detail_evidence": {"pt": "Evidência", "en": "Evidence", "es": "Evidencia"},
    "detail_action": {"pt": "Ação", "en": "Action", "es": "Acción"},
    "detail_none_detected": {"pt": "Nenhuma detectada", "en": "None detected", "es": "Ninguno detectado"},

    # -- Devices section
    "devices_title": {"pt": "Dispositivos Encontrados", "en": "Devices Found", "es": "Dispositivos Encontrados"},

    # -- Buttons
    "btn_expand_all": {"pt": "Expandir tudo", "en": "Expand all", "es": "Expandir todo"},
    "btn_collapse_all": {"pt": "Recolher tudo", "en": "Collapse all", "es": "Colapsar todo"},
    "btn_print": {"pt": "Imprimir relatório", "en": "Print report", "es": "Imprimir informe"},
    "btn_copied": {"pt": "Copiado!", "en": "Copied!", "es": "Copiado!"},
    "btn_light_mode": {"pt": "Modo claro", "en": "Light mode", "es": "Modo claro"},
    "btn_dark_mode": {"pt": "Modo escuro", "en": "Dark mode", "es": "Modo oscuro"},

    # -- Action box: each step split into prefix (bold) + suffix (normal text)
    "action_title": {"pt": "O que fazer agora", "en": "What to do now", "es": "Qué hacer ahora"},
    "action_step1_bold": {"pt": "NÃO", "en": "DO NOT", "es": "NO"},
    "action_step1_text": {
        "pt": " desconecte ou mexa no dispositivo",
        "en": " disconnect or tamper with the device",
        "es": " desconecte ni manipule el dispositivo",
    },
    "action_step2_bold": {"pt": "Fotografe", "en": "Photograph", "es": "Fotografie"},
    "action_step2_text": {
        "pt": " o dispositivo e sua localização",
        "en": " the device and its location",
        "es": " el dispositivo y su ubicación",
    },
    "action_step3_bold": {"pt": "Salve este relatório", "en": "Save this report", "es": "Guarde este informe"},
    "action_step3_text": {
        "pt": " como evidência (imprima ou tire screenshot)",
        "en": " as evidence (print or screenshot)",
        "es": " como evidencia (imprima o capture pantalla)",
    },
    "action_step4_bold": {"pt": "Contate o Suporte Airbnb:", "en": "Contact Airbnb Support:", "es": "Contacte el Soporte de Airbnb:"},
    "action_step4_text": {
        "pt": " Abra o app > Suas Viagens > Obter Ajuda > Relatar uma preocupação de segurança. Linha de emergência: +1-855-424-7262",
        "en": " Open the app > Your Trips > Get Help > Report a safety concern. Emergency line: +1-855-424-7262",
        "es": " Abra la app > Sus Viajes > Obtener Ayuda > Reportar una preocupación de seguridad. L\u00ednea de emergencia: +1-855-424-7262",
    },
    "action_step5_bold": {"pt": "Saia do imóvel imediatamente", "en": "Leave the property immediately", "es": "Abandone la propiedad inmediatamente"},
    "action_step5_text": {
        "pt": " se não se sentir seguro",
        "en": " if you feel unsafe",
        "es": " si no se siente seguro",
    },
    "action_step6_bold": {"pt": "Autoridades locais:", "en": "Local law enforcement:", "es": "Autoridades locales:"},
    "action_step6_text": {
        "pt": " câmeras ocultas são ilegais na maioria das jurisdições",
        "en": " hidden cameras are illegal in most jurisdictions",
        "es": " las cámaras ocultas son ilegales en la mayoría de jurisdicciones",
    },

    # -- Limitations
    "limitations_title": {"pt": "Limitações da Varredura", "en": "Scan Limitations", "es": "Limitaciones del Escaneo"},
    "limitation_1": {
        "pt": "Cobre apenas dispositivos conectados à mesma rede WiFi",
        "en": "Only covers devices connected to the same WiFi network",
        "es": "Solo cubre dispositivos conectados a la misma red WiFi",
    },
    "limitation_2": {
        "pt": "Não detecta câmeras em uma VLAN separada ou rede cabeada",
        "en": "Cannot detect cameras on a separate VLAN or wired-only network",
        "es": "No detecta cámaras en una VLAN separada o red cableada",
    },
    "limitation_3": {
        "pt": "Não detecta câmeras com conexão celular (4G/LTE)",
        "en": "Cannot detect cellular-connected cameras (4G/LTE)",
        "es": "No detecta cámaras con conexión celular (4G/LTE)",
    },
    "limitation_4": {
        "pt": "Não detecta câmeras que estão desligadas",
        "en": "Cannot detect cameras that are powered off",
        "es": "No detecta cámaras que estén apagadas",
    },
    "limitation_5": {
        "pt": "Não detecta dispositivos usando randomização de MAC",
        "en": "Cannot detect devices using MAC address randomization",
        "es": "No detecta dispositivos que usen aleatorización de MAC",
    },
    "limitation_6": {
        "pt": "Não detecta câmeras com armazenamento local sem conexão de rede",
        "en": "Cannot detect local-storage cameras not connected to any network",
        "es": "No detecta cámaras de almacenamiento local sin conexión de red",
    },
    "limitation_7": {
        "pt": "Não detecta dispositivos de gravação somente de áudio",
        "en": "Cannot detect audio-only recording devices",
        "es": "No detecta dispositivos de grabación solo de audio",
    },
    "limitation_8": {
        "pt": "Para detecção abrangente, realize também uma inspeção física",
        "en": "For comprehensive detection, also perform a physical inspection",
        "es": "Para una detección completa, realice también una inspección física",
    },

    # -- Platform policies
    "policy_title": {"pt": "Política de Acomodações", "en": "Rental Policy", "es": "Política de Alojamiento"},
    "policy_text": {
        "pt": "As principais plataformas de hospedagem proíbem câmeras em espaços internos:",
        "en": "Major rental platforms prohibit cameras in indoor spaces:",
        "es": "Las principales plataformas de alojamiento prohíben cámaras en espacios interiores:",
    },
    "policy_airbnb": {
        "pt": "Airbnb — Proíbe todas as câmeras e dispositivos de gravação em espaços internos, mesmo desligados. Câmeras ocultas são sempre proibidas.",
        "en": "Airbnb — Prohibits all cameras and recording devices in indoor spaces, even if turned off. Hidden cameras are always prohibited.",
        "es": "Airbnb — Prohíbe todas las cámaras y dispositivos de grabación en espacios interiores, incluso apagados. Las cámaras ocultas siempre están prohibidas.",
    },
    "policy_booking": {
        "pt": "Booking.com — Câmeras permitidas apenas em áreas comuns, visíveis e divulgadas. Proibidas onde há expectativa de privacidade.",
        "en": "Booking.com — Cameras allowed only in common areas, must be visible and disclosed. Prohibited where guests expect privacy.",
        "es": "Booking.com — Cámaras permitidas solo en áreas comunes, visibles y divulgadas. Prohibidas donde se espera privacidad.",
    },
    "policy_vrbo": {
        "pt": "Vrbo — Câmeras internas proibidas. Câmeras externas permitidas apenas para segurança, apontadas para pontos de acesso e divulgadas.",
        "en": "Vrbo — Indoor cameras prohibited. Outdoor cameras allowed only for security, pointed at access points, and disclosed.",
        "es": "Vrbo — Cámaras interiores prohibidas. Cámaras exteriores permitidas solo para seguridad, apuntando a puntos de acceso y divulgadas.",
    },

    # -- Footer
    "footer_text": {
        "pt": "Gerado por Privacy Scanner",
        "en": "Generated by Privacy Scanner",
        "es": "Generado por Privacy Scanner",
    },
    "footer_purpose": {
        "pt": "Para proteção da privacidade do hóspede",
        "en": "For guest privacy protection",
        "es": "Para la protección de la privacidad del huésped",
    },
    "footer_credit": {
        "pt": "Idealizado por Tiago Maluta e produtizado com ajuda de IA",
        "en": "Designed by Tiago Maluta and built with the help of AI",
        "es": "Ideado por Tiago Maluta y producido con ayuda de IA",
    },

    # -- Risk distribution chart
    "distribution_title": {"pt": "Distribuição de Risco", "en": "Risk Distribution", "es": "Distribución de Riesgo"},

    # -- No devices message
    "no_devices": {
        "pt": "Nenhum dispositivo encontrado nesta varredura.",
        "en": "No devices found in this scan.",
        "es": "No se encontraron dispositivos en este escaneo.",
    },

    # -- Scan mode names
    "mode_full": {"pt": "Completo", "en": "Full", "es": "Completo"},
    "mode_quick": {"pt": "Rápido", "en": "Quick", "es": "Rápido"},
}


def build_i18n_js_object():
    """Build a nested JS object: { pt: { key: val, ... }, en: { ... }, es: { ... } }"""
    langs = ["pt", "en", "es"]
    parts = []
    for lang in langs:
        entries = []
        for key, translations in sorted(I18N.items()):
            val = translations.get(lang, "")
            # Escape for JS string literal (single-quoted)
            val_escaped = val.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n")
            entries.append(f"    '{key}': '{val_escaped}'")
        parts.append(f"  '{lang}': {{\n" + ",\n".join(entries) + "\n  }")
    return "{\n" + ",\n".join(parts) + "\n}"


# ---------------------------------------------------------------------------
# Risk level configuration
# ---------------------------------------------------------------------------
RISK_ORDER = ["CRITICAL", "HIGH", "MODERATE", "LOW", "INFO"]

RISK_COLORS = {
    "CRITICAL": "#ff3b3b",
    "HIGH": "#ff9f1c",
    "MODERATE": "#ffd60a",
    "LOW": "#00e676",
    "INFO": "#448aff",
}

RISK_BG = {
    "CRITICAL": "rgba(255,59,59,0.06)",
    "HIGH": "rgba(255,159,28,0.05)",
    "MODERATE": "rgba(255,214,10,0.04)",
    "LOW": "rgba(0,230,118,0.03)",
    "INFO": "rgba(68,138,255,0.03)",
}


def generate_html(args):
    devices = load_devices(args.classifications)
    counts = load_counts(args.summary)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lang = args.lang
    total_devices = sum(counts.values())

    has_critical = counts["CRITICAL"] > 0
    has_high = counts["HIGH"] > 0
    has_threats = has_critical or has_high

    # Banner state
    if has_critical:
        banner_key = "danger"
    elif has_high:
        banner_key = "warning"
    else:
        banner_key = "safe"

    # -- Build device HTML (table rows) ------------------------------------
    devices_html_parts = []
    for level in RISK_ORDER:
        level_devices = [d for d in devices if d["risk"] == level]
        if not level_devices:
            continue
        for idx, d in enumerate(level_devices):
            color = RISK_COLORS[d["risk"]]
            bg = RISK_BG[d["risk"]]
            is_threat = d["risk"] in ("CRITICAL", "HIGH")
            open_attr = " open" if is_threat else ""
            ports_display = esc(d["ports"]) if d["ports"] else '<span data-i18n="detail_none_detected">' + esc(I18N["detail_none_detected"][lang]) + '</span>'

            device_id = "dev-" + esc(d["ip"]).replace(".", "-") + "-" + str(idx)

            devices_html_parts.append(
                '<div class="device" style="border-left: 2px solid '
                + color + ';" id="' + device_id + '"' + open_attr + ">\n"
                '  <div class="device-header" onclick="toggleDevice(this)" aria-expanded="'
                + ("true" if is_threat else "false") + '">\n'
                '    <span class="chevron">&#9656;</span>\n'
                '    <span class="risk-badge" style="background:' + color
                + ';" data-i18n="risk_' + d["risk"] + '">'
                + esc(I18N.get("risk_" + d["risk"], {}).get(lang, d["risk"])) + "</span>\n"
                '    <span class="device-ip mono-data" onclick="event.stopPropagation();copyText(this)" title="Click to copy">'
                + esc(d["ip"]) + "</span>\n"
                '    <span class="device-mac mono-data" onclick="event.stopPropagation();copyText(this)" title="Click to copy">'
                + esc(d["mac"]) + "</span>\n"
                '    <span class="device-type">' + esc(d["device_type"]) + "</span>\n"
                "  </div>\n"
                '  <div class="device-body">\n'
                '    <div class="detail-grid">\n'
                '      <div class="detail-cell"><span class="detail-label" data-i18n="detail_manufacturer">'
                + esc(I18N["detail_manufacturer"][lang]) + '</span><span class="detail-value">'
                + esc(d["manufacturer"] or "Unknown") + "</span></div>\n"
                '      <div class="detail-cell"><span class="detail-label" data-i18n="detail_type">'
                + esc(I18N["detail_type"][lang]) + '</span><span class="detail-value">'
                + esc(d["device_type"]) + "</span></div>\n"
                '      <div class="detail-cell"><span class="detail-label" data-i18n="detail_ports">'
                + esc(I18N["detail_ports"][lang]) + '</span><span class="detail-value mono-data">'
                + ports_display + "</span></div>\n"
                '      <div class="detail-cell detail-wide"><span class="detail-label" data-i18n="detail_evidence">'
                + esc(I18N["detail_evidence"][lang]) + '</span><span class="detail-value">'
                + esc(d["evidence"]) + "</span></div>\n"
                '      <div class="detail-cell detail-wide"><span class="detail-label" data-i18n="detail_action">'
                + esc(I18N["detail_action"][lang]) + '</span><span class="detail-value action-text" style="color:'
                + color + ';">' + esc(d["recommendation"]) + "</span></div>\n"
                "    </div>\n"
                "  </div>\n"
                "</div>"
            )

    devices_html = "\n".join(devices_html_parts)

    # -- Action box (only if threats) --------------------------------------
    action_html = ""
    if has_threats:
        steps = []
        for i in range(1, 7):
            bold_key = f"action_step{i}_bold"
            text_key = f"action_step{i}_text"
            steps.append(
                f'    <li><strong data-i18n="{bold_key}">{esc(I18N[bold_key][lang])}</strong>'
                f'<span data-i18n="{text_key}">{esc(I18N[text_key][lang])}</span></li>'
            )
        steps_html = "\n".join(steps)
        action_html = (
            '<div class="action-box">\n'
            '  <div class="bracket-wrap">\n'
            '    <span class="bracket-l">[</span>\n'
            '    <h3><span class="alert-icon">!</span> <span data-i18n="action_title">'
            + esc(I18N["action_title"][lang]) + "</span></h3>\n"
            '    <span class="bracket-r">]</span>\n'
            '  </div>\n'
            "  <ol>\n" + steps_html + "\n  </ol>\n"
            "</div>"
        )

    # -- Risk distribution bar segments ------------------------------------
    dist_segments = ""
    if total_devices > 0:
        for level in RISK_ORDER:
            if counts[level] > 0:
                pct = (counts[level] / total_devices) * 100
                color = RISK_COLORS[level]
                dist_segments += f'<div class="dist-seg" style="width:{pct:.1f}%;background:{color};" title="{level}: {counts[level]}"></div>'

    # -- Summary cells -----------------------------------------------------
    summary_cells = ""
    for level in RISK_ORDER:
        color = RISK_COLORS[level]
        count = counts[level]
        summary_cells += (
            f'<div class="summary-cell">\n'
            f'  <div class="sc-count" data-count="{count}" style="color:{color}">0</div>\n'
            f'  <div class="sc-label" data-i18n="risk_{level}">{esc(I18N.get("risk_" + level, {}).get(lang, level))}</div>\n'
            f"</div>\n"
        )

    # -- Duration display --------------------------------------------------
    try:
        dur_secs = int(args.duration)
    except ValueError:
        dur_secs = 0
    if dur_secs >= 60:
        dur_display = f"{dur_secs // 60}m {dur_secs % 60}s"
    else:
        dur_display = f"{dur_secs}s"

    # -- Mode display ------------------------------------------------------
    if args.mode.lower() in ("quick", "rapido", "rápido"):
        mode_i18n_key = "mode_quick"
    else:
        mode_i18n_key = "mode_full"

    # -- i18n JS object ----------------------------------------------------
    i18n_js = build_i18n_js_object()

    # -- Limitations list --------------------------------------------------
    limitations_html = ""
    for i in range(1, 9):
        key = f"limitation_{i}"
        limitations_html += f'    <li data-i18n="{key}">{esc(I18N[key][lang])}</li>\n'

    # -- Build final HTML --------------------------------------------------
    html_content = f'''<!DOCTYPE html>
<html lang="{esc(lang)}" data-lang="{esc(lang)}" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{esc(I18N["page_title"][lang])} \u2014 {esc(now)}</title>
<style>
/* == Reset & Base ========================================================= */
*, *::before, *::after {{ margin: 0; padding: 0; box-sizing: border-box; }}

:root {{
  --bg-void: #0a0a0f;
  --bg-base: #0d0d14;
  --bg-surface: #111118;
  --bg-card: #13131c;
  --border-line: #1a1a2e;
  --border-dim: #141424;
  --text-primary: #c8cdd3;
  --text-secondary: #7a8494;
  --text-muted: #4a5568;
  --text-dim: #333d4d;
  --accent: #147af3;
  --accent-dim: rgba(20,122,243,0.12);
  --red: #ff3b3b;
  --orange: #ff9f1c;
  --amber: #ffd60a;
  --green: #00e676;
  --blue: #448aff;
  --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  --font-mono: "SF Mono", "Cascadia Code", "Fira Code", Consolas, "Liberation Mono", monospace;
  --transition: 0.2s cubic-bezier(0.4, 0, 0.2, 1);
}}

/* == Light Theme ========================================================== */
html[data-theme="light"] {{
  --bg-void: #f4f5f7;
  --bg-base: #ebedf0;
  --bg-surface: #ffffff;
  --bg-card: #ffffff;
  --border-line: #d1d5db;
  --border-dim: #e5e7eb;
  --text-primary: #1a1a2e;
  --text-secondary: #4a5568;
  --text-muted: #6b7280;
  --text-dim: #9ca3af;
  --accent: #0f62c5;
  --accent-dim: rgba(15,98,197,0.08);
  --red: #dc2626;
  --orange: #d97706;
  --amber: #b45309;
  --green: #059669;
  --blue: #2563eb;
}}

html[data-theme="light"] body {{
  background-image: radial-gradient(rgba(0,0,0,0.04) 1px, transparent 1px);
}}

html[data-theme="light"] .header {{
  background: #ffffff;
  border-bottom-color: #d1d5db;
}}

html[data-theme="light"] .header::before {{
  background: linear-gradient(90deg, transparent, rgba(15,98,197,0.04), transparent);
}}

html[data-theme="light"] .header::after {{
  background: linear-gradient(90deg, transparent, var(--accent), transparent);
  opacity: 0.3;
}}

html[data-theme="light"] .device[open] .device-body {{
  border-top-color: #e5e7eb;
}}

html[data-theme="light"] .policy a {{
  color: var(--accent);
}}

html {{ scroll-behavior: smooth; }}

body {{
  font-family: var(--font-sans);
  background: var(--bg-void);
  color: var(--text-primary);
  line-height: 1.6;
  min-height: 100vh;
  background-image: radial-gradient(rgba(255,255,255,0.03) 1px, transparent 1px);
  background-size: 24px 24px;
}}

/* == Animations =========================================================== */
@keyframes scanline {{
  0% {{ background-position: -200% 0; }}
  100% {{ background-position: 200% 0; }}
}}

@keyframes countUp {{
  from {{ opacity: 0; transform: translateY(4px); }}
  to {{ opacity: 1; transform: translateY(0); }}
}}

@keyframes fadeIn {{
  from {{ opacity: 0; }}
  to {{ opacity: 1; }}
}}

/* == Header =============================================================== */
.header {{
  background: var(--bg-base);
  border-bottom: 1px solid var(--border-line);
  padding: 0.9rem 1.5rem;
  position: relative;
  overflow: hidden;
}}

.header::after {{
  content: "";
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 1px;
  background: linear-gradient(90deg,
    transparent 0%,
    var(--accent) 30%,
    var(--accent) 70%,
    transparent 100%
  );
  opacity: 0.6;
}}

.header::before {{
  content: "";
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 100%;
  background: linear-gradient(90deg, transparent, rgba(20,122,243,0.02), transparent);
  background-size: 200% 100%;
  animation: scanline 8s linear infinite;
  pointer-events: none;
}}

.header-inner {{
  max-width: 1000px;
  margin: 0 auto;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
}}

.header-brand {{
  display: flex;
  align-items: center;
  gap: 0.75rem;
}}

.header-text h1 {{
  font-size: 0.82rem;
  font-weight: 700;
  letter-spacing: 0.2em;
  text-transform: uppercase;
  color: var(--text-primary);
}}

.header-text p {{
  font-size: 0.65rem;
  color: var(--text-muted);
  margin-top: 0.1rem;
  letter-spacing: 0.05em;
  max-width: 420px;
}}

.shield-icon {{
  font-size: 1.2rem;
  line-height: 1;
  opacity: 0.7;
}}

/* == Language Switcher ===================================================== */
.lang-switcher {{
  display: flex;
  gap: 1px;
  background: var(--border-dim);
  border-radius: 1px;
  padding: 1px;
  border: 1px solid var(--border-line);
  flex-shrink: 0;
}}

.lang-btn {{
  padding: 0.25rem 0.6rem;
  font-size: 0.62rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.15em;
  color: var(--text-muted);
  background: transparent;
  border: none;
  border-radius: 0;
  cursor: pointer;
  transition: all var(--transition);
  font-family: var(--font-mono);
}}

.lang-btn:hover {{
  color: var(--text-secondary);
  background: var(--bg-surface);
}}

.lang-btn.active {{
  color: var(--accent);
  background: var(--accent-dim);
}}

/* == Container ============================================================ */
.container {{
  max-width: 1000px;
  margin: 0 auto;
  padding: 1.25rem 1.5rem 3rem;
}}

/* == Metadata Strip ======================================================= */
.meta-strip {{
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0;
  font-family: var(--font-mono);
  font-size: 0.72rem;
  color: var(--text-secondary);
  border: 1px solid var(--border-line);
  border-radius: 1px;
  background: var(--bg-base);
  margin-bottom: 1.25rem;
  padding: 0.55rem 0;
  animation: fadeIn 0.4s ease-out both;
}}

.meta-entry {{
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  padding: 0 0.85rem;
  white-space: nowrap;
}}

.meta-entry:not(:last-child) {{
  border-right: 1px solid var(--border-line);
}}

.meta-key {{
  font-size: 0.6rem;
  text-transform: uppercase;
  letter-spacing: 0.15em;
  color: var(--text-muted);
  font-weight: 600;
}}

.meta-val {{
  color: var(--text-primary);
}}

/* == Status Banner ======================================================== */
.banner {{
  padding: 0.6rem 1rem;
  border-radius: 1px;
  margin-bottom: 1.25rem;
  font-weight: 700;
  font-size: 0.75rem;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  animation: fadeIn 0.5s ease-out both;
  animation-delay: 0.1s;
  position: relative;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  background: var(--bg-base);
  border: 1px solid var(--border-line);
}}

.banner-danger {{
  border-left: 3px solid var(--red);
  color: #ff6b6b;
}}

.banner-warning {{
  border-left: 3px solid var(--orange);
  color: #ffb347;
}}

.banner-safe {{
  border-left: 3px solid var(--green);
  color: #69f0ae;
}}

.banner-icon {{
  font-size: 0.9rem;
  flex-shrink: 0;
}}

/* == Section titles ======================================================= */
.section-title {{
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.15em;
  color: var(--text-muted);
  font-weight: 700;
  margin-bottom: 0.65rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}}

.section-title::after {{
  content: "";
  flex: 1;
  height: 1px;
  background: var(--border-dim);
}}

/* == Corner bracket decorations =========================================== */
.bracket-section {{
  position: relative;
  padding: 0.15rem 0;
}}

.bracket-section::before {{
  content: "[";
  position: absolute;
  left: -0.8rem;
  top: 0;
  color: var(--text-dim);
  font-family: var(--font-mono);
  font-size: 0.9rem;
}}

.bracket-section::after {{
  content: "]";
  position: absolute;
  right: -0.8rem;
  bottom: 0;
  color: var(--text-dim);
  font-family: var(--font-mono);
  font-size: 0.9rem;
}}

/* == Summary Row ========================================================== */
.summary-row {{
  display: flex;
  gap: 1px;
  margin-bottom: 1rem;
  animation: fadeIn 0.5s ease-out both;
  animation-delay: 0.2s;
  border: 1px solid var(--border-line);
  border-radius: 1px;
  overflow: hidden;
}}

.summary-cell {{
  flex: 1;
  background: var(--bg-base);
  padding: 0.65rem 0.5rem;
  text-align: center;
  border-right: 1px solid var(--border-dim);
}}

.summary-cell:last-child {{
  border-right: none;
}}

.sc-count {{
  font-size: 1.6rem;
  font-weight: 800;
  font-family: var(--font-mono);
  font-variant-numeric: tabular-nums;
  line-height: 1.2;
  animation: countUp 0.6s ease-out both;
}}

.sc-label {{
  font-size: 0.58rem;
  text-transform: uppercase;
  letter-spacing: 0.15em;
  color: var(--text-muted);
  font-weight: 600;
  margin-top: 0.15rem;
}}

/* == Risk Distribution Bar ================================================ */
.distribution {{
  margin-bottom: 1.5rem;
  animation: fadeIn 0.5s ease-out both;
  animation-delay: 0.3s;
}}

.dist-bar {{
  display: flex;
  height: 4px;
  border-radius: 0;
  overflow: hidden;
  background: var(--bg-surface);
  gap: 1px;
}}

.dist-seg {{
  border-radius: 0;
  transition: width 0.8s ease-out;
  min-width: 3px;
}}

/* == Toolbar ============================================================== */
.toolbar {{
  display: flex;
  align-items: center;
  gap: 0.4rem;
  margin-bottom: 0.75rem;
  flex-wrap: wrap;
}}

.toolbar-btn {{
  padding: 0.3rem 0.65rem;
  font-size: 0.65rem;
  font-weight: 600;
  font-family: var(--font-mono);
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--text-muted);
  background: transparent;
  border: 1px solid var(--border-line);
  border-radius: 1px;
  cursor: pointer;
  transition: all var(--transition);
  display: inline-flex;
  align-items: center;
  gap: 0.3rem;
}}

.toolbar-btn:hover {{
  color: var(--accent);
  border-color: var(--accent);
  background: var(--accent-dim);
}}

.toolbar-spacer {{
  flex: 1;
}}

/* == Device Rows ========================================================== */
.devices-section {{
  animation: fadeIn 0.5s ease-out both;
  animation-delay: 0.35s;
}}

.device {{
  border-radius: 0;
  margin-bottom: 1px;
  overflow: hidden;
  transition: background var(--transition);
  background: var(--bg-base);
  border: 1px solid var(--border-dim);
  border-left-width: 2px;
}}

.device:hover {{
  background: var(--bg-surface);
}}

.device-header {{
  padding: 0.5rem 0.85rem;
  display: flex;
  align-items: center;
  gap: 0.65rem;
  cursor: pointer;
  transition: background var(--transition);
  user-select: none;
  font-size: 0.8rem;
}}

.device-header:hover {{
  background: rgba(20,122,243,0.03);
}}

.chevron {{
  font-size: 0.6rem;
  color: var(--text-dim);
  transition: transform var(--transition);
  flex-shrink: 0;
  width: 0.7rem;
  text-align: center;
  font-family: var(--font-mono);
}}

.device[open] > .device-header .chevron {{
  transform: rotate(90deg);
  color: var(--accent);
}}

.risk-badge {{
  padding: 0.12rem 0.45rem;
  border-radius: 1px;
  font-size: 0.55rem;
  font-weight: 700;
  color: #0a0a0f;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  flex-shrink: 0;
  font-family: var(--font-mono);
}}

.device-ip {{
  font-weight: 600;
  color: var(--text-primary);
  cursor: copy;
  padding: 0.05rem 0.2rem;
  border-radius: 1px;
  transition: background var(--transition);
}}

.device-ip:hover {{
  background: var(--accent-dim);
  color: var(--accent);
}}

.device-mac {{
  color: var(--text-muted);
  cursor: copy;
  padding: 0.05rem 0.2rem;
  border-radius: 1px;
  transition: background var(--transition);
  font-size: 0.72rem;
}}

.device-mac:hover {{
  background: var(--accent-dim);
  color: var(--accent);
}}

.mono-data {{
  font-family: var(--font-mono);
  font-size: 0.78rem;
}}

.device-type {{
  color: var(--text-muted);
  font-size: 0.7rem;
  margin-left: auto;
  text-align: right;
  letter-spacing: 0.05em;
  text-transform: uppercase;
}}

.device-body {{
  max-height: 0;
  overflow: hidden;
  transition: max-height 0.35s cubic-bezier(0.4, 0, 0.2, 1),
              padding 0.35s cubic-bezier(0.4, 0, 0.2, 1),
              opacity 0.25s ease;
  opacity: 0;
  padding: 0 0.85rem;
  border-top: 0px solid var(--border-dim);
}}

.device[open] > .device-body {{
  max-height: 600px;
  padding: 0.6rem 0.85rem 0.75rem;
  opacity: 1;
  border-top-width: 1px;
}}

.detail-grid {{
  display: grid;
  grid-template-columns: 1fr 1fr 1fr;
  gap: 0.5rem;
}}

.detail-cell {{
  display: flex;
  flex-direction: column;
  gap: 0.1rem;
}}

.detail-wide {{
  grid-column: 1 / -1;
}}

.detail-label {{
  color: var(--text-dim);
  font-weight: 600;
  font-size: 0.58rem;
  text-transform: uppercase;
  letter-spacing: 0.15em;
  font-family: var(--font-sans);
}}

.detail-value {{
  color: var(--text-secondary);
  font-size: 0.78rem;
}}

.action-text {{
  font-weight: 600;
}}

/* == Action Box =========================================================== */
.action-box {{
  background: var(--bg-base);
  border: 1px solid var(--border-line);
  border-left: 3px solid var(--red);
  border-radius: 0;
  padding: 1.2rem 1.5rem;
  margin: 1.5rem 0;
  animation: fadeIn 0.5s ease-out both;
  animation-delay: 0.4s;
}}

.bracket-wrap {{
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 0.8rem;
}}

.bracket-l, .bracket-r {{
  font-family: var(--font-mono);
  font-size: 1.2rem;
  color: var(--text-dim);
  font-weight: 300;
}}

.alert-icon {{
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 1.2rem;
  height: 1.2rem;
  background: var(--red);
  color: #0a0a0f;
  font-size: 0.7rem;
  font-weight: 900;
  font-family: var(--font-mono);
  border-radius: 1px;
  flex-shrink: 0;
}}

.action-box h3 {{
  color: #ff6b6b;
  font-size: 0.75rem;
  letter-spacing: 0.15em;
  text-transform: uppercase;
  display: flex;
  align-items: center;
  gap: 0.4rem;
}}

.action-box ol {{
  padding-left: 1.5rem;
  color: var(--text-secondary);
}}

.action-box li {{
  margin-bottom: 0.5rem;
  font-size: 0.8rem;
  line-height: 1.5;
}}

.action-box li strong {{
  color: var(--text-primary);
}}

/* == Limitations ========================================================== */
.limitations {{
  background: var(--bg-base);
  border: 1px solid var(--border-line);
  border-radius: 0;
  padding: 1rem 1.25rem;
  margin-top: 1.5rem;
}}

.limitations h3 {{
  font-size: 0.7rem;
  letter-spacing: 0.15em;
  text-transform: uppercase;
  margin-bottom: 0.6rem;
  color: var(--text-muted);
  display: flex;
  align-items: center;
  gap: 0.4rem;
}}

.limitations ul {{
  padding-left: 1.25rem;
  color: var(--text-muted);
  font-size: 0.75rem;
}}

.limitations li {{
  margin-bottom: 0.25rem;
  line-height: 1.5;
}}

/* == Policy =============================================================== */
.policy {{
  background: var(--bg-base);
  border: 1px solid var(--border-line);
  border-left: 3px solid var(--accent);
  border-radius: 0;
  padding: 1rem 1.25rem;
  margin-top: 0.5rem;
}}

.policy h3 {{
  font-size: 0.7rem;
  letter-spacing: 0.15em;
  text-transform: uppercase;
  margin-bottom: 0.5rem;
  color: var(--text-muted);
  display: flex;
  align-items: center;
  gap: 0.4rem;
}}

.policy p {{
  color: var(--text-muted);
  font-size: 0.75rem;
  line-height: 1.6;
}}

/* == Footer =============================================================== */
.footer {{
  text-align: center;
  color: var(--text-dim);
  font-size: 0.62rem;
  font-family: var(--font-mono);
  letter-spacing: 0.1em;
  text-transform: uppercase;
  margin-top: 2rem;
  padding-top: 1rem;
  border-top: 1px solid var(--border-dim);
}}

/* == Copy Toast =========================================================== */
.toast {{
  position: fixed;
  bottom: 1.5rem;
  left: 50%;
  transform: translateX(-50%) translateY(10px);
  background: var(--bg-surface);
  color: var(--accent);
  padding: 0.4rem 1rem;
  border-radius: 1px;
  font-size: 0.72rem;
  font-weight: 600;
  font-family: var(--font-mono);
  opacity: 0;
  transition: all 0.2s ease;
  pointer-events: none;
  border: 1px solid var(--accent);
  z-index: 1000;
}}

.toast.show {{
  opacity: 1;
  transform: translateX(-50%) translateY(0);
}}

/* == Responsive =========================================================== */
@media (max-width: 720px) {{
  .header {{ padding: 0.75rem 1rem; }}
  .header-inner {{ flex-direction: column; gap: 0.5rem; align-items: flex-start; }}
  .container {{ padding: 1rem 1rem 2rem; }}
  .summary-row {{ flex-wrap: wrap; }}
  .summary-cell {{ flex: 0 0 calc(33.33% - 1px); }}
  .meta-strip {{ flex-direction: column; align-items: flex-start; padding: 0.5rem 0; }}
  .meta-entry {{ padding: 0.2rem 0.85rem; border-right: none !important; }}
  .detail-grid {{ grid-template-columns: 1fr; }}
  .device-mac {{ display: none; }}
  .device-type {{ display: none; }}
  .toolbar {{ gap: 0.25rem; }}
}}

@media (max-width: 480px) {{
  .summary-cell {{ flex: 0 0 calc(50% - 1px); }}
  .header-text h1 {{ font-size: 0.72rem; }}
}}

/* == Print Mode =========================================================== */
@media print {{
  * {{ color-adjust: exact; -webkit-print-color-adjust: exact; print-color-adjust: exact; }}

  body {{
    background: #ffffff !important;
    background-image: none !important;
    color: #1a1a1a !important;
    font-size: 10pt;
    padding: 0;
  }}

  .header {{
    background: #f5f5f5 !important;
    border-bottom: 2px solid #333;
    animation: none;
  }}

  .header::before, .header::after {{ display: none; }}
  .header-text h1 {{ color: #1a1a1a !important; }}
  .header-text p {{ color: #666 !important; }}

  .lang-switcher, .toolbar, .toast, #theme-toggle {{ display: none !important; }}

  .container {{ max-width: 100%; padding: 0.75rem; }}

  .meta-strip {{
    background: #f5f5f5 !important;
    border-color: #333 !important;
    color: #333 !important;
  }}
  .meta-key {{ color: #666 !important; }}
  .meta-val {{ color: #1a1a1a !important; }}

  .banner {{
    border-width: 1px !important;
    border-left-width: 3px !important;
    background: #f5f5f5 !important;
  }}
  .banner-danger {{ color: #cc0000 !important; }}
  .banner-warning {{ color: #cc6600 !important; }}
  .banner-safe {{ color: #006600 !important; }}

  .summary-row {{ border-color: #333 !important; }}
  .summary-cell {{
    background: #f5f5f5 !important;
    border-color: #ccc !important;
  }}
  .sc-label {{ color: #666 !important; }}

  .device {{
    break-inside: avoid;
    border-color: #999 !important;
    background: #fafafa !important;
    page-break-inside: avoid;
  }}

  .device-body {{
    max-height: none !important;
    padding: 0.5rem 0.85rem 0.75rem !important;
    opacity: 1 !important;
    overflow: visible !important;
    border-top-width: 1px !important;
  }}

  .chevron {{ display: none; }}

  .detail-label {{ color: #666 !important; }}
  .detail-value {{ color: #333 !important; }}

  .action-box {{
    background: #fff5f5 !important;
    border-color: #cc0000 !important;
    break-inside: avoid;
  }}
  .action-box h3 {{ color: #cc0000 !important; }}
  .action-box li {{ color: #333 !important; }}

  .limitations {{
    background: #fafafa !important;
    border-color: #999 !important;
    break-inside: avoid;
  }}
  .limitations h3 {{ color: #333 !important; }}
  .limitations li {{ color: #666 !important; }}

  .policy {{
    background: #f0f4ff !important;
    border-color: #999 !important;
    break-inside: avoid;
  }}
  .policy h3 {{ color: #333 !important; }}
  .policy p {{ color: #666 !important; }}

  .footer {{
    color: #999 !important;
    border-color: #ccc !important;
  }}

  .dist-bar {{ border: 1px solid #ccc; }}
}}
</style>
</head>
<body>

<!-- == Header ============================================================= -->
<div class="header">
  <div class="header-inner">
    <div class="header-brand">
      <span class="shield-icon" aria-hidden="true">&#x1f6e1;&#xfe0f;</span>
      <div class="header-text">
        <h1 data-i18n="page_title">{esc(I18N["page_title"][lang])}</h1>
        <p data-i18n="subtitle">{esc(I18N["subtitle"][lang])}</p>
      </div>
    </div>
    <div style="display:flex;align-items:center;gap:0.5rem">
      <button class="lang-btn" id="theme-toggle" onclick="toggleTheme()" title="Toggle theme" aria-label="Toggle light/dark theme" style="padding:0.25rem 0.5rem;border:1px solid var(--border-line);border-radius:1px">
        <span id="theme-icon">&#9789;</span>
      </button>
      <div class="lang-switcher" role="group" aria-label="Language">
        <button class="lang-btn{' active' if lang == 'pt' else ''}" onclick="setLang('pt')">PT</button>
        <button class="lang-btn{' active' if lang == 'en' else ''}" onclick="setLang('en')">EN</button>
        <button class="lang-btn{' active' if lang == 'es' else ''}" onclick="setLang('es')">ES</button>
      </div>
    </div>
  </div>
</div>

<!-- == Main Content ======================================================= -->
<div class="container">

  <!-- Metadata Strip -->
  <div class="meta-strip">
    <span class="meta-entry"><span class="meta-key" data-i18n="meta_date">{esc(I18N["meta_date"][lang])}</span> <span class="meta-val">{esc(now)}</span></span>
    <span class="meta-entry"><span class="meta-key" data-i18n="meta_network">{esc(I18N["meta_network"][lang])}</span> <span class="meta-val">{esc(args.subnet)}</span></span>
    <span class="meta-entry"><span class="meta-key" data-i18n="meta_interface">{esc(I18N["meta_interface"][lang])}</span> <span class="meta-val">{esc(args.interface)}</span></span>
    <span class="meta-entry"><span class="meta-key" data-i18n="meta_gateway">{esc(I18N["meta_gateway"][lang])}</span> <span class="meta-val">{esc(args.gateway)}</span></span>
    <span class="meta-entry"><span class="meta-key" data-i18n="meta_scanner_ip">{esc(I18N["meta_scanner_ip"][lang])}</span> <span class="meta-val">{esc(args.scanner_ip)}</span></span>
    <span class="meta-entry"><span class="meta-key" data-i18n="meta_duration">{esc(I18N["meta_duration"][lang])}</span> <span class="meta-val">{esc(dur_display)}</span></span>
    <span class="meta-entry"><span class="meta-key" data-i18n="meta_mode">{esc(I18N["meta_mode"][lang])}</span> <span class="meta-val" data-i18n="{mode_i18n_key}">{esc(I18N[mode_i18n_key][lang])}</span></span>
  </div>

  <!-- Status Banner -->
  <div class="banner banner-{banner_key}">
    <span class="banner-icon">{"&#x26a0;&#xfe0f;" if banner_key != "safe" else "&#x2705;"}</span>
    <span data-i18n="banner_{banner_key}">{esc(I18N["banner_" + banner_key][lang])}</span>
  </div>

  <!-- Risk Summary -->
  <div class="bracket-section">
    <div class="section-title" data-i18n="risk_summary_title">{esc(I18N["risk_summary_title"][lang])}</div>
    <div class="summary-row">
{summary_cells}    </div>
  </div>

  <!-- Risk Distribution -->
  <div class="distribution">
    <div class="section-title" data-i18n="distribution_title">{esc(I18N["distribution_title"][lang])}</div>
    <div class="dist-bar">
      {dist_segments if dist_segments else '<div class="dist-seg" style="width:100%;background:var(--bg-surface);"></div>'}
    </div>
  </div>

  <!-- Devices -->
  <div class="devices-section">
    <div class="toolbar">
      <div class="section-title" style="margin-bottom:0;" data-i18n="devices_title">{esc(I18N["devices_title"][lang])}</div>
      <div class="toolbar-spacer"></div>
      <button class="toolbar-btn" onclick="expandAll()">
        <span>&#9660;</span> <span data-i18n="btn_expand_all">{esc(I18N["btn_expand_all"][lang])}</span>
      </button>
      <button class="toolbar-btn" onclick="collapseAll()">
        <span>&#9650;</span> <span data-i18n="btn_collapse_all">{esc(I18N["btn_collapse_all"][lang])}</span>
      </button>
      <button class="toolbar-btn" onclick="window.print()">
        <span>&#128424;</span> <span data-i18n="btn_print">{esc(I18N["btn_print"][lang])}</span>
      </button>
    </div>

{devices_html if devices_html else '<p style="color:var(--text-muted);text-align:center;padding:2rem 0;font-family:var(--font-mono);font-size:0.75rem;letter-spacing:0.1em;" data-i18n="no_devices">' + esc(I18N["no_devices"][lang]) + "</p>"}
  </div>

  <!-- Action Box (threats only) -->
  {action_html}

  <!-- Limitations -->
  <div class="limitations">
    <h3><span>&#9881;&#65039;</span> <span data-i18n="limitations_title">{esc(I18N["limitations_title"][lang])}</span></h3>
    <ul>
{limitations_html}    </ul>
  </div>

  <!-- Rental Policy -->
  <div class="policy">
    <h3><span>&#128203;</span> <span data-i18n="policy_title">{esc(I18N["policy_title"][lang])}</span></h3>
    <p data-i18n="policy_text" style="margin-bottom:0.75rem;color:var(--text-secondary)">{esc(I18N["policy_text"][lang])}</p>
    <div style="display:flex;flex-direction:column;gap:0.5rem">
      <div style="display:flex;align-items:baseline;gap:0.5rem;padding:0.4rem 0.6rem;border-left:2px solid var(--red);background:rgba(255,59,59,0.04)">
        <a href="https://www.airbnb.com/help/article/3061" target="_blank" rel="noopener" style="color:var(--accent);font-family:var(--font-mono);font-size:0.75rem;white-space:nowrap;text-decoration:none">airbnb.com</a>
        <span data-i18n="policy_airbnb" style="font-size:0.8rem">{esc(I18N["policy_airbnb"][lang])}</span>
      </div>
      <div style="display:flex;align-items:baseline;gap:0.5rem;padding:0.4rem 0.6rem;border-left:2px solid var(--orange);background:rgba(255,159,28,0.04)">
        <a href="https://partner.booking.com/en-us/help/legal-security/security/requirements-and-regulations-surveillance-devices" target="_blank" rel="noopener" style="color:var(--accent);font-family:var(--font-mono);font-size:0.75rem;white-space:nowrap;text-decoration:none">booking.com</a>
        <span data-i18n="policy_booking" style="font-size:0.8rem">{esc(I18N["policy_booking"][lang])}</span>
      </div>
      <div style="display:flex;align-items:baseline;gap:0.5rem;padding:0.4rem 0.6rem;border-left:2px solid var(--amber);background:rgba(255,214,10,0.04)">
        <a href="https://www.vrbo.com/tlp/trust-and-safety/use-of-surveillance-policy" target="_blank" rel="noopener" style="color:var(--accent);font-family:var(--font-mono);font-size:0.75rem;white-space:nowrap;text-decoration:none">vrbo.com</a>
        <span data-i18n="policy_vrbo" style="font-size:0.8rem">{esc(I18N["policy_vrbo"][lang])}</span>
      </div>
    </div>
  </div>

  <!-- Footer -->
  <div class="footer">
    <span data-i18n="footer_text">{esc(I18N["footer_text"][lang])}</span> &middot; {esc(now)} &middot; <span data-i18n="footer_purpose">{esc(I18N["footer_purpose"][lang])}</span>
    <br><span data-i18n="footer_credit" style="opacity:0.6">{esc(I18N["footer_credit"][lang])}</span>
  </div>

</div>

<!-- == Copy Toast ========================================================= -->
<div class="toast" id="toast"></div>

<!-- == JavaScript ========================================================= -->
<script>
(function() {{
  "use strict";

  // -- i18n data ----------------------------------------------------------
  var i18n = {i18n_js};

  var currentLang = '{esc(lang)}';

  // -- Language Switcher --------------------------------------------------
  window.setLang = function(lang) {{
    currentLang = lang;
    document.documentElement.lang = lang;
    document.documentElement.setAttribute('data-lang', lang);

    // Update all translatable elements via textContent (safe, no HTML injection)
    var els = document.querySelectorAll('[data-i18n]');
    for (var i = 0; i < els.length; i++) {{
      var key = els[i].getAttribute('data-i18n');
      if (i18n[lang] && i18n[lang][key] !== undefined) {{
        els[i].textContent = i18n[lang][key];
      }}
    }}

    // Update active button
    var btns = document.querySelectorAll('.lang-btn');
    for (var j = 0; j < btns.length; j++) {{
      btns[j].classList.remove('active');
      if (btns[j].textContent.trim().toLowerCase() === lang) {{
        btns[j].classList.add('active');
      }}
    }}

    // Update page title
    if (i18n[lang] && i18n[lang]['page_title']) {{
      document.title = i18n[lang]['page_title'] + ' \\u2014 {esc(now)}';
    }}
  }};

  // -- Theme Toggle --------------------------------------------------------
  window.toggleTheme = function() {{
    var html = document.documentElement;
    var current = html.getAttribute('data-theme') || 'dark';
    var next = current === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-theme', next);
    var icon = document.getElementById('theme-icon');
    if (icon) icon.textContent = next === 'dark' ? '\u264d' : '\u2600';
  }};

  // -- Device Toggle ------------------------------------------------------
  window.toggleDevice = function(header) {{
    var device = header.parentElement;
    if (device.hasAttribute('open')) {{
      device.removeAttribute('open');
      header.setAttribute('aria-expanded', 'false');
    }} else {{
      device.setAttribute('open', '');
      header.setAttribute('aria-expanded', 'true');
    }}
  }};

  // -- Expand / Collapse All ----------------------------------------------
  window.expandAll = function() {{
    var devs = document.querySelectorAll('.device');
    for (var i = 0; i < devs.length; i++) {{
      devs[i].setAttribute('open', '');
      var hdr = devs[i].querySelector('.device-header');
      if (hdr) hdr.setAttribute('aria-expanded', 'true');
    }}
  }};

  window.collapseAll = function() {{
    var devs = document.querySelectorAll('.device');
    for (var i = 0; i < devs.length; i++) {{
      devs[i].removeAttribute('open');
      var hdr = devs[i].querySelector('.device-header');
      if (hdr) hdr.setAttribute('aria-expanded', 'false');
    }}
  }};

  // -- Copy to clipboard --------------------------------------------------
  var toastTimer = null;

  window.copyText = function(el) {{
    var text = el.textContent.trim();
    if (!text) return;

    if (navigator.clipboard && navigator.clipboard.writeText) {{
      navigator.clipboard.writeText(text).then(showToast).catch(fallbackCopy);
    }} else {{
      fallbackCopy();
    }}

    function fallbackCopy() {{
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      try {{ document.execCommand('copy'); showToast(); }}
      catch(e) {{}}
      document.body.removeChild(ta);
    }}

    function showToast() {{
      var toast = document.getElementById('toast');
      var msg = (i18n[currentLang] && i18n[currentLang]['btn_copied']) || 'Copied!';
      toast.textContent = msg + '  ' + text;
      toast.classList.add('show');
      if (toastTimer) clearTimeout(toastTimer);
      toastTimer = setTimeout(function() {{
        toast.classList.remove('show');
      }}, 1800);
    }}
  }};

  // -- Animate Count-Up on Load -------------------------------------------
  function animateCounts() {{
    var counters = document.querySelectorAll('.sc-count');
    for (var i = 0; i < counters.length; i++) {{
      (function(el) {{
        var target = parseInt(el.getAttribute('data-count'), 10) || 0;
        if (target === 0) {{
          el.textContent = '0';
          return;
        }}
        var duration = 600;
        var start = performance.now();
        function step(now) {{
          var elapsed = now - start;
          var progress = Math.min(elapsed / duration, 1);
          var eased = 1 - Math.pow(1 - progress, 3);
          el.textContent = Math.round(eased * target);
          if (progress < 1) requestAnimationFrame(step);
        }}
        requestAnimationFrame(step);
      }})(counters[i]);
    }}
  }}

  // -- Init ---------------------------------------------------------------
  if (document.readyState === 'loading') {{
    document.addEventListener('DOMContentLoaded', animateCounts);
  }} else {{
    animateCounts();
  }}

}})();
</script>
</body>
</html>'''

    return html_content


def main():
    args = parse_args()

    # Ensure output directory exists
    output_dir = os.path.dirname(args.output)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    html_content = generate_html(args)

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(args.output)


if __name__ == "__main__":
    main()
