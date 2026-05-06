#!/usr/bin/env python3
"""
security_gate.py — Herramienta automatizada de pruebas de seguridad
Trabajo Fin de Máster · Máster en Ciberseguridad · Curso 2025/2026
Autor: [NOMBRE ALUMNO] · Centro: [UNIVERSIDAD]

Descripción:
    Orquestador de análisis de seguridad que acepta un script YAML de
    configuración, ejecuta las herramientas especificadas (Nmap, Nikto,
    Nuclei), consolida los hallazgos y determina el veredicto del despliegue.

Uso:
    python3 security_gate.py <TARGET_IP> --script <script.yaml>

Códigos de salida (POSIX):
    0 → APROBADO  — ningún hallazgo supera el umbral HIGH/CRITICAL
    1 → BLOQUEADO — existe al menos un hallazgo HIGH o CRITICAL
"""

import subprocess
import json
import sys
import argparse
import datetime
from pathlib import Path

import yaml  # pip install pyyaml

# ── Mapa de severidad ─────────────────────────────────────────────────────────
SEVERITY_RANK = {
    'CRITICAL': 4,
    'HIGH':     3,
    'MEDIUM':   2,
    'LOW':      1,
    'INFO':     0,
}
BLOCK_THRESHOLD = 'HIGH'


class SecurityGate:
    """Orquestador del security gate."""

    def __init__(self, target: str, script_path: str,
                 out_dir: str = 'reports') -> None:
        self.target   = target
        self.script   = self._load_script(script_path)
        self.out_dir  = Path(out_dir)
        self.out_dir.mkdir(exist_ok=True)
        self.findings: list[dict] = []
        self.ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

    # ── Carga del script YAML ─────────────────────────────────────────────────
    def _load_script(self, path: str) -> dict:
        with open(path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)

    # ── Módulo Nmap ───────────────────────────────────────────────────────────
    def run_nmap(self, ports: str = '1-65535',
                 args: str = '-sV -sC -T4') -> None:
        print(f'[*] Nmap → {self.target} | puertos: {ports}')
        out = f'/tmp/nmap_{self.ts}.txt'
        cmd = (f'nmap {args} -p {ports} '
               f'--script vuln,ssl-cert,ssh-auth-methods '
               f'{self.target} -oN {out}')
        subprocess.run(cmd, shell=True, capture_output=True, text=True)
        self._parse_nmap(out)

    def _parse_nmap(self, filepath: str) -> None:
        """Parsea la salida de Nmap e identifica hallazgos de seguridad."""
        import re
        try:
            content = Path(filepath).read_text(encoding='utf-8', errors='ignore')
        except FileNotFoundError:
            return

        # MySQL expuesto externamente
        if re.search(r'3306/tcp\s+open', content):
            self._add_finding(
                'MySQL expuesto externamente (puerto 3306)',
                'HIGH',
                'El servidor MySQL es accesible desde la red externa. '
                'Debe bloquearse mediante firewall (UFW/iptables).',
                'nmap'
            )

        # SSH acepta autenticación por contraseña
        if re.search(r'ssh-auth-methods.*password', content, re.IGNORECASE):
            self._add_finding(
                'SSH acepta autenticación por contraseña',
                'HIGH',
                'PasswordAuthentication=yes expone el servidor a ataques '
                'de fuerza bruta. Configurar autenticación exclusiva por clave.',
                'nmap'
            )

        # Protocolos TLS obsoletos
        insecure = re.findall(r'(SSLv[23]|TLSv1\.0|TLSv1\.1)', content)
        for ver in set(insecure):
            self._add_finding(
                f'Protocolo {ver} habilitado (inseguro)',
                'HIGH',
                f'{ver} tiene vulnerabilidades conocidas. '
                'Configurar SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1',
                'nmap'
            )

    # ── Módulo Nikto ──────────────────────────────────────────────────────────
    def run_nikto(self) -> None:
        print(f'[*] Nikto → {self.target}')
        out = f'/tmp/nikto_{self.ts}.json'
        cmd = (f'nikto -h {self.target} '
               f'-Format json -output {out} -nointeractive')
        subprocess.run(cmd, shell=True, capture_output=True)
        self._parse_nikto(out)

    def _parse_nikto(self, filepath: str) -> None:
        try:
            data = json.loads(Path(filepath).read_text(encoding='utf-8'))
        except (FileNotFoundError, json.JSONDecodeError):
            return

        for vuln in data.get('vulnerabilities', []):
            severity = 'MEDIUM'
            desc = vuln.get('msg', 'Sin descripción')
            if 'X-Frame-Options' in desc or 'HSTS' in desc:
                severity = 'MEDIUM'
            self._add_finding(
                f'Nikto: {desc[:80]}',
                severity,
                desc,
                'nikto'
            )

    # ── Módulo Nuclei ─────────────────────────────────────────────────────────
    def run_nuclei(self, templates: str = '') -> None:
        print(f'[*] Nuclei → {self.target}')
        out  = f'/tmp/nuclei_{self.ts}.json'
        tmpl = f'-t {templates}' if templates else ''
        cmd  = (f'nuclei -u http://{self.target} '
                f'{tmpl} -json -o {out} -silent')
        subprocess.run(cmd, shell=True, capture_output=True)
        self._parse_nuclei(out)

    def _parse_nuclei(self, filepath: str) -> None:
        try:
            lines = Path(filepath).read_text(encoding='utf-8').strip().split('\n')
        except FileNotFoundError:
            return

        severity_map = {
            'critical': 'CRITICAL', 'high': 'HIGH',
            'medium': 'MEDIUM',     'low': 'LOW',
            'info': 'INFO',
        }
        for line in lines:
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                sev = severity_map.get(
                    entry.get('info', {}).get('severity', 'info').lower(),
                    'INFO'
                )
                self._add_finding(
                    entry.get('info', {}).get('name', 'Nuclei finding'),
                    sev,
                    entry.get('info', {}).get('description', ''),
                    'nuclei'
                )
            except json.JSONDecodeError:
                continue

    # ── Gestión de hallazgos ──────────────────────────────────────────────────
    def _add_finding(self, title: str, severity: str,
                     desc: str, tool: str) -> None:
        self.findings.append({
            'title':       title,
            'severity':    severity.upper(),
            'description': desc,
            'tool':        tool,
        })

    # ── Evaluador del gate ────────────────────────────────────────────────────
    def _evaluate_gate(self) -> tuple[bool, int]:
        max_sev = max(
            (SEVERITY_RANK.get(f['severity'], 0) for f in self.findings),
            default=0
        )
        blocked = max_sev >= SEVERITY_RANK[BLOCK_THRESHOLD]
        return blocked, max_sev

    # ── Generador de informe JSON + HTML ──────────────────────────────────────
    def generate_report(self) -> tuple[bool, Path]:
        blocked, _ = self._evaluate_gate()
        report = {
            'schema_version': '2.0',
            'timestamp':      self.ts,
            'target':         self.target,
            'findings':       self.findings,
            'total_findings': len(self.findings),
            'by_severity': {
                s: sum(1 for f in self.findings if f['severity'] == s)
                for s in SEVERITY_RANK
            },
            'deploy_blocked': blocked,
            'verdict':        'BLOCKED' if blocked else 'APPROVED',
        }
        json_path = self.out_dir / f'report_{self.ts}.json'
        with open(json_path, 'w', encoding='utf-8') as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
        self._generate_html(report)
        return blocked, json_path

    def _generate_html(self, report: dict) -> None:
        verdict_color = '#DC2626' if report['deploy_blocked'] else '#059669'
        verdict_text  = ('DESPLIEGUE BLOQUEADO'
                         if report['deploy_blocked'] else 'DESPLIEGUE APROBADO')
        sev_colors = {
            'CRITICAL': '#DC2626', 'HIGH': '#EA580C',
            'MEDIUM': '#D97706',   'LOW': '#2563EB', 'INFO': '#059669',
        }
        rows = ''
        for f in sorted(self.findings,
                        key=lambda x: SEVERITY_RANK.get(x['severity'], 0),
                        reverse=True):
            col = sev_colors.get(f['severity'], '#000')
            rows += (f'<tr>'
                     f'<td style="color:{col};font-weight:bold">{f["severity"]}</td>'
                     f'<td>{f["title"]}</td>'
                     f'<td>{f["tool"]}</td>'
                     f'<td>{f["description"]}</td>'
                     f'</tr>')
        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Security Gate Report — {report["timestamp"]}</title>
  <style>
    body {{ font-family: Arial, sans-serif; background: #0a1628; color: #cdd9e5; padding: 20px; }}
    h1   {{ color: {verdict_color}; }}
    table{{ width:100%; border-collapse: collapse; margin-top: 20px; }}
    th   {{ background: #1a3050; color: #00c8d4; padding: 8px; text-align: left; }}
    td   {{ padding: 8px; border-bottom: 1px solid #1e3a5a; font-size: 13px; }}
    .meta{{ color: #4a6580; margin-bottom: 10px; }}
  </style>
</head>
<body>
  <h1>{verdict_text}</h1>
  <p class="meta">Target: {report["target"]} &nbsp;|&nbsp;
     Timestamp: {report["timestamp"]} &nbsp;|&nbsp;
     Total hallazgos: {report["total_findings"]}</p>
  <table>
    <tr><th>Severidad</th><th>Título</th><th>Herramienta</th><th>Descripción</th></tr>
    {rows}
  </table>
</body>
</html>"""
        html_path = self.out_dir / f'report_{self.ts}.html'
        html_path.write_text(html, encoding='utf-8')

    # ── Punto de entrada ──────────────────────────────────────────────────────
    def run(self) -> None:
        for test in self.script.get('tests', []):
            tool   = test.get('tool')
            params = test.get('params', {})
            if   tool == 'nmap':   self.run_nmap(**params)
            elif tool == 'nikto':  self.run_nikto()
            elif tool == 'nuclei': self.run_nuclei(**params)

        blocked, path = self.generate_report()
        print(f'[+] Informe generado: {path}')
        if blocked:
            print('[!] DESPLIEGUE BLOQUEADO — Hallazgos HIGH/CRITICAL detectados.')
            print(f'[!] Revisar: {path.with_suffix(".html")}')
            sys.exit(1)
        print('[+] DESPLIEGUE APROBADO — Sin hallazgos bloqueantes.')
        sys.exit(0)


# ── CLI ───────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='security_gate.py — Security Gate TFM Ciberseguridad',
        epilog='Ejemplo: python3 security_gate.py 192.168.20.10 --script basic_scan.yaml'
    )
    parser.add_argument('target',
                        help='IP o hostname del sistema objetivo del análisis')
    parser.add_argument('--script', required=True,
                        help='Ruta al script YAML de configuración de pruebas')
    args = parser.parse_args()
    SecurityGate(args.target, args.script).run()
