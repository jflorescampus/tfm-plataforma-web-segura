<<<<<<< HEAD
# tfm-plataforma-web-segura
TFM Ciberseguridad 2025/2026 — Security gate automatizado: Nmap + Nikto + Nuclei integrado en pipeline CI/CD
=======
# TFM — Plataforma Web Segura
### Despliegue, Bastionado y Gestión de Incidentes

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![TFM](https://img.shields.io/badge/Máster-Ciberseguridad_2025/2026-navy)

## ¿Qué es esto?

`security_gate.py` es una herramienta automatizada de pruebas de seguridad
que actúa como **security gate** en el pipeline CI/CD. Ejecuta Nmap, Nikto
y Nuclei contra un servidor objetivo y devuelve:

- `exit 0` → **APROBADO** — el despliegue puede continuar
- `exit 1` → **BLOQUEADO** — existe al menos un hallazgo HIGH o CRITICAL

## Uso rápido

```bash
python3 security_gate.py 192.168.20.10 --script test_scripts/basic_scan.yaml
```

## Estructura del proyecto

```
tfm-plataforma-web-segura/
├── security_gate.py          # Orquestador principal
├── modules/
│   ├── nmap_scanner.py       # Módulo Nmap + NSE
│   ├── web_scanner.py        # Módulo Nikto + Nuclei
│   └── report_generator.py   # Informes JSON + HTML
├── test_scripts/
│   ├── basic_scan.yaml       # Pruebas pre-despliegue
│   └── post_incident.yaml    # Análisis post-incidente
├── deploy.sh                 # Integración CI/CD
└── docs/                     # Documentación adicional
```

## Dependencias

```bash
pip install pyyaml
sudo apt install nmap nikto
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

## Contexto académico

Desarrollado como Trabajo Fin de Máster en Ciberseguridad (2025/2026).
Integra tres asignaturas: PPS · Bastionado · Gestión de Incidentes.
>>>>>>> 95145c4 (feat: security_gate.py inicial con módulos Nmap, Nikto y Nuclei)
