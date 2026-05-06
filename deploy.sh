#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# deploy.sh — Script de despliegue con security gate integrado
# Compatible con Jenkins, GitLab CI, GitHub Actions, Bitbucket Pipelines.
#
# Comportamiento:
#   Si security_gate.py devuelve exit 1 → el script aborta con exit 1.
#   El orquestador CI/CD interpreta exit 1 como FAILED y bloquea el despliegue.
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

TARGET_IP='192.168.20.10'
SCAN_SCRIPT='test_scripts/basic_scan.yaml'
REPORT_DIR='reports'

echo '════════════════════════════════════════════════════════════════'
echo ' [PIPELINE] SECURITY GATE: iniciando validación pre-despliegue  '
echo '════════════════════════════════════════════════════════════════'

python3 security_gate.py "${TARGET_IP}" --script "${SCAN_SCRIPT}"
GATE_EXIT=$?

if [ "${GATE_EXIT}" -ne 0 ]; then
    echo ''
    echo '[✖] PIPELINE DETENIDO — El security gate bloqueó el despliegue.'
    echo "[✖] Revisar: ${REPORT_DIR}/"
    exit 1
fi

echo '[✔] Security gate superado. Procediendo con el despliegue...'

# Insertar aquí el comando de despliegue real:
# ansible-playbook deploy.yml --inventory hosts.ini
# docker-compose -f compose.prod.yml up -d --build
# kubectl apply -f manifests/
