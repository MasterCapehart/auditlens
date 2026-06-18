"""
AuditLens CLI entry point — complete command set.
"""

from __future__ import annotations

import argparse
import sys
import platform

from . import __version__
from .analyzer import run_static_analysis
from .runner import run_script_with_hook
from .log_watcher import watch_log_file, watch_xcode_simulator


def main():
    parser = argparse.ArgumentParser(
        description='AuditLens — SAST, SCA, Taint Analysis, Auditoría ISO y Post-Mortem.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            'Ejemplos:\n'
            '  auditlens scan ./proyecto\n'
            '  auditlens scan ./proyecto --format docx -o informe.docx\n'
            '  auditlens scan ./proyecto --format pdf -o reporte.pdf\n'
            '  auditlens scan ./proyecto --format sarif -o results.sarif\n'
            '  auditlens scan ./proyecto --severity HIGH --no-sca\n'
            '  auditlens scan ./proyecto --save-baseline .auditlens-baseline.json\n'
            '  auditlens scan ./proyecto --diff-baseline .auditlens-baseline.json\n'
            '  auditlens plan ./proyecto --empresa "MiEmpresa" --sistema "SistemaX v1.0"\n'
            '  auditlens plan ./proyecto --output plan_auditoria.docx\n'
            '  auditlens serve ./proyecto\n'
            '  auditlens serve ./proyecto --port 8080 --scan-first\n'
            '  auditlens watch-repo ./proyecto\n'
            '  auditlens history ./proyecto\n'
            '  auditlens run script.py\n'
            '  auditlens watch app.log\n'
            '  auditlens watch-xcode\n'
            '  auditlens correlate ./proyecto --format html\n'
            '  auditlens auto-fix ./proyecto --severity HIGH --dry-run\n'
            '  auditlens train-ml --training-data historic_findings.json\n'
            '  auditlens scan-distributed ./proyecto --workers 8\n'
            '  auditlens policy validate findings.json\n'
            '  auditlens lsp-server --port 2087\n'
            '  auditlens predict ./proyecto --horizon 90\n'
            '  auditlens supply-chain ./proyecto --format cyclonedx\n'
            '  auditlens gen-tests ./proyecto --framework pytest\n'
            '  auditlens tenant create mi-proyecto\n'
        ),
    )
    parser.add_argument('--version', action='version', version=f'auditlens {__version__}')

    subparsers = parser.add_subparsers(dest='command', help='Comandos disponibles')

    # ── scan ─────────────────────────────────────────────────────────────────
    sp = subparsers.add_parser('scan', help='Ejecutar SAST + SCA + Taint analysis.')
    sp.add_argument('path', help='Directorio o archivo a escanear.')
    sp.add_argument(
        '--format', choices=['text', 'sarif', 'pdf', 'json', 'docx', 'html', 'xlsx'], default='text',
        help='Formato de salida (default: text). html=reporte estático, xlsx=Excel, docx=Word completo.',
    )
    sp.add_argument('--output', '-o', default=None, help='Ruta del archivo de salida.')
    sp.add_argument(
        '--severity', choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], default='LOW',
        help='Severidad mínima a reportar (default: LOW).',
    )
    sp.add_argument('--no-sca', dest='no_sca', action='store_true',
                    help='Omitir SCA — más rápido para escaneos solo SAST.')
    sp.add_argument('--save-baseline', metavar='FILE',
                    help='Guardar hallazgos como baseline.')
    sp.add_argument('--diff-baseline', metavar='FILE',
                    help='Solo reportar hallazgos nuevos vs este baseline.')
    sp.add_argument('--no-history', dest='no_history', action='store_true',
                    help='No persistir este escaneo en la base de datos de historial.')
    sp.add_argument('--interprocedural', action='store_true',
                    help='Habilitar análisis de taint entre archivos (más lento, más preciso).')
    # Audit report metadata
    sp.add_argument('--empresa', default='Empresa', help='Nombre de la empresa (para informe Word).')
    sp.add_argument('--sistema', default='Sistema de Software', help='Nombre del sistema auditado.')
    sp.add_argument('--auditor', default='[Auditor por asignar]', help='Nombre del auditor líder.')
    sp.add_argument('--trimestre', default='primer trimestre de 2025',
                    help='Período de la auditoría.')
    sp.add_argument('--ai-fix', dest='ai_fix', action='store_true',
                    help='Solicitar sugerencias de fix a AI API para hallazgos HIGH+.')
    sp.add_argument('--ai-fix-severity', dest='ai_fix_severity', default='HIGH',
                    choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
                    help='Severidad mínima para AI fixes (default: HIGH).')
    sp.add_argument('--ai-fix-output', dest='ai_fix_output', default=None,
                    help='Guardar sugerencias AI en JSON en esta ruta.')

    # ── plan ─────────────────────────────────────────────────────────────────
    pp = subparsers.add_parser(
        'plan',
        help='Generar documento de planificación de auditoría (Word/PDF).',
    )
    pp.add_argument('path', help='Directorio del proyecto a planificar.')
    pp.add_argument('--empresa', default='Empresa', help='Nombre de la empresa.')
    pp.add_argument('--sistema', default='Sistema de Software', help='Nombre del sistema.')
    pp.add_argument('--auditor', default='[Auditor por asignar]', help='Auditor líder.')
    pp.add_argument('--trimestre', default='primer trimestre de 2025',
                    help='Período de la auditoría.')
    pp.add_argument('--output', '-o', default='plan_auditoria.docx',
                    help='Archivo de salida (default: plan_auditoria.docx).')
    pp.add_argument('--no-sca', dest='no_sca', action='store_true',
                    help='Omitir SCA en el análisis previo.')

    # ── serve ─────────────────────────────────────────────────────────────────
    svp = subparsers.add_parser('serve', help='Iniciar el dashboard web (requiere flask).')
    svp.add_argument('path', help='Directorio del proyecto a visualizar.')
    svp.add_argument('--port', type=int, default=8080, help='Puerto (default: 8080).')
    svp.add_argument('--host', default='127.0.0.1', help='Host (default: 127.0.0.1).')
    svp.add_argument('--no-browser', dest='no_browser', action='store_true',
                     help='No abrir el browser automáticamente.')
    svp.add_argument('--scan-first', dest='scan_first', action='store_true',
                     help='Ejecutar un escaneo antes de abrir el dashboard.')

    # ── watch-repo ────────────────────────────────────────────────────────────
    wrp = subparsers.add_parser('watch-repo', help='Re-escanear archivos al cambiar.')
    wrp.add_argument('path', help='Directorio del proyecto a monitorear.')
    wrp.add_argument(
        '--severity', choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], default='LOW',
        help='Severidad mínima (default: LOW).',
    )
    wrp.add_argument('--no-sca', dest='no_sca', action='store_true',
                     help='Omitir SCA en cada cambio.')

    # ── run ───────────────────────────────────────────────────────────────────
    rp = subparsers.add_parser('run', help='Ejecutar script Python con diagnóstico Post-Mortem.')
    rp.add_argument('script', help='Script Python a ejecutar.')
    rp.add_argument('args', nargs=argparse.REMAINDER, help='Argumentos para el script.')

    # ── watch ─────────────────────────────────────────────────────────────────
    wp = subparsers.add_parser('watch', help='Monitorear archivo de log en tiempo real.')
    wp.add_argument('logfile', help='Ruta del archivo de log.')

    # ── watch-xcode ───────────────────────────────────────────────────────────
    subparsers.add_parser('watch-xcode', help='Monitorear logs del Simulador iOS (macOS + Xcode).')

    # ── fix ───────────────────────────────────────────────────────────────────
    fp = subparsers.add_parser('fix', help='Obtener sugerencias de fix via AI API.')
    fp.add_argument('path', help='Directorio o archivo a escanear.')
    fp.add_argument('--severity', choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], default='HIGH',
                    help='Severidad mínima (default: HIGH).')
    fp.add_argument('--rule', default=None, help='Limitar a un rule_id específico.')
    fp.add_argument('--output', '-o', default=None, help='Guardar sugerencias en JSON.')
    fp.add_argument('--no-sca', dest='no_sca', action='store_true')
    fp.add_argument('--apply', action='store_true',
                    help='Aplicar parches directamente al código fuente (usa AI para generar diffs).')
    fp.add_argument('--dry-run', dest='dry_run', action='store_true',
                    help='Simular aplicación de parches sin modificar archivos (requiere --apply).')

    # ── multi-scan ────────────────────────────────────────────────────────────
    msp = subparsers.add_parser('multi-scan', help='Escanear múltiples proyectos y mostrar resumen unificado.')
    msp.add_argument('paths', nargs='+', help='Directorios a escanear.')
    msp.add_argument('--format', choices=['text', 'html', 'json', 'xlsx'], default='text',
                     help='Formato del reporte unificado.')
    msp.add_argument('--output', '-o', default=None)
    msp.add_argument('--severity', choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], default='LOW')
    msp.add_argument('--no-sca', dest='no_sca', action='store_true')

    # ── install-hook ──────────────────────────────────────────────────────────
    ihp = subparsers.add_parser('install-hook', help='Instalar pre-commit hook de seguridad en el repo.')
    ihp.add_argument('--path', default='.', help='Ruta del repositorio (default: directorio actual).')
    ihp.add_argument('--severity', choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], default='HIGH',
                     help='Severidad que bloquea el commit (default: HIGH).')

    # ── remove-hook ───────────────────────────────────────────────────────────
    rhp = subparsers.add_parser('remove-hook', help='Eliminar el pre-commit hook instalado por AuditLens.')
    rhp.add_argument('--path', default='.', help='Ruta del repositorio (default: directorio actual).')

    # ── web-scan ──────────────────────────────────────────────────────────────
    wsp = subparsers.add_parser(
        'web-scan',
        help='Auditoría de seguridad web (DAST) sobre una URL. Requiere autorización escrita.',
    )
    wsp.add_argument('url', help='URL objetivo (ej: https://empresa.com).')
    wsp.add_argument(
        '--authorized', action='store_true', required=True,
        help='OBLIGATORIO: confirma que tienes autorización escrita del dueño del sistema.',
    )
    wsp.add_argument(
        '--depth', type=int, default=2,
        help='Profundidad de crawling (default: 2). Mayor = más páginas analizadas.',
    )
    wsp.add_argument(
        '--max-pages', dest='max_pages', type=int, default=50,
        help='Máximo de páginas a rastrear (default: 50).',
    )
    wsp.add_argument(
        '--severity', choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], default='LOW',
        help='Severidad mínima a reportar (default: LOW).',
    )
    wsp.add_argument(
        '--format', choices=['text', 'docx', 'html', 'json', 'xlsx'], default='text',
        help='Formato del reporte (default: text).',
    )
    wsp.add_argument('--output', '-o', default=None, help='Ruta del archivo de salida.')
    wsp.add_argument('--no-verify-ssl', dest='no_verify_ssl', action='store_true',
                     help='Desactivar verificación SSL (para targets con cert self-signed).')
    wsp.add_argument('--skip-dast', dest='skip_dast', action='store_true',
                     help='Omitir probes activos (XSS, SQLi, redirect). Solo análisis pasivo.')
    wsp.add_argument('--empresa', default='Empresa', help='Nombre de la empresa (para informe).')
    wsp.add_argument('--sistema', default='Aplicación Web', help='Nombre del sistema auditado.')
    wsp.add_argument('--auditor', default='[Auditor por asignar]', help='Nombre del auditor.')
    wsp.add_argument('--autorizado-por', dest='autorizado_por', default='[Responsable técnico]',
                     help='Nombre del responsable que autorizó la auditoría.')

    # ── history ───────────────────────────────────────────────────────────────
    hp = subparsers.add_parser('history', help='Mostrar historial de escaneos.')
    hp.add_argument('path', help='Ruta del proyecto.')
    hp.add_argument('--limit', type=int, default=10, help='Número de escaneos a mostrar.')

    # ── git-scan ──────────────────────────────────────────────────────────────
    gsp = subparsers.add_parser('git-scan', help='Escanear historial de Git en busca de secretos commiteados.')
    gsp.add_argument('path', help='Ruta del repositorio git.')
    gsp.add_argument('--depth', type=int, default=200, help='Número máximo de commits a analizar (default: 200).')
    gsp.add_argument('--format', choices=['text', 'json', 'html', 'xlsx', 'csv'], default='text')
    gsp.add_argument('--output', '-o', default=None)

    # ── dns-check ─────────────────────────────────────────────────────────────
    dnsp = subparsers.add_parser('dns-check', help='Verificar seguridad DNS/Email (SPF, DMARC, DKIM, DNSSEC).')
    dnsp.add_argument('domain', help='Dominio a verificar (ej: empresa.com).')
    dnsp.add_argument('--dkim-selector', dest='dkim_selector', default='default',
                      help='Selector DKIM a verificar (default: default).')
    dnsp.add_argument('--format', choices=['text', 'json', 'html', 'xlsx', 'csv'], default='text')
    dnsp.add_argument('--output', '-o', default=None)

    # ── license-check ─────────────────────────────────────────────────────────
    lcp = subparsers.add_parser('license-check', help='Verificar compatibilidad de licencias de dependencias.')
    lcp.add_argument('path', help='Ruta del proyecto.')
    lcp.add_argument('--project-type', dest='project_type', choices=['commercial', 'opensource'],
                     default='commercial', help='Tipo de proyecto (default: commercial).')
    lcp.add_argument('--format', choices=['text', 'json', 'html', 'xlsx', 'csv'], default='text')
    lcp.add_argument('--output', '-o', default=None)

    # ── dep-confusion ─────────────────────────────────────────────────────────
    dcp = subparsers.add_parser('dep-confusion', help='Detectar vectores de dependency confusion.')
    dcp.add_argument('path', help='Ruta del proyecto.')
    dcp.add_argument('--format', choices=['text', 'json', 'html', 'xlsx', 'csv'], default='text')
    dcp.add_argument('--output', '-o', default=None)

    # ── api-scan ──────────────────────────────────────────────────────────────
    asp = subparsers.add_parser(
        'api-scan',
        help='Escanear endpoints de una API definida en OpenAPI/Swagger. Requiere autorización.',
    )
    asp.add_argument('spec', help='URL o ruta al archivo OpenAPI/Swagger (JSON o YAML).')
    asp.add_argument('--authorized', action='store_true', required=True,
                     help='OBLIGATORIO: confirma autorización para escanear la API.')
    asp.add_argument('--base-url', dest='base_url', default=None,
                     help='Base URL para las llamadas (sobreescribe la spec).')
    asp.add_argument('--token', default=None,
                     help='Bearer token para autenticación (o usa AUTH_TOKEN env var).')
    asp.add_argument('--max-endpoints', dest='max_endpoints', type=int, default=50)
    asp.add_argument('--format', choices=['text', 'json', 'html', 'xlsx', 'csv'], default='text')
    asp.add_argument('--output', '-o', default=None)

    # ── github-audit ──────────────────────────────────────────────────────────
    gap = subparsers.add_parser('github-audit', help='Auditar repositorio GitHub (branch protection, permisos, Actions).')
    gap.add_argument('repo', help='Repositorio en formato owner/repo.')
    gap.add_argument('--token', default=None, help='GitHub token (o usa GITHUB_TOKEN env var).')
    gap.add_argument('--format', choices=['text', 'json', 'html', 'xlsx', 'csv'], default='text')
    gap.add_argument('--output', '-o', default=None)

    # ── sbom ──────────────────────────────────────────────────────────────────
    sbp = subparsers.add_parser('sbom', help='Generar Software Bill of Materials (CycloneDX o SPDX).')
    sbp.add_argument('path', help='Ruta del proyecto.')
    sbp.add_argument('--format', choices=['cyclonedx', 'spdx'], default='cyclonedx',
                     help='Formato SBOM (default: cyclonedx).')
    sbp.add_argument('--output', '-o', default=None, help='Archivo de salida.')
    sbp.add_argument('--project-name', dest='project_name', default='',
                     help='Nombre del proyecto para el SBOM.')

    # ── threat-model ──────────────────────────────────────────────────────────
    tmp = subparsers.add_parser('threat-model', help='Generar modelo de amenazas STRIDE con AI.')
    tmp.add_argument('path', help='Ruta del proyecto a modelar.')
    tmp.add_argument('--output', '-o', default=None, help='Guardar modelo en JSON.')
    tmp.add_argument('--model', default='ai-model-latest', help='Modelo AI a usar.')

    # ── aws-audit ─────────────────────────────────────────────────────────────
    awsp = subparsers.add_parser('aws-audit', help='Auditar cuenta AWS (IAM, S3, Security Groups, CloudTrail).')
    awsp.add_argument('--region', default=None, help='Región AWS (default: AWS_DEFAULT_REGION).')
    awsp.add_argument('--profile', default=None, help='Perfil AWS credentials.')
    awsp.add_argument('--format', choices=['text', 'json', 'html', 'xlsx', 'csv'], default='text')
    awsp.add_argument('--output', '-o', default=None)

    # ── github-pr ─────────────────────────────────────────────────────────────
    prp = subparsers.add_parser('github-pr', help='Publicar hallazgos como comentarios en un PR de GitHub.')
    prp.add_argument('repo', help='Repositorio en formato owner/repo.')
    prp.add_argument('pr', type=int, help='Número del Pull Request.')
    prp.add_argument('findings', help='Ruta al archivo JSON de hallazgos (output de auditlens scan --format json).')
    prp.add_argument('--token', default=None, help='GitHub token (o usa GITHUB_TOKEN env var).')
    prp.add_argument('--severity', choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], default='MEDIUM',
                     help='Severidad mínima a publicar (default: MEDIUM).')

    # ── trending ──────────────────────────────────────────────────────────────
    trp = subparsers.add_parser('trending', help='Dashboard de tendencias de hallazgos a lo largo del tiempo.')
    trp.add_argument('--days', type=int, default=30, help='Días de historial a mostrar (default: 30).')
    trp.add_argument('--format', choices=['text', 'html'], default='text',
                     help='text=terminal, html=dashboard interactivo.')
    trp.add_argument('--output', '-o', default='trending.html',
                     help='Archivo HTML de salida (solo con --format html).')
    trp.add_argument('--db', default=None, help='Ruta al archivo de base de datos (default: ~/.auditlens/history.db).')

    # ── graph ─────────────────────────────────────────────────────────────────
    grp = subparsers.add_parser(
        'graph',
        help='Visualizar la superficie de ataque del proyecto como grafo interactivo D3.js.',
    )
    grp.add_argument('path', help='Directorio del proyecto.')
    grp.add_argument(
        '--serve', action='store_true',
        help='Iniciar servidor web y abrir el grafo en el browser (requiere Flask).',
    )
    grp.add_argument(
        '--output', '-o', default=None,
        help='Exportar grafo a archivo HTML o JSON (ej: graph.html, graph.json).',
    )
    grp.add_argument(
        '--port', type=int, default=7777,
        help='Puerto del servidor (default: 7777). Solo con --serve.',
    )
    grp.add_argument(
        '--max-files', dest='max_files', type=int, default=200,
        help='Máximo de archivos a analizar (default: 200).',
    )
    grp.add_argument(
        '--no-browser', dest='no_browser', action='store_true',
        help='No abrir browser automáticamente con --serve.',
    )

    # ── compliance ────────────────────────────────────────────────────────────
    comp_p = subparsers.add_parser(
        'compliance',
        help='Reporte compliance multi-framework (OWASP, CWE, PCI-DSS, SOC 2, GDPR, HIPAA, NIST, ISO 27001, CMF).',
    )
    comp_p.add_argument('findings', help='Archivo JSON de hallazgos (output de auditlens scan --format json).')
    comp_p.add_argument('--format', choices=['text', 'html', 'json'], default='text')
    comp_p.add_argument('--output', '-o', default=None)
    comp_p.add_argument(
        '--frameworks', nargs='+',
        choices=['owasp', 'iso27001', 'cmf', 'gdpr', 'hipaa', 'nist', 'lcib', 'all'],
        default=['all'],
        help='Frameworks a incluir (default: all).',
    )

    # ── iso27001 ──────────────────────────────────────────────────────────────
    iso_p = subparsers.add_parser('iso27001', help='Auditoría ISO 27001:2022 — score + reporte de controles.')
    iso_p.add_argument('path', help='Directorio del proyecto.')
    iso_p.add_argument('--empresa', default='Empresa')
    iso_p.add_argument('--auditor', default='')
    iso_p.add_argument('--format', choices=['text', 'html', 'json'], default='text')
    iso_p.add_argument('--output', '-o', default=None)
    iso_p.add_argument('--no-sca', dest='no_sca', action='store_true')
    iso_p.add_argument('--severity', choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], default='LOW')

    # ── cmf ───────────────────────────────────────────────────────────────────
    cmf_p = subparsers.add_parser('cmf', help='Auditoría CMF Circular 57 / Norma 461 (Chile).')
    cmf_p.add_argument('path', help='Directorio del proyecto.')
    cmf_p.add_argument('--empresa', default='Empresa')
    cmf_p.add_argument('--auditor', default='')
    cmf_p.add_argument('--format', choices=['text', 'html', 'json'], default='text')
    cmf_p.add_argument('--output', '-o', default=None)
    cmf_p.add_argument('--no-sca', dest='no_sca', action='store_true')
    cmf_p.add_argument('--severity', choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], default='LOW')

    # ── archaeology ───────────────────────────────────────────────────────────
    archp = subparsers.add_parser(
        'archaeology',
        help='Temporal Vulnerability Archaeology: mina el historial git y reconstruye el ciclo de vida de vulns.',
    )
    archp.add_argument('path', help='Ruta del repositorio git.')
    archp.add_argument(
        '--depth', type=int, default=500,
        help='Número máximo de commits a analizar (default: 500).',
    )
    archp.add_argument(
        '--output', '-o', default=None,
        help='Exportar reporte HTML a esta ruta (ej: archaeology.html).',
    )
    archp.add_argument(
        '--format', choices=['text', 'html', 'json'], default='text',
        help='Formato de salida (default: text).',
    )
    archp.add_argument(
        '--verbose', action='store_true',
        help='Mostrar detalles de cada commit analizado.',
    )

    # ── gcp-audit ─────────────────────────────────────────────────────────────
    gcpp = subparsers.add_parser('gcp-audit', help='Auditar cuenta GCP (IAM, Storage, Firewall, CloudSQL).')
    gcpp.add_argument('--project', required=True, help='ID del proyecto GCP.')
    gcpp.add_argument('--format', choices=['text', 'json', 'html', 'xlsx'], default='text')
    gcpp.add_argument('--output', '-o', default=None)

    # ── azure-audit ───────────────────────────────────────────────────────────
    azp = subparsers.add_parser('azure-audit', help='Auditar suscripción Azure (IAM, Storage, NSG, Key Vault, App Service).')
    azp.add_argument('--subscription', default=None, help='Subscription ID (opcional).')
    azp.add_argument('--format', choices=['text', 'json', 'html', 'xlsx'], default='text')
    azp.add_argument('--output', '-o', default=None)

    # ── graphql-scan ──────────────────────────────────────────────────────────
    gqlp = subparsers.add_parser('graphql-scan', help='Auditar API GraphQL (introspection, batching, depth). Requiere autorización.')
    gqlp.add_argument('endpoint', help='URL del endpoint GraphQL.')
    gqlp.add_argument('--authorized', action='store_true', required=True,
                      help='OBLIGATORIO: confirma autorización para escanear.')
    gqlp.add_argument('--token', default=None, help='Bearer token de autenticación.')
    gqlp.add_argument('--no-verify-ssl', dest='no_verify_ssl', action='store_true')
    gqlp.add_argument('--format', choices=['text', 'json'], default='text')
    gqlp.add_argument('--output', '-o', default=None)

    # ── yara-scan ─────────────────────────────────────────────────────────────
    yara_p = subparsers.add_parser('yara-scan', help='Detectar malware, webshells y backdoors en código fuente.')
    yara_p.add_argument('path', help='Directorio a escanear.')
    yara_p.add_argument('--format', choices=['text', 'json', 'html'], default='text')
    yara_p.add_argument('--output', '-o', default=None)

    # ── heatmap ───────────────────────────────────────────────────────────────
    hmap_p = subparsers.add_parser('heatmap', help='Generar risk heatmap + compliance radar chart.')
    hmap_p.add_argument('findings', help='Archivo JSON de hallazgos.')
    hmap_p.add_argument('--output', '-o', default='risk_heatmap.html')
    hmap_p.add_argument('--radar', default='compliance_radar.html', help='Ruta del radar chart.')

    # ── headers-check ────────────────────────────────────────────────────────
    hdr_p = subparsers.add_parser('headers-check', help='Auditar HTTP security headers, CORS y TLS de una URL.')
    hdr_p.add_argument('url', help='URL a analizar (ej: https://empresa.com).')
    hdr_p.add_argument('--no-verify-ssl', dest='no_verify_ssl', action='store_true')
    hdr_p.add_argument('--format', choices=['text', 'json', 'html'], default='text')
    hdr_p.add_argument('--output', '-o', default=None)

    # ── k8s-audit ─────────────────────────────────────────────────────────────
    k8sp = subparsers.add_parser('k8s-audit', help='Auditar manifiestos Kubernetes (RBAC, privilegios, secrets, network).')
    k8sp.add_argument('path', help='Directorio con manifiestos YAML de Kubernetes.')
    k8sp.add_argument('--format', choices=['text', 'json', 'html', 'xlsx'], default='text')
    k8sp.add_argument('--output', '-o', default=None)

    # ── ai-summary ────────────────────────────────────────────────────────────
    ais_p = subparsers.add_parser('ai-summary', help='Generar resumen ejecutivo + análisis de brecha con AI.')
    ais_p.add_argument('findings', help='Archivo JSON de hallazgos.')
    ais_p.add_argument('--empresa', default='Empresa')
    ais_p.add_argument('--framework', default=None,
                       choices=['ley21719', 'iso27001', 'cmf', 'gdpr', 'hipaa', 'nist', 'pci'],
                       help='Framework para análisis de brecha.')
    ais_p.add_argument('--mode', choices=['all', 'executive', 'gap', 'remediation'], default='all')
    ais_p.add_argument('--output', '-o', default=None)

    # ── propuesta ────────────────────────────────────────────────────────────
    prop_p = subparsers.add_parser('propuesta', help='Generar propuesta comercial + contrato de auditoría (Word).')
    prop_p.add_argument('path', help='Directorio del proyecto a cotizar.')
    prop_p.add_argument('--cliente', default='Empresa Cliente', help='Nombre del cliente.')
    prop_p.add_argument('--rut-cliente', dest='rut_cliente', default='')
    prop_p.add_argument('--contacto', default='')
    prop_p.add_argument('--auditora', default='AuditLens Security', help='Nombre empresa auditora.')
    prop_p.add_argument('--auditor', default='')
    prop_p.add_argument('--rut-auditor', dest='rut_auditor', default='')
    prop_p.add_argument('--frameworks', nargs='+', default=['sast', 'sca', 'ley21719'],
                        help='Frameworks a incluir: sast sca ley21719 iso27001 cmf gdpr hipaa pci dast git')
    prop_p.add_argument('--output', '-o', default=None)
    prop_p.add_argument('--no-contrato', dest='no_contrato', action='store_true')

    # ── track ─────────────────────────────────────────────────────────────────
    trk_p = subparsers.add_parser('track', help='Comparar dos scans y reportar progreso de remediación.')
    trk_p.add_argument('baseline', help='JSON de hallazgos de la auditoría anterior.')
    trk_p.add_argument('current', help='JSON de hallazgos actuales.')
    trk_p.add_argument('--format', choices=['text', 'html', 'json'], default='text')
    trk_p.add_argument('--output', '-o', default=None)

    # ── jwt-scan ──────────────────────────────────────────────────────────────
    jwt_p = subparsers.add_parser('jwt-scan', help='Detectar vulnerabilidades JWT en código fuente.')
    jwt_p.add_argument('path', help='Directorio o archivo a escanear.')
    jwt_p.add_argument('--format', choices=['text', 'json', 'html'], default='text')
    jwt_p.add_argument('--output', '-o', default=None)

    # ── ci-setup ──────────────────────────────────────────────────────────────
    ci_p = subparsers.add_parser('ci-setup', help='Generar templates CI/CD (GitHub Actions, GitLab, Azure DevOps, etc.).')
    ci_p.add_argument('path', nargs='?', default='.', help='Directorio del proyecto (default: .).')
    ci_p.add_argument(
        '--platform', choices=['github', 'gitlab', 'azure', 'bitbucket', 'makefile', 'precommit', 'all'],
        default='all', help='Plataforma CI (default: all — genera todos).',
    )
    ci_p.add_argument('--output', '-o', default=None, help='Ruta de salida (solo para plataforma única).')

    # ── ley21719 ──────────────────────────────────────────────────────────────
    ley_p = subparsers.add_parser(
        'ley21719',
        help='Auditoría de cumplimiento Ley 21.719 — Protección de Datos Personales (Chile).',
    )
    ley_p.add_argument('path', help='Directorio del proyecto a auditar.')
    ley_p.add_argument('--empresa', default='Empresa', help='Nombre de la empresa auditada.')
    ley_p.add_argument('--rut-empresa', dest='rut_empresa', default='', help='RUT de la empresa.')
    ley_p.add_argument('--auditor', default='', help='Nombre del auditor.')
    ley_p.add_argument('--rut-auditor', dest='rut_auditor', default='', help='RUT del auditor.')
    ley_p.add_argument(
        '--format', choices=['text', 'html', 'docx', 'json', 'all'], default='all',
        help='Formato de salida: all=genera HTML+docx (default), text=solo terminal.',
    )
    ley_p.add_argument('--output', '-o', default=None,
                       help='Nombre base de los archivos de salida (sin extensión).')
    ley_p.add_argument('--no-sca', dest='no_sca', action='store_true',
                       help='Omitir SCA en el análisis estático.')
    ley_p.add_argument('--severity', choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], default='LOW',
                       help='Severidad mínima para hallazgos SAST (default: LOW).')

    # ── schedule ──────────────────────────────────────────────────────────────
    sched_p = subparsers.add_parser('schedule', help='Gestionar escaneos programados (cron).')
    sched_sub = sched_p.add_subparsers(dest='sched_command')

    sched_add = sched_sub.add_parser('add', help='Agregar un escaneo programado.')
    sched_add.add_argument('--path', required=True, help='Ruta del proyecto a escanear.')
    sched_add.add_argument('--cron', required=True, help='Expresión cron (ej: "0 2 * * *" = 2am diario).')
    sched_add.add_argument('--email', default=None, help='Email para enviar el reporte.')
    sched_add.add_argument('--severity', choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], default='MEDIUM')
    sched_add.add_argument('--format', choices=['html', 'json', 'xlsx'], default='html')
    sched_add.add_argument('--label', default='', help='Nombre descriptivo del escaneo.')

    sched_sub.add_parser('list', help='Listar escaneos programados.')

    sched_rm = sched_sub.add_parser('remove', help='Eliminar un escaneo programado.')
    sched_rm.add_argument('id', help='ID del escaneo a eliminar.')

    sched_sub.add_parser('run-pending', help='Ejecutar escaneos pendientes (llamado por cron).')

    # ── correlate ─────────────────────────────────────────────────────────────
    corr_p = subparsers.add_parser('correlate', help='Analizar cadenas de ataque y correlación de hallazgos.')
    corr_p.add_argument('path', help='Directorio del proyecto.')
    corr_p.add_argument('--format', choices=['json', 'html'], default='json',
                        help='Formato de salida (default: json).')
    corr_p.add_argument('--output', '-o', default=None)

    # ── auto-fix ──────────────────────────────────────────────────────────────
    autofix_p = subparsers.add_parser('auto-fix', help='Remediación automatizada de hallazgos.')
    autofix_p.add_argument('path', help='Directorio del proyecto.')
    autofix_p.add_argument('--severity', choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], default='MEDIUM',
                           help='Severidad mínima para auto-fix (default: MEDIUM).')
    autofix_p.add_argument('--dry-run', dest='dry_run', action='store_true',
                           help='Simular sin modificar archivos.')
    autofix_p.add_argument('--output', '-o', default=None, help='Guardar reporte en JSON.')

    # ── train-ml ──────────────────────────────────────────────────────────────
    trainml_p = subparsers.add_parser('train-ml', help='Entrenar clasificador ML de falsos positivos.')
    trainml_p.add_argument('--training-data', dest='training_data', required=True,
                           help='Path a JSON con históricos de hallazgos etiquetados.')
    trainml_p.add_argument('--output', '-o', default='fp_classifier.pkl',
                           help='Ruta del modelo entrenado (default: fp_classifier.pkl).')

    # ── scan-distributed ──────────────────────────────────────────────────────
    distrib_p = subparsers.add_parser('scan-distributed', help='Escaneo paralelo con workers distribuidos.')
    distrib_p.add_argument('path', help='Directorio del proyecto.')
    distrib_p.add_argument('--workers', type=int, default=4,
                           help='Número de workers paralelos (default: 4).')
    distrib_p.add_argument('--format', choices=['text', 'json', 'html'], default='text')
    distrib_p.add_argument('--output', '-o', default=None)
    distrib_p.add_argument('--severity', choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], default='LOW')

    # ── policy ────────────────────────────────────────────────────────────────
    policy_p = subparsers.add_parser('policy', help='Gestión de políticas de seguridad.')
    policy_sub = policy_p.add_subparsers(dest='policy_command')

    policy_sub.add_parser('list', help='Listar políticas disponibles.')

    pol_val = policy_sub.add_parser('validate', help='Validar hallazgos contra políticas.')
    pol_val.add_argument('findings', help='Archivo JSON de hallazgos.')
    pol_val.add_argument('--policy', default=None, help='Path a archivo de política personalizada.')

    pol_test = policy_sub.add_parser('test', help='Probar una política sin aplicarla.')
    pol_test.add_argument('policy', help='Path a archivo de política.')
    pol_test.add_argument('--sample', default=None, help='JSON de hallazgos de prueba.')

    # ── lsp-server ────────────────────────────────────────────────────────────
    lsp_p = subparsers.add_parser('lsp-server', help='Iniciar LSP server para integración IDE.')
    lsp_p.add_argument('--port', type=int, default=2087,
                       help='Puerto del servidor LSP (default: 2087).')
    lsp_p.add_argument('--stdio', action='store_true',
                       help='Usar stdio en lugar de socket TCP.')

    # ── predict ───────────────────────────────────────────────────────────────
    pred_p = subparsers.add_parser('predict', help='Dashboard predictivo de compliance y riesgos.')
    pred_p.add_argument('path', help='Directorio del proyecto.')
    pred_p.add_argument('--output', '-o', default='predictive_dashboard.html',
                        help='Ruta del dashboard HTML (default: predictive_dashboard.html).')
    pred_p.add_argument('--horizon', type=int, default=90,
                        help='Días futuros a predecir (default: 90).')

    # ── supply-chain ──────────────────────────────────────────────────────────
    sc_p = subparsers.add_parser('supply-chain', help='Análisis de cadena de suministro (SBOM + vulnerabilidades).')
    sc_p.add_argument('path', help='Directorio del proyecto.')
    sc_p.add_argument('--output', '-o', default='supply_chain_report.json',
                      help='Ruta del reporte SBOM (default: supply_chain_report.json).')
    sc_p.add_argument('--format', choices=['json', 'html', 'cyclonedx'], default='json')

    # ── gen-tests ─────────────────────────────────────────────────────────────
    gentest_p = subparsers.add_parser('gen-tests', help='Generar tests de seguridad automatizados.')
    gentest_p.add_argument('path', help='Directorio del proyecto.')
    gentest_p.add_argument('--output-dir', dest='output_dir', default='./security_tests',
                           help='Directorio de salida para tests (default: ./security_tests).')
    gentest_p.add_argument('--framework', choices=['pytest', 'unittest', 'jest'], default='pytest',
                           help='Framework de testing (default: pytest).')

    # ── tenant ────────────────────────────────────────────────────────────────
    tenant_p = subparsers.add_parser('tenant', help='Gestión multi-tenant (aislamiento de escaneos).')
    tenant_sub = tenant_p.add_subparsers(dest='tenant_command')

    ten_create = tenant_sub.add_parser('create', help='Crear nuevo tenant.')
    ten_create.add_argument('name', help='Nombre del tenant.')
    ten_create.add_argument('--description', default='', help='Descripción del tenant.')

    tenant_sub.add_parser('list', help='Listar tenants existentes.')

    ten_del = tenant_sub.add_parser('delete', help='Eliminar un tenant.')
    ten_del.add_argument('name', help='Nombre del tenant a eliminar.')

    args = parser.parse_args()

    if args.command == 'scan':
        exit_code = run_static_analysis(
            args.path,
            export_sarif=(args.format == 'sarif'),
            export_pdf=(args.format == 'pdf'),
            export_json=(args.format == 'json'),
            export_docx=(args.format == 'docx'),
            export_html=(args.format == 'html'),
            export_xlsx=(args.format == 'xlsx'),
            output_path=args.output,
            min_severity=args.severity,
            run_sca=not args.no_sca,
            save_baseline=args.save_baseline,
            diff_baseline=args.diff_baseline,
            record_history=not args.no_history,
            interprocedural=getattr(args, 'interprocedural', False),
            empresa=getattr(args, 'empresa', 'Empresa'),
            sistema=getattr(args, 'sistema', 'Sistema de Software'),
            auditor=getattr(args, 'auditor', '[Auditor por asignar]'),
            trimestre=getattr(args, 'trimestre', 'primer trimestre de 2025'),
            ai_fix=getattr(args, 'ai_fix', False),
            ai_fix_severity=getattr(args, 'ai_fix_severity', 'HIGH'),
            ai_fix_output=getattr(args, 'ai_fix_output', None),
        )
        sys.exit(exit_code)

    elif args.command == 'plan':
        _run_plan_command(args)

    elif args.command == 'serve':
        from .dashboard import serve_dashboard
        serve_dashboard(
            scan_path=args.path,
            port=args.port,
            host=args.host,
            open_browser=not args.no_browser,
            scan_first=args.scan_first,
        )

    elif args.command == 'watch-repo':
        from .watcher import watch_repo
        watch_repo(
            root_path=args.path,
            min_severity=args.severity,
            run_sca=not args.no_sca,
        )

    elif args.command == 'run':
        run_script_with_hook(args.script, args.args)

    elif args.command == 'watch':
        watch_log_file(args.logfile)

    elif args.command == 'watch-xcode':
        if platform.system() != 'Darwin':
            print('\033[91m[ERROR]\033[0m watch-xcode requiere macOS con Xcode instalado.')
            sys.exit(1)
        watch_xcode_simulator()

    elif args.command == 'fix':
        _run_fix_command(args)

    elif args.command == 'multi-scan':
        from .multi_scan import run_multi_scan
        exit_code = run_multi_scan(
            paths=args.paths,
            min_severity=args.severity,
            run_sca=not args.no_sca,
            export_format=args.format,
            output_path=args.output,
        )
        sys.exit(exit_code)

    elif args.command == 'install-hook':
        from .pre_commit import install_hook
        install_hook(repo_path=args.path, severity=args.severity)

    elif args.command == 'remove-hook':
        from .pre_commit import remove_hook
        remove_hook(repo_path=args.path)

    elif args.command == 'web-scan':
        _run_web_scan_command(args)

    elif args.command == 'history':
        from .history import print_history
        print_history(args.path, limit=args.limit)

    elif args.command == 'git-scan':
        _run_git_scan_command(args)

    elif args.command == 'dns-check':
        _run_dns_check_command(args)

    elif args.command == 'license-check':
        _run_license_check_command(args)

    elif args.command == 'dep-confusion':
        _run_dep_confusion_command(args)

    elif args.command == 'api-scan':
        _run_api_scan_command(args)

    elif args.command == 'github-audit':
        _run_github_audit_command(args)

    elif args.command == 'sbom':
        _run_sbom_command(args)

    elif args.command == 'threat-model':
        _run_threat_model_command(args)

    elif args.command == 'aws-audit':
        _run_aws_audit_command(args)

    elif args.command == 'github-pr':
        _run_github_pr_command(args)

    elif args.command == 'trending':
        _run_trending_command(args)

    elif args.command == 'graph':
        _run_graph_command(args)

    elif args.command == 'compliance':
        _run_compliance_command(args)

    elif args.command == 'iso27001':
        _run_iso27001_command(args)

    elif args.command == 'cmf':
        _run_cmf_command(args)

    elif args.command == 'archaeology':
        _run_archaeology_command(args)

    elif args.command == 'gcp-audit':
        _run_gcp_audit_command(args)

    elif args.command == 'azure-audit':
        _run_azure_audit_command(args)

    elif args.command == 'graphql-scan':
        _run_graphql_scan_command(args)

    elif args.command == 'yara-scan':
        _run_yara_scan_command(args)

    elif args.command == 'heatmap':
        _run_heatmap_command(args)

    elif args.command == 'headers-check':
        _run_headers_check_command(args)

    elif args.command == 'k8s-audit':
        _run_k8s_audit_command(args)

    elif args.command == 'ai-summary':
        _run_ai_summary_command(args)

    elif args.command == 'propuesta':
        _run_propuesta_command(args)

    elif args.command == 'track':
        _run_track_command(args)

    elif args.command == 'jwt-scan':
        _run_jwt_scan_command(args)

    elif args.command == 'ci-setup':
        _run_ci_setup_command(args)

    elif args.command == 'ley21719':
        _run_ley21719_command(args)

    elif args.command == 'schedule':
        _run_schedule_command(args)

    elif args.command == 'correlate':
        _run_correlate_command(args)

    elif args.command == 'auto-fix':
        _run_auto_fix_command(args)

    elif args.command == 'train-ml':
        _run_train_ml_command(args)

    elif args.command == 'scan-distributed':
        _run_scan_distributed_command(args)

    elif args.command == 'policy':
        _run_policy_command(args)

    elif args.command == 'lsp-server':
        _run_lsp_server_command(args)

    elif args.command == 'predict':
        _run_predict_command(args)

    elif args.command == 'supply-chain':
        _run_supply_chain_command(args)

    elif args.command == 'gen-tests':
        _run_gen_tests_command(args)

    elif args.command == 'tenant':
        _run_tenant_command(args)

    else:
        parser.print_help()


def _run_web_scan_command(args):
    """Execute 'auditlens web-scan' — DAST + report generation."""
    import json as _json
    from .web_scanner import run_web_scan

    print(
        '\n\033[93m[AuditLens]\033[0m AVISO LEGAL: Este módulo realiza pruebas activas sobre sistemas en vivo.\n'
        '  Úsalo solo con autorización escrita del propietario del sistema.\n'
    )

    result = run_web_scan(
        url=args.url,
        depth=args.depth,
        max_pages=args.max_pages,
        min_severity=args.severity,
        verify_ssl=not args.no_verify_ssl,
        skip_dast_probes=args.skip_dast,
    )

    fmt = args.format
    out = args.output

    if fmt == 'docx':
        from .web_docx_exporter import generate_web_docx_report
        out = out or 'informe_auditoria_web.docx'
        generate_web_docx_report(
            scan_result=result,
            output_path=out,
            empresa=args.empresa,
            sistema=args.sistema,
            auditor=args.auditor,
            authorized_by=args.autorizado_por,
        )

    elif fmt == 'html':
        from .html_exporter import generate_html_report
        out = out or 'audit_web_report.html'
        generate_html_report(result.findings, scan_path=args.url, output_path=out)

    elif fmt == 'xlsx':
        from .xlsx_exporter import generate_xlsx_report
        out = out or 'audit_web_report.xlsx'
        generate_xlsx_report(result.findings, scan_path=args.url, output_path=out)

    elif fmt == 'json':
        out = out or 'audit_web_results.json'
        data = {
            'target': result.target_url,
            'scan_time': result.scan_time,
            'duration_seconds': round(result.scan_duration, 1),
            'pages_scanned': result.pages_scanned,
            'js_files': result.js_files_scanned,
            'forms': result.forms_scanned,
            'tech_stack': result.tech_stack,
            'findings': result.findings,
        }
        with open(out, 'w', encoding='utf-8') as fh:
            _json.dump(data, fh, indent=2, default=str)
        print(f'\033[92m[AuditLens]\033[0m JSON guardado: {out}')

    has_critical = any(f['severity'] in ('CRITICAL', 'HIGH') for f in result.findings)
    sys.exit(1 if has_critical else 0)


def _run_fix_command(args):
    """Run 'auditlens fix' — scan then get AI fix suggestions."""
    import os
    from .rules_engine import RulesEngine
    from .taint_analyzer import TaintAnalyzer
    from .analyzer import analyze_file, _SUPPORTED_EXTENSIONS
    from .ai_fix import run_ai_fix

    findings_acc: list = []
    rules_engine = RulesEngine()
    taint_analyzer = TaintAnalyzer()
    exclude_dirs = {'venv', '.venv', 'env', '.env', 'node_modules', '.git', '__pycache__', 'build', 'dist'}

    if os.path.isfile(args.path):
        analyze_file(args.path, rules_engine, taint_analyzer, min_severity=args.severity,
                     all_findings_accumulator=findings_acc)
    elif os.path.isdir(args.path):
        for dirpath, dirnames, files in os.walk(args.path):
            dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                base = fname.lower()
                if ext in _SUPPORTED_EXTENSIONS or base.startswith('dockerfile'):
                    analyze_file(os.path.join(dirpath, fname), rules_engine, taint_analyzer,
                                 min_severity=args.severity, all_findings_accumulator=findings_acc)

    run_ai_fix(
        findings_acc,
        min_severity=args.severity,
        rule_filter=args.rule,
        output_path=args.output,
        apply_patches=getattr(args, 'apply', False),
        dry_run=getattr(args, 'dry_run', False),
        project_root=args.path if os.path.isdir(args.path) else os.path.dirname(args.path),
    )


def _run_plan_command(args):
    """
    Execute 'auditlens plan' — generates a single unified Word document
    containing both the audit planning sections AND the scan results.
    """
    import os
    from .audit_planner import generate_audit_plan
    from .docx_exporter import generate_docx_report
    from .rules_engine import RulesEngine
    from .taint_analyzer import TaintAnalyzer
    from .analyzer import analyze_file, _SUPPORTED_EXTENSIONS

    print(f'\033[94m[AuditLens]\033[0m Generando documento de auditoría unificado...\n')

    # ── Collect findings ──────────────────────────────────────────────────────
    print('\033[94m[AuditLens]\033[0m Escaneando código fuente...')
    findings_acc: list = []
    rules_engine = RulesEngine()
    taint_analyzer = TaintAnalyzer()
    exclude_dirs = {
        'venv', '.venv', 'env', '.env', 'node_modules', '.git',
        '__pycache__', 'build', 'dist', 'site-packages',
    }

    for dirpath, dirnames, files in os.walk(args.path):
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in _SUPPORTED_EXTENSIONS:
                analyze_file(
                    os.path.join(dirpath, fname),
                    rules_engine, taint_analyzer,
                    min_severity='LOW',
                    all_findings_accumulator=findings_acc,
                )

    # ── Generate unified document ─────────────────────────────────────────────
    output = args.output
    if not output.endswith('.docx'):
        output = output + '.docx'

    try:
        generate_docx_report(
            findings=findings_acc,
            scan_path=args.path,
            output_path=output,
            empresa=args.empresa,
            sistema=args.sistema,
            auditor=args.auditor,
            trimestre=args.trimestre,
        )
    except ImportError as e:
        print(f'\033[91m[ERROR]\033[0m {e}')
        print('Instala con: pip install python-docx --break-system-packages')
        sys.exit(1)

    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for f in findings_acc:
        sev = f.get('severity', 'LOW').upper()
        if sev in counts:
            counts[sev] += 1

    print(f'\n\033[92m[AuditLens]\033[0m Documento de auditoría generado exitosamente.')
    print(f'   Archivo:   \033[1m{os.path.abspath(output)}\033[0m')
    print(f'   Empresa:   {args.empresa}')
    print(f'   Sistema:   {args.sistema}')
    print(f'   Hallazgos: {len(findings_acc)} total '
          f'(CRÍTICO:{counts["CRITICAL"]} ALTO:{counts["HIGH"]} '
          f'MEDIO:{counts["MEDIUM"]} BAJO:{counts["LOW"]})')
    print(f'\n   El documento incluye:')
    print(f'   ✓ Tabla de Contenidos con índice automático')
    print(f'   ✓ Planificación (alcance, objetivos SMART, metodología, roles)')
    print(f'   ✓ Hallazgos con Condición/Criterio/Causa/Efecto')
    print(f'   ✓ Análisis de brechas ISO 25040 / ISO 12207 / ISO 14764')
    print(f'   ✓ Cobertura de pruebas y brechas detectadas')
    print(f'   ✓ Conclusiones y recomendaciones priorizadas')
    print(f'   ✓ Plan de seguimiento con KPIs')
    print(f'   ✓ Anexos')
    print(f'\n   \033[90mAbra el documento en Word y presione Ctrl+A → F9 para actualizar el índice.\033[0m')


def _export_findings(findings, fmt, out, scan_path=''):
    """Helper to export findings in various formats."""
    import json as _json
    if fmt == 'json':
        out = out or 'findings.json'
        with open(out, 'w', encoding='utf-8') as fh:
            _json.dump(findings, fh, indent=2, default=str)
        print(f'\033[92m[AuditLens]\033[0m JSON guardado: {out}')
    elif fmt == 'html':
        from .html_exporter import generate_html_report
        out = out or 'report.html'
        generate_html_report(findings, scan_path=scan_path, output_path=out)
    elif fmt == 'xlsx':
        from .xlsx_exporter import generate_xlsx_report
        out = out or 'report.xlsx'
        generate_xlsx_report(findings, scan_path=scan_path, output_path=out)
    elif fmt == 'csv':
        from .csv_exporter import generate_csv_report
        out = out or 'findings.csv'
        generate_csv_report(findings, scan_path=scan_path, output_path=out)
    elif fmt == 'text':
        _print_findings_text(findings)


def _print_findings_text(findings):
    """Minimal text printer for non-scan commands."""
    _SEV_COLORS = {
        'CRITICAL': '\033[91m', 'HIGH': '\033[93m',
        'MEDIUM': '\033[94m', 'LOW': '\033[92m',
    }
    RESET = '\033[0m'
    for f in sorted(findings, key=lambda x: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}.get(x.get('severity', 'LOW'), 4)):
        sev = f.get('severity', 'LOW')
        color = _SEV_COLORS.get(sev, '')
        print(f'{color}[{sev}]{RESET} {f.get("rule_id", "")} — {f.get("name", "")}')
        print(f'  {f.get("file", "")}:{f.get("line", "")}')
        desc = f.get('description', '')
        print(f'  {desc[:200]}{"..." if len(desc) > 200 else ""}')
        print()


def _run_git_scan_command(args):
    from .git_secrets_scanner import scan_git_history
    findings = scan_git_history(args.path, max_commits=args.depth)
    _export_findings(findings, args.format, args.output, scan_path=args.path)
    has_critical = any(f['severity'] in ('CRITICAL', 'HIGH') for f in findings)
    sys.exit(1 if has_critical else 0)


def _run_dns_check_command(args):
    from .dns_checker import run_dns_check
    findings = run_dns_check(args.domain, dkim_selector=args.dkim_selector)
    _export_findings(findings, args.format, args.output, scan_path=args.domain)
    has_critical = any(f['severity'] in ('CRITICAL', 'HIGH') for f in findings)
    sys.exit(1 if has_critical else 0)


def _run_license_check_command(args):
    from .license_checker import check_licenses
    findings = check_licenses(args.path, project_type=args.project_type)
    _export_findings(findings, args.format, args.output, scan_path=args.path)
    sys.exit(0)


def _run_dep_confusion_command(args):
    from .dep_confusion import scan_dependency_confusion
    findings = scan_dependency_confusion(args.path)
    _export_findings(findings, args.format, args.output, scan_path=args.path)
    has_critical = any(f['severity'] == 'HIGH' for f in findings)
    sys.exit(1 if has_critical else 0)


def _run_api_scan_command(args):
    import os
    from .api_scanner import run_api_scan
    print(
        '\n\033[93m[AuditLens]\033[0m AVISO: api-scan realiza llamadas HTTP activas a la API objetivo.\n'
        '  Usa solo con autorización del propietario.\n'
    )
    token = args.token or os.environ.get('AUTH_TOKEN', '')
    headers = {'Authorization': f'Bearer {token}'} if token else None
    findings = run_api_scan(
        spec_source=args.spec,
        base_url=args.base_url,
        headers=headers,
        max_endpoints=args.max_endpoints,
    )
    _export_findings(findings, args.format, args.output, scan_path=args.spec)
    has_critical = any(f['severity'] in ('CRITICAL', 'HIGH') for f in findings)
    sys.exit(1 if has_critical else 0)


def _run_github_audit_command(args):
    from .github_auditor import run_github_audit
    findings = run_github_audit(args.repo, token=args.token)
    _export_findings(findings, args.format, args.output, scan_path=args.repo)
    has_critical = any(f['severity'] in ('CRITICAL', 'HIGH') for f in findings)
    sys.exit(1 if has_critical else 0)


def _run_sbom_command(args):
    from .sbom_exporter import generate_cyclonedx, generate_spdx
    fmt = args.format
    project_name = args.project_name or ''
    if fmt == 'spdx':
        out = args.output or 'sbom.spdx.json'
        generate_spdx(args.path, out, project_name=project_name)
    else:
        out = args.output or 'sbom.cyclonedx.json'
        generate_cyclonedx(args.path, out, project_name=project_name)
    sys.exit(0)


def _run_threat_model_command(args):
    import os
    from .threat_modeler import run_threat_model, print_threat_model
    api_key = os.environ.get('ANTHROPIC_API_KEY', '')
    if not api_key:
        print('\033[91m[AuditLens]\033[0m Configura ANTHROPIC_API_KEY para usar threat-model.')
        sys.exit(1)
    result = run_threat_model(
        project_path=args.path,
        api_key=api_key,
        model=args.model,
        output_path=args.output,
    )
    print_threat_model(result)
    sys.exit(0)


def _run_aws_audit_command(args):
    from .aws_auditor import run_aws_audit
    findings = run_aws_audit(region=args.region, profile=args.profile)
    _export_findings(findings, args.format, args.output, scan_path='AWS')
    has_critical = any(f['severity'] in ('CRITICAL', 'HIGH') for f in findings)
    sys.exit(1 if has_critical else 0)


def _run_github_pr_command(args):
    from .github_pr import run_github_pr_comment
    run_github_pr_comment(
        repo=args.repo,
        pr_number=args.pr,
        findings_source=args.findings,
        min_severity=args.severity,
        token=args.token,
    )
    sys.exit(0)


def _run_trending_command(args):
    import os
    from .trending import _DB_PATH, print_trending_dashboard, generate_trending_html
    db = args.db or _DB_PATH
    if args.format == 'html':
        out = args.output or 'trending.html'
        generate_trending_html(db_path=db, days=args.days, output_path=out)
    else:
        print_trending_dashboard(db_path=db, days=args.days)
    sys.exit(0)


def _run_graph_command(args):
    """Execute 'auditlens graph' — build and visualize the attack surface graph."""
    import json as _json
    from .attack_surface import build_attack_surface_graph
    from .attack_surface_server import export_graph_html, serve_attack_surface_graph, _save_and_open

    graph_data = build_attack_surface_graph(
        project_path=args.path,
        max_files=args.max_files,
    )

    output = args.output

    if output:
        if output.endswith('.json'):
            with open(output, 'w', encoding='utf-8') as fh:
                _json.dump(graph_data, fh, indent=2, ensure_ascii=False)
            print(f'\033[92m[AuditLens]\033[0m JSON exportado: {output}')
        else:
            # Default to HTML
            if not output.endswith('.html'):
                output += '.html'
            export_graph_html(graph_data, output)
    elif args.serve:
        serve_attack_surface_graph(
            graph_data,
            port=args.port,
            host='127.0.0.1',
            open_browser=not args.no_browser,
        )
    else:
        # No output specified — save to temp file and open
        _save_and_open(graph_data, open_browser=True)

    # Print summary
    stats = graph_data['stats']
    sev = stats['severity_counts']
    types = stats['type_counts']
    print(f'\n\033[1m=== ATTACK SURFACE SUMMARY ===\033[0m')
    print(f'  Nodos totales:   {stats["total_nodes"]}')
    print(f'  Entry points:    {types.get("entry", 0)}')
    print(f'  Sinks peligrosos:{types.get("sink", 0)}')
    print(f'  Funciones:       {types.get("function", 0)}')
    print(f'  Nodos tainted:   {stats["tainted_nodes"]}')
    print(f'  CRITICAL: {sev["CRITICAL"]}  HIGH: {sev["HIGH"]}  MEDIUM: {sev["MEDIUM"]}  LOW: {sev["LOW"]}')
    sys.exit(1 if sev['CRITICAL'] + sev['HIGH'] > 0 else 0)


def _run_compliance_command(args):
    """Execute 'auditlens compliance' — map findings to OWASP/CWE/PCI-DSS/SOC 2."""
    import json as _json
    from .compliance_mapper import enrich_with_compliance, generate_compliance_report, print_compliance_summary

    with open(args.findings, encoding='utf-8') as fh:
        findings = _json.load(fh)

    findings = enrich_with_compliance(findings)
    report   = generate_compliance_report(findings)

    fmt = getattr(args, 'format', 'text')
    out = getattr(args, 'output', None)

    if fmt == 'json' or (out and out.endswith('.json')):
        json_out = out or 'compliance_report.json'
        with open(json_out, 'w', encoding='utf-8') as fh:
            _json.dump(report, fh, indent=2)
        print(f'\033[92m[AuditLens Compliance]\033[0m JSON guardado: {json_out}')
    elif fmt == 'html' or (out and out.endswith('.html')):
        _generate_compliance_html(report, findings, out or 'compliance_report.html')
    else:
        print_compliance_summary(report)

    sys.exit(0)


def _generate_compliance_html(report: dict, findings: list, output_path: str) -> None:
    """Generate standalone HTML compliance gap report."""
    import json as _json

    def _gauge(pct, label):
        color = '#3fb950' if pct >= 60 else '#e3b341' if pct >= 30 else '#da3633'
        return f'''<div class="gauge-wrap">
          <svg viewBox="0 0 100 60" class="gauge">
            <path d="M10,55 A40,40 0 0,1 90,55" fill="none" stroke="#21262d" stroke-width="10"/>
            <path d="M10,55 A40,40 0 0,1 90,55" fill="none" stroke="{color}" stroke-width="10"
              stroke-dasharray="{pct*1.257} 125.7" stroke-linecap="round"/>
            <text x="50" y="52" text-anchor="middle" fill="{color}" font-size="18" font-weight="bold">{pct}%</text>
          </svg>
          <div class="gauge-label">{label}</div>
        </div>'''

    gauges = (
        _gauge(report['owasp']['pct'],   'OWASP Top 10') +
        _gauge(report['pci_dss']['pct'], 'PCI-DSS v4.0') +
        _gauge(report['soc2']['pct'],    'SOC 2 TSC')
    )

    def _fw_table(fw_data, code_names):
        rows = ''
        for code in sorted(fw_data.get('covered', [])):
            count = fw_data.get('details', {}).get(code, {})
            n = count.get('count', count) if isinstance(count, dict) else count
            rows += f'<tr><td class="code">{code}</td><td>{code_names.get(code, "")}</td><td style="color:#3fb950">{n} hallazgo(s)</td><td>✓</td></tr>'
        for code in sorted(fw_data.get('uncovered', [])):
            rows += f'<tr><td class="code" style="color:#6e7681">{code}</td><td style="color:#6e7681">{code_names.get(code, "")}</td><td style="color:#6e7681">—</td><td style="color:#6e7681">○</td></tr>'
        return rows

    from .compliance_mapper import _OWASP_NAMES, _PCI_NAMES, _SOC2_NAMES
    html = f"""<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8">
<title>AuditLens — Compliance Report</title>
<style>
* {{ box-sizing: border-box; margin:0; padding:0; }}
body {{ font-family:'Segoe UI',system-ui,sans-serif; background:#0d1117; color:#e6edf3; padding:24px; }}
h1 {{ color:#58a6ff; font-size:20px; margin-bottom:4px; }}
.sub {{ color:#8b949e; font-size:12px; margin-bottom:24px; }}
h2 {{ color:#58a6ff; font-size:13px; text-transform:uppercase; letter-spacing:1px; margin-bottom:12px; }}
.gauges {{ display:flex; gap:32px; justify-content:center; margin-bottom:28px; }}
.gauge-wrap {{ text-align:center; }}
.gauge {{ width:140px; }}
.gauge-label {{ font-size:12px; color:#8b949e; margin-top:4px; }}
.section {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:20px; margin-bottom:16px; }}
table {{ width:100%; border-collapse:collapse; font-size:12px; }}
th {{ text-align:left; padding:8px; color:#8b949e; border-bottom:1px solid #30363d; font-size:11px; text-transform:uppercase; }}
td {{ padding:7px 8px; border-bottom:1px solid #21262d; }}
.code {{ font-family:monospace; color:#79c0ff; }}
</style></head>
<body>
<h1>🔒 Compliance Coverage Report</h1>
<p class="sub">{len(findings)} hallazgos analizados</p>
<div class="gauges">{gauges}</div>
<div class="section"><h2>OWASP Top 10 (2021)</h2>
<table><thead><tr><th>ID</th><th>Categoría</th><th>Hallazgos</th><th>Estado</th></tr></thead>
<tbody>{_fw_table(report['owasp'], _OWASP_NAMES)}</tbody></table></div>
<div class="section"><h2>PCI-DSS v4.0</h2>
<table><thead><tr><th>Req.</th><th>Descripción</th><th>Hallazgos</th><th>Estado</th></tr></thead>
<tbody>{_fw_table(report['pci_dss'], _PCI_NAMES)}</tbody></table></div>
<div class="section"><h2>SOC 2 — Trust Service Criteria</h2>
<table><thead><tr><th>Criterio</th><th>Descripción</th><th>Hallazgos</th><th>Estado</th></tr></thead>
<tbody>{_fw_table(report['soc2'], _SOC2_NAMES)}</tbody></table></div>
<div class="section"><h2>CWE identificados ({len(report['cwe']['covered'])})</h2>
<p style="font-size:12px;color:#8b949e">{', '.join(sorted(report['cwe']['covered']))}</p>
</div></body></html>"""

    with open(output_path, 'w', encoding='utf-8') as fh:
        fh.write(html)
    print(f'\033[92m[AuditLens Compliance]\033[0m HTML generado: {output_path}')
    import webbrowser, os
    webbrowser.open(f'file://{os.path.abspath(output_path)}')


def _run_archaeology_command(args):
    """Execute 'auditlens archaeology' — temporal vulnerability lifecycle analysis."""
    import json as _json
    from .temporal_archaeology import run_archaeology

    fmt = getattr(args, 'format', 'text')
    out = getattr(args, 'output', None)

    result = run_archaeology(
        repo_path=args.path,
        max_commits=args.depth,
        verbose=getattr(args, 'verbose', False),
    )

    if fmt == 'html' or (out and out.endswith('.html')):
        from .archaeology_exporter import generate_archaeology_html
        html_out = out or 'archaeology_report.html'
        generate_archaeology_html(result, html_out)
        import webbrowser, os
        webbrowser.open(f'file://{os.path.abspath(html_out)}')

    elif fmt == 'json' or (out and out.endswith('.json')):
        json_out = out or 'archaeology_results.json'
        with open(json_out, 'w', encoding='utf-8') as fh:
            _json.dump(result, fh, indent=2, default=str)
        print(f'\033[92m[AuditLens Archaeology]\033[0m JSON guardado: {json_out}')

    # Always print terminal summary (already done inside run_archaeology)
    stats = result.get('stats', {})
    open_vulns = stats.get('open_vulnerabilities', 0)
    sys.exit(1 if open_vulns > 0 else 0)


def _run_ley21719_command(args):
    """Execute 'auditlens ley21719' — full Ley 21.719 compliance audit."""
    import json as _json
    import os

    from .pii_detector import scan_directory_for_pii
    from .ley21719_mapper import enrich_with_ley21719, calculate_compliance_score, print_ley21719_summary

    path    = args.path
    empresa = getattr(args, 'empresa', 'Empresa')
    fmt     = getattr(args, 'format', 'all')
    out_base = getattr(args, 'output', None) or f'ley21719_{empresa.replace(" ", "_")}'

    print(f'\n\033[1m\033[94m[AuditLens] Auditoría Ley 21.719 — {empresa}\033[0m')
    print(f'\033[90mProyecto: {os.path.abspath(path)}\033[0m\n')

    # Step 1 — PII scan
    pii_findings = scan_directory_for_pii(path)

    # Step 2 — Static analysis
    print('\033[94m[AuditLens]\033[0m Ejecutando análisis estático SAST...')
    from .rules_engine import RulesEngine
    from .taint_analyzer import TaintAnalyzer
    from .analyzer import analyze_file, _SUPPORTED_EXTENSIONS

    sast_findings: list = []
    rules_engine = RulesEngine()
    taint_analyzer = TaintAnalyzer()
    exclude_dirs = {'venv', '.venv', 'env', 'node_modules', '.git', '__pycache__', 'build', 'dist'}

    if os.path.isfile(path):
        analyze_file(path, rules_engine, taint_analyzer,
                     min_severity=getattr(args, 'severity', 'LOW'),
                     all_findings_accumulator=sast_findings)
    else:
        for dirpath, dirnames, files in os.walk(path):
            dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext in _SUPPORTED_EXTENSIONS or fname.lower().startswith('dockerfile'):
                    analyze_file(os.path.join(dirpath, fname), rules_engine, taint_analyzer,
                                 min_severity=getattr(args, 'severity', 'LOW'),
                                 all_findings_accumulator=sast_findings)

    # Step 3 — SCA (unless disabled)
    sca_findings: list = []
    if not getattr(args, 'no_sca', False):
        try:
            from .sca import run_sca
            sca_findings = run_sca(path) or []
        except Exception:
            pass

    all_findings = pii_findings + sast_findings + sca_findings

    # Step 4 — Enrich with Ley 21.719 articles
    all_findings = enrich_with_ley21719(all_findings)

    # Step 5 — Calculate score
    score_data = calculate_compliance_score(all_findings)

    # Step 6 — Output
    if fmt in ('text', 'all'):
        print_ley21719_summary(score_data, all_findings)

    if fmt in ('json', 'all'):
        json_out = f'{out_base}.json'
        with open(json_out, 'w', encoding='utf-8') as fh:
            _json.dump({
                'score_data': score_data,
                'findings': all_findings,
                'empresa': empresa,
                'rut_empresa': getattr(args, 'rut_empresa', ''),
                'auditor': getattr(args, 'auditor', ''),
            }, fh, indent=2, default=str)
        print(f'\033[92m[AuditLens Ley 21.719]\033[0m JSON guardado: {json_out}')

    if fmt in ('html', 'all'):
        from .ley21719_reporter import generate_ley21719_html
        html_out = f'{out_base}.html'
        generate_ley21719_html(
            findings=all_findings,
            score_data=score_data,
            output_path=html_out,
            empresa=empresa,
            rut_empresa=getattr(args, 'rut_empresa', ''),
            auditor=getattr(args, 'auditor', ''),
        )

    if fmt in ('docx', 'all'):
        from .ley21719_reporter import generate_ley21719_docx
        docx_out = f'{out_base}.docx'
        generate_ley21719_docx(
            findings=all_findings,
            score_data=score_data,
            output_path=docx_out,
            empresa=empresa,
            rut_empresa=getattr(args, 'rut_empresa', ''),
            auditor=getattr(args, 'auditor', ''),
            rut_auditor=getattr(args, 'rut_auditor', ''),
        )

    score = score_data['score']
    sys.exit(0 if score >= 70 else 1)


def _run_gcp_audit_command(args):
    import json as _json
    from .gcp_auditor import audit_gcp
    findings = audit_gcp(args.project)
    _output_findings(findings, args, 'gcp_audit')


def _run_azure_audit_command(args):
    import json as _json
    from .azure_auditor import audit_azure
    findings = audit_azure(getattr(args, 'subscription', None))
    _output_findings(findings, args, 'azure_audit')


def _run_graphql_scan_command(args):
    import json as _json, os
    from .graphql_scanner import scan_graphql
    token = getattr(args, 'token', None) or os.environ.get('AUTH_TOKEN')
    findings = scan_graphql(args.endpoint, token=token, verify_ssl=not getattr(args, 'no_verify_ssl', False))
    _output_findings(findings, args, 'graphql_findings')


def _run_yara_scan_command(args):
    from .yara_scanner import scan_directory_for_malware, scan_file_for_malware
    import os
    if os.path.isfile(args.path):
        findings = scan_file_for_malware(args.path)
    else:
        findings = scan_directory_for_malware(args.path)
    _output_findings(findings, args, 'yara_findings')
    sys.exit(1 if findings else 0)


def _run_heatmap_command(args):
    import json as _json
    from .risk_heatmap import generate_risk_heatmap_html, generate_compliance_radar_html
    with open(args.findings, encoding='utf-8') as fh:
        data = _json.load(fh)
    findings = data if isinstance(data, list) else data.get('findings', [])
    out  = getattr(args, 'output', 'risk_heatmap.html')
    radar = getattr(args, 'radar', 'compliance_radar.html')
    generate_risk_heatmap_html(findings, out)
    generate_compliance_radar_html(findings, radar)
    sys.exit(0)


def _output_findings(findings, args, default_name: str):
    """Generic output helper for commands that produce findings."""
    import json as _json
    fmt = getattr(args, 'format', 'text')
    out = getattr(args, 'output', None)
    if fmt == 'json' or (out and str(out).endswith('.json')):
        out = out or f'{default_name}.json'
        with open(out, 'w', encoding='utf-8') as fh:
            _json.dump(findings, fh, indent=2, default=str)
        print(f'\033[92m[AuditLens]\033[0m JSON: {out}')
    elif fmt == 'html' or (out and str(out).endswith('.html')):
        from .html_exporter import generate_html_report
        generate_html_report(findings, scan_path='', output_path=out or f'{default_name}.html')
    elif fmt == 'xlsx' or (out and str(out).endswith('.xlsx')):
        from .xlsx_exporter import generate_xlsx_report
        generate_xlsx_report(findings, scan_path='', output_path=out or f'{default_name}.xlsx')
    else:
        for f in findings:
            sev = f.get('severity', 'LOW')
            col = '\033[91m' if sev in ('CRITICAL','HIGH') else '\033[93m' if sev=='MEDIUM' else '\033[90m'
            print(f'{col}[{f.get("rule_id","")}]\033[0m {f.get("file","").split("/")[-1]}:{f.get("line","")} — {f.get("name","")}')
    sys.exit(1 if any(f.get('severity') in ('CRITICAL','HIGH') for f in findings) else 0)


def _run_headers_check_command(args):
    import json as _json
    from .headers_checker import check_headers, print_headers_summary
    findings = check_headers(args.url, verify_ssl=not getattr(args, 'no_verify_ssl', False))
    fmt = getattr(args, 'format', 'text')
    out = getattr(args, 'output', None)
    if fmt == 'json' or (out and out.endswith('.json')):
        with open(out or 'headers_findings.json', 'w') as fh:
            _json.dump(findings, fh, indent=2)
    else:
        print_headers_summary(findings, args.url)
    sys.exit(1 if any(f.get('severity') in ('CRITICAL', 'HIGH') for f in findings) else 0)


def _run_k8s_audit_command(args):
    import json as _json
    from .k8s_auditor import scan_k8s_manifests
    findings = scan_k8s_manifests(args.path)
    fmt = getattr(args, 'format', 'text')
    out = getattr(args, 'output', None)
    if fmt == 'json' or (out and out.endswith('.json')):
        with open(out or 'k8s_findings.json', 'w') as fh:
            _json.dump(findings, fh, indent=2)
    elif fmt == 'html' or (out and out.endswith('.html')):
        from .html_exporter import generate_html_report
        generate_html_report(findings, scan_path=args.path, output_path=out or 'k8s_report.html')
    elif fmt == 'xlsx' or (out and out.endswith('.xlsx')):
        from .xlsx_exporter import generate_xlsx_report
        generate_xlsx_report(findings, scan_path=args.path, output_path=out or 'k8s_report.xlsx')
    else:
        for f in findings:
            sev = f.get('severity', 'LOW')
            col = '\033[91m' if sev in ('CRITICAL','HIGH') else '\033[93m'
            print(f'{col}[{f["rule_id"]}]\033[0m {f["file"]}:{f["line"]} — {f["name"]}')
    sys.exit(1 if any(f.get('severity') in ('CRITICAL', 'HIGH') for f in findings) else 0)


def _run_ai_summary_command(args):
    import json as _json
    from .ai_summary import run_ai_summary
    with open(args.findings, encoding='utf-8') as fh:
        data = _json.load(fh)
    findings   = data if isinstance(data, list) else data.get('findings', data.get('results', []))
    score_data = data.get('score_data') if isinstance(data, dict) else None
    run_ai_summary(
        findings=findings,
        score_data=score_data,
        empresa=getattr(args, 'empresa', 'Empresa'),
        framework=getattr(args, 'framework', None),
        output_path=getattr(args, 'output', None),
        mode=getattr(args, 'mode', 'all'),
    )
    sys.exit(0)


def _run_propuesta_command(args):
    from .proposal_generator import generate_proposal_docx
    out = getattr(args, 'output', None) or f'propuesta_{args.cliente.replace(" ","_")}.docx'
    generate_proposal_docx(
        project_path=args.path,
        output_path=out,
        empresa_cliente=args.cliente,
        rut_cliente=getattr(args, 'rut_cliente', ''),
        contacto_cliente=getattr(args, 'contacto', ''),
        empresa_auditora=getattr(args, 'auditora', 'AuditLens Security'),
        auditor=getattr(args, 'auditor', ''),
        rut_auditor=getattr(args, 'rut_auditor', ''),
        frameworks=getattr(args, 'frameworks', ['sast', 'sca', 'ley21719']),
        incluir_contrato=not getattr(args, 'no_contrato', False),
    )
    sys.exit(0)


def _run_track_command(args):
    import json as _json
    from .remediation_tracker import compare_findings, print_remediation_summary, generate_tracker_html
    with open(args.baseline, encoding='utf-8') as fh:
        baseline = _json.load(fh)
    with open(args.current, encoding='utf-8') as fh:
        current = _json.load(fh)
    result = compare_findings(baseline, current)
    fmt = getattr(args, 'format', 'text')
    out = getattr(args, 'output', None)
    if fmt == 'html' or (out and out.endswith('.html')):
        generate_tracker_html(result, out or 'remediation_tracker.html')
    elif fmt == 'json' or (out and out.endswith('.json')):
        with open(out or 'remediation_tracker.json', 'w') as fh:
            _json.dump(result, fh, indent=2, default=str)
    else:
        print_remediation_summary(result)
    sys.exit(0)


def _run_jwt_scan_command(args):
    import json as _json, os
    from .jwt_auditor import scan_directory_for_jwt_issues, scan_file_for_jwt_issues
    if os.path.isfile(args.path):
        findings = scan_file_for_jwt_issues(args.path)
    else:
        findings = scan_directory_for_jwt_issues(args.path)
    fmt = getattr(args, 'format', 'text')
    out = getattr(args, 'output', None)
    if not findings:
        print('\033[92m[AuditLens JWT]\033[0m No se detectaron vulnerabilidades JWT.')
        sys.exit(0)
    if fmt == 'json' or (out and out.endswith('.json')):
        with open(out or 'jwt_findings.json', 'w') as fh:
            _json.dump(findings, fh, indent=2)
    else:
        for f in findings:
            sev = f.get('severity','LOW')
            col = '\033[91m' if sev == 'CRITICAL' else '\033[93m' if sev == 'HIGH' else '\033[94m'
            print(f'{col}[{f["rule_id"]}] {f["file"]}:{f["line"]} — {f["name"]}\033[0m')
            print(f'   \033[90m{f["description"][:100]}\033[0m')
    sys.exit(1 if any(f.get('severity') in ('CRITICAL','HIGH') for f in findings) else 0)


def _run_ci_setup_command(args):
    from .ci_templates import generate_ci_template, generate_all_templates
    platform = getattr(args, 'platform', 'all')
    path     = getattr(args, 'path', '.')
    out      = getattr(args, 'output', None)
    if platform == 'all':
        files = generate_all_templates(path)
        print(f'\033[92m[AuditLens CI]\033[0m {len(files)} templates generados en {path}')
    else:
        generate_ci_template(platform, path, out)
    sys.exit(0)


def _run_iso27001_command(args):
    """Execute 'auditlens iso27001' — ISO 27001:2022 compliance audit."""
    import json as _json, os
    from .iso27001_mapper import enrich_with_iso27001, calculate_iso_score, print_iso_summary
    findings = _collect_findings(args)
    findings = enrich_with_iso27001(findings)
    score_data = calculate_iso_score(findings)
    fmt = getattr(args, 'format', 'text')
    out = getattr(args, 'output', None)
    print_iso_summary(score_data)
    if fmt == 'json' or (out and out.endswith('.json')):
        out = out or 'iso27001_report.json'
        with open(out, 'w', encoding='utf-8') as fh:
            _json.dump({'score_data': score_data, 'findings': findings}, fh, indent=2, default=str)
        print(f'\033[92m[AuditLens ISO 27001]\033[0m JSON guardado: {out}')
    sys.exit(0 if score_data['score'] >= 70 else 1)


def _run_cmf_command(args):
    """Execute 'auditlens cmf' — CMF Circular 57 / Norma 461 audit."""
    import json as _json, os
    from .cmf_mapper import enrich_with_cmf, calculate_cmf_score, print_cmf_summary
    findings = _collect_findings(args)
    findings = enrich_with_cmf(findings)
    score_data = calculate_cmf_score(findings)
    fmt = getattr(args, 'format', 'text')
    out = getattr(args, 'output', None)
    print_cmf_summary(score_data)
    if fmt == 'json' or (out and out.endswith('.json')):
        out = out or 'cmf_report.json'
        with open(out, 'w', encoding='utf-8') as fh:
            _json.dump({'score_data': score_data, 'findings': findings}, fh, indent=2, default=str)
        print(f'\033[92m[AuditLens CMF]\033[0m JSON guardado: {out}')
    sys.exit(0 if score_data['score'] >= 70 else 1)


def _collect_findings(args) -> list:
    """Shared helper: run SAST+SCA on args.path and return findings list."""
    import os
    from .rules_engine import RulesEngine
    from .taint_analyzer import TaintAnalyzer
    from .analyzer import analyze_file, _SUPPORTED_EXTENSIONS
    findings: list = []
    rules_engine = RulesEngine()
    taint_analyzer = TaintAnalyzer()
    exclude = {'venv', '.venv', 'env', 'node_modules', '.git', '__pycache__', 'build', 'dist'}
    path = args.path
    if os.path.isfile(path):
        analyze_file(path, rules_engine, taint_analyzer,
                     min_severity=getattr(args, 'severity', 'LOW'),
                     all_findings_accumulator=findings)
    else:
        for dirpath, dirnames, files in os.walk(path):
            dirnames[:] = [d for d in dirnames if d not in exclude]
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext in _SUPPORTED_EXTENSIONS or fname.lower().startswith('dockerfile'):
                    analyze_file(os.path.join(dirpath, fname), rules_engine, taint_analyzer,
                                 min_severity=getattr(args, 'severity', 'LOW'),
                                 all_findings_accumulator=findings)
    if not getattr(args, 'no_sca', False):
        try:
            from .sca import run_sca
            findings += run_sca(path) or []
        except Exception:
            pass
    return findings


def _run_schedule_command(args):
    from .scheduler import add_schedule, list_schedules, remove_schedule, run_pending_schedules
    cmd = getattr(args, 'sched_command', None)
    if cmd == 'add':
        add_schedule(
            scan_path=args.path,
            cron_expression=args.cron,
            email=args.email,
            min_severity=args.severity,
            scan_format=args.format,
            label=args.label,
        )
    elif cmd == 'list':
        list_schedules()
    elif cmd == 'remove':
        remove_schedule(args.id)
    elif cmd == 'run-pending':
        run_pending_schedules()
    else:
        print('Uso: auditlens schedule [add|list|remove|run-pending]')
    sys.exit(0)


def _run_correlate_command(args):
    """Execute 'auditlens correlate' — analyze attack chains and correlation."""
    import json as _json
    try:
        from .correlation_engine import CorrelationEngine
        engine = CorrelationEngine()
        result = engine.analyze_attack_chains(args.path)

        fmt = getattr(args, 'format', 'json')
        out = getattr(args, 'output', None)

        if fmt == 'html' or (out and out.endswith('.html')):
            html_out = out or 'correlation_report.html'
            engine.export_html(result, html_out)
            print(f'\033[92m[AuditLens Correlate]\033[0m HTML generado: {html_out}')
        else:
            json_out = out or 'correlation_report.json'
            with open(json_out, 'w', encoding='utf-8') as fh:
                _json.dump(result, fh, indent=2, default=str)
            print(f'\033[92m[AuditLens Correlate]\033[0m JSON guardado: {json_out}')

        sys.exit(0)
    except ImportError:
        print('\033[91m[ERROR]\033[0m Módulo correlation_engine no disponible.')
        sys.exit(1)


def _run_auto_fix_command(args):
    """Execute 'auditlens auto-fix' — automated remediation."""
    import json as _json
    try:
        from .remediation_engine import RemediationEngine
        engine = RemediationEngine()
        result = engine.auto_remediate(
            project_path=args.path,
            min_severity=getattr(args, 'severity', 'MEDIUM'),
            dry_run=getattr(args, 'dry_run', False),
        )

        out = getattr(args, 'output', None)
        if out:
            with open(out, 'w', encoding='utf-8') as fh:
                _json.dump(result, fh, indent=2, default=str)
            print(f'\033[92m[AuditLens Auto-Fix]\033[0m Reporte guardado: {out}')

        print(f'\n\033[1m=== AUTO-FIX SUMMARY ===\033[0m')
        print(f'  Hallazgos procesados: {result.get("total_findings", 0)}')
        print(f'  Remediados: {result.get("remediated", 0)}')
        print(f'  Fallidos: {result.get("failed", 0)}')

        sys.exit(0)
    except ImportError:
        print('\033[91m[ERROR]\033[0m Módulo remediation_engine no disponible.')
        sys.exit(1)


def _run_train_ml_command(args):
    """Execute 'auditlens train-ml' — train false positive classifier."""
    try:
        from .ml_classifier import FalsePositiveClassifier
        classifier = FalsePositiveClassifier()

        training_data = getattr(args, 'training_data', None)
        output_path = getattr(args, 'output', 'fp_classifier.pkl')

        print('\033[94m[AuditLens ML]\033[0m Entrenando clasificador de falsos positivos...')
        classifier.train_from_file(training_data)
        classifier.save_model(output_path)

        print(f'\033[92m[AuditLens ML]\033[0m Modelo entrenado y guardado: {output_path}')
        sys.exit(0)
    except ImportError:
        print('\033[91m[ERROR]\033[0m Módulo ml_classifier no disponible.')
        sys.exit(1)


def _run_scan_distributed_command(args):
    """Execute 'auditlens scan-distributed' — parallel scanning with workers."""
    try:
        from .distributed_scanner import DistributedScanner
        scanner = DistributedScanner(num_workers=getattr(args, 'workers', 4))

        print(f'\033[94m[AuditLens Distributed]\033[0m Iniciando escaneo con {args.workers} workers...')
        findings = scanner.scan_project(
            project_path=args.path,
            min_severity=getattr(args, 'severity', 'LOW'),
        )

        _export_findings(findings, getattr(args, 'format', 'text'), getattr(args, 'output', None), scan_path=args.path)

        has_critical = any(f.get('severity') in ('CRITICAL', 'HIGH') for f in findings)
        sys.exit(1 if has_critical else 0)
    except ImportError:
        print('\033[91m[ERROR]\033[0m Módulo distributed_scanner no disponible.')
        sys.exit(1)


def _run_policy_command(args):
    """Execute 'auditlens policy' — policy management."""
    try:
        from .policy_engine import PolicyEngine
        engine = PolicyEngine()

        cmd = getattr(args, 'policy_command', None)

        if cmd == 'list':
            policies = engine.list_policies()
            print('\033[1m=== POLÍTICAS DISPONIBLES ===\033[0m')
            for p in policies:
                print(f'  • {p["name"]}: {p["description"]}')

        elif cmd == 'validate':
            import json as _json
            with open(args.findings, encoding='utf-8') as fh:
                findings = _json.load(fh)

            policy_file = getattr(args, 'policy', None)
            violations = engine.validate_against_policy(findings, policy_file)

            if violations:
                print(f'\033[91m[Policy Violations]\033[0m {len(violations)} violación(es) detectada(s):')
                for v in violations:
                    print(f'  • {v["rule"]}: {v["message"]}')
                sys.exit(1)
            else:
                print('\033[92m[Policy]\033[0m Todos los hallazgos cumplen con la política.')
                sys.exit(0)

        elif cmd == 'test':
            result = engine.test_policy(args.policy, getattr(args, 'sample', None))
            print(f'\033[92m[Policy Test]\033[0m Resultado: {result["status"]}')
            sys.exit(0 if result['status'] == 'pass' else 1)

        else:
            print('Uso: auditlens policy [list|validate|test]')
            sys.exit(1)

    except ImportError:
        print('\033[91m[ERROR]\033[0m Módulo policy_engine no disponible.')
        sys.exit(1)


def _run_lsp_server_command(args):
    """Execute 'auditlens lsp-server' — start Language Server Protocol server."""
    try:
        from .lsp_server import AuditLensLanguageServer

        port = getattr(args, 'port', 2087)
        use_stdio = getattr(args, 'stdio', False)

        print(f'\033[94m[AuditLens LSP]\033[0m Iniciando servidor LSP...')

        server = AuditLensLanguageServer()

        if use_stdio:
            print('  Modo: stdio')
            server.start_stdio()
        else:
            print(f'  Modo: TCP socket en puerto {port}')
            server.start_tcp(port=port)

    except ImportError:
        print('\033[91m[ERROR]\033[0m Módulo lsp_server no disponible.')
        sys.exit(1)
    except KeyboardInterrupt:
        print('\n\033[93m[AuditLens LSP]\033[0m Servidor detenido.')
        sys.exit(0)


def _run_predict_command(args):
    """Execute 'auditlens predict' — predictive compliance dashboard."""
    try:
        from .predictive_dashboard import CompliancePredictor
        predictor = CompliancePredictor()

        horizon = getattr(args, 'horizon', 90)
        output_path = getattr(args, 'output', 'predictive_dashboard.html')

        print(f'\033[94m[AuditLens Predict]\033[0m Generando predicciones para {horizon} días...')
        predictor.generate_dashboard(
            project_path=args.path,
            horizon_days=horizon,
            output_path=output_path,
        )

        print(f'\033[92m[AuditLens Predict]\033[0m Dashboard generado: {output_path}')

        import webbrowser, os
        webbrowser.open(f'file://{os.path.abspath(output_path)}')
        sys.exit(0)

    except ImportError:
        print('\033[91m[ERROR]\033[0m Módulo predictive_dashboard no disponible.')
        sys.exit(1)


def _run_supply_chain_command(args):
    """Execute 'auditlens supply-chain' — SBOM + vulnerability analysis."""
    try:
        from .supply_chain_guard import SupplyChainGuard
        guard = SupplyChainGuard()

        print('\033[94m[AuditLens Supply Chain]\033[0m Analizando cadena de suministro...')
        result = guard.analyze_project(args.path)

        fmt = getattr(args, 'format', 'json')
        out = getattr(args, 'output', 'supply_chain_report.json')

        if fmt == 'cyclonedx':
            guard.export_cyclonedx(result, out)
        elif fmt == 'html':
            guard.export_html(result, out)
        else:
            import json as _json
            with open(out, 'w', encoding='utf-8') as fh:
                _json.dump(result, fh, indent=2, default=str)

        print(f'\033[92m[AuditLens Supply Chain]\033[0m Reporte generado: {out}')

        critical = result.get('critical_vulnerabilities', 0)
        sys.exit(1 if critical > 0 else 0)

    except ImportError:
        print('\033[91m[ERROR]\033[0m Módulo supply_chain_guard no disponible.')
        sys.exit(1)


def _run_gen_tests_command(args):
    """Execute 'auditlens gen-tests' — generate security tests."""
    try:
        from .security_test_generator import SecurityTestGenerator
        generator = SecurityTestGenerator()

        output_dir = getattr(args, 'output_dir', './security_tests')
        framework = getattr(args, 'framework', 'pytest')

        print(f'\033[94m[AuditLens Gen-Tests]\033[0m Generando tests de seguridad ({framework})...')
        result = generator.generate_tests(
            project_path=args.path,
            output_dir=output_dir,
            framework=framework,
        )

        print(f'\033[92m[AuditLens Gen-Tests]\033[0m Tests generados:')
        for test_file in result.get('generated_files', []):
            print(f'  • {test_file}')

        print(f'\n  Total: {len(result.get("generated_files", []))} archivo(s) en {output_dir}')
        sys.exit(0)

    except ImportError:
        print('\033[91m[ERROR]\033[0m Módulo security_test_generator no disponible.')
        sys.exit(1)


def _run_tenant_command(args):
    """Execute 'auditlens tenant' — multi-tenant management."""
    try:
        from .tenant_manager import TenantManager
        manager = TenantManager()

        cmd = getattr(args, 'tenant_command', None)

        if cmd == 'create':
            name = args.name
            description = getattr(args, 'description', '')
            tenant_id = manager.create_tenant(name, description)
            print(f'\033[92m[AuditLens Tenant]\033[0m Tenant creado: {name} (ID: {tenant_id})')

        elif cmd == 'list':
            tenants = manager.list_tenants()
            print('\033[1m=== TENANTS ===\033[0m')
            for t in tenants:
                print(f'  • {t["name"]} (ID: {t["id"]}) — {t["description"]}')

        elif cmd == 'delete':
            name = args.name
            manager.delete_tenant(name)
            print(f'\033[92m[AuditLens Tenant]\033[0m Tenant eliminado: {name}')

        else:
            print('Uso: auditlens tenant [create|list|delete]')
            sys.exit(1)

        sys.exit(0)

    except ImportError:
        print('\033[91m[ERROR]\033[0m Módulo tenant_manager no disponible.')
        sys.exit(1)


if __name__ == '__main__':
    main()
