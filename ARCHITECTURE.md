# ARCHITECTURE.md

## 1. Diagrama de Arquitectura General

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          AUDITLENS ENTERPRISE SUITE                              │
│                      Security Analysis & Compliance Platform                     │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────┐
│                             CLI INTERFACE (Entry Point)                          │
│  cli.py → 43 comandos: scan, plan, serve, fix, web-scan, api-scan, aws-audit,  │
│  gcp-audit, azure-audit, k8s-audit, graphql-scan, ley21719, iso27001, cmf, etc.│
└──────────────────────────────────┬──────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           CORE ANALYSIS ENGINES                                  │
├─────────────────────────────────────────────────────────────────────────────────┤
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────────────┐  │
│  │ SAST Engine      │  │ SCA Engine       │  │ Taint Analyzer               │  │
│  │ analyzer.py      │  │ sca_engine.py    │  │ taint_analyzer.py            │  │
│  │                  │  │                  │  │                              │  │
│  │ • Tree-sitter    │  │ • OSV API        │  │ • Data Flow Tracking        │  │
│  │ • AST parsing    │  │ • lockfile scan  │  │ • Source → Sink detection   │  │
│  │ • Multi-language │  │ • CVE enrichment │  │ • Interprocedural analysis  │  │
│  │ • Rules engine   │  │ • License check  │  │ • User input detection      │  │
│  └──────────────────┘  └──────────────────┘  └──────────────────────────────┘  │
│                                                                                  │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────────────┐  │
│  │ Rules Engine     │  │ Attack Surface   │  │ Entropy Scanner              │  │
│  │ rules_engine.py  │  │ attack_surface.py│  │ entropy_scanner.py           │  │
│  │                  │  │                  │  │                              │  │
│  │ • YAML-based     │  │ • Graph builder  │  │ • Secret detection           │  │
│  │ • 200+ rules     │  │ • Entry points   │  │ • High-entropy strings       │  │
│  │ • OWASP mapping  │  │ • Sink detection │  │ • Base64/hex patterns        │  │
│  │ • CWE mapping    │  │ • D3.js export   │  │ • Git history scanning       │  │
│  └──────────────────┘  └──────────────────┘  └──────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        SPECIALIZED SCANNERS (27 Modules)                        │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │ CLOUD INFRASTRUCTURE AUDITORS                                           │   │
│  │  • aws_auditor.py    → IAM, S3, Security Groups, CloudTrail, KMS       │   │
│  │  • gcp_auditor.py    → IAM, Storage, Firewall, CloudSQL, Secrets       │   │
│  │  • azure_auditor.py  → IAM, Storage, NSG, Key Vault, App Service       │   │
│  │  • k8s_auditor.py    → RBAC, Pods, Secrets, Network Policies           │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │ APPLICATION SECURITY SCANNERS                                           │   │
│  │  • web_scanner.py       → DAST (XSS, SQLi, CSRF, Open Redirect)        │   │
│  │  • api_scanner.py       → OpenAPI/Swagger endpoint testing             │   │
│  │  • graphql_scanner.py   → Introspection, depth limits, batching        │   │
│  │  • jwt_auditor.py       → Algorithm confusion, weak signing, timing    │   │
│  │  • headers_checker.py   → CSP, HSTS, X-Frame, CORS, TLS config         │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │ SUPPLY CHAIN & SECRETS                                                  │   │
│  │  • git_secrets_scanner.py  → Historical secret leaks in commits        │   │
│  │  • dep_confusion.py        → Typosquatting, namespace hijacking        │   │
│  │  • license_checker.py      → GPL/AGPL compliance for commercial use    │   │
│  │  • yara_scanner.py         → Malware, webshells, backdoor detection    │   │
│  │  • pii_detector.py         → Ley 21.719 PII detection (RUT, email)     │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │ EXTERNAL INTEGRATIONS                                                   │   │
│  │  • github_auditor.py   → Branch protection, Actions secrets, perms     │   │
│  │  • github_pr.py        → Inline PR comments for CI/CD blocking         │   │
│  │  • dns_checker.py      → SPF, DMARC, DKIM, DNSSEC verification         │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        COMPLIANCE & REPORTING LAYER                             │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │ COMPLIANCE MAPPERS (Multi-Framework)                                    │   │
│  │  • compliance_mapper.py  → OWASP Top 10, CWE, PCI-DSS, SOC 2, GDPR    │   │
│  │  • iso27001_mapper.py    → ISO 27001:2022 controls + scoring           │   │
│  │  • cmf_mapper.py         → CMF Circular 57 / Norma 461 (Chile)         │   │
│  │  • ley21719_mapper.py    → Ley de Datos Personales Chile               │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │ EXPORTERS (8 formatos)                                                  │   │
│  │  • docx_exporter.py     → Word reports with TOC, tables, executive sum │   │
│  │  • pdf_exporter.py      → PDF reports with charts (fpdf2)              │   │
│  │  • html_exporter.py     → Static HTML reports                          │   │
│  │  • xlsx_exporter.py     → Excel spreadsheets (openpyxl)                │   │
│  │  • csv_exporter.py      → CSV for data pipelines                       │   │
│  │  • sarif_exporter.py    → SARIF v2.1.0 for GitHub Security/SonarQube  │   │
│  │  • sbom_exporter.py     → CycloneDX & SPDX SBOM generation             │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          AI & AUTOMATION LAYER                                  │
├─────────────────────────────────────────────────────────────────────────────────┤
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────────────┐  │
│  │ AI Fix Engine    │  │ AI Summary       │  │ Threat Modeler               │  │
│  │ ai_fix.py        │  │ ai_summary.py    │  │ threat_modeler.py            │  │
│  │                  │  │                  │  │                              │  │
│  │ • AI API         │  │ • Executive sum  │  │ • STRIDE analysis            │  │
│  │ • Auto-patch gen │  │ • Gap analysis   │  │ • Asset identification       │  │
│  │ • --apply mode   │  │ • Remediation    │  │ • Attack scenarios           │  │
│  │ • Dry-run        │  │ • Multi-framework│  │ • Mitigation strategies      │  │
│  └──────────────────┘  └──────────────────┘  └──────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    PERSISTENCE & TRENDING LAYER                                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────────────┐  │
│  │ History DB       │  │ Baseline Manager │  │ Trending Dashboard           │  │
│  │ history.py       │  │ baseline.py      │  │ trending.py                  │  │
│  │                  │  │                  │  │                              │  │
│  │ • SQLite         │  │ • Fingerprinting │  │ • Time-series charts         │  │
│  │ • Scan records   │  │ • Diff mode      │  │ • Severity trends            │  │
│  │ • Git commits    │  │ • False positive │  │ • Fix velocity metrics       │  │
│  │ • Severity trend │  │   suppression    │  │ • Regression detection       │  │
│  └──────────────────┘  └──────────────────┘  └──────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                      WEB DASHBOARD & API (Flask + Gunicorn)                     │
├─────────────────────────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────────────────────────┐  │
│  │ dashboard.py → Flask app with:                                           │  │
│  │  • /api/findings → JSON API for findings                                 │  │
│  │  • /api/scan → Trigger new scans                                         │  │
│  │  • /api/history → Historical trend data                                  │  │
│  │  • /api/stats → Aggregated severity stats                                │  │
│  │  • Chart.js integration (severity trends, file heatmap)                  │  │
│  │  • Filterable findings table                                             │  │
│  │  • Basic auth (AUDITLENS_USER / AUDITLENS_PASSWORD)                      │  │
│  └──────────────────────────────────────────────────────────────────────────┘  │
│                                                                                  │
│  ┌──────────────────────────────────────────────────────────────────────────┐  │
│  │ attack_surface_server.py → D3.js force-directed graph server             │  │
│  │  • Interactive attack surface visualization                              │  │
│  │  • Entry point → Sink path highlighting                                  │  │
│  │  • Node filtering by severity                                            │  │
│  └──────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        NOTIFICATIONS & INTEGRATIONS                             │
├─────────────────────────────────────────────────────────────────────────────────┤
│  notifications.py → Multi-channel alerting:                                     │
│    • Slack webhooks (Block Kit formatting, severity filtering)                  │
│    • JIRA ticket auto-creation (customizable issue types, labels)               │
│    • Email notifications (SMTP, HTML templates)                                 │
│    • Configurable via .auditlens.yaml with env var expansion                    │
└─────────────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         DEPLOYMENT LAYER (Containerized)                        │
├─────────────────────────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────────────────────────┐  │
│  │ Dockerfile (multi-stage build):                                          │  │
│  │  • Stage 1: Builder (gcc, g++, git, pip install with [all])              │  │
│  │  • Stage 2: Runtime (slim Python 3.11, non-root user)                    │  │
│  │  • Gunicorn as WSGI server (WEB_CONCURRENCY=2)                           │  │
│  │  • Health check endpoint: /api/findings                                  │  │
│  └──────────────────────────────────────────────────────────────────────────┘  │
│                                                                                  │
│  ┌──────────────────────────────────────────────────────────────────────────┐  │
│  │ docker-compose.yml:                                                       │  │
│  │  • Service: dashboard (port 8080)                                         │  │
│  │  • Volumes: /data/scan (RO), /data/db (persistent SQLite)                │  │
│  │  • Environment: SCAN_PATH, AUDITLENS_DB, auth credentials                │  │
│  │  • Health check with retry/timeout configuration                         │  │
│  └──────────────────────────────────────────────────────────────────────────┘  │
│                                                                                  │
│  ┌──────────────────────────────────────────────────────────────────────────┐  │
│  │ Azure App Service deployment:                                            │  │
│  │  • docker-entrypoint.sh → Runs scan + Gunicorn                           │  │
│  │  • Persistent storage for SQLite at /data/db                             │  │
│  │  • Environment variables for credentials & scan targets                  │  │
│  └──────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           CI/CD INTEGRATION LAYER                               │
├─────────────────────────────────────────────────────────────────────────────────┤
│  ci_templates.py → Auto-generated pipeline templates:                           │
│    • GitHub Actions (.github/workflows/auditlens.yml)                           │
│    • GitLab CI (.gitlab-ci.yml)                                                 │
│    • Azure DevOps (azure-pipelines.yml)                                         │
│    • Bitbucket Pipelines (bitbucket-pipelines.yml)                              │
│    • Pre-commit hooks (.pre-commit-config.yaml)                                 │
│    • Makefile (make security-scan)                                              │
│  pre_commit.py → Git pre-commit hook installer (severity-based blocking)        │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## 2. Descripción de Módulos Nuevos (v0.9.0 → v0.10.0)

### Módulos Core Agregados

#### **attack_surface.py & attack_surface_server.py**
- **Propósito**: Construir y visualizar el grafo de superficie de ataque del proyecto
- **Funcionalidad**:
  - Parsea AST de Python/JavaScript para extraer entry points (HTTP routes, CLI args, env vars)
  - Detecta sinks peligrosos (SQL, subprocess, eval, file operations)
  - Construye grafo dirigido: entry point → función → sink
  - Identifica taint paths entre entrada externa y sinks críticos
  - Exporta a JSON para visualización D3.js force-directed
  - Servidor Flask integrado para visualización interactiva en navegador
- **Patrones detectados**:
  - Flask/FastAPI/Django decorators (`@app.route`, `@api_view`)
  - Express.js route handlers (`app.get`, `router.post`)
  - CLI parsers (argparse, sys.argv)
  - Environment variable reads (os.environ, process.env)

#### **temporal_archaeology.py & archaeology_exporter.py**
- **Propósito**: Análisis temporal del ciclo de vida de vulnerabilidades en Git history
- **Funcionalidad**:
  - Escanea cada commit del historial con motor SAST completo
  - Reconstruye timeline: cuándo se introdujo, cuánto tiempo vivió, cuándo se corrigió
  - Detecta vulnerabilidades "zombies" (reintroducidas después de ser corregidas)
  - Calcula métricas: MTTR (Mean Time To Remediation), regresiones por commit
  - Identifica commits más riesgosos (mayor cantidad de vulns introducidas)
  - Genera reporte HTML interactivo con timeline Chart.js

#### **entropy_scanner.py**
- **Propósito**: Detección de secretos hardcoded mediante análisis de entropía
- **Funcionalidad**:
  - Calcula entropía de Shannon para cada string literal
  - Detecta patrones: API keys, tokens, JWT, private keys, AWS credentials
  - Identifica Base64/hex strings de alta entropía (posibles secretos)
  - Filtra falsos positivos comunes (imports, URLs, comentarios)
  - Integrado en SAST core como regla `SEC-25-HIGH-ENTROPY-SECRET`

#### **compliance_mapper.py**
- **Propósito**: Mapper multi-framework para compliance gaps
- **Funcionalidad**:
  - Mapea hallazgos a 8 frameworks: OWASP Top 10, CWE, PCI-DSS, SOC 2, GDPR, HIPAA, NIST, ISO 27001
  - Genera gap report: controles cubiertos vs. no cubiertos
  - Calcula cobertura porcentual por framework
  - Exporta HTML con gauges, tablas de controles, radar charts
  - Identifica CWEs únicos en el proyecto
- **Output**: JSON estructurado + HTML interactivo

#### **iso27001_mapper.py & cmf_mapper.py**
- **Propósito**: Auditorías específicas de normativa regional
- **iso27001_mapper.py**:
  - Mapea a controles ISO 27001:2022 (Anexo A)
  - Scoring 0-100 basado en hallazgos por dominio (A.5 - A.8)
  - Identifica brechas por control (ej: A.8.9 - Configuration Management)
  - Genera reporte HTML con scoring breakdown
- **cmf_mapper.py**:
  - Auditoría CMF Circular 57 / Norma 461 (regulación financiera Chile)
  - Mapea a artículos de la normativa
  - Scoring específico para entidades bancarias/financieras
  - Reporte adaptado a terminología CMF

#### **ley21719_mapper.py & ley21719_reporter.py**
- **Propósito**: Cumplimiento Ley 21.719 de Protección de Datos Personales (Chile)
- **Funcionalidad**:
  - Integra PII detector (pii_detector.py) para detectar RUTs, emails, teléfonos
  - Mapea hallazgos a artículos de Ley 21.719 (Arts. 7, 12, 13, 14, 17)
  - Scoring de cumplimiento: 0-100 basado en criticidad de brechas
  - Genera 3 formatos: HTML interactivo, Word oficial, JSON structured
  - Incluye secciones: alcance, marco normativo, hallazgos por artículo, plan de remediación
- **Output**: `ley21719_[empresa].html` + `.docx` + `.json`

#### **ai_fix.py**
- **Propósito**: Generación automatizada de parches de seguridad con AI API
- **Funcionalidad**:
  - Analiza hallazgos HIGH/CRITICAL y solicita fix suggestions a AI
  - Genera diffs aplicables (formato unified diff)
  - Modo `--apply`: aplica parches automáticamente al código
  - Modo `--dry-run`: simula cambios sin modificar archivos
  - Incluye contexto: snippet de código, CWE, recomendaciones OWASP
  - Rate limiting + error handling para API calls
- **Comando**: `auditlens fix ./proyecto --apply --severity HIGH`

#### **ai_summary.py**
- **Propósito**: Generación de resúmenes ejecutivos y análisis de brecha con LLM
- **Funcionalidad**:
  - Modo `--mode executive`: Resumen ejecutivo para C-level (3 páginas max)
  - Modo `--mode gap`: Gap analysis contra framework específico (ISO/Ley21719/PCI)
  - Modo `--mode remediation`: Priorización de remediación con ROI estimado
  - Contexto: findings + score data + framework seleccionado
  - Output: Markdown o HTML con secciones: situación actual, brechas críticas, roadmap
- **Comando**: `auditlens ai-summary findings.json --framework iso27001 --mode gap`

#### **threat_modeler.py**
- **Propósito**: Threat modeling automatizado con AI Engine
- **Funcionalidad**:
  - Analiza arquitectura del proyecto (importa, stack tecnológico, entry points)
  - Genera STRIDE analysis: Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation
  - Identifica assets críticos y threat actors
  - Propone mitigaciones específicas por amenaza
  - Output JSON estructurado con scoring de riesgo
- **Comando**: `auditlens threat-model ./proyecto -o threat_model.json`

### Módulos de Infraestructura Cloud

#### **aws_auditor.py**
- **Propósito**: Auditoría automatizada de cuenta AWS
- **Checks**:
  - IAM: Root account MFA, weak password policies, unused access keys
  - S3: Public buckets, encryption at rest, versioning disabled
  - Security Groups: 0.0.0.0/0 ingress on ports 22/3389/3306
  - CloudTrail: Logging disabled, log file validation
  - KMS: Key rotation disabled
- **Autenticación**: AWS credentials file o environment variables
- **Output**: JSON findings con severidad CRITICAL/HIGH/MEDIUM

#### **gcp_auditor.py**
- **Propósito**: Auditoría GCP project
- **Checks**:
  - IAM: Over-permissive roles (Editor, Owner a service accounts)
  - Storage: Public buckets, encryption config
  - Firewall: 0.0.0.0/0 ingress rules
  - CloudSQL: Public IP addresses, SSL enforcement
  - Secrets Manager: Secret rotation policies
- **Autenticación**: gcloud SDK credentials
- **Output**: JSON findings

#### **azure_auditor.py**
- **Propósito**: Auditoría Azure subscription
- **Checks**:
  - IAM: Role assignments a nivel subscription/resource group
  - Storage: Public blob containers, encryption, HTTPS only
  - Network Security Groups: Permissive rules
  - Key Vault: Soft delete disabled, purge protection
  - App Service: HTTPS only, client certs, managed identity
- **Autenticación**: Azure CLI credentials o service principal
- **Output**: JSON findings

#### **k8s_auditor.py**
- **Propósito**: Análisis estático de manifiestos Kubernetes
- **Checks**:
  - RBAC: ClusterRoleBindings a default service accounts
  - Pod Security: privileged containers, hostPath volumes
  - Secrets: Mounted as env vars (inseguro), no encryption at rest
  - Network Policies: Missing isolation
  - Resource limits: Missing CPU/memory limits
- **Input**: Directorio con .yaml/.yml manifests
- **Output**: JSON findings con referencia a archivo:línea

### Módulos de Application Security

#### **graphql_scanner.py**
- **Propósito**: Auditoría de APIs GraphQL
- **Checks**:
  - Introspection habilitado en producción
  - Query depth limits (previene DoS)
  - Batching attacks (múltiples queries en un request)
  - Field-level authorization
  - Mutation rate limiting
- **Autenticación**: Bearer token opcional
- **Output**: JSON findings

#### **jwt_auditor.py**
- **Propósito**: Detección de vulnerabilidades JWT en código fuente
- **Patrones detectados**:
  - Algorithm confusion (`alg: none`, `alg: HS256` con RSA key)
  - Weak signing keys (< 256 bits)
  - Token verification bypass (`verify=False`)
  - Hardcoded secrets en jwt.encode()
  - Missing expiration checks
- **Output**: JSON findings con snippet de código vulnerable

#### **headers_checker.py**
- **Propósito**: Auditoría de HTTP security headers y TLS config
- **Checks**:
  - CSP (Content-Security-Policy): Missing o permissive
  - HSTS: Missing, max-age too short
  - X-Frame-Options: Clickjacking protection
  - X-Content-Type-Options: MIME sniffing
  - CORS: Wildcard origins, credentials exposure
  - TLS: Protocol version, cipher suites, certificate validation
- **Output**: JSON findings + terminal summary con color coding

#### **yara_scanner.py**
- **Propósito**: Detección de malware, webshells y backdoors en código
- **YARA Rules incluidas**:
  - PHP webshells (c99, r57, b374k, WSO)
  - Python reverse shells
  - Eval-based backdoors
  - Obfuscated code (base64 decode + exec)
  - Cryptocurrency miners
- **Output**: JSON findings con rule name + matched strings

### Módulos de Análisis de Supply Chain

#### **dep_confusion.py**
- **Propósito**: Detectar vectores de dependency confusion attack
- **Checks**:
  - Packages en requirements.txt/package.json no presentes en registry público
  - Internal package names que podrían ser typosquatted
  - Missing package integrity checks (SHA256, lock file)
  - Suspicious package names (similar to popular packages)
- **Output**: JSON findings con recomendación de usar private registry

#### **license_checker.py**
- **Propósito**: Verificación de compatibilidad de licencias
- **Funcionalidad**:
  - Escanea dependencies en requirements.txt/package.json
  - Identifica licencias GPL/AGPL en proyectos comerciales
  - Flag licenses con restricción copyleft
  - Detecta dual-licensing
  - Genera matriz de compatibilidad
- **Output**: JSON findings con license type + compatibility status

#### **git_secrets_scanner.py**
- **Propósito**: Escaneo histórico de secretos commiteados
- **Patrones detectados**:
  - AWS credentials (AKIA*, AWS_SECRET_ACCESS_KEY)
  - Private keys (BEGIN RSA PRIVATE KEY)
  - API tokens (Bearer, OAuth)
  - Database credentials en connection strings
  - Hardcoded passwords en config files
- **Funcionalidad**: Escanea diffs de commits (no solo HEAD)
- **Output**: JSON findings con commit hash + autor + timestamp

### Módulos de Reporting Avanzado

#### **risk_heatmap.py**
- **Propósito**: Visualización de riesgo mediante heatmaps y radar charts
- **Output**:
  - Risk Heatmap: Matriz de frecuencia (eje Y: file, eje X: severity)
  - Compliance Radar Chart: Cobertura multi-framework en spider chart
  - HTML interactivo con Chart.js
  - Color coding: CRITICAL (rojo), HIGH (naranja), MEDIUM (amarillo), LOW (azul)

#### **remediation_tracker.py**
- **Propósito**: Comparación de scans para tracking de remediación
- **Funcionalidad**:
  - Diff entre baseline.json y current.json
  - Identifica: fixed (resueltos), new (nuevos), persisting (persistentes)
  - Calcula fix velocity: hallazgos resueltos / día
  - Detecta regresiones (vulns reintroducidas)
  - Genera HTML con progress bars, timeline, severity breakdown
- **Comando**: `auditlens track baseline.json current.json --format html`

#### **proposal_generator.py**
- **Propósito**: Generación de propuestas comerciales y contratos
- **Funcionalidad**:
  - Escanea proyecto y estima alcance (SLOC, archivos, tecnologías)
  - Genera pricing basado en frameworks solicitados (SAST, SCA, ISO, Ley21719)
  - Incluye: cotización detallada, cronograma Gantt, matriz RACI, T&C
  - Opcional: contrato de auditoría con cláusulas estándar
  - Output: Word document con branding personalizable
- **Comando**: `auditlens propuesta ./proyecto --cliente "Banco XYZ" --frameworks sast sca ley21719`

### Módulos de Persistencia y Trending

#### **history.py**
- **Propósito**: Base de datos SQLite para tracking temporal
- **Schema**:
  - Tabla `scans`: id, scanned_at, scan_path, git_commit, total, critical, high, medium, low, findings_json
  - Index en scan_path para queries rápidas
- **Funcionalidad**:
  - Auto-persist cada scan (salvo flag `--no-history`)
  - Detección automática de git commit hash
  - Query por proyecto + time range
  - Feed para trending dashboard

#### **trending.py**
- **Propósito**: Dashboard de tendencias temporales
- **Funcionalidad**:
  - Query histórico de SQLite (últimos N días)
  - Genera gráficos: severity trend, fix velocity, top files
  - Detecta picos anómalos (commits que incrementan hallazgos >30%)
  - Output: HTML con Chart.js line/bar charts + tabla de scans
- **Comando**: `auditlens trending --days 30 --format html`

#### **baseline.py**
- **Propósito**: Gestión de baselines para CI/CD diff mode
- **Funcionalidad**:
  - Fingerprinting: hash SHA256 de (file + line + rule_id)
  - `--save-baseline`: Persiste fingerprints a JSON
  - `--diff-baseline`: Solo reporta hallazgos nuevos vs baseline
  - Reduce ruido en PRs (no reporta issues ya conocidos)
- **Comando**: `auditlens scan ./proyecto --diff-baseline .auditlens-baseline.json`

### Módulos de Integración CI/CD

#### **ci_templates.py**
- **Propósito**: Auto-generación de pipelines de seguridad
- **Templates incluidos**:
  - GitHub Actions: `.github/workflows/auditlens.yml`
  - GitLab CI: `.gitlab-ci.yml`
  - Azure DevOps: `azure-pipelines.yml`
  - Bitbucket: `bitbucket-pipelines.yml`
  - Pre-commit: `.pre-commit-config.yaml`
  - Makefile: `make security-scan`
- **Configuración**:
  - Severity threshold para fail pipeline (default: HIGH)
  - SARIF upload a GitHub Security tab
  - Artifact preservation (findings.json)
  - Caching de dependencies para speed

#### **pre_commit.py**
- **Propósito**: Git pre-commit hook para blocking local
- **Funcionalidad**:
  - Instala hook en `.git/hooks/pre-commit`
  - Escanea solo archivos staged (`git diff --cached --name-only`)
  - Bloquea commit si hay hallazgos >= severity threshold
  - Permite bypass con `git commit --no-verify` (desaconsejado)
  - Configurable per-project en `.auditlens.yaml`
- **Comando**: `auditlens install-hook --severity HIGH`

### Módulos de Notificaciones

#### **notifications.py**
- **Propósito**: Multi-channel alerting para hallazgos críticos
- **Integraciones**:
  - **Slack**: Webhooks con Block Kit formatting
    - Severity-based filtering (min_severity: HIGH)
    - Top 5 findings en mensaje
    - Color coding por severity
    - Link a dashboard (opcional)
  - **JIRA**: Auto-creación de tickets
    - Customizable issue type (Bug, Security, Task)
    - Labels automáticos (auditlens, security, severity)
    - Assignee por defecto
    - Descripción con snippet de código
  - **Email**: SMTP con HTML templates
- **Configuración**: `.auditlens.yaml` con env var expansion (`${SLACK_WEBHOOK}`)

## 3. Flujos de Datos Entre Componentes

### Flujo 1: Escaneo Básico (SAST + SCA)

```
┌─────────────┐
│   CLI       │ auditlens scan ./proyecto
│  cli.py     │
└──────┬──────┘
       │
       ▼
┌────────────────────────────────────────────┐
│  analyzer.py (orchestrator)                │
│  • Detecta lenguaje por extensión          │
│  • Carga parser Tree-sitter                │
│  • Itera archivos recursivamente           │
└──────┬────────────────────┬────────────────┘
       │                    │
       ▼                    ▼
┌─────────────────┐  ┌──────────────────┐
│ rules_engine.py │  │ taint_analyzer.py│
│ • Regex match   │  │ • Source detect  │
│ • AST scan      │  │ • Sink detect    │
│ • Severity map  │  │ • Flow tracking  │
└────────┬────────┘  └────────┬─────────┘
         │                    │
         └────────┬───────────┘
                  │
                  ▼
         ┌────────────────┐
         │  Findings List │ (JSON in-memory)
         └────────┬───────┘
                  │
         ┌────────▼─────────┬────────────┐
         │                  │            │
         ▼                  ▼            ▼
  ┌───────────┐      ┌──────────┐  ┌─────────┐
  │ SCA       │      │ Entropy  │  │ PII     │
  │sca_engine │      │ Scanner  │  │Detector │
  └─────┬─────┘      └────┬─────┘  └────┬────┘
        │                 │             │
        │  OSV API call   │             │
        └────────┬────────┴─────────────┘
                 │
                 ▼
         ┌────────────────┐
         │All Findings    │ (merged)
         │ + CVE enriched │
         └────────┬───────┘
                  │
         ┌────────▼────────┬──────────┬──────────┐
         │                 │          │          │
         ▼                 ▼          ▼          ▼
  ┌──────────┐   ┌─────────────┐  ┌────────┐ ┌─────────┐
  │compliance│   │ history.py  │  │Exporter│ │Notifier │
  │ mapper   │   │ SQLite save │  │ (SARIF,│ │ (Slack, │
  │          │   │             │  │ DOCX)  │ │  JIRA)  │
  └──────────┘   └─────────────┘  └────────┘ └─────────┘
```

### Flujo 2: AI Auto-Fix con Apply

```
┌─────────────┐
│   CLI       │ auditlens fix ./proyecto --apply --severity HIGH
│  cli.py     │
└──────┬──────┘
       │
       ▼
┌──────────────┐
│ analyzer.py  │ (ejecuta scan completo)
└──────┬───────┘
       │
       ▼
┌─────────────────────┐
│ findings filtered   │ (severity >= HIGH)
└──────┬──────────────┘
       │
       ▼
┌───────────────────────────────────────────────────┐
│  ai_fix.py                                        │
│  Para cada finding:                               │
│    1. Extrae snippet de código (±10 líneas)       │
│    2. Construye prompt con contexto:              │
│       • Rule ID + description                     │
│       • CWE + OWASP mapping                       │
│       • Snippet actual                            │
│    3. Llama AI API con temperature=0              │
│    4. Parsea respuesta → diff unificado           │
│    5. Si --apply: aplica patch con difflib       │
│    6. Si --dry-run: solo muestra diff             │
└───────┬───────────────────────────────────────────┘
        │
        ▼
┌────────────────┐
│ Modified files │ (con parches aplicados)
│ + AI report    │ (JSON: original → fixed)
└────────────────┘
```

### Flujo 3: Temporal Archaeology (Git History Mining)

```
┌─────────────┐
│   CLI       │ auditlens archaeology ./proyecto --depth 500
│  cli.py     │
└──────┬──────┘
       │
       ▼
┌──────────────────────────────────────────┐
│ temporal_archaeology.py                  │
│  1. git log --reverse --format="%H %at"  │
│  2. Para cada commit (más antiguo → HEAD)│
│     • git checkout <commit> (detached)   │
│     • Run full SAST scan                 │
│     • Store findings with commit hash    │
│  3. Construye timeline:                  │
│     • Introduced: primera aparición      │
│     • Fixed: desaparición                │
│     • Zombie: reintroducción             │
└──────┬───────────────────────────────────┘
       │
       ▼
┌───────────────────────────────────────┐
│ Vulnerability lifecycle dataset       │
│ {                                     │
│   rule_id, file, line,                │
│   introduced_commit, introduced_date, │
│   fixed_commit, fixed_date,           │
│   lifespan_days,                      │
│   is_zombie                           │
│ }                                     │
└──────┬────────────────────────────────┘
       │
       ▼
┌──────────────────────────┐
│ archaeology_exporter.py  │
│ • Timeline chart (D3.js) │
│ • MTTR metrics           │
│ • Riskiest commits table │
│ • Zombie vulns highlight │
└──────┬───────────────────┘
       │
       ▼
┌────────────────────┐
│archaeology.html    │ (interactive report)
└────────────────────┘
```

### Flujo 4: Attack Surface Graph

```
┌─────────────┐
│   CLI       │ auditlens graph ./proyecto --serve
│  cli.py     │
└──────┬──────┘
       │
       ▼
┌──────────────────────────────────────────────┐
│ attack_surface.py                            │
│  1. Walk directory (Python/JS files only)   │
│  2. Para cada archivo:                       │
│     • Parse AST con Tree-sitter              │
│     • Extract entry points:                  │
│       - HTTP decorators (@app.route)         │
│       - CLI parsers (argparse)               │
│       - Env reads (os.environ)               │
│     • Extract functions (def/function)       │
│     • Extract sinks (eval, subprocess, SQL)  │
│     • Build call edges (function → function) │
│  3. Taint propagation:                       │
│     • BFS from entry points                  │
│     • Mark reachable sinks                   │
│     • Calculate severity (entry → sink path) │
└──────┬───────────────────────────────────────┘
       │
       ▼
┌────────────────────────────────────┐
│ Graph JSON                         │
│ {                                  │
│   nodes: [{id, type, severity}],  │
│   links: [{source, target, type}],│
│   stats: {severity_counts, paths} │
│ }                                  │
└──────┬─────────────────────────────┘
       │
       ▼
┌──────────────────────────────┐
│ attack_surface_server.py     │
│ • Flask server on port 7777  │
│ • D3.js force-directed layout│
│ • Interactive filtering      │
│ • Path highlighting          │
└──────┬───────────────────────┘
       │
       ▼
┌────────────────────┐
│ Browser: localhost │
│   :7777            │
└────────────────────┘
```

### Flujo 5: Web Dashboard (Flask + Gunicorn)

```
┌──────────────┐
│ Docker build │
└──────┬───────┘
       │
       ▼
┌─────────────────────────────────────┐
│ docker-entrypoint.sh                │
│  1. Si SCAN_FIRST=true:             │
│     auditlens scan $SCAN_PATH       │
│  2. Gunicorn dashboard:wsgi --bind  │
│     0.0.0.0:8080 --workers=$WEB_    │
│     CONCURRENCY                     │
└──────┬──────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────┐
│ dashboard.py (Flask app)            │
│  Routes:                            │
│  • GET  / → HTML dashboard          │
│  • GET  /api/findings → JSON        │
│  • POST /api/scan → Trigger scan    │
│  • GET  /api/history → Trends       │
│  • GET  /api/stats → Aggregates     │
│  Auth: Basic (AUDITLENS_USER/PWD)   │
└──────┬──────────────────────────────┘
       │
       ▼
┌──────────────────┬──────────────────┐
│                  │                  │
▼                  ▼                  ▼
┌────────┐   ┌──────────┐   ┌─────────────┐
│history │   │analyzer  │   │notifications│
│.py     │   │.py       │   │.py          │
│SQLite  │   │Run scan  │   │Send alerts  │
└────────┘   └──────────┘   └─────────────┘
       │
       └──────> Chart.js frontend
                (trends, heatmaps)
```

### Flujo 6: CI/CD Integration (GitHub Actions)

```
┌──────────────────┐
│ git push origin  │
│   feature-branch │
└────────┬─────────┘
         │
         ▼
┌─────────────────────────────────────┐
│ GitHub Actions Trigger              │
│ (.github/workflows/auditlens.yml)   │
└────────┬────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│ Workflow steps:                     │
│  1. Checkout code                   │
│  2. Install auditlens               │
│  3. Run: auditlens scan . --format  │
│     sarif -o results.sarif          │
│  4. Upload SARIF to GitHub Security │
│  5. Fail if CRITICAL/HIGH found     │
└────────┬────────────────────────────┘
         │
    ┌────▼────┬───────────┐
    │         │           │
    ▼         ▼           ▼
┌────────┐ ┌──────┐ ┌──────────┐
│Security│ │Slack │ │PR Comment│
│  Tab   │ │Alert │ │github_pr │
└────────┘ └──────┘ └──────────┘
```

## 4. Decisiones Arquitectónicas

### ¿Por qué Tree-sitter en lugar de regex puro?

**Decisión**: Motor SAST basado en Tree-sitter para AST parsing.

**Razones**:
1. **Precisión**: Reduce falsos positivos al entender estructura sintáctica
2. **Multi-lenguaje**: Parser universal para Python, JS, TypeScript, Swift, Go
3. **Performance**: Parsing incremental (cache de nodos sin cambios)
4. **Mantenibilidad**: Gramáticas mantenidas por comunidad (tree-sitter org)
5. **False Negative Reduction**: Detecta patrones complejos (nested functions, decorators)

**Trade-offs**:
- Requiere instalación de bindings por lenguaje (`tree-sitter-python`, etc.)
- Fallback a regex cuando parser no disponible

---

### ¿Por qué SQLite en lugar de MongoDB/PostgreSQL?

**Decisión**: SQLite para persistencia de scan history.

**Razones**:
1. **Zero config**: No requiere servidor separado
2. **Portabilidad**: Single file database (`.auditlens/history.db`)
3. **Suficiente escala**: Miles de scans sin degradación
4. **Transaccionalidad**: ACID guarantees para writes concurrentes
5. **Deployment sencillo**: En Docker, solo montar volume para `/data/db`

**Cuándo migrar**:
- Si multi-tenancy (>100 proyectos concurrentes)
- Si análisis distribuido en cluster
- Si queries complejas (JOIN de hallazgos con metadata externa)

---

### ¿Por qué Flask + Gunicorn en lugar de FastAPI?

**Decisión**: Flask para web dashboard, Gunicorn como WSGI server.

**Razones**:
1. **Madurez**: Ecosistema estable, plugins probados
2. **Simplicidad**: Dashboard no requiere async (scans son background tasks)
3. **Despliegue**: Gunicorn battle-tested en producción
4. **Memory footprint**: Menor que FastAPI + Uvicorn en cargas bajas
5. **Auth**: Flask-HTTPAuth simplifica Basic Auth

**Trade-offs**:
- No async/await nativo (no necesario para dashboard read-heavy)
- Si se requiere SSE (Server-Sent Events) para logs en tiempo real → considerar FastAPI

---

### ¿Por qué no Redis/Celery para distributed scanning?

**Decisión**: Escaneo síncrono en proceso único (no distribuido).

**Razones actuales**:
1. **Simplicidad**: 90% de proyectos escanean en <60 segundos
2. **Resource efficiency**: Tree-sitter ya usa threads internos
3. **Deployment**: No requiere infraestructura adicional (Redis broker, workers)
4. **Debugging**: Stack traces completos sin distribuir contexto

**Cuándo agregar Celery**:
- Proyectos >100k SLOC (scan time >5 minutos)
- Multi-tenancy con cola de prioridad
- Scheduled scans (cron) con rate limiting
- Parallel scanning de múltiples repos

**Implementación futura**:
```python
# Propuesta de arquitectura distribuida
┌──────────────┐     ┌───────────┐     ┌──────────────┐
│  Dashboard   │────▶│ Redis     │────▶│ Celery Worker│
│  (Submit job)│     │ (Queue)   │     │ (Scan task)  │
└──────────────┘     └───────────┘     └──────┬───────┘
       │                                       │
       │                                       ▼
       │                              ┌────────────────┐
       └──────────(Poll status)───────│  Result store  │
                                      │  (Redis/SQL)   │
                                      └────────────────┘
```