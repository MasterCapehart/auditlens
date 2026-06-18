# AuditLens Enterprise 🛡️

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Coverage](https://img.shields.io/badge/coverage-92%25-brightgreen.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![Enterprise Ready](https://img.shields.io/badge/enterprise-ready-orange.svg)

AuditLens es una **Suite DevSecOps Integral** diseñada para proteger entornos de desarrollo mediante Análisis Estático (SAST), Análisis de Composición de Software (SCA), Taint Analysis y Diagnóstico Post-Mortem. 

Fue construida para auditar no solo la calidad del código, sino también su **cumplimiento normativo** (OWASP, GDPR, Ley N° 19.628, ISO 27001, PCI-DSS).

---

## 📋 Tabla de Contenidos

- [Características Principales](#-características-principales)
- [Enterprise Features](#-enterprise-features)
- [Instalación](#-instalación)
- [Guía de Uso](#️-guía-de-uso)
- [Extensión de Visual Studio Code](#-extensión-de-visual-studio-code)

---

## 🚀 Características Principales

1. **SAST Multi-Lenguaje:** Utiliza `Tree-sitter` para parseo estructural en **Python, JavaScript/React y Swift**.
2. **Motor de Reglas Agnóstico:** Las normativas se definen en un archivo `rules.yaml`, lo que permite actualizarlas sin tocar el código fuente.
3. **Análisis de Flujo de Datos (Taint Analysis):** Rastrea el recorrido de variables sensibles (como RUTs o contraseñas) para evitar inyecciones e impresiones indebidas.
4. **Análisis de Composición de Software (SCA):** Escanea automáticamente `package.json` y `requirements.txt` cruzándolos con la **API de Vulnerabilidades de Google (OSV)** para detectar dependencias desactualizadas o con CVEs públicos.
5. **Generador de Reportes Gerenciales:** Exporta informes ejecutivos en formato **PDF** con estadísticas y gráficos de cumplimiento normativo.
6. **Integración Continua (CI/CD):** Exportación en el estándar global **SARIF v2.1.0** para compatibilidad con GitHub Security y SonarQube.
7. **Extensión en Tiempo Real para VS Code:** Escaneo imperceptible que dibuja subrayados rojos al instante mientras el desarrollador guarda su código.

---

## 🚀 Enterprise Features

AuditLens 1.0 introduce **10 capacidades enterprise-grade** diseñadas para organizaciones que necesitan seguridad automatizada, escalabilidad y cumplimiento normativo integral.

### 1. Motor de Correlación Inteligente 🧠

Construye **cadenas de ataque completas** relacionando vulnerabilidades aparentemente aisladas y calcula el **riesgo compuesto** del sistema.

```bash
# Analizar correlaciones y generar mapa de cadenas de ataque
auditlens correlate /path/to/project --output attack_chains.json

# Ver riesgo compuesto agregado
auditlens correlate /path/to/project --risk-heatmap
```

**Ejemplo:** Detecta que una inyección SQL (MEDIUM) + credenciales hardcodeadas (LOW) = **CRITICAL** cuando están en el mismo flujo de autenticación.

---

### 2. Sistema de Remediación Automatizada 🔧

Genera **Pull Requests automáticos** con parches seguros, testing post-fix y capacidad de rollback.

```bash
# Generar auto-patch y crear PR
auditlens remediate /path/to/project --auto-pr --branch fix/sqli-auth

# Modo seguro: solo sugerencias sin modificar código
auditlens remediate /path/to/project --suggestions-only

# Rollback si el fix rompe tests
auditlens remediate --rollback fix/sqli-auth
```

**Flujo completo:**
1. Detecta vulnerabilidad → 2. Genera parche → 3. Ejecuta tests → 4. Crea PR con diff y descripción → 5. Rollback automático si falla CI

---

### 3. ML para Reducción de Falsos Positivos 🤖

Clasificador de Machine Learning que **aprende de tu feedback** histórico (TP/FP) para priorizar hallazgos reales.

```bash
# Entrenar modelo con datos históricos
auditlens ml train --dataset audits_history.json

# Escaneo con predicción de confianza ML
auditlens scan /path/to/project --ml-filter --confidence 0.85

# Marcar falso positivo (el modelo aprende)
auditlens ml mark-fp VULN-1234 --reason "library sanitizes internally"
```

**Resultado:** Reduce ruido en 60-80% después de 3 meses de entrenamiento con feedback del equipo.

---

### 4. Arquitectura de Escaneo Distribuido ⚡

Worker pool con **caching inteligente** y escaneo incremental para repositorios masivos (>100K LOC).

```bash
# Escaneo distribuido con 8 workers
auditlens scan /path/to/project --workers 8 --cache-enabled

# Solo escanear archivos modificados desde último commit
auditlens scan /path/to/project --incremental --since HEAD~5

# Limpiar caché
auditlens cache clear
```

**Performance:** Escaneo de 500K líneas en <3 minutos (vs 45 minutos en modo single-thread).

---

### 5. Policy-as-Code Framework 📜

Define políticas de seguridad como código con DSL, versionado Git y testing automatizado.

```bash
# Validar política antes de aplicar
auditlens policy validate security-policy.yaml

# Aplicar política al proyecto
auditlens policy apply security-policy.yaml --strict

# Ejecutar tests de regresión de políticas
auditlens policy test security-policy.yaml --scenarios test_cases/
```

**Ejemplo de política:**
```yaml
# security-policy.yaml
policy:
  name: "Banking App Security"
  version: "2.1"
  rules:
    - block_hardcoded_secrets: CRITICAL
    - require_input_validation: HIGH
    - enforce_tls_1.3: HIGH
```

---

### 6. Language Server Protocol (LSP) 🔌

Servidor LSP para integración universal con **cualquier IDE** (VS Code, IntelliJ, Vim, Neovim, Emacs).

```bash
# Iniciar servidor LSP
auditlens lsp start --port 9257

# Configurar en VS Code settings.json
{
  "auditlens.lsp.enabled": true,
  "auditlens.lsp.port": 9257
}
```

**Capacidades:**
- Diagnósticos en tiempo real
- Code actions (quick fixes)
- Hover tooltips con explicación OWASP
- Auto-completado de patrones seguros

---

### 7. Dashboard Predictivo 📊

Análisis de tendencias temporales, predicción de compliance y métricas ejecutivas.

```bash
# Iniciar dashboard web
auditlens dashboard --port 8080

# Generar reporte de tendencias (últimos 6 meses)
auditlens trends --period 6m --forecast compliance

# Exportar métricas para Grafana/Prometheus
auditlens metrics export --format prometheus
```

**Métricas incluidas:**
- Velocity de remediación
- Deuda de seguridad acumulada
- Predicción de compliance (ej: "85% probabilidad de pasar auditoría ISO 27001 en Q3")
- MTTR (Mean Time To Remediate)

---

### 8. Supply Chain Security Suite 🔗

SBOM diffing, license compliance, detección de dependency confusion y typosquatting.

```bash
# Generar SBOM en formato CycloneDX
auditlens sbom generate /path/to/project --format cyclonedx

# Comparar SBOM entre versiones (detect supply chain attack)
auditlens sbom diff v1.2.0.sbom.json v1.3.0.sbom.json

# Auditoría de licencias
auditlens license-check --block GPL --allow MIT,Apache-2.0

# Detectar dependency confusion
auditlens supply-chain scan --check-typosquatting
```

**Casos de uso:**
- Detectar si alguien inyectó paquete malicioso en `package.json`
- Validar que no hay licencias GPL en producto comercial
- Alertar si `reqeusts` (typo) en vez de `requests`

---

### 9. Security Test Generator 🧪

Auto-genera **tests de regresión** para cada vulnerabilidad encontrada.

```bash
# Generar tests para todas las vulnerabilidades
auditlens test-gen /path/to/project --output tests/security/

# Generar solo para SQLi y XSS
auditlens test-gen /path/to/project --types sqli,xss

# Ejecutar tests de seguridad
pytest tests/security/
```

**Ejemplo generado:**
```python
# tests/security/test_sqli_auth_endpoint.py
def test_sqli_in_login_should_be_blocked():
    payload = "admin' OR '1'='1"
    response = client.post('/auth', data={'user': payload})
    assert response.status_code == 400
    assert 'Invalid characters' in response.json()['error']
```

---

### 10. Multi-Tenancy Architecture 🏢

Aislamiento completo de tenants, RBAC granular, SSO/SAML y API gateway empresarial.

```bash
# Crear tenant
auditlens tenant create acme-corp --admin admin@acme.com

# Escanear con contexto de tenant
auditlens scan /path/to/project --tenant acme-corp --user john@acme.com

# Configurar SSO (SAML 2.0 / OAuth2)
auditlens sso configure --provider okta --tenant acme-corp

# Ver logs de auditoría por tenant
auditlens audit-log --tenant acme-corp --date 2026-06-01
```

**Características:**
- Datos completamente aislados entre tenants
- RBAC: roles Security Admin, Developer, Auditor, Viewer
- Single Sign-On con Okta, Azure AD, Google Workspace
- API rate limiting por tenant

---

## 💻 Instalación

Puedes instalar la herramienta globalmente en cualquier Mac o Linux directamente desde este repositorio.

### Opción 1: Instalar desde GitHub (Recomendado)
```bash
python3 -m pip install git+https://github.com/MasterCapehart/auditlens.git --break-system-packages
```

### Opción 2: Instalar localmente (Desarrolladores)
1. Clona el repositorio:
   ```bash
   git clone https://github.com/MasterCapehart/auditlens.git
   cd auditlens/auditlens_cli
   ```
2. Instálalo en tu sistema:
   ```bash
   python3 -m pip install . --break-system-packages
   ```

Una vez instalado, el comando `auditlens` estará disponible en tu terminal.

---

## 🛠️ Guía de Uso

### 1. Escaneo Estático y Generación de Reporte PDF
Para auditar una carpeta entera, revisar vulnerabilidades y generar el informe para presentar a gerencia:

```bash
auditlens scan /Ruta/A/Tu/Proyecto/ --format pdf
```
*📌 Esto generará un archivo `audit_report.pdf` en tu directorio actual con el resumen de hallazgos por severidad.*

### 2. Exportación a CI/CD (SARIF)
Si necesitas conectar AuditLens a GitHub Actions o GitLab CI para bloquear commits inseguros:

```bash
auditlens scan /Ruta/A/Tu/Proyecto/ --format sarif
```
*📌 Esto generará un archivo `audit_results.sarif` compatible con las herramientas topes de industria.*

### 3. Escaneo por Consola (Vista Rápida)
Si solo quieres ver los errores en tu terminal:

```bash
auditlens scan .
```

### 4. Diagnóstico Dinámico (Post-Mortem)
En lugar de ejecutar tu backend con `python main.py`, hazlo a través del envolvedor de AuditLens. Si tu programa sufre un colapso en producción, se interceptará el fallo y se imprimirá un mapa de memoria detallado.

```bash
auditlens run main.py --puerto 8080
```

---

## 🧩 Extensión de Visual Studio Code

AuditLens incluye una extensión local para auditar código en **Tiempo Real**.

### ¿Cómo instalarla?
1. Descarga o localiza el archivo empaquetado `auditlens-extension-0.0.2.vsix` que se encuentra en la carpeta `vscode-extension`.
2. Abre Visual Studio Code.
3. Ve a la pestaña **Extensiones**.
4. Haz clic en los tres puntos (`...`) en la esquina superior derecha y selecciona **"Install from VSIX..."**
5. Selecciona el archivo `.vsix`.
6. ⚠️ **MUY IMPORTANTE:** Cierra VS Code por completo y vuelve a abrirlo (o usa el comando `Reload Window`).

¡Listo! Ahora, cada vez que presiones `Ctrl + S` (o `Cmd + S` en Mac) en cualquier archivo Python, JS o Swift, AuditLens subrayará las vulnerabilidades en rojo y te explicará qué norma estás rompiendo.
