# AuditLens Enterprise 🛡️

AuditLens es una **Suite DevSecOps Integral** diseñada para proteger entornos de desarrollo mediante Análisis Estático (SAST), Análisis de Composición de Software (SCA), Taint Analysis y Diagnóstico Post-Mortem. 

Fue construida para auditar no solo la calidad del código, sino también su **cumplimiento normativo** (OWASP, GDPR, Ley N° 19.628, ISO 27001, PCI-DSS).

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
