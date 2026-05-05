# AuditLens CLI

AuditLens es una Herramienta Integral de Análisis SAST, Diagnóstico Post-Mortem y Compliance Normativo para Entornos de Desarrollo. 

Esta herramienta CLI te permite escanear proyectos en busca de secretos expuestos y problemas legales de manejo de datos (como la Ley N° 19.628), además de proveer una envoltura de ejecución que diagnostica *crashes* en tiempo real con gran detalle.

## Instalación

Puedes instalar esta herramienta globalmente en tu sistema directamente desde GitHub utilizando `pip`:

```bash
pip install git+https://github.com/MasterCapehart/auditlens.git
```


Una vez instalado, el comando `auditlens` estará disponible en tu terminal.

## Uso

### 1. Escaneo Estático (SAST & Compliance)

Escanea un archivo o toda una carpeta en busca de malas prácticas y datos sensibles hardcodeados.

```bash
auditlens scan .
auditlens scan src/main.py
```

### 2. Diagnóstico Dinámico (Post-Mortem)

En lugar de correr tu programa con `python main.py`, córrelo con AuditLens. Si tu programa sufre un error crítico, AuditLens lo atrapará e imprimirá un reporte detallado.

```bash
auditlens run main.py
```

Si tu script usa argumentos:

```bash
auditlens run main.py --puerto 8080
```
