# AuditLens — Enterprise Deployment Guide

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Enterprise Ready](https://img.shields.io/badge/enterprise-ready-orange.svg)

Guía completa para desplegar AuditLens Dashboard en entornos productivos empresariales con alta disponibilidad, escalabilidad y observabilidad.

---

## 📋 Tabla de Contenidos

1. [Requisitos de Sistema](#1-requisitos-de-sistema)
2. [Deployment con Docker/Kubernetes](#2-deployment-con-dockerkubernetes)
3. [Configuración de Redis/Celery](#3-configuración-de-rediscelery)
4. [Setup de Base de Datos PostgreSQL Multi-tenant](#4-setup-de-base-de-datos-postgresql-multi-tenant)
5. [Variables de Entorno](#5-variables-de-entorno)
6. [Monitoreo y Observabilidad](#6-monitoreo-y-observabilidad)
7. [Backup y Disaster Recovery](#7-backup-y-disaster-recovery)
8. [Scaling Guide](#8-scaling-guide)

---

## 1. Requisitos de Sistema

### 1.1 Requisitos Mínimos (Desarrollo/Staging)

| Componente | Especificación |
|------------|----------------|
| **CPU** | 2 vCPUs |
| **RAM** | 4 GB |
| **Storage** | 20 GB SSD |
| **Python** | 3.9+ |
| **Docker** | 20.10+ |
| **OS** | Linux (Ubuntu 22.04 LTS recomendado) |

### 1.2 Requisitos Recomendados (Producción)

| Componente | Especificación |
|------------|----------------|
| **CPU** | 4-8 vCPUs |
| **RAM** | 16-32 GB |
| **Storage** | 100+ GB SSD (NVMe recomendado) |
| **Network** | 1 Gbps+ |
| **Load Balancer** | Nginx/HAProxy/Cloud LB |
| **Database** | PostgreSQL 14+ (RDS/Cloud SQL) |
| **Cache** | Redis 6+ (ElastiCache/MemoryStore) |
| **Message Broker** | RabbitMQ 3.11+ / Redis (Celery backend) |

### 1.3 Dependencias del Sistema

#### Ubuntu/Debian
```bash
sudo apt-get update && sudo apt-get install -y \
    python3.11 python3.11-venv python3-pip \
    gcc g++ git build-essential \
    postgresql-client libpq-dev \
    redis-tools \
    curl wget ca-certificates
```

#### RHEL/CentOS/Rocky
```bash
sudo yum install -y \
    python3.11 python3-pip \
    gcc gcc-c++ git make \
    postgresql-devel \
    redis \
    curl wget ca-certificates
```

### 1.4 Certificados SSL/TLS

**Producción debe usar HTTPS exclusivamente:**
- Certificado válido (Let's Encrypt recomendado)
- TLS 1.2+ únicamente
- Cipher suites seguros (Mozilla Modern)

---

## 2. Deployment con Docker/Kubernetes

### 2.1 Docker Compose — Entorno Local/Testing

#### Estructura de archivos
```bash
auditlens/
├── docker-compose.yml
├── docker-compose.prod.yml
├── Dockerfile
├── docker-entrypoint.sh
├── .dockerignore
└── auditlens/
```

#### docker-compose.yml (Development)
```yaml
version: '3.8'

services:
  # Dashboard web
  dashboard:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "8080:8080"
    environment:
      AUDITLENS_USER: admin
      AUDITLENS_PASSWORD: changeme
      SCAN_PATH: /data/scan
      AUDITLENS_DB: postgresql://auditlens:password@postgres:5432/auditlens
      REDIS_URL: redis://redis:6379/0
      CELERY_BROKER_URL: redis://redis:6379/1
      WEB_CONCURRENCY: "2"
    volumes:
      - ./:/data/scan:ro
      - auditlens_uploads:/data/uploads
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/api/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  # PostgreSQL database
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: auditlens
      POSTGRES_USER: auditlens
      POSTGRES_PASSWORD: password
      POSTGRES_INITDB_ARGS: "-E UTF8 --locale=C"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./scripts/init-db.sql:/docker-entrypoint-initdb.d/01-init.sql
    ports:
      - "5432:5432"
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U auditlens"]
      interval: 10s
      timeout: 5s
      retries: 5

  # Redis cache & message broker
  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes --requirepass redispassword
    volumes:
      - redis_data:/data
    ports:
      - "6379:6379"
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "redis-cli", "--raw", "incr", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  # Celery worker (background scans)
  celery_worker:
    build:
      context: .
      dockerfile: Dockerfile
    command: celery -A auditlens.celery_app worker -l info -Q scans,analysis,reports
    environment:
      AUDITLENS_DB: postgresql://auditlens:password@postgres:5432/auditlens
      CELERY_BROKER_URL: redis://redis:6379/1
      CELERY_RESULT_BACKEND: redis://redis:6379/2
      REDIS_URL: redis://redis:6379/0
      C_FORCE_ROOT: "true"
    volumes:
      - ./:/data/scan:ro
      - auditlens_uploads:/data/uploads
    depends_on:
      - postgres
      - redis
    restart: unless-stopped

  # Celery beat (scheduled scans)
  celery_beat:
    build:
      context: .
      dockerfile: Dockerfile
    command: celery -A auditlens.celery_app beat -l info
    environment:
      AUDITLENS_DB: postgresql://auditlens:password@postgres:5432/auditlens
      CELERY_BROKER_URL: redis://redis:6379/1
      REDIS_URL: redis://redis:6379/0
    depends_on:
      - postgres
      - redis
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
  auditlens_uploads:
```

#### docker-compose.prod.yml (Production overrides)
```yaml
version: '3.8'

services:
  dashboard:
    environment:
      AUDITLENS_DB: postgresql://auditlens:${DB_PASSWORD}@${DB_HOST}:5432/auditlens?sslmode=require
      REDIS_URL: redis://:${REDIS_PASSWORD}@${REDIS_HOST}:6379/0
      CELERY_BROKER_URL: redis://:${REDIS_PASSWORD}@${REDIS_HOST}:6379/1
      WEB_CONCURRENCY: "4"
      GUNICORN_TIMEOUT: "300"
      LOG_LEVEL: "warning"
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: '2'
          memory: 4G
        reservations:
          cpus: '1'
          memory: 2G
    logging:
      driver: "json-file"
      options:
        max-size: "50m"
        max-file: "10"

  celery_worker:
    deploy:
      replicas: 2
      resources:
        limits:
          cpus: '4'
          memory: 8G
        reservations:
          cpus: '2'
          memory: 4G
```

#### Comandos de deployment
```bash
# Development
docker compose up --build -d

# Production
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Ver logs
docker compose logs -f dashboard

# Verificar salud
docker compose ps
curl http://localhost:8080/api/health
```

### 2.2 Kubernetes — Entorno Productivo

#### Namespace y ConfigMap
```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: auditlens-prod
  labels:
    name: auditlens-prod
    environment: production
---
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: auditlens-config
  namespace: auditlens-prod
data:
  WEB_CONCURRENCY: "4"
  GUNICORN_TIMEOUT: "300"
  LOG_LEVEL: "info"
  SCAN_PATH: "/data/scan"
  PYTHONUNBUFFERED: "1"
```

#### Secrets
```bash
# Crear secrets desde archivo .env
kubectl create secret generic auditlens-secrets \
  --from-literal=AUDITLENS_USER=admin \
  --from-literal=AUDITLENS_PASSWORD="$(openssl rand -base64 32)" \
  --from-literal=DB_PASSWORD="$(openssl rand -base64 32)" \
  --from-literal=REDIS_PASSWORD="$(openssl rand -base64 32)" \
  --from-literal=SECRET_KEY="$(openssl rand -base64 64)" \
  -n auditlens-prod
```

#### Deployment del Dashboard
```yaml
# k8s/deployment-dashboard.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auditlens-dashboard
  namespace: auditlens-prod
  labels:
    app: auditlens
    component: dashboard
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  selector:
    matchLabels:
      app: auditlens
      component: dashboard
  template:
    metadata:
      labels:
        app: auditlens
        component: dashboard
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8080"
        prometheus.io/path: "/metrics"
    spec:
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchExpressions:
                - key: app
                  operator: In
                  values:
                  - auditlens
                - key: component
                  operator: In
                  values:
                  - dashboard
              topologyKey: kubernetes.io/hostname
      containers:
      - name: dashboard
        image: your-registry.azurecr.io/auditlens:1.0.0
        imagePullPolicy: Always
        ports:
        - containerPort: 8080
          name: http
          protocol: TCP
        env:
        - name: AUDITLENS_USER
          valueFrom:
            secretKeyRef:
              name: auditlens-secrets
              key: AUDITLENS_USER
        - name: AUDITLENS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: auditlens-secrets
              key: AUDITLENS_PASSWORD
        - name: AUDITLENS_DB
          value: "postgresql://auditlens:$(DB_PASSWORD)@postgres-service:5432/auditlens?sslmode=require"
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: auditlens-secrets
              key: DB_PASSWORD
        - name: REDIS_URL
          value: "redis://:$(REDIS_PASSWORD)@redis-service:6379/0"
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: auditlens-secrets
              key: REDIS_PASSWORD
        - name: CELERY_BROKER_URL
          value: "redis://:$(REDIS_PASSWORD)@redis-service:6379/1"
        envFrom:
        - configMapRef:
            name: auditlens-config
        resources:
          requests:
            cpu: 1000m
            memory: 2Gi
          limits:
            cpu: 2000m
            memory: 4Gi
        livenessProbe:
          httpGet:
            path: /api/health
            port: 8080
          initialDelaySeconds: 60
          periodSeconds: 30
          timeoutSeconds: 10
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /api/ready
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        volumeMounts:
        - name: uploads
          mountPath: /data/uploads
        - name: tmp
          mountPath: /tmp
      volumes:
      - name: uploads
        persistentVolumeClaim:
          claimName: auditlens-uploads-pvc
      - name: tmp
        emptyDir: {}
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
```

#### Service y Ingress
```yaml
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: auditlens-dashboard
  namespace: auditlens-prod
  labels:
    app: auditlens
    component: dashboard
spec:
  type: ClusterIP
  ports:
  - port: 80
    targetPort: 8080
    protocol: TCP
    name: http
  selector:
    app: auditlens
    component: dashboard
---
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: auditlens-ingress
  namespace: auditlens-prod
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/proxy-body-size: "50m"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "300"
    nginx.ingress.kubernetes.io/rate-limit: "100"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - auditlens.yourdomain.com
    secretName: auditlens-tls
  rules:
  - host: auditlens.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: auditlens-dashboard
            port:
              number: 80
```

#### HorizontalPodAutoscaler
```yaml
# k8s/hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: auditlens-dashboard-hpa
  namespace: auditlens-prod
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: auditlens-dashboard
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 100
        periodSeconds: 30
      - type: Pods
        value: 2
        periodSeconds: 30
      selectPolicy: Max
```

#### Despliegue a Kubernetes
```bash
# Aplicar configuración
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secrets.yaml
kubectl apply -f k8s/postgres/
kubectl apply -f k8s/redis/
kubectl apply -f k8s/deployment-dashboard.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/ingress.yaml
kubectl apply -f k8s/hpa.yaml

# Verificar estado
kubectl get all -n auditlens-prod
kubectl get ing -n auditlens-prod
kubectl logs -f deployment/auditlens-dashboard -n auditlens-prod

# Rollout y rollback
kubectl rollout status deployment/auditlens-dashboard -n auditlens-prod
kubectl rollout undo deployment/auditlens-dashboard -n auditlens-prod
```

---

## 3. Configuración de Redis/Celery

### 3.1 Redis para Cache y Message Broker

#### redis.conf (Producción)
```conf
# /etc/redis/redis.conf

# Network
bind 0.0.0.0
port 6379
protected-mode yes
requirepass your_secure_redis_password_here

# General
daemonize no
pidfile /var/run/redis/redis-server.pid
loglevel notice
logfile /var/log/redis/redis-server.log

# Snapshotting (persistencia)
save 900 1
save 300 10
save 60 10000
stop-writes-on-bgsave-error yes
rdbcompression yes
rdbchecksum yes
dbfilename dump.rdb
dir /var/lib/redis

# Replication (para HA)
# slaveof <masterip> <masterport>
# masterauth <master-password>

# Security
rename-command FLUSHDB ""
rename-command FLUSHALL ""
rename-command CONFIG "CONFIG_b8f3c9d2e1a6"

# Limits
maxclients 10000
maxmemory 4gb
maxmemory-policy allkeys-lru

# Append Only File (AOF) - durabilidad
appendonly yes
appendfilename "appendonly.aof"
appendfsync everysec
no-appendfsync-on-rewrite no
auto-aof-rewrite-percentage 100
auto-aof-rewrite-min-size 64mb
```

#### Deployment Redis en K8s (StatefulSet)
```yaml
# k8s/redis/statefulset.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: redis
  namespace: auditlens-prod
spec:
  serviceName: redis-service
  replicas: 3
  selector:
    matchLabels:
      app: redis
  template:
    metadata:
      labels:
        app: redis
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        command:
        - redis-server
        - /usr/local/etc/redis/redis.conf
        - --requirepass
        - $(REDIS_PASSWORD)
        env:
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: auditlens-secrets
              key: REDIS_PASSWORD
        ports:
        - containerPort: 6379
          name: redis
        volumeMounts:
        - name: redis-data
          mountPath: /data
        - name: redis-config
          mountPath: /usr/local/etc/redis
        resources:
          requests:
            cpu: 500m
            memory: 1Gi
          limits:
            cpu: 1000m
            memory: 2Gi
        livenessProbe:
          tcpSocket:
            port: 6379
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          exec:
            command:
            - redis-cli
            - ping
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: redis-config
        configMap:
          name: redis-config
  volumeClaimTemplates:
  - metadata:
      name: redis-data
    spec:
      accessModes: ["ReadWriteOnce"]
      storageClassName: fast-ssd
      resources:
        requests:
          storage: 20Gi
```

### 3.2 Celery — Workers y Beat Scheduler

#### auditlens/celery_app.py
```python
"""
Celery application for AuditLens — background task processing.
"""
from __future__ import annotations

import os
from celery import Celery
from celery.schedules import crontab

# Configuración de Celery
broker_url = os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/1')
result_backend = os.environ.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/2')

app = Celery('auditlens', broker=broker_url, backend=result_backend)

app.conf.update(
    # Serialización
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    
    # Task routing
    task_routes={
        'auditlens.tasks.scan_project': {'queue': 'scans'},
        'auditlens.tasks.analyze_findings': {'queue': 'analysis'},
        'auditlens.tasks.generate_report': {'queue': 'reports'},
    },
    
    # Rate limiting
    task_annotations={
        'auditlens.tasks.scan_project': {'rate_limit': '10/m'},
        'auditlens.tasks.generate_report': {'rate_limit': '30/m'},
    },
    
    # Retry policy
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_time_limit=3600,  # 1 hora
    task_soft_time_limit=3300,  # 55 minutos
    
    # Result backend
    result_expires=86400,  # 24 horas
    result_extended=True,
    
    # Worker
    worker_prefetch_multiplier=4,
    worker_max_tasks_per_child=1000,
    worker_disable_rate_limits=False,
    
    # Beat scheduler (scans periódicos)
    beat_schedule={
        'scheduled-scan-daily': {
            'task': 'auditlens.tasks.scheduled_scan',
            'schedule': crontab(hour=2, minute=0),  # 2 AM diario
            'args': (),
        },
        'cleanup-old-scans': {
            'task': 'auditlens.tasks.cleanup_old_scans',
            'schedule': crontab(hour=3, minute=0, day_of_week=0),  # Domingo 3 AM
            'args': (90,),  # Eliminar scans > 90 días
        },
        'refresh-cve-database': {
            'task': 'auditlens.tasks.refresh_cve_db',
            'schedule': crontab(hour=1, minute=0),  # 1 AM diario
            'args': (),
        },
    },
)

# Auto-discover tasks
app.autodiscover_tasks(['auditlens'])
```

#### auditlens/tasks.py
```python
"""
Celery tasks for background processing.
"""
from __future__ import annotations

import logging
from typing import Dict, List

from .celery_app import app
from .analyzer import run_static_analysis
from .sca_scanner import run_sca_scan
from .report_generator import generate_pdf_report
from .history import cleanup_scans_older_than

logger = logging.getLogger(__name__)


@app.task(bind=True, name='auditlens.tasks.scan_project')
def scan_project(self, project_path: str, options: Dict) -> Dict:
    """
    Background task: escanear un proyecto completo.
    """
    try:
        logger.info(f"Starting scan for project: {project_path}")
        
        # Actualizar estado
        self.update_state(state='PROGRESS', meta={'step': 'SAST analysis'})
        
        findings = run_static_analysis(
            project_path,
            run_sca=options.get('run_sca', True),
            record_history=True,
        )
        
        self.update_state(state='PROGRESS', meta={'step': 'SCA scan'})
        
        if options.get('run_sca'):
            sca_findings = run_sca_scan(project_path)
            findings.extend(sca_findings)
        
        logger.info(f"Scan completed: {len(findings)} findings")
        
        return {
            'status': 'completed',
            'findings_count': len(findings),
            'project_path': project_path,
        }
        
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        raise self.retry(exc=e, countdown=60, max_retries=3)


@app.task(name='auditlens.tasks.generate_report')
def generate_report(scan_id: int, format: str = 'pdf') -> str:
    """
    Background task: generar reporte de escaneo.
    """
    logger.info(f"Generating {format} report for scan {scan_id}")
    
    if format == 'pdf':
        output_path = generate_pdf_report(scan_id)
    else:
        raise ValueError(f"Unsupported format: {format}")
    
    logger.info(f"Report generated: {output_path}")
    return output_path


@app.task(name='auditlens.tasks.scheduled_scan')
def scheduled_scan() -> Dict:
    """
    Background task: escaneo programado diario.
    """
    # Leer proyectos configurados desde DB
    projects = _get_scheduled_projects()
    
    results = []
    for project in projects:
        result = scan_project.delay(project['path'], project.get('options', {}))
        results.append({'project': project['name'], 'task_id': result.id})
    
    return {'status': 'scheduled', 'projects': results}


@app.task(name='auditlens.tasks.cleanup_old_scans')
def cleanup_old_scans(days: int = 90) -> Dict:
    """
    Background task: limpiar scans antiguos.
    """
    deleted_count = cleanup_scans_older_than(days)
    logger.info(f"Cleaned up {deleted_count} scans older than {days} days")
    return {'status': 'completed', 'deleted_count': deleted_count}


@app.task(name='auditlens.tasks.refresh_cve_db')
def refresh_cve_db() -> Dict:
    """
    Background task: actualizar base de datos de CVEs.
    """
    from .sca_scanner import refresh_osv_cache
    
    updated_count = refresh_osv_cache()
    logger.info(f"CVE database refreshed: {updated_count} entries")
    return {'status': 'completed', 'updated_count': updated_count}


def _get_scheduled_projects() -> List[Dict]:
    """Helper: obtener proyectos configurados para escaneo programado."""
    # TODO: implementar lectura desde DB
    return []
```

#### Deployment Celery Worker en K8s
```yaml
# k8s/celery/deployment-worker.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: celery-worker
  namespace: auditlens-prod
spec:
  replicas: 3
  selector:
    matchLabels:
      app: auditlens
      component: celery-worker
  template:
    metadata:
      labels:
        app: auditlens
        component: celery-worker
    spec:
      containers:
      - name: celery-worker
        image: your-registry.azurecr.io/auditlens:1.0.0
        command:
        - celery
        - -A
        - auditlens.celery_app
        - worker
        - -l
        - info
        - -Q
        - scans,analysis,reports
        - --concurrency=4
        - --max-tasks-per-child=100
        env:
        - name: AUDITLENS_DB
          value: "postgresql://auditlens:$(DB_PASSWORD)@postgres-service:5432/auditlens"
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: auditlens-secrets
              key: DB_PASSWORD
        - name: CELERY_BROKER_URL
          value: "redis://:$(REDIS_PASSWORD)@redis-service:6379/1"
        - name: CELERY_RESULT_BACKEND
          value: "redis://:$(REDIS_PASSWORD)@redis-service:6379/2"
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: auditlens-secrets
              key: REDIS_PASSWORD
        - name: C_FORCE_ROOT
          value: "false"
        resources:
          requests:
            cpu: 2000m
            memory: 4Gi
          limits:
            cpu: 4000m
            memory: 8Gi
        volumeMounts:
        - name: uploads
          mountPath: /data/uploads
      volumes:
      - name: uploads
        persistentVolumeClaim:
          claimName: auditlens-uploads-pvc
---
# k8s/celery/deployment-beat.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: celery-beat
  namespace: auditlens-prod
spec:
  replicas: 1  # Solo 1 instancia de beat scheduler
  selector:
    matchLabels:
      app: auditlens
      component: celery-beat
  template:
    metadata:
      labels:
        app: auditlens
        component: celery-beat
    spec:
      containers:
      - name: celery-beat
        image: your-registry.azurecr.io/auditlens:1.0.0
        command:
        - celery
        - -A
        - auditlens.celery_app
        - beat
        - -l
        - info
        - --schedule=/tmp/celerybeat-schedule
        env:
        - name: AUDITLENS_DB
          value: "postgresql://auditlens:$(DB_PASSWORD)@postgres-service:5432/auditlens"
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: auditlens-secrets
              key: DB_PASSWORD
        - name: CELERY_BROKER_URL
          value: "redis://:$(REDIS_PASSWORD)@redis-service:6379/1"
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: auditlens-secrets
              key: REDIS_PASSWORD
        resources:
          requests:
            cpu: 100m
            memory: 256Mi
          limits:
            cpu: 500m
            memory: 512Mi
```

---

## 4. Setup de Base de Datos PostgreSQL Multi-tenant

### 4.1 Esquema de Base de Datos

#### scripts/init-db.sql
```sql
-- AuditLens Enterprise — PostgreSQL Schema
-- Multi-tenant con row-level security

-- Extensiones
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";  -- Para búsqueda full-text
CREATE EXTENSION IF NOT EXISTS "btree_gin";

-- ══════════════════════════════════════════════════════════════════════════════
-- 1. TENANTS (Multi-tenancy)
-- ══════════════════════════════════════════════════════════════════════════════

CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    slug VARCHAR(100) NOT NULL UNIQUE,
    plan VARCHAR(50) NOT NULL DEFAULT 'free',  -- free, pro, enterprise
    max_projects INT NOT NULL DEFAULT 5,
    max_users INT NOT NULL DEFAULT 10,
    features JSONB DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE INDEX idx_tenants_slug ON tenants(slug);
CREATE INDEX idx_tenants_plan ON tenants(plan);

-- ══════════════════════════════════════════════════════════════════════════════
-- 2. USERS & AUTHENTICATION
-- ══════════════════════════════════════════════════════════════════════════════

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    username VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'viewer',  -- admin, editor, viewer
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    last_login_at TIMESTAMPTZ,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, email),
    UNIQUE(tenant_id, username)
);

CREATE INDEX idx_users_tenant ON users(tenant_id);
CREATE INDEX idx_users_email ON users(email);

-- API tokens
CREATE TABLE api_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    scopes TEXT[] DEFAULT ARRAY[]::TEXT[],
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

CREATE INDEX idx_api_tokens_tenant ON api_tokens(tenant_id);
CREATE INDEX idx_api_tokens_hash ON api_tokens(token_hash);

-- ══════════════════════════════════════════════════════════════════════════════
-- 3. PROJECTS & SCANS
-- ══════════════════════════════════════════════════════════════════════════════

CREATE TABLE projects (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) NOT NULL,
    description TEXT,
    repository_url VARCHAR(500),
    scan_schedule VARCHAR(50),  -- cron expression
    settings JSONB DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    UNIQUE(tenant_id, slug)
);

CREATE INDEX idx_projects_tenant ON projects(tenant_id);
CREATE INDEX idx_projects_slug ON projects(tenant_id, slug);

CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    scan_type VARCHAR(50) NOT NULL,  -- sast, sca, dast, combined
    status VARCHAR(50) NOT NULL DEFAULT 'pending',  -- pending, running, completed, failed
    trigger VARCHAR(50) NOT NULL DEFAULT 'manual',  -- manual, scheduled, api, webhook
    triggered_by UUID REFERENCES users(id) ON DELETE SET NULL,
    
    -- Métricas
    total_findings INT NOT NULL DEFAULT 0,
    critical_count INT NOT NULL DEFAULT 0,
    high_count INT NOT NULL DEFAULT 0,
    medium_count INT NOT NULL DEFAULT 0,
    low_count INT NOT NULL DEFAULT 0,
    info_count INT NOT NULL DEFAULT 0,
    
    -- Metadatos
    duration_seconds INT,
    files_scanned INT,
    lines_scanned INT,
    git_commit VARCHAR(40),
    git_branch VARCHAR(255),
    
    settings JSONB DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    error_message TEXT,
    
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scans_tenant ON scans(tenant_id);
CREATE INDEX idx_scans_project ON scans(project_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created ON scans(created_at DESC);

-- ══════════════════════════════════════════════════════════════════════════════
-- 4. FINDINGS (Vulnerabilidades)
-- ══════════════════════════════════════════════════════════════════════════════

CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    
    -- Identificación
    rule_id VARCHAR(100) NOT NULL,
    rule_name VARCHAR(255) NOT NULL,
    category VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,  -- CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence VARCHAR(20) NOT NULL DEFAULT 'HIGH',  -- HIGH, MEDIUM, LOW
    
    -- Ubicación
    file_path VARCHAR(1000) NOT NULL,
    start_line INT NOT NULL,
    end_line INT,
    start_column INT,
    end_column INT,
    code_snippet TEXT,
    
    -- Descripción
    title VARCHAR(500) NOT NULL,
    description TEXT,
    recommendation TEXT,
    cwe_id VARCHAR(20),
    owasp_category VARCHAR(100),
    
    -- Cumplimiento
    compliance_standards TEXT[],  -- OWASP, PCI-DSS, GDPR, etc.
    
    -- Estado
    status VARCHAR(50) NOT NULL DEFAULT 'open',  -- open, fixed, false_positive, wontfix, suppressed
    resolved_at TIMESTAMPTZ,
    resolved_by UUID REFERENCES users(id) ON DELETE SET NULL,
    resolution_comment TEXT,
    
    -- ML Classification
    ml_confidence FLOAT,
    ml_is_false_positive BOOLEAN,
    
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_findings_tenant ON findings(tenant_id);
CREATE INDEX idx_findings_scan ON findings(scan_id);
CREATE INDEX idx_findings_project ON findings(project_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_findings_rule ON findings(rule_id);
CREATE INDEX idx_findings_file ON findings USING gin(file_path gin_trgm_ops);

-- ══════════════════════════════════════════════════════════════════════════════
-- 5. SUPPRESSIONS (Reglas de supresión)
-- ══════════════════════════════════════════════════════════════════════════════

CREATE TABLE suppressions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    
    rule_id VARCHAR(100),
    file_pattern VARCHAR(500),
    reason TEXT NOT NULL,
    expires_at TIMESTAMPTZ,
    
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE INDEX idx_suppressions_tenant ON suppressions(tenant_id);
CREATE INDEX idx_suppressions_project ON suppressions(project_id);
CREATE INDEX idx_suppressions_rule ON suppressions(rule_id);

-- ══════════════════════════════════════════════════════════════════════════════
-- 6. REPORTS
-- ══════════════════════════════════════════════════════════════════════════════

CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    
    format VARCHAR(20) NOT NULL,  -- pdf, html, json, sarif, excel
    file_path VARCHAR(500),
    file_size_bytes BIGINT,
    
    generated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    
    metadata JSONB DEFAULT '{}'
);

CREATE INDEX idx_reports_tenant ON reports(tenant_id);
CREATE INDEX idx_reports_scan ON reports(scan_id);
CREATE INDEX idx_reports_project ON reports(project_id);

-- ══════════════════════════════════════════════════════════════════════════════
-- 7. AUDIT LOG (Trazabilidad)
-- ══════════════════════════════════════════════════════════════════════════════

CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    
    action VARCHAR(100) NOT NULL,  -- scan.created, finding.resolved, etc.
    resource_type VARCHAR(50) NOT NULL,  -- scan, finding, project, etc.
    resource_id UUID NOT NULL,
    
    ip_address INET,
    user_agent TEXT,
    changes JSONB DEFAULT '{}',
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_tenant ON audit_logs(tenant_id);
CREATE INDEX idx_audit_user ON audit_logs(user_id);
CREATE INDEX idx_audit_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX idx_audit_created ON audit_logs(created_at DESC);

-- ══════════════════════════════════════════════════════════════════════════════
-- 8. NOTIFICATIONS & WEBHOOKS
-- ══════════════════════════════════════════════════════════════════════════════

CREATE TABLE notification_channels (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    
    name VARCHAR(255) NOT NULL,
    channel_type VARCHAR(50) NOT NULL,  -- email, slack, webhook, jira
    config JSONB NOT NULL,
    filters JSONB DEFAULT '{}',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_notifications_tenant ON notification_channels(tenant_id);

-- ══════════════════════════════════════════════════════════════════════════════
-- 9. ROW-LEVEL SECURITY (RLS)
-- ══════════════════════════════════════════════════════════════════════════════

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE suppressions ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- Policy: Los usuarios solo ven datos de su tenant
CREATE POLICY tenant_isolation_policy ON users
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

CREATE POLICY tenant_isolation_policy ON projects
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

CREATE POLICY tenant_isolation_policy ON scans
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

CREATE POLICY tenant_isolation_policy ON findings
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

CREATE POLICY tenant_isolation_policy ON suppressions
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

CREATE POLICY tenant_isolation_policy ON reports
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

CREATE POLICY tenant_isolation_policy ON audit_logs
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

-- ══════════════════════════════════════════════════════════════════════════════
-- 10. FUNCTIONS & TRIGGERS
-- ══════════════════════════════════════════════════════════════════════════════

-- Actualizar updated_at automáticamente
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_tenants_updated_at BEFORE UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_projects_updated_at BEFORE UPDATE ON projects
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_findings_updated_at BEFORE UPDATE ON findings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Actualizar contadores de severidad en scans
CREATE OR REPLACE FUNCTION update_scan_severity_counts()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE scans
    SET
        total_findings = (SELECT COUNT(*) FROM findings WHERE scan_id = NEW.scan_id),
        critical_count = (SELECT COUNT(*) FROM findings WHERE scan_id = NEW.scan_id AND severity = 'CRITICAL'),
        high_count = (SELECT COUNT(*) FROM findings WHERE scan_id = NEW.scan_id AND severity = 'HIGH'),
        medium_count = (SELECT COUNT(*) FROM findings WHERE scan_id = NEW.scan_id AND severity = 'MEDIUM'),
        low_count = (SELECT COUNT(*) FROM findings WHERE scan_id = NEW.scan_id AND severity = 'LOW'),
        info_count = (SELECT COUNT(*) FROM findings WHERE scan_id = NEW.scan_id AND severity = 'INFO')
    WHERE id = NEW.scan_id;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_scan_counts_on_finding_insert
    AFTER INSERT ON findings
    FOR EACH ROW EXECUTE FUNCTION update_scan_severity_counts();

-- ══════════════════════════════════════════════════════════════════════════════
-- 11. VIEWS (Vistas útiles)
-- ══════════════════════════════════════════════════════════════════════════════

-- Vista: Resumen de proyectos con últimos scans
CREATE VIEW project_summary AS
SELECT 
    p.id AS project_id,
    p.tenant_id,
    p.name,
    p.slug,
    COUNT(DISTINCT s.id) AS total_scans,
    MAX(s.completed_at) AS last_scan_at,
    COALESCE(SUM(s.total_findings), 0) AS total_findings,
    COALESCE(SUM(s.critical_count), 0) AS critical_count,
    COALESCE(SUM(s.high_count), 0) AS high_count,
    COALESCE(SUM(s.medium_count), 0) AS medium_count,
    COALESCE(SUM(s.low_count), 0) AS low_count
FROM projects p
LEFT JOIN scans s ON p.id = s.project_id AND s.status = 'completed'
GROUP BY p.id, p.tenant_id, p.name, p.slug;

-- Vista: Findings abiertos por proyecto
CREATE VIEW open_findings_by_project AS
SELECT 
    f.project_id,
    f.tenant_id,
    p.name AS project_name,
    f.severity,
    COUNT(*) AS findings_count
FROM findings f
JOIN projects p ON f.project_id = p.id
WHERE f.status = 'open'
GROUP BY f.project_id, f.tenant_id, p.name, f.severity;

-- ══════════════════════════════════════════════════════════════════════════════
-- 12. SEED DATA (opcional para testing)
-- ══════════════════════════════════════════════════════════════════════════════

-- Crear tenant demo
INSERT INTO tenants (id, name, slug, plan, max_projects, max_users)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'Demo Organization',
    'demo',
    'enterprise',
    100,
    50
);

-- Crear usuario admin demo
INSERT INTO users (tenant_id, email, username, password_hash, role)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'admin@demo.com',
    'admin',
    -- password: 'admin123' (bcrypt hash)
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/Eam3LjMdGGmMqPY7e',
    'admin'
);
```

### 4.2 Migración desde SQLite a PostgreSQL

#### scripts/migrate-sqlite-to-postgres.py
```python
"""
Migrar datos desde SQLite a PostgreSQL.
"""
import sqlite3
import psycopg2
from psycopg2.extras import execute_values
import os

def migrate():
    # Conexiones
    sqlite_conn = sqlite3.connect('history.db')
    sqlite_conn.row_factory = sqlite3.Row
    
    pg_conn = psycopg2.connect(os.environ['AUDITLENS_DB'])
    pg_cur = pg_conn.cursor()
    
    # Obtener tenant_id (asumiendo tenant 'demo')
    pg_cur.execute("SELECT id FROM tenants WHERE slug = 'demo'")
    tenant_id = pg_cur.fetchone()[0]
    
    # Migrar scans
    sqlite_cur = sqlite_conn.execute("""
        SELECT id, path, scanned_at, critical, high, medium, low, findings_json
        FROM scans
        ORDER BY id
    """)
    
    scans_data = []
    for row in sqlite_cur:
        scans_data.append((
            tenant_id,
            row['path'],
            row['scanned_at'],
            row['critical'] + row['high'] + row['medium'] + row['low'],
            row['critical'],
            row['high'],
            row['medium'],
            row['low'],
            row['findings_json'],
        ))
    
    execute_values(pg_cur, """
        INSERT INTO scans (
            tenant_id, project_id, scan_type, status, total_findings,
            critical_count, high_count, medium_count, low_count,
            metadata, completed_at, created_at
        ) VALUES (
            %s, 
            (SELECT id FROM projects WHERE tenant_id = %s LIMIT 1),
            'combined',
            'completed',
            %s, %s, %s, %s, %s,
            %s::jsonb,
            %s, %s
        )
    """, scans_data)
    
    pg_conn.commit()
    print(f"Migrated {len(scans_data)} scans to PostgreSQL")
    
    sqlite_conn.close()
    pg_conn.close()

if __name__ == '__main__':
    migrate()
```

### 4.3 PostgreSQL Deployment en K8s

```yaml
# k8s/postgres/statefulset.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
  namespace: auditlens-prod
spec:
  serviceName: postgres-service
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:15-alpine
        env:
        - name: POSTGRES_DB
          value: auditlens
        - name: POSTGRES_USER
          value: auditlens
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: auditlens-secrets
              key: DB_PASSWORD
        - name: PGDATA
          value: /var/lib/postgresql/data/pgdata
        ports:
        - containerPort: 5432
          name: postgres
        volumeMounts:
        - name: postgres-data
          mountPath: /var/lib/postgresql/data
        - name: init-scripts
          mountPath: /docker-entrypoint-initdb.d
        resources:
          requests:
            cpu: 1000m
            memory: 2Gi
          limits:
            cpu: 2000m
            memory: 4Gi
        livenessProbe:
          exec:
            command:
            - pg_isready
            - -U
            - auditlens
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          exec:
            command:
            - pg_isready
            - -U
            - auditlens
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: init-scripts
        configMap:
          name: postgres-init-scripts
  volumeClaimTemplates:
  - metadata:
      name: postgres-data
    spec:
      accessModes: ["ReadWriteOnce"]
      storageClassName: fast-ssd
      resources:
        requests:
          storage: 100Gi
---
apiVersion: v1
kind: Service
metadata:
  name: postgres-service
  namespace: auditlens-prod
spec:
  selector:
    app: postgres
  ports:
  - port: 5432
    targetPort: 5432
  clusterIP: None  # Headless service for StatefulSet
```

---

## 5. Variables de Entorno

### 5.1 Variables Requeridas

```bash
# ══════════════════════════════════════════════════════════════════════════════
# AUDITLENS ENTERPRISE — PRODUCTION ENVIRONMENT VARIABLES
# ══════════════════════════════════════════════════════════════════════════════

# ── Application ───────────────────────────────────────────────────────────────
AUDITLENS_ENV=production
DEBUG=false
SECRET_KEY=<GENERATE_STRONG_SECRET_KEY_HERE>  # openssl rand -base64 64

# ── Authentication ────────────────────────────────────────────────────────────
AUDITLENS_USER=admin
AUDITLENS_PASSWORD=<STRONG_PASSWORD_HERE>  # openssl rand -base64 32

# ── Database (PostgreSQL) ─────────────────────────────────────────────────────
DATABASE_URL=postgresql://auditlens:PASSWORD@postgres-host:5432/auditlens?sslmode=require
DB_POOL_SIZE=20
DB_MAX_OVERFLOW=40
DB_POOL_TIMEOUT=30
DB_POOL_RECYCLE=3600

# Alternatively, individual components:
DB_HOST=postgres-service
DB_PORT=5432
DB_NAME=auditlens
DB_USER=auditlens
DB_PASSWORD=<DB_PASSWORD_HERE>
DB_SSL_MODE=require

# ── Redis (Cache & Message Broker) ────────────────────────────────────────────
REDIS_URL=redis://:PASSWORD@redis-host:6379/0
REDIS_PASSWORD=<REDIS_PASSWORD_HERE>
REDIS_MAX_CONNECTIONS=50

# ── Celery (Background Tasks) ─────────────────────────────────────────────────
CELERY_BROKER_URL=redis://:PASSWORD@redis-host:6379/1
CELERY_RESULT_BACKEND=redis://:PASSWORD@redis-host:6379/2
CELERY_TASK_ALWAYS_EAGER=false  # false en producción
CELERY_TASK_EAGER_PROPAGATES=false

# ── Web Server (Gunicorn) ─────────────────────────────────────────────────────
WEB_CONCURRENCY=4  # Workers (2x CPU cores + 1)
GUNICORN_TIMEOUT=300  # 5 minutos
GUNICORN_KEEPALIVE=5
GUNICORN_MAX_REQUESTS=1000
GUNICORN_MAX_REQUESTS_JITTER=100
HOST=0.0.0.0
PORT=8080

# ── Storage ───────────────────────────────────────────────────────────────────
SCAN_PATH=/data/scan
UPLOAD_PATH=/data/uploads
MAX_UPLOAD_SIZE=52428800  # 50 MB
ALLOWED_EXTENSIONS=py,js,jsx,ts,tsx,swift,go,java,rb,php

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_LEVEL=info  # debug, info, warning, error, critical
LOG_FORMAT=json  # json, text
SENTRY_DSN=<SENTRY_DSN_HERE>  # opcional

# ── Security ──────────────────────────────────────────────────────────────────
ALLOWED_HOSTS=auditlens.yourdomain.com,*.yourdomain.com
CORS_ORIGINS=https://auditlens.yourdomain.com
SESSION_COOKIE_SECURE=true
SESSION_COOKIE_HTTPONLY=true
SESSION_COOKIE_SAMESITE=Lax
CSRF_COOKIE_SECURE=true

# ── Rate Limiting ─────────────────────────────────────────────────────────────
RATELIMIT_ENABLED=true
RATELIMIT_STORAGE_URL=redis://:PASSWORD@redis-host:6379/3
RATELIMIT_DEFAULT=100/hour

# ── External Services ─────────────────────────────────────────────────────────
# OpenAI / Anthropic (AI features)
ANTHROPIC_API_KEY=<ANTHROPIC_API_KEY_HERE>
OPENAI_API_KEY=<OPENAI_API_KEY_HERE>

# AWS (para AWS auditor)
AWS_ACCESS_KEY_ID=<AWS_ACCESS_KEY_ID_HERE>
AWS_SECRET_ACCESS_KEY=<AWS_SECRET_ACCESS_KEY_HERE>
AWS_DEFAULT_REGION=us-east-1

# GitHub (para GitHub scanner)
GITHUB_TOKEN=<GITHUB_TOKEN_HERE>

# Jira (notificaciones)
JIRA_URL=https://yourcompany.atlassian.net
JIRA_USER=<JIRA_USER_HERE>
JIRA_TOKEN=<JIRA_TOKEN_HERE>

# Slack (notificaciones)
SLACK_WEBHOOK_URL=<SLACK_WEBHOOK_URL_HERE>

# ── Monitoring ────────────────────────────────────────────────────────────────
PROMETHEUS_ENABLED=true
PROMETHEUS_PORT=9090
GRAFANA_ENABLED=true
ENABLE_METRICS=true

# ── Feature Flags ─────────────────────────────────────────────────────────────
FEATURE_AI_AUTOFIX=true
FEATURE_ML_CLASSIFIER=true
FEATURE_ATTACK_CHAINS=true
FEATURE_SUPPLY_CHAIN=true
FEATURE_K8S_AUDITOR=true
FEATURE_NOTIFICATIONS=true

# ── Backup ────────────────────────────────────────────────────────────────────
BACKUP_ENABLED=true
BACKUP_SCHEDULE="0 3 * * *"  # 3 AM diario
BACKUP_RETENTION_DAYS=30
S3_BACKUP_BUCKET=auditlens-backups
```

### 5.2 Gestión de Secrets

#### Usar External Secrets Operator (K8s)
```yaml
# k8s/external-secret.yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: auditlens-secrets
  namespace: auditlens-prod
spec:
  secretStoreRef:
    name: aws-secretsmanager
    kind: SecretStore
  target:
    name: auditlens-secrets
    creationPolicy: Owner
  data:
  - secretKey: AUDITLENS_PASSWORD
    remoteRef:
      key: auditlens/production
      property: password
  - secretKey: DB_PASSWORD
    remoteRef:
      key: auditlens/production
      property: db_password
  - secretKey: REDIS_PASSWORD
    remoteRef:
      key: auditlens/production
      property: redis_password
  - secretKey: ANTHROPIC_API_KEY
    remoteRef:
      key: auditlens/production
      property: anthropic_api_key
```

#### Usando Azure Key Vault
```bash
# Crear Key Vault
az keyvault create \
  --name auditlens-kv \
  --resource-group rg-auditlens \
  --location eastus

# Agregar secrets
az keyvault secret set --vault-name auditlens-kv --name DB-PASSWORD --value "$(openssl rand -base64 32)"
az keyvault secret set --vault-name auditlens-kv --name REDIS-PASSWORD --value "$(openssl rand -base64 32)"
az keyvault secret set --vault-name auditlens-kv --name SECRET-KEY --value "$(openssl rand -base64 64)"

# Dar acceso a la App Service
az webapp identity assign --name auditlens-dashboard --resource-group rg-auditlens
IDENTITY_ID=$(az webapp identity show --name auditlens-dashboard --resource-group rg-auditlens --query principalId -o tsv)

az keyvault set-policy --name auditlens-kv --object-id $IDENTITY_ID --secret-permissions get list
```

---

## 6. Monitoreo y Observabilidad

### 6.1 Prometheus + Grafana

#### Exportar métricas desde Flask
```python
# auditlens/metrics.py
"""
Prometheus metrics exporter.
"""
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
from flask import Response
import time

# Métricas
http_requests_total = Counter(
    'auditlens_http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

http_request_duration_seconds = Histogram(
    'auditlens_http_request_duration_seconds',
    'HTTP request duration',
    ['method', 'endpoint']
)

scans_total = Counter(
    'auditlens_scans_total',
    'Total scans performed',
    ['scan_type', 'status']
)

findings_total = Counter(
    'auditlens_findings_total',
    'Total findings detected',
    ['severity', 'category']
)

active_scans = Gauge(
    'auditlens_active_scans',
    'Number of currently running scans'
)

celery_tasks_total = Counter(
    'auditlens_celery_tasks_total',
    'Total Celery tasks',
    ['task_name', 'status']
)

def metrics_endpoint():
    """Endpoint /metrics para Prometheus."""
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)
```

#### Grafana Dashboard JSON
```json
{
  "dashboard": {
    "title": "AuditLens Enterprise Dashboard",
    "panels": [
      {
        "title": "HTTP Requests per Second",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(auditlens_http_requests_total[5m])",
            "legendFormat": "{{method}} {{endpoint}}"
          }
        ]
      },
      {
        "title": "Scan Throughput",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(auditlens_scans_total[5m])",
            "legendFormat": "{{scan_type}}"
          }
        ]
      },
      {
        "title": "Active Scans",
        "type": "singlestat",
        "targets": [
          {
            "expr": "auditlens_active_scans"
          }
        ]
      },
      {
        "title": "Findings by Severity",
        "type": "piechart",
        "targets": [
          {
            "expr": "sum by (severity) (auditlens_findings_total)",
            "legendFormat": "{{severity}}"
          }
        ]
      }
    ]
  }
}
```

### 6.2 Structured Logging (JSON)

#### auditlens/logger.py
```python
"""
Structured JSON logging para producción.
"""
import logging
import json
import sys
from datetime import datetime
from typing import Any, Dict

class JSONFormatter(logging.Formatter):
    """Formatter para logs en JSON."""
    
    def format(self, record: logging.LogRecord) -> str:
        log_data: Dict[str, Any] = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }
        
        # Agregar extra fields
        if hasattr(record, 'tenant_id'):
            log_data['tenant_id'] = record.tenant_id
        if hasattr(record, 'user_id'):
            log_data['user_id'] = record.user_id
        if hasattr(record, 'scan_id'):
            log_data['scan_id'] = record.scan_id
        
        # Exception info
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
        
        return json.dumps(log_data)

def setup_logging(level: str = 'INFO', log_format: str = 'json'):
    """Configurar logging para la aplicación."""
    root_logger = logging.getLogger()
    root_logger.setLevel(level.upper())
    
    # Remove default handlers
    root_logger.handlers.clear()
    
    # Console handler
    handler = logging.StreamHandler(sys.stdout)
    
    if log_format == 'json':
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
    
    root_logger.addHandler(handler)
    
    # Configurar niveles de bibliotecas
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    logging.getLogger('celery').setLevel(logging.INFO)
```

### 6.3 Health Checks

#### auditlens/healthcheck.py
```python
"""
Health check endpoints para Kubernetes.
"""
from flask import jsonify
import psycopg2
import redis
from typing import Dict, Tuple

def check_database() -> Tuple[bool, str]:
    """Verificar conexión a PostgreSQL."""
    try:
        conn = psycopg2.connect(os.environ['AUDITLENS_DB'])
        cursor = conn.cursor()
        cursor.execute('SELECT 1')
        cursor.close()
        conn.close()
        return True, "OK"
    except Exception as e:
        return False, str(e)

def check_redis() -> Tuple[bool, str]:
    """Verificar conexión a Redis."""
    try:
        r = redis.from_url(os.environ['REDIS_URL'])
        r.ping()
        return True, "OK"
    except Exception as e:
        return False, str(e)

def check_celery() -> Tuple[bool, str]:
    """Verificar workers de Celery."""
    try:
        from .celery_app import app
        inspect = app.control.inspect()
        stats = inspect.stats()
        if stats and len(stats) > 0:
            return True, f"{len(stats)} workers active"
        return False, "No workers available"
    except Exception as e:
        return False, str(e)

def health_endpoint():
    """Endpoint /api/health para readiness probe."""
    db_ok, db_msg = check_database()
    redis_ok, redis_msg = check_redis()
    
    if db_ok and redis_ok:
        return jsonify({'status': 'healthy', 'database': db_msg, 'redis': redis_msg}), 200
    else:
        return jsonify({'status': 'unhealthy', 'database': db_msg, 'redis': redis_msg}), 503

def ready_endpoint():
    """Endpoint /api/ready para liveness probe."""
    return jsonify({'status': 'ready'}), 200
```

### 6.4 Distributed Tracing con OpenTelemetry

```python
# auditlens/tracing.py
"""
OpenTelemetry tracing para observabilidad distribuida.
"""
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.instrumentation.psycopg2 import Psycopg2Instrumentor
from opentelemetry.instrumentation.redis import RedisInstrumentor

def setup_tracing(service_name: str = 'auditlens-dashboard'):
    """Configurar OpenTelemetry tracing."""
    trace.set_tracer_provider(TracerProvider())
    tracer_provider = trace.get_tracer_provider()
    
    # Jaeger exporter
    jaeger_exporter = JaegerExporter(
        agent_host_name=os.environ.get('JAEGER_AGENT_HOST', 'localhost'),
        agent_port=int(os.environ.get('JAEGER_AGENT_PORT', 6831)),
    )
    
    tracer_provider.add_span_processor(
        BatchSpanProcessor(jaeger_exporter)
    )
    
    # Auto-instrumentación
    FlaskInstrumentor().instrument()
    RequestsInstrumentor().instrument()
    Psycopg2Instrumentor().instrument()
    RedisInstrumentor().instrument()
```

---

## 7. Backup y Disaster Recovery

### 7.1 Backup Automático de PostgreSQL

#### scripts/backup-postgres.sh
```bash
#!/bin/bash
# Backup automático de PostgreSQL a S3

set -euo pipefail

# Variables
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/tmp/backups"
BACKUP_FILE="auditlens_backup_${TIMESTAMP}.sql.gz"
S3_BUCKET="${S3_BACKUP_BUCKET:-auditlens-backups}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"

mkdir -p "${BACKUP_DIR}"

echo "[$(date)] Starting PostgreSQL backup..."

# Backup con pg_dump
pg_dump "${AUDITLENS_DB}" | gzip > "${BACKUP_DIR}/${BACKUP_FILE}"

echo "[$(date)] Backup created: ${BACKUP_FILE} ($(du -h ${BACKUP_DIR}/${BACKUP_FILE} | cut -f1))"

# Upload a S3
if command -v aws &> /dev/null; then
    aws s3 cp "${BACKUP_DIR}/${BACKUP_FILE}" "s3://${S3_BUCKET}/postgres/" \
        --storage-class STANDARD_IA \
        --metadata "timestamp=${TIMESTAMP},database=auditlens"
    
    echo "[$(date)] Backup uploaded to S3: s3://${S3_BUCKET}/postgres/${BACKUP_FILE}"
    
    # Eliminar backups antiguos (> RETENTION_DAYS)
    CUTOFF_DATE=$(date -d "${RETENTION_DAYS} days ago" +%Y-%m-%d)
    aws s3 ls "s3://${S3_BUCKET}/postgres/" | while read -r line; do
        FILE=$(echo $line | awk '{print $4}')
        FILE_DATE=$(echo $FILE | grep -oP '\d{8}' | head -1)
        if [[ ! -z "$FILE_DATE" ]] && [[ "$FILE_DATE" < "$(echo $CUTOFF_DATE | tr -d '-')" ]]; then
            aws s3 rm "s3://${S3_BUCKET}/postgres/${FILE}"
            echo "[$(date)] Deleted old backup: ${FILE}"
        fi
    done
else
    echo "[$(date)] WARNING: AWS CLI not found, backup not uploaded"
fi

# Cleanup local
rm -f "${BACKUP_DIR}/${BACKUP_FILE}"
echo "[$(date)] Backup completed successfully"
```

#### CronJob en K8s
```yaml
# k8s/backup/cronjob.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: postgres-backup
  namespace: auditlens-prod
spec:
  schedule: "0 3 * * *"  # 3 AM diario
  successfulJobsHistoryLimit: 7
  failedJobsHistoryLimit: 3
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: postgres:15-alpine
            command:
            - /bin/sh
            - -c
            - |
              apk add --no-cache aws-cli gzip
              /scripts/backup-postgres.sh
            env:
            - name: AUDITLENS_DB
              value: "postgresql://auditlens:$(DB_PASSWORD)@postgres-service:5432/auditlens"
            - name: DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: auditlens-secrets
                  key: DB_PASSWORD
            - name: S3_BACKUP_BUCKET
              value: auditlens-backups
            - name: AWS_ACCESS_KEY_ID
              valueFrom:
                secretKeyRef:
                  name: aws-credentials
                  key: access_key_id
            - name: AWS_SECRET_ACCESS_KEY
              valueFrom:
                secretKeyRef:
                  name: aws-credentials
                  key: secret_access_key
            - name: AWS_DEFAULT_REGION
              value: us-east-1
            volumeMounts:
            - name: backup-scripts
              mountPath: /scripts
          restartPolicy: OnFailure
          volumes:
          - name: backup-scripts
            configMap:
              name: backup-scripts
              defaultMode: 0755
```

### 7.2 Restore desde Backup

#### scripts/restore-postgres.sh
```bash
#!/bin/bash
# Restaurar backup de PostgreSQL desde S3

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <backup-file>"
    echo "Example: $0 auditlens_backup_20260617_030000.sql.gz"
    exit 1
fi

BACKUP_FILE=$1
S3_BUCKET="${S3_BACKUP_BUCKET:-auditlens-backups}"
TEMP_FILE="/tmp/${BACKUP_FILE}"

echo "[$(date)] Starting restore from backup: ${BACKUP_FILE}"

# Download desde S3
aws s3 cp "s3://${S3_BUCKET}/postgres/${BACKUP_FILE}" "${TEMP_FILE}"

echo "[$(date)] Backup downloaded, restoring database..."

# Restore
gunzip -c "${TEMP_FILE}" | psql "${AUDITLENS_DB}"

# Cleanup
rm -f "${TEMP_FILE}"

echo "[$(date)] Restore completed successfully"
```

### 7.3 Disaster Recovery Plan

#### Runbook: Recuperación ante desastre

**RTO (Recovery Time Objective):** 2 horas  
**RPO (Recovery Point Objective):** 24 horas (backups diarios)

**Procedimiento:**

1. **Identificar el alcance del desastre**
   ```bash
   kubectl get pods -n auditlens-prod
   kubectl logs -n auditlens-prod deployment/auditlens-dashboard --tail=100
   ```

2. **Listar backups disponibles**
   ```bash
   aws s3 ls s3://auditlens-backups/postgres/ | tail -10
   ```

3. **Provisionar nueva base de datos (si es necesario)**
   ```bash
   kubectl apply -f k8s/postgres/statefulset.yaml
   kubectl wait --for=condition=ready pod/postgres-0 -n auditlens-prod --timeout=300s
   ```

4. **Restaurar desde backup**
   ```bash
   LATEST_BACKUP=$(aws s3 ls s3://auditlens-backups/postgres/ | tail -1 | awk '{print $4}')
   ./scripts/restore-postgres.sh "$LATEST_BACKUP"
   ```

5. **Verificar integridad de datos**
   ```bash
   psql "${AUDITLENS_DB}" -c "SELECT COUNT(*) FROM scans;"
   psql "${AUDITLENS_DB}" -c "SELECT COUNT(*) FROM findings;"
   ```

6. **Reiniciar aplicación**
   ```bash
   kubectl rollout restart deployment/auditlens-dashboard -n auditlens-prod
   kubectl rollout status deployment/auditlens-dashboard -n auditlens-prod
   ```

7. **Verificar funcionamiento**
   ```bash
   curl -u admin:password https://auditlens.yourdomain.com/api/health
   ```

---

## 8. Scaling Guide

### 8.1 Horizontal Scaling — Pods

#### Auto-scaling basado en CPU/Memory (ya configurado en HPA)
```bash
# Ver estado del HPA
kubectl get hpa -n auditlens-prod

# Escalar manualmente (temporal)
kubectl scale deployment auditlens-dashboard --replicas=5 -n auditlens-prod

# Ver uso de recursos
kubectl top pods -n auditlens-prod
kubectl top nodes
```

### 8.2 Vertical Scaling — Recursos por Pod

#### Ajustar requests/limits
```yaml
# k8s/deployment-dashboard.yaml (ajustar)
resources:
  requests:
    cpu: 2000m    # 2 CPUs
    memory: 4Gi   # 4 GB
  limits:
    cpu: 4000m    # 4 CPUs
    memory: 8Gi   # 8 GB
```

### 8.3 Database Scaling

#### PostgreSQL Read Replicas
```yaml
# k8s/postgres/statefulset-replica.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres-replica
  namespace: auditlens-prod
spec:
  serviceName: postgres-replica-service
  replicas: 2
  selector:
    matchLabels:
      app: postgres-replica
  template:
    metadata:
      labels:
        app: postgres-replica
    spec:
      containers:
      - name: postgres
        image: postgres:15-alpine
        env:
        - name: POSTGRES_USER
          value: auditlens
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: auditlens-secrets
              key: DB_PASSWORD
        - name: PGDATA
          value: /var/lib/postgresql/data/pgdata
        # Configuración de replica
        - name: POSTGRES_REPLICATION_MODE
          value: slave
        - name: POSTGRES_MASTER_HOST
          value: postgres-service
        - name: POSTGRES_MASTER_PORT
          value: "5432"
        ports:
        - containerPort: 5432
          name: postgres
        volumeMounts:
        - name: postgres-data
          mountPath: /var/lib/postgresql/data
        resources:
          requests:
            cpu: 1000m
            memory: 2Gi
          limits:
            cpu: 2000m
            memory: 4Gi
  volumeClaimTemplates:
  - metadata:
      name: postgres-data
    spec:
      accessModes: ["ReadWriteOnce"]
      storageClassName: fast-ssd
      resources:
        requests:
          storage: 100Gi
```

#### Connection Pooling con PgBouncer
```yaml
# k8s/postgres/pgbouncer.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pgbouncer
  namespace: auditlens-prod
spec:
  replicas: 2
  selector:
    matchLabels:
      app: pgbouncer
  template:
    metadata:
      labels:
        app: pgbouncer
    spec:
      containers:
      - name: pgbouncer
        image: edoburu/pgbouncer:1.20.0
        env:
        - name: DATABASE_URL
          value: "postgres://auditlens:$(DB_PASSWORD)@postgres-service:5432/auditlens"
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: auditlens-secrets
              key: DB_PASSWORD
        - name: POOL_MODE
          value: transaction
        - name: MAX_CLIENT_CONN
          value: "1000"
        - name: DEFAULT_POOL_SIZE
          value: "25"
        - name: MIN_POOL_SIZE
          value: "10"
        - name: RESERVE_POOL_SIZE
          value: "5"
        - name: RESERVE_POOL_TIMEOUT
          value: "5"
        ports:
        - containerPort: 5432
          name: postgres
        resources:
          requests:
            cpu: 500m
            memory: 512Mi
          limits:
            cpu: 1000m
            memory: 1Gi
---
apiVersion: v1
kind: Service
metadata:
  name: pgbouncer-service
  namespace: auditlens-prod
spec:
  selector:
    app: pgbouncer
  ports:
  - port: 5432
    targetPort: 5432
  type: ClusterIP
```

### 8.4 Redis Scaling (Redis Cluster)

```yaml
# k8s/redis/redis-cluster.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: redis-cluster
  namespace: auditlens-prod
spec:
  serviceName: redis-cluster-service
  replicas: 6  # 3 masters + 3 replicas
  selector:
    matchLabels:
      app: redis-cluster
  template:
    metadata:
      labels:
        app: redis-cluster
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        command:
        - redis-server
        - /conf/redis.conf
        - --cluster-enabled
        - "yes"
        - --cluster-config-file
        - /data/nodes.conf
        - --cluster-node-timeout
        - "5000"
        - --requirepass
        - $(REDIS_PASSWORD)
        env:
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: auditlens-secrets
              key: REDIS_PASSWORD
        ports:
        - containerPort: 6379
          name: client
        - containerPort: 16379
          name: gossip
        volumeMounts:
        - name: redis-data
          mountPath: /data
        - name: redis-config
          mountPath: /conf
        resources:
          requests:
            cpu: 500m
            memory: 1Gi
          limits:
            cpu: 1000m
            memory: 2Gi
      volumes:
      - name: redis-config
        configMap:
          name: redis-cluster-config
  volumeClaimTemplates:
  - metadata:
      name: redis-data
    spec:
      accessModes: ["ReadWriteOnce"]
      storageClassName: fast-ssd
      resources:
        requests:
          storage: 10Gi
```

### 8.5 Celery Workers Scaling

```bash
# Auto-scaling basado en longitud de cola
kubectl apply -f k8s/celery/hpa-celery-worker.yaml
```

```yaml
# k8s/celery/hpa-celery-worker.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: celery-worker-hpa
  namespace: auditlens-prod
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: celery-worker
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  # Custom metric: longitud de cola de Celery
  - type: External
    external:
      metric:
        name: celery_queue_length
        selector:
          matchLabels:
            queue_name: scans
      target:
        type: AverageValue
        averageValue: "10"
```

### 8.6 CDN & Caching Strategy

#### CloudFront (AWS) o Azure CDN
```yaml
# cloudfront-distribution.yaml
Resources:
  AuditLensCDN:
    Type: AWS::CloudFront::Distribution
    Properties:
      DistributionConfig:
        Enabled: true
        Origins:
        - Id: auditlens-origin
          DomainName: auditlens.yourdomain.com
          CustomOriginConfig:
            HTTPSPort: 443
            OriginProtocolPolicy: https-only
        DefaultCacheBehavior:
          TargetOriginId: auditlens-origin
          ViewerProtocolPolicy: redirect-to-https
          AllowedMethods: [GET, HEAD, OPTIONS, PUT, POST, PATCH, DELETE]
          CachedMethods: [GET, HEAD, OPTIONS]
          ForwardedValues:
            QueryString: true
            Headers:
            - Authorization
            - Host
            Cookies:
              Forward: all
          Compress: true
          MinTTL: 0
          DefaultTTL: 0  # No cachear por defecto (dashboard dinámico)
        CacheBehaviors:
        - PathPattern: /static/*
          TargetOriginId: auditlens-origin
          ViewerProtocolPolicy: redirect-to-https
          ForwardedValues:
            QueryString: false
          Compress: true
          MinTTL: 3600
          DefaultTTL: 86400  # 24 horas para assets estáticos
          MaxTTL: 31536000   # 1 año
```

### 8.7 Load Testing

#### k6 Load Test Script
```javascript
// loadtest.js
import http from 'k6/http';
import { check, sleep } from 'k6';

export let options = {
  stages: [
    { duration: '2m', target: 100 },   // Ramp-up a 100 usuarios
    { duration: '5m', target: 100 },   // Stay at 100 usuarios
    { duration: '2m', target: 200 },   // Ramp-up a 200 usuarios
    { duration: '5m', target: 200 },   // Stay at 200 usuarios
    { duration: '2m', target: 0 },     // Ramp-down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'],  // 95% de requests < 500ms
    http_req_failed: ['rate<0.01'],    // <1% error rate
  },
};

const BASE_URL = 'https://auditlens.yourdomain.com';
const USERNAME = 'admin';
const PASSWORD = __ENV.AUDITLENS_PASSWORD;

export default function () {
  // Login (Basic Auth)
  const credentials = `${USERNAME}:${PASSWORD}`;
  const encodedCredentials = encoding.b64encode(credentials);
  const params = {
    headers: {
      'Authorization': `Basic ${encodedCredentials}`,
    },
  };
  
  // Test endpoints
  let res = http.get(`${BASE_URL}/api/findings`, params);
  check(res, {
    'status is 200': (r) => r.status === 200,
    'response time < 500ms': (r) => r.timings.duration < 500,
  });
  
  res = http.get(`${BASE_URL}/api/history`, params);
  check(res, {
    'status is 200': (r) => r.status === 200,
  });
  
  sleep(1);
}
```

#### Ejecutar load test
```bash
# Instalar k6
brew install k6  # macOS
# o
sudo apt-get install k6  # Ubuntu

# Run test
k6 run --vus 100 --duration 10m loadtest.js

# Con Grafana Live Dashboard
k6 run --out influxdb=http://localhost:8086/k6 loadtest.js
```

---

## 9. Checklist de Deployment

### Pre-deployment
- [ ] Variables de entorno configuradas
- [ ] Secrets rotados y almacenados en vault
- [ ] Certificados SSL/TLS válidos
- [ ] Base de datos inicializada y migrada
- [ ] Backup inicial creado
- [ ] Load balancer configurado
- [ ] DNS apuntando a load balancer
- [ ] Monitoreo configurado (Prometheus/Grafana)
- [ ] Logging centralizado configurado
- [ ] Rate limiting habilitado
- [ ] CORS configurado correctamente

### Post-deployment
- [ ] Health checks respondiendo 200 OK
- [ ] Dashboard accesible vía HTTPS
- [ ] Login funcionando correctamente
- [ ] Scans ejecutándose sin errores
- [ ] Celery workers procesando tareas
- [ ] Redis respondiendo correctamente
- [ ] PostgreSQL aceptando conexiones
- [ ] Métricas apareciendo en Prometheus
- [ ] Logs estructurados en CloudWatch/ELK
- [ ] Backups automáticos funcionando
- [ ] Alertas configuradas en Slack/PagerDuty
- [ ] Load test ejecutado exitosamente

### Security Hardening
- [ ] Firewall configurado (solo puertos necesarios)
- [ ] Network policies en K8s aplicadas
- [ ] Pod security policies habilitadas
- [ ] Service accounts con mínimos permisos
- [ ] Secrets encriptados at-rest
- [ ] TLS entre servicios internos
- [ ] Rate limiting por IP/usuario
- [ ] CSRF protection habilitado
- [ ] SQL injection prevention (ORM)
- [ ] XSS prevention (Content Security Policy)

---

## 10. Troubleshooting

### Problema: Dashboard no inicia
```bash
# Ver logs
kubectl logs -f deployment/auditlens-dashboard -n auditlens-prod

# Verificar variables de entorno
kubectl exec -it deployment/auditlens-dashboard -n auditlens-prod -- env | grep AUDITLENS

# Verificar conectividad a DB
kubectl exec -it deployment/auditlens-dashboard -n auditlens-prod -- \
  psql "${AUDITLENS_DB}" -c "SELECT 1"
```

### Problema: Scans lentos
```bash
# Ver workers activos
celery -A auditlens.celery_app inspect active

# Ver cola de tareas
celery -A auditlens.celery_app inspect reserved

# Escalar workers
kubectl scale deployment celery-worker --replicas=5 -n auditlens-prod
```

### Problema: Alta memoria
```bash
# Ver uso de memoria
kubectl top pods -n auditlens-prod

# Reiniciar pods con high memory
kubectl rollout restart deployment/auditlens-dashboard -n auditlens-prod

# Ajustar limits
kubectl set resources deployment/auditlens-dashboard -n auditlens-prod \
  --limits=memory=4Gi --requests=memory=2Gi
```

---

## 11. Contacto y Soporte

**Documentación:** https://github.com/MasterCapehart/auditlens  
**Issues:** https://github.com/MasterCapehart/auditlens/issues  
**Email:** support@auditlens.io  

---

**🛡️ AuditLens Enterprise — Deployment Guide v1.0.0**  
*Última actualización: Junio 2026*
```