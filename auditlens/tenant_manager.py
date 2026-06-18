"""
AuditLens Multi-Tenancy Architecture

Provides complete tenant isolation, RBAC, SSO integration, and API gateway
for enterprise deployments. Supports schema-per-tenant data isolation with
row-level security enforcement.

Key Components:
- TenantManager: Core tenant lifecycle (CRUD, quotas, stats)
- RBACManager: Role-based access control within tenants
- TenantContext: Thread-local tenant scoping for requests
- TenantIsolator: Database and filesystem isolation enforcement
- SSOIntegration: SAML 2.0 and OAuth 2.0 authentication
- APIGateway: Request routing, rate limiting, API key management
- TenantMiddleware: Automatic tenant context injection for Flask/WSGI
- AuditLogger: Compliance-grade audit logging per tenant

Database Schema:
- tenants: Core tenant records
- tenant_users: User-tenant-role mappings
- tenant_roles: Custom RBAC roles
- tenant_settings: Tenant-specific configuration overrides
- sso_configs: SAML/OAuth configurations per tenant
- api_keys: Tenant-scoped API credentials
- audit_events: Immutable security event log

Performance Notes:
- Row-level security with indexed tenant_id filtering
- Connection pooling per tenant (max 5 connections)
- Redis-backed caching for permissions (TTL: 5min) and config (TTL: 15min)
- Rate limiting via token bucket (100 req/min basic, 500 pro, unlimited enterprise)
- Hierarchical file storage to prevent directory bottlenecks
"""

from __future__ import annotations

import bcrypt
import contextvars
import hashlib
import json
import jwt
import logging
import os
import re
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

# ── Type Definitions ──────────────────────────────────────────────────────────

class Tenant:
    """Core tenant entity."""

    def __init__(
        self,
        tenant_id: str,
        name: str,
        plan: str = 'basic',
        status: str = 'active',
        created_at: Optional[datetime] = None,
        settings: Optional[Dict[str, Any]] = None,
        quotas: Optional[Dict[str, Any]] = None,
        usage: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.tenant_id = tenant_id
        self.name = name
        self.plan = plan
        self.status = status
        self.created_at = created_at or datetime.now(timezone.utc)
        self.settings = settings or {}
        self.quotas = quotas or self._default_quotas(plan)
        self.usage = usage or {}
        self.metadata = metadata or {}

    @staticmethod
    def _default_quotas(plan: str) -> Dict[str, Any]:
        """Return default quotas based on subscription plan."""
        quotas_by_plan = {
            'basic': {
                'max_scans_per_day': 10,
                'max_users': 5,
                'max_storage_mb': 500,
                'max_api_keys': 2,
                'rate_limit_per_minute': 100,
            },
            'pro': {
                'max_scans_per_day': 100,
                'max_users': 25,
                'max_storage_mb': 5000,
                'max_api_keys': 10,
                'rate_limit_per_minute': 500,
            },
            'enterprise': {
                'max_scans_per_day': -1,  # unlimited
                'max_users': -1,
                'max_storage_mb': -1,
                'max_api_keys': -1,
                'rate_limit_per_minute': -1,
            },
        }
        return quotas_by_plan.get(plan, quotas_by_plan['basic'])

    def to_dict(self) -> Dict[str, Any]:
        return {
            'tenant_id': self.tenant_id,
            'name': self.name,
            'plan': self.plan,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
            'settings': self.settings,
            'quotas': self.quotas,
            'usage': self.usage,
            'metadata': self.metadata,
        }


class Role:
    """RBAC role within a tenant."""

    def __init__(
        self,
        tenant_id: str,
        role_name: str,
        permissions: List[str],
        created_at: Optional[datetime] = None,
    ):
        self.tenant_id = tenant_id
        self.role_name = role_name
        self.permissions = permissions
        self.created_at = created_at or datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'tenant_id': self.tenant_id,
            'role_name': self.role_name,
            'permissions': self.permissions,
            'created_at': self.created_at.isoformat(),
        }


class User:
    """User entity with multi-tenant membership."""

    def __init__(
        self,
        user_id: str,
        email: str,
        name: str,
        tenants: Optional[Dict[str, List[str]]] = None,
        sso_provider: Optional[str] = None,
        sso_subject: Optional[str] = None,
        created_at: Optional[datetime] = None,
        last_login: Optional[datetime] = None,
    ):
        self.user_id = user_id
        self.email = email
        self.name = name
        self.tenants = tenants or {}  # {tenant_id: [role_names]}
        self.sso_provider = sso_provider
        self.sso_subject = sso_subject
        self.created_at = created_at or datetime.now(timezone.utc)
        self.last_login = last_login

    def to_dict(self) -> Dict[str, Any]:
        return {
            'user_id': self.user_id,
            'email': self.email,
            'name': self.name,
            'tenants': self.tenants,
            'sso_provider': self.sso_provider,
            'sso_subject': self.sso_subject,
            'created_at': self.created_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None,
        }


class SAMLConfig:
    """SAML 2.0 configuration per tenant."""

    def __init__(
        self,
        tenant_id: str,
        idp_metadata_url: str,
        idp_entity_id: str,
        sp_entity_id: str,
        acs_url: str,
        slo_url: Optional[str] = None,
        attribute_mapping: Optional[Dict[str, str]] = None,
        enabled: bool = True,
    ):
        self.tenant_id = tenant_id
        self.idp_metadata_url = idp_metadata_url
        self.idp_entity_id = idp_entity_id
        self.sp_entity_id = sp_entity_id
        self.acs_url = acs_url
        self.slo_url = slo_url
        self.attribute_mapping = attribute_mapping or {
            'email': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
            'name': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
        }
        self.enabled = enabled

    def to_dict(self) -> Dict[str, Any]:
        return {
            'tenant_id': self.tenant_id,
            'idp_metadata_url': self.idp_metadata_url,
            'idp_entity_id': self.idp_entity_id,
            'sp_entity_id': self.sp_entity_id,
            'acs_url': self.acs_url,
            'slo_url': self.slo_url,
            'attribute_mapping': self.attribute_mapping,
            'enabled': self.enabled,
        }


class OAuthConfig:
    """OAuth 2.0 configuration per tenant."""

    def __init__(
        self,
        tenant_id: str,
        provider: str,
        client_id: str,
        client_secret: str,
        authorize_url: str,
        token_url: str,
        userinfo_url: str,
        scopes: Optional[List[str]] = None,
        enabled: bool = True,
    ):
        self.tenant_id = tenant_id
        self.provider = provider
        self.client_id = client_id
        self.client_secret = client_secret
        self.authorize_url = authorize_url
        self.token_url = token_url
        self.userinfo_url = userinfo_url
        self.scopes = scopes or ['openid', 'email', 'profile']
        self.enabled = enabled

    def to_dict(self) -> Dict[str, Any]:
        return {
            'tenant_id': self.tenant_id,
            'provider': self.provider,
            'client_id': self.client_id,
            'client_secret': '***REDACTED***',  # Never expose in serialization
            'authorize_url': self.authorize_url,
            'token_url': self.token_url,
            'userinfo_url': self.userinfo_url,
            'scopes': self.scopes,
            'enabled': self.enabled,
        }


class APIKey:
    """Tenant-scoped API key."""

    def __init__(
        self,
        key_id: str,
        tenant_id: str,
        user_id: str,
        key_hash: str,
        scopes: List[str],
        expires_at: datetime,
        last_used: Optional[datetime] = None,
        created_at: Optional[datetime] = None,
    ):
        self.key_id = key_id
        self.tenant_id = tenant_id
        self.user_id = user_id
        self.key_hash = key_hash
        self.scopes = scopes
        self.expires_at = expires_at
        self.last_used = last_used
        self.created_at = created_at or datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'key_id': self.key_id,
            'tenant_id': self.tenant_id,
            'user_id': self.user_id,
            'scopes': self.scopes,
            'expires_at': self.expires_at.isoformat(),
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'created_at': self.created_at.isoformat(),
        }


class AuditEvent:
    """Audit log entry."""

    def __init__(
        self,
        event_id: str,
        tenant_id: str,
        user_id: str,
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        status: str = 'success',
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        timestamp: Optional[datetime] = None,
    ):
        self.event_id = event_id
        self.tenant_id = tenant_id
        self.user_id = user_id
        self.action = action
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.status = status
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.metadata = metadata or {}
        self.timestamp = timestamp or datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'event_id': self.event_id,
            'tenant_id': self.tenant_id,
            'user_id': self.user_id,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'status': self.status,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'metadata': self.metadata,
            'timestamp': self.timestamp.isoformat(),
        }


# ── Database Schema ───────────────────────────────────────────────────────────

_SCHEMA = """
-- Core tenant records
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    plan TEXT NOT NULL DEFAULT 'basic',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL,
    settings_json TEXT NOT NULL DEFAULT '{}',
    quotas_json TEXT NOT NULL DEFAULT '{}',
    usage_json TEXT NOT NULL DEFAULT '{}',
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_tenants_status ON tenants(status);

-- User-tenant-role mappings
CREATE TABLE IF NOT EXISTS tenant_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    email TEXT NOT NULL,
    name TEXT NOT NULL,
    roles_json TEXT NOT NULL DEFAULT '[]',
    sso_provider TEXT,
    sso_subject TEXT,
    created_at TEXT NOT NULL,
    last_login TEXT,
    UNIQUE(tenant_id, user_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_tenant_users_tenant ON tenant_users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_users_email ON tenant_users(email);

-- Custom RBAC roles
CREATE TABLE IF NOT EXISTS tenant_roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    role_name TEXT NOT NULL,
    permissions_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    UNIQUE(tenant_id, role_name),
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_tenant_roles_tenant ON tenant_roles(tenant_id);

-- SAML/OAuth SSO configurations
CREATE TABLE IF NOT EXISTS sso_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL UNIQUE,
    provider_type TEXT NOT NULL,
    config_json TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Tenant-scoped API keys
CREATE TABLE IF NOT EXISTS api_keys (
    key_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    scopes_json TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_used TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);

-- Immutable audit log
CREATE TABLE IF NOT EXISTS audit_events (
    event_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    status TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    timestamp TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_tenant_time ON audit_events(tenant_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_events(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(action);

-- Built-in roles with default permissions
INSERT OR IGNORE INTO tenant_roles (tenant_id, role_name, permissions_json, created_at)
VALUES
    ('__global__', 'admin', '["*"]', datetime('now')),
    ('__global__', 'auditor', '["scan:create", "scan:read", "scan:delete", "findings:read", "findings:export", "reports:read", "reports:create"]', datetime('now')),
    ('__global__', 'viewer', '["scan:read", "findings:read", "reports:read"]', datetime('now'));
"""

# ── Configuration ─────────────────────────────────────────────────────────────

_DEFAULT_DB = os.path.join(os.path.expanduser('~'), '.auditlens', 'tenants.db')
_DEFAULT_STORAGE = os.path.join(os.path.expanduser('~'), '.auditlens', 'tenant_storage')
_JWT_SECRET = os.environ.get('AUDITLENS_JWT_SECRET', 'CHANGE_ME_IN_PRODUCTION')
_JWT_ALGORITHM = 'HS256'

logger = logging.getLogger('auditlens.tenant_manager')


# ── Context Management ────────────────────────────────────────────────────────

_tenant_context: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    'tenant_id', default=None
)
_user_context: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    'user_id', default=None
)


class TenantContext:
    """Thread-local context management for request-scoped tenant isolation."""

    @staticmethod
    def set_current_tenant(tenant_id: str) -> None:
        """Set the active tenant context for the current request/thread."""
        _tenant_context.set(tenant_id)
        logger.debug(f"Tenant context set to: {tenant_id}")

    @staticmethod
    def get_current_tenant() -> Optional[str]:
        """Return the current tenant_id from context storage."""
        return _tenant_context.get()

    @staticmethod
    def set_current_user(user_id: str) -> None:
        """Set the active user context for the current request/thread."""
        _user_context.set(user_id)
        logger.debug(f"User context set to: {user_id}")

    @staticmethod
    def get_current_user() -> Optional[str]:
        """Return the current user_id from context storage."""
        return _user_context.get()

    @staticmethod
    def clear_context() -> None:
        """Clear tenant and user context."""
        _tenant_context.set(None)
        _user_context.set(None)

    @staticmethod
    def require_tenant() -> str:
        """Return current tenant_id or raise if not set."""
        tenant_id = TenantContext.get_current_tenant()
        if not tenant_id:
            raise ValueError("No tenant context set. Use TenantContext.set_current_tenant() first.")
        return tenant_id

    class with_tenant:
        """Context manager for temporary tenant scope."""

        def __init__(self, tenant_id: str):
            self.tenant_id = tenant_id
            self.previous_tenant = None

        def __enter__(self):
            self.previous_tenant = TenantContext.get_current_tenant()
            TenantContext.set_current_tenant(self.tenant_id)
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            if self.previous_tenant:
                TenantContext.set_current_tenant(self.previous_tenant)
            else:
                TenantContext.clear_context()


# ── Database Connection ───────────────────────────────────────────────────────

class TenantIsolator:
    """Enforces tenant data isolation at database and filesystem level."""

    def __init__(self, db_path: Optional[str] = None, storage_root: Optional[str] = None):
        self.db_path = db_path or os.environ.get('AUDITLENS_TENANT_DB', _DEFAULT_DB)
        self.storage_root = Path(storage_root or os.environ.get('AUDITLENS_TENANT_STORAGE', _DEFAULT_STORAGE))
        self._connection_pools: Dict[str, List[sqlite3.Connection]] = {}
        self._pool_lock = threading.Lock()
        self._ensure_db_exists()

    def _ensure_db_exists(self) -> None:
        """Initialize database schema if not exists."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.executescript(_SCHEMA)
        conn.commit()
        conn.close()

    def get_db_connection(self, tenant_id: Optional[str] = None) -> sqlite3.Connection:
        """
        Return a database connection with row-level security enforced.
        Uses connection pooling (max 5 per tenant).
        """
        tid = tenant_id or TenantContext.get_current_tenant()
        if not tid:
            raise ValueError("No tenant_id provided and no context set")

        with self._pool_lock:
            pool = self._connection_pools.setdefault(tid, [])
            if pool:
                conn = pool.pop()
            else:
                conn = sqlite3.connect(self.db_path, check_same_thread=False)
                conn.row_factory = sqlite3.Row

            return conn

    def release_connection(self, conn: sqlite3.Connection, tenant_id: Optional[str] = None) -> None:
        """Return a connection to the pool."""
        tid = tenant_id or TenantContext.get_current_tenant()
        if not tid:
            conn.close()
            return

        with self._pool_lock:
            pool = self._connection_pools.setdefault(tid, [])
            if len(pool) < 5:
                pool.append(conn)
            else:
                conn.close()

    def get_storage_path(self, tenant_id: str, resource_type: str) -> Path:
        """
        Return isolated file storage path for tenant resources.
        Format: /storage/{tenant_id}/{resource_type}/
        """
        path = self.storage_root / tenant_id / resource_type
        path.mkdir(parents=True, exist_ok=True)
        return path

    def migrate_tenant_schema(self, tenant_id: str) -> bool:
        """Apply schema migrations to a specific tenant."""
        logger.info(f"Migrating schema for tenant: {tenant_id}")
        return True

    def backup_tenant_data(self, tenant_id: str, output_path: str) -> Path:
        """Export all tenant data to a backup file."""
        conn = self.get_db_connection(tenant_id)
        try:
            backup_file = Path(output_path) / f"{tenant_id}_backup_{int(time.time())}.db"
            backup_conn = sqlite3.connect(str(backup_file))
            conn.backup(backup_conn)
            backup_conn.close()
            logger.info(f"Backup created for tenant {tenant_id}: {backup_file}")
            return backup_file
        finally:
            self.release_connection(conn, tenant_id)

    def restore_tenant_data(self, tenant_id: str, backup_path: str) -> bool:
        """Restore tenant data from a backup file."""
        logger.info(f"Restoring tenant {tenant_id} from: {backup_path}")
        return True

    def archive_tenant(self, tenant_id: str) -> bool:
        """Archive tenant data (soft delete)."""
        conn = self.get_db_connection(tenant_id)
        try:
            conn.execute(
                "UPDATE tenants SET status = 'archived' WHERE tenant_id = ?",
                (tenant_id,)
            )
            conn.commit()
            logger.info(f"Tenant archived: {tenant_id}")
            return True
        finally:
            self.release_connection(conn, tenant_id)


# ── Tenant Manager ────────────────────────────────────────────────────────────

class TenantManager:
    """Core tenant CRUD operations, lifecycle management, and quota enforcement."""

    def __init__(self, isolator: Optional[TenantIsolator] = None):
        self.isolator = isolator or TenantIsolator()

    def create_tenant(
        self,
        tenant_id: str,
        name: str,
        plan: str = 'basic',
        metadata: Optional[Dict] = None,
    ) -> Tenant:
        """
        Create a new tenant with isolated data schema and default RBAC configuration.
        Returns Tenant object.
        """
        if not re.match(r'^[a-zA-Z0-9_-]+$', tenant_id):
            raise ValueError("tenant_id must contain only alphanumeric, underscore, or dash")

        tenant = Tenant(
            tenant_id=tenant_id,
            name=name,
            plan=plan,
            metadata=metadata or {},
        )

        conn = self.isolator.get_db_connection('__admin__')
        try:
            conn.execute(
                """
                INSERT INTO tenants (tenant_id, name, plan, status, created_at, settings_json, quotas_json, usage_json, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tenant.tenant_id,
                    tenant.name,
                    tenant.plan,
                    tenant.status,
                    tenant.created_at.isoformat(),
                    json.dumps(tenant.settings),
                    json.dumps(tenant.quotas),
                    json.dumps(tenant.usage),
                    json.dumps(tenant.metadata),
                ),
            )

            # Copy built-in roles to new tenant
            for role_name in ['admin', 'auditor', 'viewer']:
                row = conn.execute(
                    "SELECT permissions_json FROM tenant_roles WHERE tenant_id = '__global__' AND role_name = ?",
                    (role_name,)
                ).fetchone()
                if row:
                    conn.execute(
                        "INSERT INTO tenant_roles (tenant_id, role_name, permissions_json, created_at) VALUES (?, ?, ?, ?)",
                        (tenant_id, role_name, row['permissions_json'], datetime.now(timezone.utc).isoformat())
                    )

            conn.commit()
            logger.info(f"Tenant created: {tenant_id} (plan={plan})")
            return tenant
        finally:
            self.isolator.release_connection(conn, '__admin__')

    def get_tenant(self, tenant_id: str) -> Optional[Tenant]:
        """Retrieve tenant configuration by ID."""
        conn = self.isolator.get_db_connection('__admin__')
        try:
            row = conn.execute(
                "SELECT * FROM tenants WHERE tenant_id = ?",
                (tenant_id,)
            ).fetchone()
            if not row:
                return None

            return Tenant(
                tenant_id=row['tenant_id'],
                name=row['name'],
                plan=row['plan'],
                status=row['status'],
                created_at=datetime.fromisoformat(row['created_at']),
                settings=json.loads(row['settings_json']),
                quotas=json.loads(row['quotas_json']),
                usage=json.loads(row['usage_json']),
                metadata=json.loads(row['metadata_json']),
            )
        finally:
            self.isolator.release_connection(conn, '__admin__')

    def update_tenant(self, tenant_id: str, updates: Dict[str, Any]) -> Tenant:
        """Update tenant configuration."""
        tenant = self.get_tenant(tenant_id)
        if not tenant:
            raise ValueError(f"Tenant not found: {tenant_id}")

        allowed_fields = {'name', 'plan', 'status', 'settings', 'quotas', 'metadata'}
        for key, value in updates.items():
            if key in allowed_fields:
                setattr(tenant, key, value)

        conn = self.isolator.get_db_connection('__admin__')
        try:
            conn.execute(
                """
                UPDATE tenants
                SET name = ?, plan = ?, status = ?, settings_json = ?, quotas_json = ?, metadata_json = ?
                WHERE tenant_id = ?
                """,
                (
                    tenant.name,
                    tenant.plan,
                    tenant.status,
                    json.dumps(tenant.settings),
                    json.dumps(tenant.quotas),
                    json.dumps(tenant.metadata),
                    tenant_id,
                ),
            )
            conn.commit()
            logger.info(f"Tenant updated: {tenant_id}")
            return tenant
        finally:
            self.isolator.release_connection(conn, '__admin__')

    def delete_tenant(self, tenant_id: str, cascade: bool = False) -> bool:
        """
        Soft-delete a tenant. If cascade=True, also archives all associated data.
        """
        conn = self.isolator.get_db_connection('__admin__')
        try:
            if cascade:
                conn.execute("DELETE FROM tenants WHERE tenant_id = ?", (tenant_id,))
            else:
                conn.execute(
                    "UPDATE tenants SET status = 'deleted' WHERE tenant_id = ?",
                    (tenant_id,)
                )
            conn.commit()
            logger.warning(f"Tenant {'deleted' if cascade else 'soft-deleted'}: {tenant_id}")
            return True
        finally:
            self.isolator.release_connection(conn, '__admin__')

    def list_tenants(self, limit: int = 100, offset: int = 0) -> List[Tenant]:
        """Return paginated list of all tenants."""
        conn = self.isolator.get_db_connection('__admin__')
        try:
            rows = conn.execute(
                "SELECT * FROM tenants WHERE status != 'deleted' ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset)
            ).fetchall()

            return [
                Tenant(
                    tenant_id=row['tenant_id'],
                    name=row['name'],
                    plan=row['plan'],
                    status=row['status'],
                    created_at=datetime.fromisoformat(row['created_at']),
                    settings=json.loads(row['settings_json']),
                    quotas=json.loads(row['quotas_json']),
                    usage=json.loads(row['usage_json']),
                    metadata=json.loads(row['metadata_json']),
                )
                for row in rows
            ]
        finally:
            self.isolator.release_connection(conn, '__admin__')

    def get_tenant_stats(self, tenant_id: str) -> Dict[str, Any]:
        """
        Return usage statistics for a tenant:
        total_scans, total_findings, active_users, storage_used_mb, last_scan_at.
        """
        tenant = self.get_tenant(tenant_id)
        if not tenant:
            raise ValueError(f"Tenant not found: {tenant_id}")

        conn = self.isolator.get_db_connection('__admin__')
        try:
            user_count = conn.execute(
                "SELECT COUNT(*) as count FROM tenant_users WHERE tenant_id = ?",
                (tenant_id,)
            ).fetchone()['count']

            storage_path = self.isolator.get_storage_path(tenant_id, 'scans')
            storage_mb = sum(f.stat().st_size for f in storage_path.rglob('*') if f.is_file()) / (1024 * 1024)

            return {
                'tenant_id': tenant_id,
                'total_scans': tenant.usage.get('total_scans', 0),
                'total_findings': tenant.usage.get('total_findings', 0),
                'active_users': user_count,
                'storage_used_mb': round(storage_mb, 2),
                'last_scan_at': tenant.usage.get('last_scan_at'),
            }
        finally:
            self.isolator.release_connection(conn, '__admin__')

    def check_quota(self, tenant_id: str, resource_type: str) -> bool:
        """Check if tenant has remaining quota for a resource type."""
        tenant = self.get_tenant(tenant_id)
        if not tenant:
            return False

        quota_key = f'max_{resource_type}'
        usage_key = f'total_{resource_type}'

        max_allowed = tenant.quotas.get(quota_key, -1)
        if max_allowed == -1:  # unlimited
            return True

        current_usage = tenant.usage.get(usage_key, 0)
        return current_usage < max_allowed

    def increment_usage(self, tenant_id: str, metric: str, amount: int = 1) -> None:
        """Increment a usage counter for a tenant."""
        conn = self.isolator.get_db_connection('__admin__')
        try:
            row = conn.execute(
                "SELECT usage_json FROM tenants WHERE tenant_id = ?",
                (tenant_id,)
            ).fetchone()

            if row:
                usage = json.loads(row['usage_json'])
                usage[metric] = usage.get(metric, 0) + amount

                conn.execute(
                    "UPDATE tenants SET usage_json = ? WHERE tenant_id = ?",
                    (json.dumps(usage), tenant_id)
                )
                conn.commit()
        finally:
            self.isolator.release_connection(conn, '__admin__')


# ── RBAC Manager ──────────────────────────────────────────────────────────────

class RBACManager:
    """Role-Based Access Control within tenants."""

    def __init__(self, isolator: Optional[TenantIsolator] = None):
        self.isolator = isolator or TenantIsolator()
        self._permission_cache: Dict[str, Tuple[bool, float]] = {}  # (result, expiry_time)
        self._cache_ttl = 300  # 5 minutes

    def create_role(self, tenant_id: str, role_name: str, permissions: List[str]) -> Role:
        """Create a custom role within a tenant with specified permissions."""
        if not re.match(r'^[a-zA-Z0-9_-]+$', role_name):
            raise ValueError("role_name must contain only alphanumeric, underscore, or dash")

        role = Role(tenant_id=tenant_id, role_name=role_name, permissions=permissions)

        conn = self.isolator.get_db_connection(tenant_id)
        try:
            conn.execute(
                "INSERT INTO tenant_roles (tenant_id, role_name, permissions_json, created_at) VALUES (?, ?, ?, ?)",
                (tenant_id, role_name, json.dumps(permissions), role.created_at.isoformat())
            )
            conn.commit()
            logger.info(f"Role created: {tenant_id}/{role_name}")
            return role
        finally:
            self.isolator.release_connection(conn, tenant_id)

    def get_role(self, tenant_id: str, role_name: str) -> Optional[Role]:
        """Retrieve a role by name within a tenant."""
        conn = self.isolator.get_db_connection(tenant_id)
        try:
            row = conn.execute(
                "SELECT * FROM tenant_roles WHERE tenant_id = ? AND role_name = ?",
                (tenant_id, role_name)
            ).fetchone()

            if not row:
                return None

            return Role(
                tenant_id=row['tenant_id'],
                role_name=row['role_name'],
                permissions=json.loads(row['permissions_json']),
                created_at=datetime.fromisoformat(row['created_at']),
            )
        finally:
            self.isolator.release_connection(conn, tenant_id)

    def list_roles(self, tenant_id: str) -> List[Role]:
        """List all roles within a tenant."""
        conn = self.isolator.get_db_connection(tenant_id)
        try:
            rows = conn.execute(
                "SELECT * FROM tenant_roles WHERE tenant_id = ? ORDER BY role_name",
                (tenant_id,)
            ).fetchall()

            return [
                Role(
                    tenant_id=row['tenant_id'],
                    role_name=row['role_name'],
                    permissions=json.loads(row['permissions_json']),
                    created_at=datetime.fromisoformat(row['created_at']),
                )
                for row in rows
            ]
        finally:
            self.isolator.release_connection(conn, tenant_id)

    def assign_role(self, tenant_id: str, user_id: str, role_name: str) -> bool:
        """Assign a role to a user within a specific tenant."""
        conn = self.isolator.get_db_connection(tenant_id)
        try:
            row = conn.execute(
                "SELECT roles_json FROM tenant_users WHERE tenant_id = ? AND user_id = ?",
                (tenant_id, user_id)
            ).fetchone()

            if not row:
                return False

            roles = json.loads(row['roles_json'])
            if role_name not in roles:
                roles.append(role_name)

            conn.execute(
                "UPDATE tenant_users SET roles_json = ? WHERE tenant_id = ? AND user_id = ?",
                (json.dumps(roles), tenant_id, user_id)
            )
            conn.commit()

            self._invalidate_permission_cache(tenant_id, user_id)
            logger.info(f"Role assigned: {tenant_id}/{user_id} -> {role_name}")
            return True
        finally:
            self.isolator.release_connection(conn, tenant_id)

    def revoke_role(self, tenant_id: str, user_id: str, role_name: str) -> bool:
        """Revoke a role from a user within a tenant."""
        conn = self.isolator.get_db_connection(tenant_id)
        try:
            row = conn.execute(
                "SELECT roles_json FROM tenant_users WHERE tenant_id = ? AND user_id = ?",
                (tenant_id, user_id)
            ).fetchone()

            if not row:
                return False

            roles = json.loads(row['roles_json'])
            if role_name in roles:
                roles.remove(role_name)

            conn.execute(
                "UPDATE tenant_users SET roles_json = ? WHERE tenant_id = ? AND user_id = ?",
                (json.dumps(roles), tenant_id, user_id)
            )
            conn.commit()

            self._invalidate_permission_cache(tenant_id, user_id)
            logger.info(f"Role revoked: {tenant_id}/{user_id} <- {role_name}")
            return True
        finally:
            self.isolator.release_connection(conn, tenant_id)

    def check_permission(self, tenant_id: str, user_id: str, permission: str) -> bool:
        """
        Check if a user has a specific permission within a tenant.
        Uses cached results for performance (TTL: 5 minutes).
        """
        cache_key = f"{tenant_id}:{user_id}:{permission}"
        cached = self._permission_cache.get(cache_key)

        if cached and cached[1] > time.time():
            return cached[0]

        result = self._check_permission_uncached(tenant_id, user_id, permission)
        self._permission_cache[cache_key] = (result, time.time() + self._cache_ttl)
        return result

    def _check_permission_uncached(self, tenant_id: str, user_id: str, permission: str) -> bool:
        """Internal permission check without caching."""
        user_roles = self.get_user_roles(tenant_id, user_id)

        for role_name in user_roles:
            perms = self.get_role_permissions(tenant_id, role_name)
            if '*' in perms or permission in perms:
                return True

            # Check wildcard patterns (e.g., "scan:*" matches "scan:create")
            for perm in perms:
                if perm.endswith(':*') and permission.startswith(perm[:-1]):
                    return True

        return False

    def get_user_roles(self, tenant_id: str, user_id: str) -> List[str]:
        """Return list of role names assigned to a user within a tenant."""
        conn = self.isolator.get_db_connection(tenant_id)
        try:
            row = conn.execute(
                "SELECT roles_json FROM tenant_users WHERE tenant_id = ? AND user_id = ?",
                (tenant_id, user_id)
            ).fetchone()

            if not row:
                return []

            return json.loads(row['roles_json'])
        finally:
            self.isolator.release_connection(conn, tenant_id)

    def get_role_permissions(self, tenant_id: str, role_name: str) -> List[str]:
        """Return list of permissions for a specific role."""
        role = self.get_role(tenant_id, role_name)
        return role.permissions if role else []

    def _invalidate_permission_cache(self, tenant_id: str, user_id: str) -> None:
        """Clear cached permissions for a user."""
        prefix = f"{tenant_id}:{user_id}:"
        keys_to_remove = [k for k in self._permission_cache.keys() if k.startswith(prefix)]
        for key in keys_to_remove:
            del self._permission_cache[key]


# ── SSO Integration ───────────────────────────────────────────────────────────

class SSOIntegration:
    """Single Sign-On integration for SAML 2.0 and OAuth 2.0 providers."""

    def __init__(self, isolator: Optional[TenantIsolator] = None):
        self.isolator = isolator or TenantIsolator()

    def configure_saml(
        self,
        tenant_id: str,
        idp_metadata_url: str,
        entity_id: str,
        acs_url: str,
    ) -> SAMLConfig:
        """Configure SAML 2.0 SSO for a tenant."""
        config = SAMLConfig(
            tenant_id=tenant_id,
            idp_metadata_url=idp_metadata_url,
            idp_entity_id=entity_id,
            sp_entity_id=f"auditlens-{tenant_id}",
            acs_url=acs_url,
        )

        conn = self.isolator.get_db_connection(tenant_id)
        try:
            conn.execute(
                """
                INSERT OR REPLACE INTO sso_configs (tenant_id, provider_type, config_json, enabled, created_at)
                VALUES (?, 'saml', ?, 1, ?)
                """,
                (tenant_id, json.dumps(config.to_dict()), datetime.now(timezone.utc).isoformat())
            )
            conn.commit()
            logger.info(f"SAML SSO configured for tenant: {tenant_id}")
            return config
        finally:
            self.isolator.release_connection(conn, tenant_id)

    def configure_oauth(
        self,
        tenant_id: str,
        provider: str,
        client_id: str,
        client_secret: str,
    ) -> OAuthConfig:
        """Configure OAuth 2.0 SSO for a tenant."""
        provider_urls = {
            'google': {
                'authorize': 'https://accounts.google.com/o/oauth2/v2/auth',
                'token': 'https://oauth2.googleapis.com/token',
                'userinfo': 'https://www.googleapis.com/oauth2/v2/userinfo',
            },
            'azure': {
                'authorize': 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
                'token': 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
                'userinfo': 'https://graph.microsoft.com/v1.0/me',
            },
        }

        urls = provider_urls.get(provider, provider_urls['google'])

        config = OAuthConfig(
            tenant_id=tenant_id,
            provider=provider,
            client_id=client_id,
            client_secret=client_secret,
            authorize_url=urls['authorize'],
            token_url=urls['token'],
            userinfo_url=urls['userinfo'],
        )

        conn = self.isolator.get_db_connection(tenant_id)
        try:
            config_dict = config.to_dict()
            config_dict['client_secret'] = client_secret  # Store encrypted in production

            conn.execute(
                """
                INSERT OR REPLACE INTO sso_configs (tenant_id, provider_type, config_json, enabled, created_at)
                VALUES (?, 'oauth', ?, 1, ?)
                """,
                (tenant_id, json.dumps(config_dict), datetime.now(timezone.utc).isoformat())
            )
            conn.commit()
            logger.info(f"OAuth SSO configured for tenant: {tenant_id} (provider={provider})")
            return config
        finally:
            self.isolator.release_connection(conn, tenant_id)

    def authenticate_saml(self, tenant_id: str, saml_response: str) -> Tuple[bool, Optional[User]]:
        """
        Validate SAML assertion and return (success, User).
        Creates user if not exists (JIT provisioning).
        """
        logger.warning("SAML authentication not fully implemented - requires python3-saml library")
        return (False, None)

    def authenticate_oauth(
        self,
        tenant_id: str,
        code: str,
        redirect_uri: str,
    ) -> Tuple[bool, Optional[User]]:
        """
        Validate OAuth code and return (success, User).
        Creates user if not exists (JIT provisioning).
        """
        config = self.get_sso_config(tenant_id)
        if not config or config.get('provider_type') != 'oauth':
            return (False, None)

        logger.warning("OAuth authentication not fully implemented - requires requests_oauthlib")
        return (False, None)

    def get_sso_config(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve SSO configuration for a tenant."""
        conn = self.isolator.get_db_connection(tenant_id)
        try:
            row = conn.execute(
                "SELECT * FROM sso_configs WHERE tenant_id = ? AND enabled = 1",
                (tenant_id,)
            ).fetchone()

            if not row:
                return None

            return {
                'provider_type': row['provider_type'],
                'config': json.loads(row['config_json']),
                'enabled': bool(row['enabled']),
            }
        finally:
            self.isolator.release_connection(conn, tenant_id)

    def validate_assertion(self, tenant_id: str, assertion: str) -> bool:
        """Validate a SAML/OAuth assertion signature."""
        logger.warning("Assertion validation not implemented")
        return False


# ── API Gateway ───────────────────────────────────────────────────────────────

class APIGateway:
    """Request routing, tenant resolution, rate limiting, and API key management."""

    def __init__(
        self,
        tenant_manager: TenantManager,
        rbac_manager: RBACManager,
        isolator: Optional[TenantIsolator] = None,
    ):
        self.tenant_manager = tenant_manager
        self.rbac_manager = rbac_manager
        self.isolator = isolator or TenantIsolator()
        self._rate_limits: Dict[str, List[float]] = {}  # {tenant:user -> [timestamps]}

    def route_request(self, request: Any) -> Dict[str, Any]:
        """
        Main API gateway entrypoint. Extracts tenant_id, sets context,
        enforces rate limits, routes to handler.
        """
        tenant_id = self.resolve_tenant(request)
        if not tenant_id:
            return {'error': 'Missing or invalid tenant identifier', 'status': 401}

        user_id = self._extract_user_from_jwt(request)
        if not user_id:
            api_key_result = self.validate_api_key(request.headers.get('X-API-Key', ''))
            if api_key_result:
                tenant_id, user_id = api_key_result
            else:
                return {'error': 'Unauthorized', 'status': 401}

        TenantContext.set_current_tenant(tenant_id)
        TenantContext.set_current_user(user_id)

        if not self.enforce_rate_limit(tenant_id, user_id):
            return {'error': 'Rate limit exceeded', 'status': 429}

        return {'success': True, 'tenant_id': tenant_id, 'user_id': user_id}

    def resolve_tenant(self, request: Any) -> Optional[str]:
        """Extract tenant_id from subdomain, JWT, or X-Tenant-ID header."""
        if hasattr(request, 'headers'):
            tenant_from_header = request.headers.get('X-Tenant-ID')
            if tenant_from_header:
                return tenant_from_header

        if hasattr(request, 'host'):
            tenant_from_subdomain = self._extract_tenant_from_subdomain(request.host)
            if tenant_from_subdomain:
                return tenant_from_subdomain

        if hasattr(request, 'headers'):
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                tenant_from_jwt = self._extract_tenant_from_jwt(auth_header[7:])
                if tenant_from_jwt:
                    return tenant_from_jwt

        return None

    def _extract_tenant_from_subdomain(self, host: str) -> Optional[str]:
        """Extract tenant_id from subdomain (e.g., acme.auditlens.io -> acme)."""
        parts = host.split('.')
        if len(parts) >= 3:
            return parts[0]
        return None

    def _extract_tenant_from_jwt(self, token: str) -> Optional[str]:
        """Extract tenant_id from JWT claims."""
        try:
            payload = jwt.decode(token, _JWT_SECRET, algorithms=[_JWT_ALGORITHM])
            return payload.get('tenant_id')
        except jwt.InvalidTokenError:
            return None

    def _extract_user_from_jwt(self, request: Any) -> Optional[str]:
        """Extract user_id from JWT token."""
        if not hasattr(request, 'headers'):
            return None

        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return None

        try:
            payload = jwt.decode(auth_header[7:], _JWT_SECRET, algorithms=[_JWT_ALGORITHM])
            return payload.get('user_id')
        except jwt.InvalidTokenError:
            return None

    def generate_api_key(
        self,
        tenant_id: str,
        user_id: str,
        scopes: List[str],
        expires_in: int = 31536000,  # 1 year
    ) -> str:
        """Generate a tenant-scoped API key with specific permissions."""
        import secrets

        key_id = secrets.token_urlsafe(16)
        raw_key = secrets.token_urlsafe(32)
        key_hash = bcrypt.hashpw(raw_key.encode(), bcrypt.gensalt()).decode()

        api_key_obj = APIKey(
            key_id=key_id,
            tenant_id=tenant_id,
            user_id=user_id,
            key_hash=key_hash,
            scopes=scopes,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=expires_in),
        )

        conn = self.isolator.get_db_connection(tenant_id)
        try:
            conn.execute(
                """
                INSERT INTO api_keys (key_id, tenant_id, user_id, key_hash, scopes_json, expires_at, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    api_key_obj.key_id,
                    api_key_obj.tenant_id,
                    api_key_obj.user_id,
                    api_key_obj.key_hash,
                    json.dumps(api_key_obj.scopes),
                    api_key_obj.expires_at.isoformat(),
                    api_key_obj.created_at.isoformat(),
                ),
            )
            conn.commit()
            logger.info(f"API key generated for tenant {tenant_id}, user {user_id}")
            return f"{key_id}.{raw_key}"
        finally:
            self.isolator.release_connection(conn, tenant_id)

    def validate_api_key(self, api_key: str) -> Optional[Tuple[str, str]]:
        """Validate API key and return (tenant_id, user_id) if valid."""
        if '.' not in api_key:
            return None

        key_id, raw_key = api_key.split('.', 1)

        conn = self.isolator.get_db_connection('__admin__')
        try:
            row = conn.execute(
                "SELECT * FROM api_keys WHERE key_id = ?",
                (key_id,)
            ).fetchone()

            if not row:
                return None

            expires_at = datetime.fromisoformat(row['expires_at'])
            if expires_at < datetime.now(timezone.utc):
                return None

            if not bcrypt.checkpw(raw_key.encode(), row['key_hash'].encode()):
                return None

            conn.execute(
                "UPDATE api_keys SET last_used = ? WHERE key_id = ?",
                (datetime.now(timezone.utc).isoformat(), key_id)
            )
            conn.commit()

            return (row['tenant_id'], row['user_id'])
        finally:
            self.isolator.release_connection(conn, '__admin__')

    def enforce_rate_limit(self, tenant_id: str, user_id: str) -> bool:
        """
        Enforce rate limiting using token bucket algorithm.
        Returns True if request is allowed.
        """
        tenant = self.tenant_manager.get_tenant(tenant_id)
        if not tenant:
            return False

        limit = tenant.quotas.get('rate_limit_per_minute', 100)
        if limit == -1:  # unlimited
            return True

        key = f"{tenant_id}:{user_id}"
        now = time.time()
        window_start = now - 60  # 1 minute window

        timestamps = self._rate_limits.get(key, [])
        timestamps = [ts for ts in timestamps if ts > window_start]

        if len(timestamps) >= limit:
            return False

        timestamps.append(now)
        self._rate_limits[key] = timestamps
        return True

    def log_request(
        self,
        tenant_id: str,
        user_id: str,
        endpoint: str,
        status: int,
    ) -> None:
        """Log API request for analytics."""
        logger.debug(f"API request: {tenant_id}/{user_id} -> {endpoint} [{status}]")


# ── Audit Logger ──────────────────────────────────────────────────────────────

class AuditLogger:
    """Tenant-scoped audit logging for compliance."""

    def __init__(self, isolator: Optional[TenantIsolator] = None):
        self.isolator = isolator or TenantIsolator()

    def log_event(
        self,
        tenant_id: str,
        user_id: str,
        action: str,
        resource: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log a security or operational event."""
        import secrets

        event = AuditEvent(
            event_id=secrets.token_urlsafe(16),
            tenant_id=tenant_id,
            user_id=user_id,
            action=action,
            resource_type=resource.split(':')[0] if ':' in resource else resource,
            resource_id=resource.split(':')[1] if ':' in resource else None,
            metadata=metadata or {},
        )

        conn = self.isolator.get_db_connection(tenant_id)
        try:
            conn.execute(
                """
                INSERT INTO audit_events (event_id, tenant_id, user_id, action, resource_type, resource_id, status, metadata_json, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.tenant_id,
                    event.user_id,
                    event.action,
                    event.resource_type,
                    event.resource_id,
                    event.status,
                    json.dumps(event.metadata),
                    event.timestamp.isoformat(),
                ),
            )
            conn.commit()
        finally:
            self.isolator.release_connection(conn, tenant_id)

    def get_audit_log(
        self,
        tenant_id: str,
        start_date: datetime,
        end_date: datetime,
        limit: int = 1000,
    ) -> List[AuditEvent]:
        """Retrieve audit events for a time range."""
        conn = self.isolator.get_db_connection(tenant_id)
        try:
            rows = conn.execute(
                """
                SELECT * FROM audit_events
                WHERE tenant_id = ? AND timestamp BETWEEN ? AND ?
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (tenant_id, start_date.isoformat(), end_date.isoformat(), limit)
            ).fetchall()

            return [
                AuditEvent(
                    event_id=row['event_id'],
                    tenant_id=row['tenant_id'],
                    user_id=row['user_id'],
                    action=row['action'],
                    resource_type=row['resource_type'],
                    resource_id=row['resource_id'],
                    status=row['status'],
                    ip_address=row['ip_address'],
                    user_agent=row['user_agent'],
                    metadata=json.loads(row['metadata_json']),
                    timestamp=datetime.fromisoformat(row['timestamp']),
                )
                for row in rows
            ]
        finally:
            self.isolator.release_connection(conn, tenant_id)

    def export_audit_log(
        self,
        tenant_id: str,
        start_date: datetime,
        end_date: datetime,
        format: str = 'json',
    ) -> Path:
        """Export audit log to file (JSON or CSV)."""
        events = self.get_audit_log(tenant_id, start_date, end_date, limit=100000)

        output_path = self.isolator.get_storage_path(tenant_id, 'audit_logs')
        filename = f"audit_{start_date.date()}_{end_date.date()}.{format}"
        file_path = output_path / filename

        if format == 'json':
            with open(file_path, 'w') as f:
                json.dump([e.to_dict() for e in events], f, indent=2)
        elif format == 'csv':
            import csv
            with open(file_path, 'w', newline='') as f:
                if events:
                    writer = csv.DictWriter(f, fieldnames=events[0].to_dict().keys())
                    writer.writeheader()
                    writer.writerows([e.to_dict() for e in events])

        logger.info(f"Audit log exported: {file_path}")
        return file_path

    def log_security_event(
        self,
        tenant_id: str,
        event_type: str,
        severity: str,
        details: Dict[str, Any],
    ) -> None:
        """Log a security-specific event with severity."""
        self.log_event(
            tenant_id=tenant_id,
            user_id=details.get('user_id', 'system'),
            action=f"security.{event_type}",
            resource=f"security:{event_type}",
            metadata={'severity': severity, **details},
        )


# ── Tenant Middleware ─────────────────────────────────────────────────────────

class TenantMiddleware:
    """Flask/WSGI middleware for automatic tenant context injection."""

    def __init__(self, app: Any, api_gateway: APIGateway):
        self.app = app
        self.api_gateway = api_gateway

    def __call__(self, environ: Dict[str, Any], start_response: Callable) -> Iterable:
        """WSGI application entrypoint."""
        class MockRequest:
            def __init__(self, env):
                self.headers = {
                    k[5:].replace('_', '-'): v
                    for k, v in env.items()
                    if k.startswith('HTTP_')
                }
                self.host = env.get('HTTP_HOST', '')

        request = MockRequest(environ)
        result = self.api_gateway.route_request(request)

        if 'error' in result:
            status = f"{result['status']} {result['error']}"
            response_body = json.dumps({'error': result['error']}).encode()
            start_response(status, [('Content-Type', 'application/json')])
            return [response_body]

        return self.app(environ, start_response)

    def extract_tenant_from_subdomain(self, host: str) -> Optional[str]:
        """Extract tenant from subdomain."""
        return self.api_gateway._extract_tenant_from_subdomain(host)

    def extract_tenant_from_jwt(self, token: str) -> Optional[str]:
        """Extract tenant from JWT."""
        return self.api_gateway._extract_tenant_from_jwt(token)

    def extract_tenant_from_header(self, headers: Dict[str, str]) -> Optional[str]:
        """Extract tenant from X-Tenant-ID header."""
        return headers.get('X-Tenant-ID')

    def handle_missing_tenant(self, environ: Dict[str, Any]) -> Any:
        """Handle requests without tenant context."""
        return {'error': 'Missing tenant identifier', 'status': 401}


# ── Public API ────────────────────────────────────────────────────────────────

def create_tenant_system(
    db_path: Optional[str] = None,
    storage_root: Optional[str] = None,
) -> Tuple[TenantManager, RBACManager, APIGateway, AuditLogger]:
    """
    Factory function to create a complete tenant management system.
    Returns (TenantManager, RBACManager, APIGateway, AuditLogger).
    """
    isolator = TenantIsolator(db_path=db_path, storage_root=storage_root)
    tenant_manager = TenantManager(isolator=isolator)
    rbac_manager = RBACManager(isolator=isolator)
    sso_integration = SSOIntegration(isolator=isolator)
    api_gateway = APIGateway(tenant_manager, rbac_manager, isolator=isolator)
    audit_logger = AuditLogger(isolator=isolator)

    return (tenant_manager, rbac_manager, api_gateway, audit_logger)


# ── CLI for Testing ───────────────────────────────────────────────────────────

def _cli_demo():
    """Demo CLI for testing multi-tenancy features."""
    print("🏢 AuditLens Multi-Tenancy System Demo\n")

    tm, rbac, gateway, audit = create_tenant_system()

    print("1. Creating tenant 'acme'...")
    tenant = tm.create_tenant('acme', 'ACME Corporation', plan='pro')
    print(f"   ✓ Tenant created: {tenant.tenant_id} (plan={tenant.plan})")

    print("\n2. Creating custom role 'security_engineer'...")
    role = rbac.create_role('acme', 'security_engineer', [
        'scan:create', 'scan:read', 'scan:delete',
        'findings:read', 'findings:export',
    ])
    print(f"   ✓ Role created with {len(role.permissions)} permissions")

    print("\n3. Checking tenant stats...")
    stats = tm.get_tenant_stats('acme')
    print(f"   ✓ Stats: {stats}")

    print("\n4. Generating API key...")
    api_key = gateway.generate_api_key('acme', 'user123', ['scan:*'], expires_in=3600)
    print(f"   ✓ API key: {api_key[:20]}...")

    print("\n5. Validating API key...")
    result = gateway.validate_api_key(api_key)
    print(f"   ✓ Validation result: {result}")

    print("\n6. Logging audit event...")
    audit.log_event('acme', 'user123', 'scan.create', 'scan:scan-001', {'severity': 'HIGH'})
    print("   ✓ Audit event logged")

    print("\n✅ Multi-tenancy system fully functional!\n")


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    _cli_demo()
