"""
Test suite for auditlens.tenant_manager

Tests multi-tenancy architecture, RBAC, SSO integration, and API gateway.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone, timedelta
import sqlite3

from auditlens.tenant_manager import (
    TenantManager,
    RBACManager,
    SSOIntegration,
    APIGateway,
    AuditLogger,
    TenantIsolator,
    TenantContext,
    TenantMiddleware,
    Tenant,
    Role,
    User,
    APIKey,
    AuditEvent,
    VCSType,
    create_tenant_system,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def tenant_isolator(tmp_path):
    """TenantIsolator with temp storage."""
    db_path = str(tmp_path / 'tenants.db')
    storage = str(tmp_path / 'storage')
    return TenantIsolator(db_path=db_path, storage_root=storage)


@pytest.fixture
def tenant_manager(tenant_isolator):
    """TenantManager instance."""
    return TenantManager(isolator=tenant_isolator)


@pytest.fixture
def rbac_manager(tenant_isolator):
    """RBACManager instance."""
    return RBACManager(isolator=tenant_isolator)


@pytest.fixture
def sample_tenant(tenant_manager):
    """Sample tenant for testing."""
    return tenant_manager.create_tenant('acme', 'ACME Corp', plan='pro')


# ── TenantContext Tests ───────────────────────────────────────────────────────

def test_tenant_context_set_and_get():
    """Test tenant context storage."""
    TenantContext.set_current_tenant('tenant_123')

    assert TenantContext.get_current_tenant() == 'tenant_123'


def test_tenant_context_clear():
    """Test context clearing."""
    TenantContext.set_current_tenant('tenant_123')
    TenantContext.clear_context()

    assert TenantContext.get_current_tenant() is None


def test_tenant_context_with_tenant():
    """Test context manager."""
    TenantContext.set_current_tenant('original')

    with TenantContext.with_tenant('temporary'):
        assert TenantContext.get_current_tenant() == 'temporary'

    assert TenantContext.get_current_tenant() == 'original'


def test_tenant_context_require_tenant():
    """Test requiring tenant context."""
    TenantContext.clear_context()

    with pytest.raises(ValueError, match='No tenant context'):
        TenantContext.require_tenant()


# ── Tenant Tests ──────────────────────────────────────────────────────────────

def test_tenant_initialization():
    """Test Tenant initialization."""
    tenant = Tenant(tenant_id='test', name='Test Corp', plan='basic')

    assert tenant.tenant_id == 'test'
    assert tenant.name == 'Test Corp'
    assert tenant.plan == 'basic'


def test_tenant_default_quotas():
    """Test default quota assignment."""
    basic = Tenant('t1', 'Basic', plan='basic')
    pro = Tenant('t2', 'Pro', plan='pro')
    enterprise = Tenant('t3', 'Enterprise', plan='enterprise')

    assert basic.quotas['max_scans_per_day'] == 10
    assert pro.quotas['max_scans_per_day'] == 100
    assert enterprise.quotas['max_scans_per_day'] == -1  # unlimited


# ── TenantIsolator Tests ──────────────────────────────────────────────────────

def test_tenant_isolator_initialization(tenant_isolator):
    """Test TenantIsolator initialization."""
    assert tenant_isolator.db_path
    assert tenant_isolator.storage_root.exists()


def test_tenant_isolator_get_storage_path(tenant_isolator):
    """Test isolated storage path generation."""
    path = tenant_isolator.get_storage_path('tenant_123', 'scans')

    assert 'tenant_123' in str(path)
    assert 'scans' in str(path)
    assert path.exists()


def test_tenant_isolator_connection_pooling(tenant_isolator):
    """Test database connection pooling."""
    conn1 = tenant_isolator.get_db_connection('tenant_123')
    tenant_isolator.release_connection(conn1, 'tenant_123')

    conn2 = tenant_isolator.get_db_connection('tenant_123')

    # Should reuse pooled connection
    assert conn2 is not None


# ── TenantManager Tests ───────────────────────────────────────────────────────

def test_tenant_manager_create_tenant(tenant_manager):
    """Test tenant creation."""
    tenant = tenant_manager.create_tenant('test123', 'Test Company', plan='basic')

    assert tenant.tenant_id == 'test123'
    assert tenant.plan == 'basic'


def test_tenant_manager_get_tenant(tenant_manager, sample_tenant):
    """Test tenant retrieval."""
    retrieved = tenant_manager.get_tenant(sample_tenant.tenant_id)

    assert retrieved is not None
    assert retrieved.tenant_id == sample_tenant.tenant_id


def test_tenant_manager_update_tenant(tenant_manager, sample_tenant):
    """Test tenant updates."""
    updates = {'plan': 'enterprise', 'status': 'active'}
    updated = tenant_manager.update_tenant(sample_tenant.tenant_id, updates)

    assert updated.plan == 'enterprise'


def test_tenant_manager_delete_tenant(tenant_manager, sample_tenant):
    """Test tenant deletion."""
    result = tenant_manager.delete_tenant(sample_tenant.tenant_id, cascade=False)

    assert result is True

    # Should be soft-deleted
    tenant = tenant_manager.get_tenant(sample_tenant.tenant_id)
    assert tenant.status == 'deleted'


def test_tenant_manager_check_quota(tenant_manager, sample_tenant):
    """Test quota checking."""
    has_quota = tenant_manager.check_quota(sample_tenant.tenant_id, 'scans_per_day')

    assert has_quota is True


def test_tenant_manager_increment_usage(tenant_manager, sample_tenant):
    """Test usage counter incrementation."""
    tenant_manager.increment_usage(sample_tenant.tenant_id, 'total_scans', 5)

    tenant = tenant_manager.get_tenant(sample_tenant.tenant_id)
    assert tenant.usage.get('total_scans') == 5


# ── RBACManager Tests ─────────────────────────────────────────────────────────

def test_rbac_manager_create_role(rbac_manager, sample_tenant):
    """Test role creation."""
    role = rbac_manager.create_role(
        sample_tenant.tenant_id,
        'security_admin',
        ['scan:*', 'findings:*'],
    )

    assert role.role_name == 'security_admin'
    assert len(role.permissions) == 2


def test_rbac_manager_get_role(rbac_manager, sample_tenant):
    """Test role retrieval."""
    rbac_manager.create_role(sample_tenant.tenant_id, 'test_role', ['read'])

    role = rbac_manager.get_role(sample_tenant.tenant_id, 'test_role')

    assert role is not None
    assert role.role_name == 'test_role'


def test_rbac_manager_check_permission(rbac_manager, sample_tenant, tenant_isolator):
    """Test permission checking."""
    # Create role and assign to user
    rbac_manager.create_role(sample_tenant.tenant_id, 'admin', ['*'])

    # Create user (manual DB insertion for test)
    conn = tenant_isolator.get_db_connection(sample_tenant.tenant_id)
    conn.execute(
        """INSERT INTO tenant_users (tenant_id, user_id, email, name, roles_json, created_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (sample_tenant.tenant_id, 'user_1', 'test@example.com', 'Test User',
         '["admin"]', datetime.now(timezone.utc).isoformat())
    )
    conn.commit()
    tenant_isolator.release_connection(conn, sample_tenant.tenant_id)

    # Check permission
    has_perm = rbac_manager.check_permission(sample_tenant.tenant_id, 'user_1', 'scan:create')

    assert has_perm is True


def test_rbac_manager_wildcard_permissions(rbac_manager, sample_tenant, tenant_isolator):
    """Test wildcard permission matching."""
    rbac_manager.create_role(sample_tenant.tenant_id, 'scanner', ['scan:*'])

    # Create user
    conn = tenant_isolator.get_db_connection(sample_tenant.tenant_id)
    conn.execute(
        """INSERT INTO tenant_users (tenant_id, user_id, email, name, roles_json, created_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (sample_tenant.tenant_id, 'user_2', 'user@example.com', 'User',
         '["scanner"]', datetime.now(timezone.utc).isoformat())
    )
    conn.commit()
    tenant_isolator.release_connection(conn, sample_tenant.tenant_id)

    # Should match wildcard
    assert rbac_manager.check_permission(sample_tenant.tenant_id, 'user_2', 'scan:create')
    assert rbac_manager.check_permission(sample_tenant.tenant_id, 'user_2', 'scan:delete')


# ── APIGateway Tests ──────────────────────────────────────────────────────────

def test_api_gateway_initialization(tenant_manager, rbac_manager):
    """Test APIGateway initialization."""
    gateway = APIGateway(tenant_manager, rbac_manager)

    assert gateway.tenant_manager is tenant_manager
    assert gateway.rbac_manager is rbac_manager


def test_api_gateway_generate_api_key(tenant_manager, rbac_manager, sample_tenant, tenant_isolator):
    """Test API key generation."""
    gateway = APIGateway(tenant_manager, rbac_manager, tenant_isolator)

    api_key = gateway.generate_api_key(
        sample_tenant.tenant_id,
        'user_123',
        ['scan:read', 'scan:create'],
        expires_in=3600,
    )

    assert '.' in api_key  # Format: key_id.raw_key
    assert len(api_key) > 20


def test_api_gateway_validate_api_key(tenant_manager, rbac_manager, sample_tenant, tenant_isolator):
    """Test API key validation."""
    gateway = APIGateway(tenant_manager, rbac_manager, tenant_isolator)

    # Generate key
    api_key = gateway.generate_api_key(sample_tenant.tenant_id, 'user_123', ['scan:*'])

    # Validate
    result = gateway.validate_api_key(api_key)

    assert result is not None
    assert result[0] == sample_tenant.tenant_id


def test_api_gateway_rate_limiting(tenant_manager, rbac_manager, sample_tenant):
    """Test rate limit enforcement."""
    gateway = APIGateway(tenant_manager, rbac_manager)

    # Should allow within limits
    for _ in range(10):
        allowed = gateway.enforce_rate_limit(sample_tenant.tenant_id, 'user_123')
        assert allowed is True


# ── AuditLogger Tests ─────────────────────────────────────────────────────────

def test_audit_logger_log_event(tenant_isolator, sample_tenant):
    """Test audit event logging."""
    logger = AuditLogger(tenant_isolator)

    logger.log_event(
        sample_tenant.tenant_id,
        'user_123',
        'scan.create',
        'scan:scan_001',
        metadata={'severity': 'HIGH'},
    )

    # Verify logged
    conn = tenant_isolator.get_db_connection(sample_tenant.tenant_id)
    count = conn.execute('SELECT COUNT(*) FROM audit_events').fetchone()[0]
    tenant_isolator.release_connection(conn, sample_tenant.tenant_id)

    assert count >= 1


def test_audit_logger_get_audit_log(tenant_isolator, sample_tenant):
    """Test audit log retrieval."""
    logger = AuditLogger(tenant_isolator)

    # Log events
    logger.log_event(sample_tenant.tenant_id, 'user_1', 'action_1', 'resource_1')
    logger.log_event(sample_tenant.tenant_id, 'user_2', 'action_2', 'resource_2')

    # Retrieve
    start = datetime.now(timezone.utc) - timedelta(hours=1)
    end = datetime.now(timezone.utc) + timedelta(hours=1)

    events = logger.get_audit_log(sample_tenant.tenant_id, start, end)

    assert len(events) >= 2


# ── Integration Tests ─────────────────────────────────────────────────────────

def test_create_tenant_system_factory(tmp_path):
    """Test system factory function."""
    db_path = str(tmp_path / 'tenants.db')

    tm, rbac, gateway, audit = create_tenant_system(db_path=db_path)

    assert isinstance(tm, TenantManager)
    assert isinstance(rbac, RBACManager)
    assert isinstance(gateway, APIGateway)
    assert isinstance(audit, AuditLogger)


def test_end_to_end_tenant_workflow(tmp_path):
    """Test complete multi-tenancy workflow."""
    # Initialize system
    tm, rbac, gateway, audit = create_tenant_system(db_path=str(tmp_path / 'test.db'))

    # Create tenant
    tenant = tm.create_tenant('company', 'Company Inc', plan='pro')

    # Create role
    role = rbac.create_role(tenant.tenant_id, 'admin', ['*'])

    # Generate API key
    api_key = gateway.generate_api_key(tenant.tenant_id, 'user_1', ['*'])

    # Validate key
    result = gateway.validate_api_key(api_key)
    assert result[0] == tenant.tenant_id

    # Log event
    audit.log_event(tenant.tenant_id, 'user_1', 'test', 'resource')

    # Verify stats
    stats = tm.get_tenant_stats(tenant.tenant_id)
    assert stats['tenant_id'] == tenant.tenant_id
