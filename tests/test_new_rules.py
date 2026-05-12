"""
Tests for new rules (Go, Java, Ruby, framework-specific, cloud, secrets).
"""
from __future__ import annotations
import pytest
from auditlens.rules_engine import RulesEngine


def _engine():
    return RulesEngine()


# ── Language mapping ──────────────────────────────────────────────────────────
def test_go_rules_loaded():
    e = _engine()
    go_rules = e.get_rules_for_language('.go')
    go_ids = {r.id for r in go_rules}
    assert 'GO-01-SQL-INJECTION' in go_ids
    assert 'GO-05-TLS-INSECURE' in go_ids


def test_java_rules_loaded():
    e = _engine()
    java_rules = e.get_rules_for_language('.java')
    java_ids = {r.id for r in java_rules}
    assert 'JAVA-01-SQL-INJECTION' in java_ids
    assert 'JAVA-03-DESERIALIZATION' in java_ids


def test_kotlin_rules_loaded():
    e = _engine()
    kt_rules = e.get_rules_for_language('.kt')
    kt_ids = {r.id for r in kt_rules}
    assert 'JAVA-01-SQL-INJECTION' in kt_ids  # kotlin shares java rules


def test_ruby_rules_loaded():
    e = _engine()
    rb_rules = e.get_rules_for_language('.rb')
    rb_ids = {r.id for r in rb_rules}
    assert 'RUBY-01-SQL-INJECTION' in rb_ids
    assert 'RUBY-05-YAML-LOAD' in rb_ids


# ── Go rule matching ──────────────────────────────────────────────────────────
def test_go_sql_injection_match():
    e = _engine()
    rules = {r.id: r for r in e.get_rules_for_language('.go')}
    rule = rules.get('GO-01-SQL-INJECTION')
    assert rule is not None
    assert rule.match_text('db.QueryRow(fmt.Sprintf("SELECT * FROM users WHERE id=%d", id))')
    assert not rule.match_text('db.QueryRow("SELECT * FROM users WHERE id=?", id)')


def test_go_tls_insecure_match():
    e = _engine()
    rules = {r.id: r for r in e.get_rules_for_language('.go')}
    rule = rules.get('GO-05-TLS-INSECURE')
    assert rule is not None
    assert rule.match_text('TLSClientConfig: &tls.Config{InsecureSkipVerify: true}')


def test_go_weak_random_match():
    e = _engine()
    rules = {r.id: r for r in e.get_rules_for_language('.go')}
    rule = rules.get('GO-04-WEAK-RANDOM')
    assert rule is not None
    assert rule.match_text('token := rand.Intn(100000)')


# ── Java rule matching ────────────────────────────────────────────────────────
def test_java_deserialization_match():
    e = _engine()
    rules = {r.id: r for r in e.get_rules_for_language('.java')}
    rule = rules.get('JAVA-03-DESERIALIZATION')
    assert rule is not None
    assert rule.match_text('ObjectInputStream ois = new ObjectInputStream(inputStream);')


def test_java_weak_hash_match():
    e = _engine()
    rules = {r.id: r for r in e.get_rules_for_language('.java')}
    rule = rules.get('JAVA-05-WEAK-HASH')
    assert rule is not None
    assert rule.match_text('MessageDigest md = MessageDigest.getInstance("MD5");')
    assert not rule.match_text('MessageDigest md = MessageDigest.getInstance("SHA-256");')


# ── Ruby rule matching ────────────────────────────────────────────────────────
def test_ruby_sql_injection_match():
    e = _engine()
    rules = {r.id: r for r in e.get_rules_for_language('.rb')}
    rule = rules.get('RUBY-01-SQL-INJECTION')
    assert rule is not None
    assert rule.match_text('User.where("name = \'#{params[:name]}\'")')


def test_ruby_yaml_load_match():
    e = _engine()
    rules = {r.id: r for r in e.get_rules_for_language('.rb')}
    rule = rules.get('RUBY-05-YAML-LOAD')
    assert rule is not None
    assert rule.match_text('data = YAML.load(user_input)')
    assert not rule.match_text('data = YAML.safe_load(user_input)')


# ── Secrets patterns ─────────────────────────────────────────────────────────
def test_stripe_key_match():
    e = _engine()
    all_rules = e.rules
    stripe_rule = next((r for r in all_rules if r.id == 'PY-HARDCODED-STRIPE-KEY'), None)
    assert stripe_rule is not None
    # Use a clearly fake/test key that won't trigger secret scanning
    fake_key = 'sk_live_' + 'X' * 30  # clearly not a real key
    assert stripe_rule.match_text(f'stripe.api_key = "{fake_key}"')


def test_aws_key_match():
    e = _engine()
    rule = next((r for r in e.rules if r.id == 'SEC-08-AWS-ACCESS-KEY'), None)
    assert rule is not None
    assert rule.match_text('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"')


def test_private_key_match():
    e = _engine()
    rule = next((r for r in e.rules if r.id == 'SEC-11-PRIVATE-KEY-BLOCK'), None)
    assert rule is not None
    assert rule.match_text('-----BEGIN RSA PRIVATE KEY-----')
    assert rule.match_text('-----BEGIN EC PRIVATE KEY-----')


# ── Cloud rules ───────────────────────────────────────────────────────────────
def test_s3_public_acl_match():
    e = _engine()
    rule = next((r for r in e.rules if r.id == 'CLOUD-01-S3-PUBLIC-ACL'), None)
    assert rule is not None
    assert rule.match_text("s3.put_object(Bucket='my-bucket', ACL='public-read')")


def test_azure_connection_string_match():
    e = _engine()
    rule = next((r for r in e.rules if r.id == 'CLOUD-02-AZURE-CONNECTION-STRING'), None)
    assert rule is not None
    assert rule.match_text('DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=abc123def456ghi789jkl012mno345pqr678stu901vwx234yz==;EndpointSuffix=core.windows.net')


# ── Total rule count ─────────────────────────────────────────────────────────
def test_total_rule_count_above_80():
    """Ensure we have at least 80 rules loaded (target: 88+)."""
    e = _engine()
    assert len(e.rules) >= 80
