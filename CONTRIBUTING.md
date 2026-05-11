# Contributing to AuditLens

Thank you for your interest in contributing! This document explains how to get
started, how to add new detection rules, and how to submit pull requests.

---

## Getting started

```bash
git clone https://github.com/MasterCapehart/auditlens
cd auditlens
pip install -e ".[dev]"
pytest tests/ -v
```

---

## How to add a new detection rule

Rules live in `auditlens/rules.yaml`. Each rule is a YAML mapping:

```yaml
- id: "SEC-XX-SHORT-DESCRIPTION"    # unique, uppercase, hyphens only
  name: "Human-readable rule name"
  description: >
    One or two sentences explaining what the rule detects and why it matters.
    Include remediation guidance.
  languages: ["python", "javascript", "typescript", "swift"]   # subset as needed
  regex_pattern: "(?i)your_regex_here"   # Python re syntax, double-escaped
  compliance: ["OWASP-A3:2021", "CWE-89"]   # OWASP, CWE, PCI-DSS, GDPR, etc.
  severity: "HIGH"    # LOW | MEDIUM | HIGH | CRITICAL
```

**Regex tips:**
- Double-escape backslashes: `\\.` in YAML → `\.` in regex
- Use `(?i)` for case-insensitive matching
- Test with [regex101.com](https://regex101.com) (Python flavour)
- Validate against `test_script.py` or your own sample

**Compliance references:**
- OWASP Top 10 2021: `OWASP-A1:2021` through `OWASP-A10:2021`
- CWE: `CWE-89` (SQL injection), `CWE-79` (XSS), etc.
- PCI-DSS: `PCI-DSS 6.3.1`
- GDPR: `GDPR Art. 5`

After adding a rule, run:
```bash
pytest tests/ -v
```

And add a test case in `tests/test_rules_engine.py`.

---

## How to add a taint source or sink

Edit `auditlens/taint_analyzer.py`:

- **Sources** (`self.source_name_patterns` / `self._input_source_patterns`): variable
  name fragments or function call patterns that produce tainted/user-controlled data.
- **Sinks** (`self.sink_patterns`): function calls where tainted data must not reach
  without sanitization.

Add a corresponding test in `tests/test_taint_analyzer.py`.

---

## Running tests

```bash
# All tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=auditlens --cov-report=term-missing

# Single test file
pytest tests/test_rules_engine.py -v
```

---

## PR checklist

- [ ] Tests pass (`pytest tests/ -v`)
- [ ] New feature has at least one test
- [ ] No secrets or personal data committed
- [ ] Rule IDs are unique (check `auditlens/rules.yaml`)
- [ ] Compliance tags reference real standards
- [ ] Commit message follows the format: `type: short description` (e.g., `feat: add JWT none algorithm rule`)

---

## Commit message types

| Type | When to use |
|---|---|
| `feat` | New rule, feature, or CLI flag |
| `fix` | Bug fix |
| `perf` | Performance improvement |
| `test` | New or updated tests |
| `docs` | Documentation only |
| `refactor` | Code cleanup without behaviour change |
| `ci` | CI/CD workflow changes |

---

## Reporting security issues

Please **do not** open a public issue for security vulnerabilities in AuditLens
itself. Instead, email `security@auditlens.dev` with a description and we will
respond within 48 hours. See [SECURITY.md](SECURITY.md) for details.

---

## Questions?

Open a [GitHub Discussion](https://github.com/MasterCapehart/auditlens/discussions)
or file an issue with the `question` label.
