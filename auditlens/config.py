"""
AuditLens Project Config — reads .auditlens.yaml from the project root.

Config file format (.auditlens.yaml):
    min_severity: HIGH          # LOW | MEDIUM | HIGH | CRITICAL
    exclude_paths:
      - tests/
      - migrations/
      - vendor/
    disable_rules:
      - DATA-02-HARDCODED-IP
    sca: true                   # enable/disable SCA
    fail_on: CRITICAL           # minimum severity that causes exit code 1
    baseline: .auditlens-baseline.json
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


_DEFAULTS: Dict[str, Any] = {
    'min_severity': 'LOW',
    'exclude_paths': [],
    'disable_rules': [],
    'sca': True,
    'fail_on': 'LOW',
    'baseline': None,
    'notifications': {},
}

# Candidate config file names (first found wins)
_CONFIG_FILENAMES = ['.auditlens.yaml', '.auditlens.yml', 'auditlens.yaml']


class AuditLensConfig:
    """Merged configuration from project file + CLI overrides."""

    def __init__(self, data: Dict[str, Any]):
        self.min_severity: str = str(data.get('min_severity', _DEFAULTS['min_severity'])).upper()
        self.exclude_paths: List[str] = list(data.get('exclude_paths', _DEFAULTS['exclude_paths']))
        self.disable_rules: List[str] = list(data.get('disable_rules', _DEFAULTS['disable_rules']))
        self.sca: bool = bool(data.get('sca', _DEFAULTS['sca']))
        self.fail_on: str = str(data.get('fail_on', _DEFAULTS['fail_on'])).upper()
        self.baseline: Optional[str] = data.get('baseline', _DEFAULTS['baseline'])
        self.notifications: Dict[str, Any] = data.get('notifications', _DEFAULTS['notifications']) or {}

    # ── Helpers ───────────────────────────────────────────────────────────────

    def is_path_excluded(self, file_path: str) -> bool:
        """Return True if file_path matches any excluded path prefix."""
        norm = os.path.normpath(file_path)
        for excl in self.exclude_paths:
            excl_norm = os.path.normpath(excl)
            if norm.startswith(excl_norm):
                return True
            # Also match by basename for simple patterns like "migrations/"
            if os.path.basename(norm) == excl_norm.rstrip(os.sep):
                return True
        return False

    def is_rule_disabled(self, rule_id: str) -> bool:
        return rule_id in self.disable_rules

    def __repr__(self) -> str:
        return (
            f"AuditLensConfig(min_severity={self.min_severity!r}, "
            f"sca={self.sca}, fail_on={self.fail_on!r}, "
            f"exclude_paths={self.exclude_paths}, "
            f"disable_rules={self.disable_rules})"
        )


def load_config(start_dir: str = '.') -> AuditLensConfig:
    """
    Search for a config file starting from start_dir, walking up to the root.
    Returns a config with defaults if no file is found.
    """
    search_dir = os.path.abspath(start_dir)
    while True:
        for name in _CONFIG_FILENAMES:
            candidate = os.path.join(search_dir, name)
            if os.path.isfile(candidate):
                return _parse_config_file(candidate)

        parent = os.path.dirname(search_dir)
        if parent == search_dir:
            break  # reached filesystem root
        search_dir = parent

    return AuditLensConfig(_DEFAULTS.copy())


def _parse_config_file(path: str) -> AuditLensConfig:
    if not _YAML_AVAILABLE:
        print(
            "\033[93m[AuditLens] Warning: pyyaml not installed — "
            f"cannot load config file {path}. Using defaults.\033[0m"
        )
        return AuditLensConfig(_DEFAULTS.copy())

    try:
        with open(path, 'r', encoding='utf-8') as fh:
            data = yaml.safe_load(fh) or {}
        print(f"\033[90m[AuditLens] Config loaded from {path}\033[0m")
        return AuditLensConfig({**_DEFAULTS, **data})
    except (yaml.YAMLError, OSError) as exc:
        print(f"\033[91m[AuditLens] Error reading config {path}: {exc}. Using defaults.\033[0m")
        return AuditLensConfig(_DEFAULTS.copy())
