"""
AuditLens Pre-commit Hook — blocks commits with HIGH/CRITICAL findings.

Install:
    auditlens install-hook [--path ./project] [--severity HIGH]

This writes .git/hooks/pre-commit (chmod +x) in the target repo.
The hook runs 'auditlens scan' on staged Python/JS/TS files only for speed.

Remove:
    auditlens remove-hook [--path ./project]
"""

from __future__ import annotations

import os
import stat

_HOOK_TEMPLATE = """\
#!/usr/bin/env bash
# AuditLens pre-commit hook — auto-generated, do not edit manually.
# To remove: auditlens remove-hook

set -euo pipefail

# Only scan staged files that AuditLens supports
STAGED=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\\.(py|js|jsx|ts|tsx|swift|go|java|rb|php)$' || true)

if [ -z "$STAGED" ]; then
  exit 0
fi

echo "[AuditLens] Scanning staged files for security issues..."

FAIL=0
while IFS= read -r FILE; do
  if [ -f "$FILE" ]; then
    auditlens scan "$FILE" --severity {severity} --no-sca --no-history 2>/dev/null
    STATUS=$?
    if [ $STATUS -eq 1 ]; then
      FAIL=1
    fi
  fi
done <<< "$STAGED"

if [ $FAIL -eq 1 ]; then
  echo ""
  echo "[AuditLens] Commit BLOCKED: {severity}+ security findings detected."
  echo "  Fix the issues above or add '# auditlens: ignore RULE-ID' to suppress."
  echo "  To skip this check (not recommended): git commit --no-verify"
  exit 1
fi

exit 0
"""


def install_hook(repo_path: str = '.', severity: str = 'HIGH') -> None:
    """Write the pre-commit hook into repo_path/.git/hooks/pre-commit."""
    git_dir = _find_git_dir(repo_path)
    if not git_dir:
        print(f'\033[91m[AuditLens]\033[0m No .git directory found at or above: {os.path.abspath(repo_path)}')
        return

    hooks_dir = os.path.join(git_dir, 'hooks')
    os.makedirs(hooks_dir, exist_ok=True)
    hook_path = os.path.join(hooks_dir, 'pre-commit')

    if os.path.exists(hook_path):
        with open(hook_path, 'r') as fh:
            existing = fh.read()
        if 'AuditLens' in existing:
            print(f'\033[93m[AuditLens]\033[0m Pre-commit hook already installed at {hook_path}. Overwriting.')
        else:
            print(
                f'\033[91m[AuditLens]\033[0m A pre-commit hook already exists at {hook_path} '
                f'(not from AuditLens). Aborting to avoid overwriting. '
                f'Remove it manually first, then re-run.'
            )
            return

    hook_content = _HOOK_TEMPLATE.format(severity=severity.upper())
    with open(hook_path, 'w') as fh:
        fh.write(hook_content)

    # Make executable
    current = os.stat(hook_path).st_mode
    os.chmod(hook_path, current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    print(f'\033[92m[AuditLens]\033[0m Pre-commit hook installed: {hook_path}')
    print(f'   Blocks commits with {severity.upper()}+ findings.')
    print(f'   Suppress inline: # auditlens: ignore RULE-ID')


def remove_hook(repo_path: str = '.') -> None:
    git_dir = _find_git_dir(repo_path)
    if not git_dir:
        print(f'\033[91m[AuditLens]\033[0m No .git directory found.')
        return

    hook_path = os.path.join(git_dir, 'hooks', 'pre-commit')
    if not os.path.exists(hook_path):
        print('\033[90m[AuditLens]\033[0m No pre-commit hook found.')
        return

    with open(hook_path, 'r') as fh:
        content = fh.read()

    if 'AuditLens' not in content:
        print('\033[91m[AuditLens]\033[0m Existing pre-commit hook was not created by AuditLens. Not removing.')
        return

    os.remove(hook_path)
    print(f'\033[92m[AuditLens]\033[0m Pre-commit hook removed: {hook_path}')


def _find_git_dir(start: str) -> str | None:
    """Walk up from start looking for a .git directory."""
    current = os.path.abspath(start)
    while True:
        candidate = os.path.join(current, '.git')
        if os.path.isdir(candidate):
            return candidate
        parent = os.path.dirname(current)
        if parent == current:
            return None
        current = parent
