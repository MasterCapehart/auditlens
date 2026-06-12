"""
AuditLens AI Fix Engine — uses Claude API to suggest patches for findings.

Usage:
    auditlens fix ./project
    auditlens fix ./project --severity HIGH
    auditlens fix ./project --rule SEC-01-HARDCODED-SECRET

Requires:
    pip install anthropic --break-system-packages
    export ANTHROPIC_API_KEY=sk-ant-...
"""

from __future__ import annotations

import os
from typing import List, Optional

_SEVERITY_RANK = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
_MODEL = 'claude-sonnet-4-6'
_MAX_TOKENS = 1024


def _read_context(file_path: str, line: int, context: int = 10) -> str:
    """Return up to 2*context lines around the finding line."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as fh:
            lines = fh.readlines()
        start = max(0, line - context - 1)
        end = min(len(lines), line + context)
        numbered = []
        for i, l in enumerate(lines[start:end], start=start + 1):
            marker = '>>>' if i == line else '   '
            numbered.append(f'{marker} {i:4d} | {l.rstrip()}')
        return '\n'.join(numbered)
    except OSError:
        return '(could not read file)'


def _build_prompt(finding: dict, code_context: str) -> str:
    return f"""You are a senior security engineer reviewing a static analysis finding.

## Finding
- **Rule**: {finding.get('rule_id')} — {finding.get('name')}
- **Severity**: {finding.get('severity')}
- **File**: {finding.get('file')}:{finding.get('line')}
- **Compliance**: {', '.join(finding.get('compliance', []))}
- **Description**: {finding.get('description')}

## Code Context (line {finding.get('line')} marked with >>>)
```
{code_context}
```

## Task
1. Explain in 1-2 sentences WHY this is a vulnerability.
2. Provide a concrete, minimal code fix (show only the changed lines, no boilerplate).
3. Add one sentence on how to verify the fix.

Be concise. Use the same language as the code (Python / JavaScript / etc.)."""


def suggest_fix(
    finding: dict,
    api_key: Optional[str] = None,
    model: str = _MODEL,
) -> Optional[str]:
    """Return a fix suggestion string, or None on error."""
    try:
        import anthropic
    except ImportError:
        print(
            '\033[91m[AuditLens AI Fix]\033[0m anthropic not installed.\n'
            'Install with: pip install anthropic --break-system-packages'
        )
        return None

    key = api_key or os.environ.get('ANTHROPIC_API_KEY')
    if not key:
        print('\033[91m[AuditLens AI Fix]\033[0m ANTHROPIC_API_KEY not set.')
        return None

    file_path = finding.get('file', '')
    line = int(finding.get('line', 0))
    code_ctx = _read_context(file_path, line)
    prompt = _build_prompt(finding, code_ctx)

    try:
        client = anthropic.Anthropic(api_key=key)
        message = client.messages.create(
            model=model,
            max_tokens=_MAX_TOKENS,
            messages=[{'role': 'user', 'content': prompt}],
        )
        return message.content[0].text
    except Exception as exc:
        print(f'\033[91m[AuditLens AI Fix]\033[0m API error: {exc}')
        return None


def run_ai_fix(
    findings: List[dict],
    min_severity: str = 'HIGH',
    rule_filter: Optional[str] = None,
    api_key: Optional[str] = None,
    model: str = _MODEL,
    output_path: Optional[str] = None,
) -> None:
    """Iterate filtered findings and print/save AI fix suggestions."""
    rank = _SEVERITY_RANK.get(min_severity.upper(), 2)
    filtered = [
        f for f in findings
        if _SEVERITY_RANK.get(f.get('severity', 'LOW').upper(), 0) >= rank
    ]
    if rule_filter:
        filtered = [f for f in filtered if f.get('rule_id') == rule_filter]

    if not filtered:
        print(f'\033[90m[AuditLens AI Fix]\033[0m No findings at or above {min_severity}.')
        return

    print(
        f'\033[94m[AuditLens AI Fix]\033[0m Requesting fixes for '
        f'{len(filtered)} finding(s) via {model}...\n'
    )

    results = []
    for i, f in enumerate(filtered, 1):
        file_short = '/'.join(f.get('file', '').split('/')[-2:])
        print(
            f'\033[94m[{i}/{len(filtered)}]\033[0m '
            f'{f.get("rule_id")} — {file_short}:{f.get("line")}'
        )
        suggestion = suggest_fix(f, api_key=api_key, model=model)
        if suggestion:
            print(suggestion)
            results.append({
                'finding': f,
                'suggestion': suggestion,
            })
        print()

    if output_path and results:
        import json
        with open(output_path, 'w', encoding='utf-8') as fh:
            json.dump(results, fh, indent=2, default=str)
        print(f'\033[92m[AuditLens AI Fix]\033[0m Sugerencias guardadas en: {output_path}')
