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
import re
import subprocess
from typing import List, Optional, Tuple

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


def _build_prompt(finding: dict, code_context: str, patch_mode: bool = False) -> str:
    base = f"""You are a senior security engineer reviewing a static analysis finding.

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
"""
    if patch_mode:
        return base + """
## Task — PATCH MODE
Return ONLY a unified diff patch that fixes this vulnerability.
- Use standard unified diff format (--- a/file, +++ b/file, @@ lines)
- The patch MUST apply cleanly to the code shown above
- Make the minimal change needed — do not refactor surrounding code
- Do not include any explanation, only the raw diff

Example format:
--- a/path/to/file.py
+++ b/path/to/file.py
@@ -12,7 +12,7 @@
-    vulnerable_code()
+    safe_code()
"""
    return base + """
## Task
1. Explain in 1-2 sentences WHY this is a vulnerability.
2. Provide a concrete, minimal code fix (show only the changed lines, no boilerplate).
3. Add one sentence on how to verify the fix.

Be concise. Use the same language as the code (Python / JavaScript / etc.)."""


def _extract_diff(text: str) -> Optional[str]:
    """Extract a unified diff block from Claude's response."""
    # Look for ```diff ... ``` or raw diff starting with ---
    fenced = re.search(r'```(?:diff)?\s*\n([\s\S]+?)```', text)
    if fenced:
        return fenced.group(1).strip()
    # Raw diff heuristic: starts with --- a/ or ---
    lines = text.splitlines()
    start = next(
        (i for i, l in enumerate(lines) if l.startswith('--- ')), None
    )
    if start is not None:
        return '\n'.join(lines[start:])
    return None


def apply_patch(
    diff_text: str,
    base_dir: str,
    dry_run: bool = False,
) -> Tuple[bool, str]:
    """
    Apply a unified diff patch to the filesystem.
    Returns (success, message).
    """
    import tempfile
    try:
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.patch', delete=False, encoding='utf-8'
        ) as tf:
            tf.write(diff_text)
            patch_file = tf.name

        cmd = ['patch', '--strip=1', '--input', patch_file]
        if dry_run:
            cmd.append('--dry-run')

        result = subprocess.run(
            cmd, cwd=base_dir,
            capture_output=True, text=True, timeout=30,
        )
        os.unlink(patch_file)

        if result.returncode == 0:
            action = 'simulado (dry-run)' if dry_run else 'aplicado'
            return True, f'Patch {action} correctamente.\n{result.stdout.strip()}'
        else:
            return False, f'Patch falló:\n{result.stderr.strip() or result.stdout.strip()}'
    except FileNotFoundError:
        return False, 'El comando `patch` no está disponible en este sistema.'
    except Exception as exc:
        return False, f'Error aplicando patch: {exc}'


def suggest_fix(
    finding: dict,
    api_key: Optional[str] = None,
    model: str = _MODEL,
    patch_mode: bool = False,
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
    prompt = _build_prompt(finding, code_ctx, patch_mode=patch_mode)

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
    apply_patches: bool = False,
    dry_run: bool = False,
    project_root: Optional[str] = None,
) -> None:
    """
    Iterate filtered findings and print/save AI fix suggestions.

    With apply_patches=True: Claude generates a unified diff and it is applied
    directly to the source file. Use dry_run=True to preview without writing.
    """
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

    mode_label = ('PATCH DRY-RUN' if dry_run else 'AUTO-PATCH') if apply_patches else 'SUGGEST'
    print(
        f'\033[94m[AuditLens AI Fix]\033[0m [{mode_label}] '
        f'{len(filtered)} finding(s) via {model}...\n'
    )

    base_dir = project_root or os.getcwd()
    results = []

    for i, f in enumerate(filtered, 1):
        file_short = '/'.join(f.get('file', '').split('/')[-2:])
        print(
            f'\033[94m[{i}/{len(filtered)}]\033[0m '
            f'{f.get("rule_id")} — {file_short}:{f.get("line")}'
        )
        suggestion = suggest_fix(f, api_key=api_key, model=model, patch_mode=apply_patches)
        if not suggestion:
            print()
            continue

        result_entry: dict = {'finding': f, 'suggestion': suggestion}

        if apply_patches:
            diff_text = _extract_diff(suggestion)
            if diff_text:
                success, msg = apply_patch(diff_text, base_dir, dry_run=dry_run)
                color = '\033[92m' if success else '\033[91m'
                print(f'{color}  → {msg}\033[0m')
                result_entry['patch_applied'] = success
                result_entry['patch_result']  = msg
                result_entry['diff'] = diff_text
            else:
                print('\033[93m  → No se pudo extraer un diff del output de Claude.\033[0m')
                print(suggestion)
                result_entry['patch_applied'] = False
        else:
            print(suggestion)

        results.append(result_entry)
        print()

    if output_path and results:
        import json
        with open(output_path, 'w', encoding='utf-8') as fh:
            json.dump(results, fh, indent=2, default=str)
        print(f'\033[92m[AuditLens AI Fix]\033[0m Sugerencias guardadas en: {output_path}')

    if apply_patches:
        applied = sum(1 for r in results if r.get('patch_applied'))
        print(f'\033[92m[AuditLens AI Fix]\033[0m Patches aplicados: {applied}/{len(results)}')
