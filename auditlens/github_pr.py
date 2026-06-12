"""
AuditLens GitHub PR Commenter — publica hallazgos como comentarios
inline en un Pull Request de GitHub.

Requires: GITHUB_TOKEN env var.

Usage:
    auditlens github-pr owner/repo 42 ./findings.json
    auditlens scan ./src --format json --output findings.json
    auditlens github-pr owner/repo 42 findings.json
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

import requests

_SEV_EMOJI = {
    'CRITICAL': ':rotating_light: **CRITICAL**',
    'HIGH':     ':warning: **HIGH**',
    'MEDIUM':   ':yellow_circle: **MEDIUM**',
    'LOW':      ':information_source: LOW',
}


class GitHubPRCommenter:
    def __init__(self, token: Optional[str] = None):
        self.token = token or os.environ.get('GITHUB_TOKEN', '')
        if not self.token:
            raise ValueError('GitHub token required. Set GITHUB_TOKEN env var.')
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'token {self.token}',
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
        })
        self.base = 'https://api.github.com'

    def _get_pr_head_sha(self, repo: str, pr_number: int) -> Optional[str]:
        resp = self.session.get(
            f'{self.base}/repos/{repo}/pulls/{pr_number}',
            timeout=15,
        )
        if resp.status_code == 200:
            return resp.json().get('head', {}).get('sha')
        return None

    def _get_pr_files(self, repo: str, pr_number: int) -> List[Dict]:
        resp = self.session.get(
            f'{self.base}/repos/{repo}/pulls/{pr_number}/files',
            timeout=15,
        )
        if resp.status_code == 200:
            return resp.json()
        return []

    def _post_review_comment(
        self,
        repo: str,
        pr_number: int,
        commit_sha: str,
        path: str,
        line: int,
        body: str,
    ) -> bool:
        payload = {
            'body': body,
            'commit_id': commit_sha,
            'path': path,
            'line': max(line, 1),
            'side': 'RIGHT',
        }
        resp = self.session.post(
            f'{self.base}/repos/{repo}/pulls/{pr_number}/comments',
            json=payload,
            timeout=15,
        )
        return resp.status_code in (200, 201)

    def _post_pr_comment(self, repo: str, pr_number: int, body: str) -> bool:
        resp = self.session.post(
            f'{self.base}/repos/{repo}/issues/{pr_number}/comments',
            json={'body': body},
            timeout=15,
        )
        return resp.status_code in (200, 201)

    def post_findings(
        self,
        repo: str,
        pr_number: int,
        findings: List[Dict],
        min_severity: str = 'MEDIUM',
    ) -> Dict[str, int]:
        """Post findings as PR review comments. Returns counts."""
        _SEV_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        min_idx = _SEV_ORDER.get(min_severity, 2)

        filtered = [
            f for f in findings
            if _SEV_ORDER.get(f.get('severity', 'LOW'), 3) <= min_idx
        ]

        if not filtered:
            self._post_pr_comment(
                repo, pr_number,
                '## AuditLens Security Scan\n\n:white_check_mark: No security issues found above the severity threshold.',
            )
            return {'posted': 0, 'failed': 0}

        commit_sha = self._get_pr_head_sha(repo, pr_number)
        pr_files = {f['filename'] for f in self._get_pr_files(repo, pr_number)}

        posted = 0
        failed = 0
        inline_failed = []

        for finding in filtered:
            sev = finding.get('severity', 'LOW')
            sev_label = _SEV_EMOJI.get(sev, sev)
            rule_id = finding.get('rule_id', '')
            name = finding.get('name', '')
            description = finding.get('description', '')
            file_path = finding.get('file', '')
            line_no = finding.get('line', 1) or 1
            compliance = finding.get('compliance', [])
            if isinstance(compliance, list):
                compliance_str = ' | '.join(compliance)
            else:
                compliance_str = str(compliance)

            body = (
                f'## {sev_label} — {rule_id}\n\n'
                f'**{name}**\n\n'
                f'{description}\n\n'
                f'**Compliance:** {compliance_str or "N/A"}\n\n'
                f'---\n*AuditLens Security Scanner*'
            )

            # Try inline comment if file is in the PR diff
            if commit_sha and file_path in pr_files:
                ok = self._post_review_comment(
                    repo, pr_number, commit_sha, file_path, line_no, body,
                )
                if ok:
                    posted += 1
                    continue
            inline_failed.append(finding)

        # Post summary comment for findings that couldn't be inline
        if inline_failed:
            rows = []
            for f in inline_failed:
                sev_label = _SEV_EMOJI.get(f.get('severity', 'LOW'), f.get('severity', 'LOW'))
                rows.append(
                    f'| {sev_label} | {f.get("rule_id", "")} | `{f.get("file", "")}:{f.get("line", "")}` | {f.get("name", "")[:80]} |'
                )
            table = '\n'.join(rows)
            summary = (
                '## AuditLens Security Scan Results\n\n'
                f'Found **{len(filtered)}** issues ({len(inline_failed)} shown here, rest as inline comments).\n\n'
                '| Severity | Rule | Location | Issue |\n'
                '|----------|------|----------|-------|\n'
                f'{table}\n\n'
                '---\n*AuditLens Security Scanner*'
            )
            ok = self._post_pr_comment(repo, pr_number, summary)
            if ok:
                posted += len(inline_failed)
            else:
                failed += len(inline_failed)

        return {'posted': posted, 'failed': failed}


def run_github_pr_comment(
    repo: str,
    pr_number: int,
    findings_source,
    min_severity: str = 'MEDIUM',
    token: Optional[str] = None,
) -> None:
    """
    Post findings to a GitHub PR.
    findings_source: list of findings OR path to JSON file.
    """
    if isinstance(findings_source, str):
        with open(findings_source, encoding='utf-8') as fh:
            findings = json.load(fh)
    else:
        findings = findings_source

    try:
        commenter = GitHubPRCommenter(token=token)
    except ValueError as exc:
        print(f'\033[91m[AuditLens GH-PR]\033[0m {exc}')
        return

    print(f'\033[94m[AuditLens GH-PR]\033[0m Publicando {len(findings)} hallazgos en {repo}#{pr_number}...')
    result = commenter.post_findings(repo, pr_number, findings, min_severity=min_severity)
    print(
        f'\033[92m[AuditLens GH-PR]\033[0m '
        f'{result["posted"]} comentarios publicados, {result["failed"]} fallidos.'
    )
