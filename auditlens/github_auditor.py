"""
AuditLens GitHub Repository Auditor — audita protección de ramas,
secretos públicos, permisos de colaboradores y configuración de seguridad.

Requires: GITHUB_TOKEN env var with repo read access.

Usage:
    auditlens github-audit owner/repo
    auditlens github-audit owner/repo --token ghp_xxx
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import requests

_COMPLIANCE = ['CWE-284', 'CWE-732', 'ISO-27001:A.9', 'OWASP-A5:2021']


class GitHubAuditor:
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

    def _get(self, path: str) -> Any:
        resp = self.session.get(f'{self.base}{path}', timeout=15)
        if resp.status_code == 200:
            return resp.json()
        return None

    def _paginate(self, path: str) -> List[Any]:
        results = []
        page = 1
        while True:
            resp = self.session.get(
                f'{self.base}{path}', params={'per_page': 100, 'page': page}, timeout=15,
            )
            if resp.status_code != 200:
                break
            data = resp.json()
            if not data:
                break
            results.extend(data)
            if len(data) < 100:
                break
            page += 1
        return results

    def check_repo_info(self, repo: str) -> List[dict]:
        findings = []
        info = self._get(f'/repos/{repo}')
        if not info:
            return findings

        if info.get('private') is False:
            findings.append({
                'rule_id': 'GH-REPO-01',
                'name': f'Repository is Public: {repo}',
                'description': (
                    f'GitHub repository {repo} is publicly visible. '
                    'Ensure no sensitive code, secrets, or internal logic is exposed. '
                    'If this should be private, change visibility in Settings.'
                ),
                'severity': 'MEDIUM',
                'compliance': _COMPLIANCE,
                'file': repo,
                'line': 0,
                'source': 'GITHUB',
            })

        if not info.get('security_and_analysis', {}).get('secret_scanning', {}).get('status') == 'enabled':
            findings.append({
                'rule_id': 'GH-SEC-01',
                'name': f'GitHub Secret Scanning Not Enabled: {repo}',
                'description': (
                    'GitHub Advanced Security secret scanning is not enabled. '
                    'Secret scanning automatically detects tokens and credentials committed to the repo. '
                    'Enable in Settings > Code security and analysis.'
                ),
                'severity': 'HIGH',
                'compliance': _COMPLIANCE + ['CWE-798'],
                'file': repo,
                'line': 0,
                'source': 'GITHUB',
            })

        if not info.get('security_and_analysis', {}).get('dependabot_security_updates', {}).get('status') == 'enabled':
            findings.append({
                'rule_id': 'GH-SEC-02',
                'name': f'Dependabot Not Enabled: {repo}',
                'description': (
                    'Dependabot security updates are not enabled. '
                    'Dependabot automatically creates PRs to fix vulnerable dependencies. '
                    'Enable in Settings > Code security and analysis.'
                ),
                'severity': 'MEDIUM',
                'compliance': ['OWASP-A6:2021', 'CWE-1104'],
                'file': repo,
                'line': 0,
                'source': 'GITHUB',
            })

        return findings

    def check_branch_protection(self, repo: str) -> List[dict]:
        findings = []
        branches = self._paginate(f'/repos/{repo}/branches')
        default_branch = None
        info = self._get(f'/repos/{repo}')
        if info:
            default_branch = info.get('default_branch', 'main')

        for branch in branches:
            bname = branch.get('name', '')
            is_default = bname == default_branch
            protected = branch.get('protected', False)

            if not protected and is_default:
                findings.append({
                    'rule_id': 'GH-BP-01',
                    'name': f'Default Branch Unprotected: {repo}/{bname}',
                    'description': (
                        f'The default branch "{bname}" has no branch protection rules. '
                        'Anyone with write access can force-push or delete the branch. '
                        'Enable branch protection: require PR reviews, status checks, no force-push.'
                    ),
                    'severity': 'HIGH',
                    'compliance': _COMPLIANCE,
                    'file': repo,
                    'line': 0,
                    'source': 'GITHUB',
                })
            elif protected:
                bp = self._get(f'/repos/{repo}/branches/{bname}/protection')
                if bp:
                    if not bp.get('required_pull_request_reviews'):
                        findings.append({
                            'rule_id': 'GH-BP-02',
                            'name': f'Branch Protection: No Required PR Reviews: {repo}/{bname}',
                            'description': (
                                f'Branch "{bname}" is protected but does not require pull request reviews. '
                                'Enable "Require a pull request before merging" with at least 1 approving review.'
                            ),
                            'severity': 'MEDIUM',
                            'compliance': _COMPLIANCE,
                            'file': repo,
                            'line': 0,
                            'source': 'GITHUB',
                        })
                    if not bp.get('required_status_checks'):
                        findings.append({
                            'rule_id': 'GH-BP-03',
                            'name': f'Branch Protection: No Required Status Checks: {repo}/{bname}',
                            'description': (
                                f'Branch "{bname}" does not require CI status checks to pass before merging. '
                                'Enable required status checks (CI/CD, tests) for the default branch.'
                            ),
                            'severity': 'LOW',
                            'compliance': _COMPLIANCE,
                            'file': repo,
                            'line': 0,
                            'source': 'GITHUB',
                        })
                    allow_force = bp.get('allow_force_pushes', {}).get('enabled', True)
                    if allow_force:
                        findings.append({
                            'rule_id': 'GH-BP-04',
                            'name': f'Force Push Allowed on Protected Branch: {repo}/{bname}',
                            'description': (
                                f'Branch "{bname}" allows force pushes, which can rewrite history '
                                'and destroy code review evidence. Disable "Allow force pushes".'
                            ),
                            'severity': 'HIGH',
                            'compliance': _COMPLIANCE,
                            'file': repo,
                            'line': 0,
                            'source': 'GITHUB',
                        })

        return findings

    def check_collaborators(self, repo: str) -> List[dict]:
        findings = []
        collabs = self._paginate(f'/repos/{repo}/collaborators')
        admins = [c for c in collabs if c.get('permissions', {}).get('admin')]

        if len(admins) > 3:
            findings.append({
                'rule_id': 'GH-PERM-01',
                'name': f'Too Many Admin Collaborators: {repo} ({len(admins)} admins)',
                'description': (
                    f'Repository {repo} has {len(admins)} collaborators with admin permissions. '
                    'Follow least-privilege: limit admin access to those who truly need it. '
                    f'Admins: {", ".join(c["login"] for c in admins[:5])}{"..." if len(admins) > 5 else ""}.'
                ),
                'severity': 'MEDIUM',
                'compliance': ['CWE-269', 'ISO-27001:A.9', 'OWASP-A5:2021'],
                'file': repo,
                'line': 0,
                'source': 'GITHUB',
            })

        return findings

    def check_actions_security(self, repo: str) -> List[dict]:
        findings = []
        workflows_dir = self._get(f'/repos/{repo}/contents/.github/workflows')
        if not isinstance(workflows_dir, list):
            return findings

        for wf in workflows_dir:
            if not wf.get('name', '').endswith(('.yml', '.yaml')):
                continue
            content_resp = self._get(f'/repos/{repo}/contents/{wf["path"]}')
            if not content_resp:
                continue
            import base64
            try:
                raw = base64.b64decode(content_resp.get('content', '')).decode('utf-8', errors='replace')
            except Exception:
                continue

            if 'pull_request_target' in raw and 'github.event.pull_request' in raw:
                findings.append({
                    'rule_id': 'GH-ACT-01',
                    'name': f'Unsafe pull_request_target in Workflow: {wf["name"]}',
                    'description': (
                        f'Workflow {wf["name"]} uses pull_request_target trigger and accesses '
                        'PR data, which can allow untrusted code to access secrets if checkout is included. '
                        'Review for pwn-request vulnerabilities (GitHub Advisory: GHSL-2021-1038).'
                    ),
                    'severity': 'CRITICAL',
                    'compliance': ['CWE-284', 'OWASP-CI/CD-SEC-01'],
                    'file': wf.get('path', ''),
                    'line': 0,
                    'source': 'GITHUB',
                })

            if '${{ github.event.issue.title' in raw or '${{ github.event.comment.body' in raw:
                findings.append({
                    'rule_id': 'GH-ACT-02',
                    'name': f'Script Injection Risk in Workflow: {wf["name"]}',
                    'description': (
                        f'Workflow {wf["name"]} uses untrusted input (${{{{ github.event.* }}}}) directly '
                        'in a run: step, which can allow command injection. '
                        'Use an intermediate environment variable instead of inline expressions.'
                    ),
                    'severity': 'HIGH',
                    'compliance': ['CWE-77', 'CWE-94'],
                    'file': wf.get('path', ''),
                    'line': 0,
                    'source': 'GITHUB',
                })

        return findings


def run_github_audit(repo: str, token: Optional[str] = None) -> List[dict]:
    """Run all GitHub repository security checks."""
    print(f'\033[94m[AuditLens GitHub]\033[0m Auditando repositorio: {repo}')
    try:
        auditor = GitHubAuditor(token=token)
    except ValueError as exc:
        print(f'\033[91m[AuditLens GitHub]\033[0m {exc}')
        return []

    findings: List[dict] = []
    findings.extend(auditor.check_repo_info(repo))
    findings.extend(auditor.check_branch_protection(repo))
    findings.extend(auditor.check_collaborators(repo))
    findings.extend(auditor.check_actions_security(repo))

    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for f in findings:
        sev = f.get('severity', 'LOW')
        if sev in counts:
            counts[sev] += 1

    print(
        f'\033[92m[AuditLens GitHub]\033[0m {len(findings)} hallazgos '
        f'(CRITICAL:{counts["CRITICAL"]} HIGH:{counts["HIGH"]})'
    )
    return findings
