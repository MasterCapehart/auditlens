"""
AuditLens Notification Engine — Slack and JIRA integrations.

Configure in .auditlens.yaml:

    notifications:
      slack:
        webhook: ${SLACK_WEBHOOK_URL}   # env var reference supported
        min_severity: HIGH
        channel: "#security-alerts"     # optional, overrides webhook default
      jira:
        url: https://company.atlassian.net
        project: SEC
        username: ${JIRA_USER}
        api_token: ${JIRA_TOKEN}
        auto_create_tickets: true
        min_severity: CRITICAL
        issue_type: Bug
        labels:
          - auditlens
          - security
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional

import requests

_SEVERITY_RANK = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}

_SEV_EMOJI = {
    'CRITICAL': ':red_circle:',
    'HIGH':     ':large_orange_circle:',
    'MEDIUM':   ':large_yellow_circle:',
    'LOW':      ':large_blue_circle:',
}

_SEV_COLOR = {
    'CRITICAL': '#ef4444',
    'HIGH':     '#f97316',
    'MEDIUM':   '#eab308',
    'LOW':      '#3b82f6',
}


def _resolve_env(value: str) -> str:
    """Replace ${VAR_NAME} references with environment variable values."""
    def _replace(m):
        return os.environ.get(m.group(1), m.group(0))
    return re.sub(r'\$\{([^}]+)\}', _replace, str(value))


# ── Slack ─────────────────────────────────────────────────────────────────────

def _build_slack_payload(
    findings: List[dict],
    scan_path: str,
    min_severity: str = 'HIGH',
) -> Optional[Dict]:
    """Build a Slack Block Kit message payload."""
    rank = _SEVERITY_RANK.get(min_severity.upper(), 2)
    filtered = [f for f in findings if _SEVERITY_RANK.get(f['severity'].upper(), 0) >= rank]
    if not filtered:
        return None

    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for f in filtered:
        sev = f['severity'].upper()
        if sev in counts:
            counts[sev] += 1

    summary_parts = []
    for sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
        if counts[sev]:
            summary_parts.append(f"{_SEV_EMOJI[sev]} *{counts[sev]} {sev}*")

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "🛡️ AuditLens Security Report"}
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Scan path:* `{scan_path}`\n*Findings:* {' · '.join(summary_parts)}"
            }
        },
        {"type": "divider"},
    ]

    # Top 5 most critical findings
    for finding in sorted(filtered, key=lambda x: -_SEVERITY_RANK.get(x['severity'].upper(), 0))[:5]:
        file_short = '/'.join(finding.get('file', '').split('/')[-2:])
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"{_SEV_EMOJI.get(finding['severity'].upper(), '')} "
                    f"*[{finding['rule_id']}]* {finding['name']}\n"
                    f"`{file_short}:{finding.get('line', '')}`\n"
                    f"_{finding.get('description', '')[:120]}_"
                )
            }
        })

    if len(filtered) > 5:
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"_...and {len(filtered) - 5} more findings_"}]
        })

    return {"blocks": blocks, "text": f"AuditLens: {len(filtered)} security findings detected"}


def notify_slack(
    findings: List[dict],
    scan_path: str,
    webhook_url: str,
    min_severity: str = 'HIGH',
) -> bool:
    """Send findings to a Slack Incoming Webhook. Returns True on success."""
    webhook_url = _resolve_env(webhook_url)
    if not webhook_url or webhook_url.startswith('${'):
        print('\033[93m[AuditLens Notifications] Slack webhook URL not set.\033[0m')
        return False

    payload = _build_slack_payload(findings, scan_path, min_severity)
    if payload is None:
        print(f'\033[90m[AuditLens Notifications] No findings at or above {min_severity} — Slack skipped.\033[0m')
        return True

    try:
        resp = requests.post(webhook_url, json=payload, timeout=10)
        resp.raise_for_status()
        print(f'\033[92m[AuditLens Notifications]\033[0m Slack notification sent.')
        return True
    except requests.RequestException as exc:
        print(f'\033[91m[AuditLens Notifications] Slack error: {exc}\033[0m')
        return False


# ── JIRA ──────────────────────────────────────────────────────────────────────

def _jira_search_existing(
    jira_url: str,
    project_key: str,
    rule_id: str,
    file_path: str,
    auth: tuple,
    headers: dict,
) -> Optional[str]:
    """
    Search Jira for an open issue with the same rule_id + file path.
    Returns the issue key (e.g. 'SEC-42') if found, else None.
    Uses JQL: project = KEY AND summary ~ "rule_id" AND summary ~ "file" AND statusCategory != Done
    """
    file_short = os.path.basename(file_path)
    jql = (
        f'project = "{project_key}" '
        f'AND summary ~ "[AuditLens]" '
        f'AND summary ~ "{rule_id}" '
        f'AND summary ~ "{file_short}" '
        f'AND statusCategory != Done'
    )
    try:
        resp = requests.get(
            f'{jira_url}/rest/api/2/search',
            params={'jql': jql, 'fields': 'summary', 'maxResults': 1},
            auth=auth,
            headers=headers,
            timeout=10,
        )
        resp.raise_for_status()
        issues = resp.json().get('issues', [])
        if issues:
            return issues[0]['key']
    except requests.RequestException:
        pass
    return None


def _build_jira_description(finding: dict) -> str:
    """Build a JIRA issue description in Atlassian Document Format (ADF) / wiki markup."""
    file_path = finding.get('file', 'unknown')
    line = finding.get('line', '')
    compliance = ', '.join(finding.get('compliance', []))
    return (
        f"h2. Finding Details\n\n"
        f"||Field||Value||\n"
        f"|Rule ID|{{code}}{finding.get('rule_id', '')}{{code}}|\n"
        f"|Severity|*{finding.get('severity', '')}*|\n"
        f"|File|{{code}}{file_path}:{line}{{code}}|\n"
        f"|Compliance|{compliance}|\n\n"
        f"h3. Description\n\n"
        f"{finding.get('description', '')}\n\n"
        f"h3. Remediation\n\n"
        f"Review the code at {{code}}{file_path}{{code}} line {line} and apply "
        f"appropriate sanitization or use secure alternatives.\n\n"
        f"_Detected by AuditLens — https://github.com/MasterCapehart/auditlens_"
    )


def notify_jira(
    findings: List[dict],
    scan_path: str,
    jira_url: str,
    project_key: str,
    username: str,
    api_token: str,
    min_severity: str = 'CRITICAL',
    issue_type: str = 'Bug',
    labels: Optional[List[str]] = None,
    auto_create: bool = True,
) -> int:
    """
    Create JIRA tickets for findings at or above min_severity.
    Returns number of tickets created.
    """
    jira_url   = _resolve_env(jira_url).rstrip('/')
    username   = _resolve_env(username)
    api_token  = _resolve_env(api_token)
    project_key = _resolve_env(project_key)

    if not all([jira_url, username, api_token, project_key]):
        print('\033[93m[AuditLens Notifications] JIRA config incomplete.\033[0m')
        return 0

    rank = _SEVERITY_RANK.get(min_severity.upper(), 3)
    filtered = [f for f in findings if _SEVERITY_RANK.get(f['severity'].upper(), 0) >= rank]

    if not filtered:
        print(f'\033[90m[AuditLens Notifications] No findings at or above {min_severity} — JIRA skipped.\033[0m')
        return 0

    if not auto_create:
        print(f'\033[90m[AuditLens Notifications] JIRA: {len(filtered)} findings would create tickets (auto_create=false).\033[0m')
        return 0

    auth = (username, api_token)
    headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    api_base = f'{jira_url}/rest/api/2/issue'
    created = 0
    skipped = 0

    for finding in filtered:
        file_short = '/'.join(finding.get('file', '').split('/')[-2:])
        summary = f"[AuditLens][{finding['severity']}] {finding['rule_id']} in {file_short}:{finding.get('line', '')}"

        # Deduplication: skip if an open ticket already exists for this rule+file
        existing = _jira_search_existing(
            jira_url=jira_url,
            project_key=project_key,
            rule_id=finding['rule_id'],
            file_path=finding.get('file', ''),
            auth=auth,
            headers=headers,
        )
        if existing:
            print(
                f'\033[90m[AuditLens Notifications] JIRA: skipping {finding["rule_id"]} — '
                f'existing open ticket {existing}\033[0m'
            )
            skipped += 1
            continue

        payload: Dict[str, Any] = {
            "fields": {
                "project":     {"key": project_key},
                "summary":     summary[:255],
                "description": _build_jira_description(finding),
                "issuetype":   {"name": issue_type},
                "priority":    {"name": _jira_priority(finding['severity'])},
            }
        }
        if labels:
            payload["fields"]["labels"] = labels

        try:
            resp = requests.post(api_base, json=payload, auth=auth, headers=headers, timeout=15)
            resp.raise_for_status()
            issue_key = resp.json().get('key', '?')
            print(f'\033[92m[AuditLens Notifications]\033[0m JIRA ticket created: {issue_key} — {summary[:60]}')
            created += 1
        except requests.RequestException as exc:
            print(f'\033[91m[AuditLens Notifications] JIRA error for {finding["rule_id"]}: {exc}\033[0m')

    if skipped:
        print(f'\033[90m[AuditLens Notifications] JIRA: {skipped} duplicate(s) skipped.\033[0m')
    return created


def _jira_priority(severity: str) -> str:
    return {
        'CRITICAL': 'Highest',
        'HIGH':     'High',
        'MEDIUM':   'Medium',
        'LOW':      'Low',
    }.get(severity.upper(), 'Medium')


# ── Dispatcher ────────────────────────────────────────────────────────────────

def dispatch_notifications(
    findings: List[dict],
    scan_path: str,
    notif_config: Dict,
) -> None:
    """
    Read notification config from .auditlens.yaml and dispatch to enabled channels.

    notif_config example:
      {
        "slack": {"webhook": "${SLACK_WEBHOOK}", "min_severity": "HIGH"},
        "jira":  {"url": "...", "project": "SEC", "username": "...",
                  "api_token": "${JIRA_TOKEN}", "auto_create_tickets": True,
                  "min_severity": "CRITICAL"}
      }
    """
    if not notif_config:
        return

    # Slack
    slack_cfg = notif_config.get('slack')
    if slack_cfg:
        notify_slack(
            findings=findings,
            scan_path=scan_path,
            webhook_url=slack_cfg.get('webhook', ''),
            min_severity=slack_cfg.get('min_severity', 'HIGH'),
        )

    # JIRA
    jira_cfg = notif_config.get('jira')
    if jira_cfg:
        notify_jira(
            findings=findings,
            scan_path=scan_path,
            jira_url=jira_cfg.get('url', ''),
            project_key=jira_cfg.get('project', ''),
            username=jira_cfg.get('username', ''),
            api_token=jira_cfg.get('api_token', ''),
            min_severity=jira_cfg.get('min_severity', 'CRITICAL'),
            issue_type=jira_cfg.get('issue_type', 'Bug'),
            labels=jira_cfg.get('labels'),
            auto_create=jira_cfg.get('auto_create_tickets', False),
        )
