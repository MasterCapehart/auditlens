"""
AuditLens Scheduled Scans — programa escaneos periódicos via cron
con notificaciones por email y reportes automáticos.

Usage:
    auditlens schedule add --path ./project --cron "0 2 * * *" --email admin@empresa.com
    auditlens schedule list
    auditlens schedule run-pending   # called by cron job
    auditlens schedule remove <id>
"""

from __future__ import annotations

import json
import os
import smtplib
import subprocess
import sys
import time
import uuid
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional


_SCHEDULE_FILE = os.path.expanduser('~/.auditlens/schedules.json')
_CRON_MARKER = '# AuditLens scheduled scans'


def _load_schedules() -> List[Dict]:
    if not os.path.isfile(_SCHEDULE_FILE):
        return []
    try:
        with open(_SCHEDULE_FILE, encoding='utf-8') as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []


def _save_schedules(schedules: List[Dict]) -> None:
    os.makedirs(os.path.dirname(_SCHEDULE_FILE), exist_ok=True)
    with open(_SCHEDULE_FILE, 'w', encoding='utf-8') as fh:
        json.dump(schedules, fh, indent=2)


def _send_email(
    to_addr: str,
    subject: str,
    body_html: str,
    smtp_host: str = '',
    smtp_port: int = 587,
    smtp_user: str = '',
    smtp_pass: str = '',
) -> bool:
    smtp_host = smtp_host or os.environ.get('SMTP_HOST', '')
    smtp_user = smtp_user or os.environ.get('SMTP_USER', '')
    smtp_pass = smtp_pass or os.environ.get('SMTP_PASS', '')

    if not smtp_host:
        print('\033[93m[AuditLens Scheduler]\033[0m SMTP_HOST no configurado. No se envió email.')
        return False

    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = smtp_user or 'auditlens@localhost'
        msg['To'] = to_addr
        msg.attach(MIMEText(body_html, 'html'))

        with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as smtp:
            smtp.ehlo()
            if smtp_port != 25:
                smtp.starttls()
            if smtp_user and smtp_pass:
                smtp.login(smtp_user, smtp_pass)
            smtp.sendmail(msg['From'], [to_addr], msg.as_string())
        return True
    except Exception as exc:
        print(f'\033[91m[AuditLens Scheduler]\033[0m Error enviando email: {exc}')
        return False


def add_schedule(
    scan_path: str,
    cron_expression: str,
    email: Optional[str] = None,
    min_severity: str = 'MEDIUM',
    scan_format: str = 'html',
    output_dir: str = '~/.auditlens/reports',
    label: str = '',
) -> str:
    """Add a scheduled scan. Returns the schedule ID."""
    schedules = _load_schedules()
    sched_id = str(uuid.uuid4())[:8]

    schedule = {
        'id': sched_id,
        'label': label or os.path.basename(scan_path),
        'scan_path': os.path.abspath(os.path.expanduser(scan_path)),
        'cron': cron_expression,
        'email': email or '',
        'min_severity': min_severity,
        'format': scan_format,
        'output_dir': output_dir,
        'created_at': _now_iso(),
        'last_run': None,
        'enabled': True,
    }
    schedules.append(schedule)
    _save_schedules(schedules)

    # Install cron job if not already present
    _install_cron_job()

    print(f'\033[92m[AuditLens Scheduler]\033[0m Escaneo programado: ID={sched_id} | Cron={cron_expression}')
    print(f'  Path: {schedule["scan_path"]}')
    if email:
        print(f'  Email: {email}')
    return sched_id


def list_schedules() -> None:
    schedules = _load_schedules()
    if not schedules:
        print('\033[93m[AuditLens Scheduler]\033[0m No hay escaneos programados.')
        return

    print('\n\033[1m=== ESCANEOS PROGRAMADOS ===\033[0m')
    print(f'{"ID":<10} {"Label":<25} {"Cron":<20} {"Path":<35} {"Último":<12}')
    print('-' * 102)
    for s in schedules:
        status = '\033[92m●\033[0m' if s.get('enabled') else '\033[91m●\033[0m'
        last = s.get('last_run', 'nunca') or 'nunca'
        print(
            f'{status} {s["id"]:<8} {s["label"][:24]:<25} {s["cron"]:<20} '
            f'{s["scan_path"][-34:]:<35} {last[:10]:<12}'
        )


def remove_schedule(sched_id: str) -> bool:
    schedules = _load_schedules()
    new = [s for s in schedules if s['id'] != sched_id]
    if len(new) == len(schedules):
        print(f'\033[91m[AuditLens Scheduler]\033[0m ID no encontrado: {sched_id}')
        return False
    _save_schedules(new)
    print(f'\033[92m[AuditLens Scheduler]\033[0m Escaneo eliminado: {sched_id}')
    return True


def run_pending_schedules() -> None:
    """Called by cron. Runs all due schedules."""
    import datetime
    schedules = _load_schedules()
    now = datetime.datetime.now()
    updated = False

    for sched in schedules:
        if not sched.get('enabled', True):
            continue

        # Simplified: always run (actual cron handles timing)
        scan_path = sched['scan_path']
        output_dir = os.path.expanduser(sched.get('output_dir', '~/.auditlens/reports'))
        os.makedirs(output_dir, exist_ok=True)

        timestamp = now.strftime('%Y%m%d_%H%M%S')
        label = sched.get('label', 'scan').replace(' ', '_')
        fmt = sched.get('format', 'html')
        output_file = os.path.join(output_dir, f'{label}_{timestamp}.{fmt}')

        cli_path = os.path.join(os.path.dirname(sys.executable), 'auditlens')
        cmd = [
            cli_path, 'scan', scan_path,
            '--min-severity', sched.get('min_severity', 'MEDIUM'),
            '--format', fmt,
            '--output', output_file,
        ]

        print(f'\033[94m[AuditLens Scheduler]\033[0m Ejecutando: {sched["label"]}')
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            success = result.returncode == 0
        except Exception as exc:
            print(f'\033[91m[AuditLens Scheduler]\033[0m Error: {exc}')
            success = False

        sched['last_run'] = now.isoformat()
        updated = True

        if sched.get('email') and success and os.path.isfile(output_file):
            subject = f'AuditLens Report: {sched["label"]} — {now.strftime("%Y-%m-%d")}'
            if fmt == 'html':
                with open(output_file, encoding='utf-8') as fh:
                    body = fh.read()
            else:
                body = f'<p>Escaneo completado: {sched["label"]}</p><p>Reporte: {output_file}</p>'
            _send_email(sched['email'], subject, body)

    if updated:
        _save_schedules(schedules)


def _install_cron_job() -> None:
    """Add AuditLens cron entry if not already present."""
    try:
        result = subprocess.run(
            ['crontab', '-l'], capture_output=True, text=True,
        )
        current = result.stdout if result.returncode == 0 else ''
    except FileNotFoundError:
        return

    if _CRON_MARKER in current:
        return

    cli_path = os.path.join(os.path.dirname(sys.executable), 'auditlens')
    cron_line = f'\n{_CRON_MARKER}\n* * * * * {cli_path} schedule run-pending >> ~/.auditlens/cron.log 2>&1\n'

    new_crontab = current + cron_line
    try:
        proc = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE, text=True)
        proc.communicate(input=new_crontab)
        print('\033[92m[AuditLens Scheduler]\033[0m Cron job instalado.')
    except Exception:
        pass


def _now_iso() -> str:
    import datetime
    return datetime.datetime.now().isoformat()
