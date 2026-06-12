"""AuditLens CSV Exporter."""

from __future__ import annotations

import csv
import os
from typing import List


def generate_csv_report(findings: List[dict], scan_path: str, output_path: str) -> str:
    """Export findings to CSV."""
    fieldnames = [
        'severity', 'rule_id', 'name', 'file', 'line',
        'description', 'compliance', 'source',
    ]

    _SEV_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    sorted_findings = sorted(findings, key=lambda f: _SEV_ORDER.get(f.get('severity', 'LOW'), 4))

    with open(output_path, 'w', newline='', encoding='utf-8') as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        for f in sorted_findings:
            row = {k: f.get(k, '') for k in fieldnames}
            if isinstance(row.get('compliance'), list):
                row['compliance'] = ', '.join(row['compliance'])
            writer.writerow(row)

    print(f'\033[92m[AuditLens CSV]\033[0m {len(findings)} hallazgos exportados a {output_path}')
    return output_path
