"""
AuditLens Risk Scorer — aggregates findings per file into a risk score
and prints a "Top Risky Files" table at the end of a scan.
"""

from __future__ import annotations

from typing import List

_SEVERITY_WEIGHTS = {
    'CRITICAL': 10,
    'HIGH':     5,
    'MEDIUM':   2,
    'LOW':      1,
}


def compute_file_risk(findings: List[dict]) -> List[dict]:
    """
    Returns a list of dicts sorted by risk score (descending):
      { file, total, critical, high, medium, low, score }
    """
    stats: dict = {}
    for f in findings:
        fp = f.get('file', 'unknown')
        sev = f.get('severity', 'LOW').upper()
        if fp not in stats:
            stats[fp] = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        if sev in stats[fp]:
            stats[fp][sev] += 1

    result = []
    for fp, s in stats.items():
        score = sum(s[sev] * _SEVERITY_WEIGHTS[sev] for sev in _SEVERITY_WEIGHTS)
        result.append({
            'file': fp,
            'total': sum(s.values()),
            'critical': s['CRITICAL'],
            'high': s['HIGH'],
            'medium': s['MEDIUM'],
            'low': s['LOW'],
            'score': score,
        })

    return sorted(result, key=lambda x: -x['score'])


def print_risk_table(findings: List[dict], top_n: int = 10) -> None:
    """Print a coloured top-N risky files table to stdout."""
    if not findings:
        return

    ranked = compute_file_risk(findings)[:top_n]

    print('\n\033[94m[AuditLens]\033[0m Top Risky Files:')
    print(f"  {'Score':>6}  {'C':>3} {'H':>3} {'M':>3} {'L':>3}  File")
    print('  ' + '─' * 60)
    for r in ranked:
        # shorten path to last 3 segments for readability
        short = '/'.join(r['file'].split('/')[-3:])
        c_col = f'\033[91m{r["critical"]:>3}\033[0m' if r['critical'] else f'{r["critical"]:>3}'
        h_col = f'\033[93m{r["high"]:>3}\033[0m'    if r['high']     else f'{r["high"]:>3}'
        print(
            f"  \033[1m{r['score']:>6}\033[0m  {c_col} {h_col} "
            f"{r['medium']:>3} {r['low']:>3}  {short}"
        )
