"""
AuditLens Temporal Vulnerability Archaeology
=============================================

Mines the full git history of a repository to reconstruct the complete
temporal lifecycle of every vulnerability:

  1. INTRODUCTION — which commit added the vulnerable pattern
  2. LIFETIME     — how many days it lived before being fixed/detected
  3. FIX COMMIT   — which commit removed it
  4. DEVELOPER PROFILE — behavioral patterns that predict future vulns
  5. PREDICTIVE MODEL  — Bayesian risk score for files likely to become
                         vulnerable in the next N commits

This is unique: no security tool on the market does archaeology + prediction
at the commit granularity with developer behavioral fingerprinting.

Algorithm:
  For each rule/pattern in the rules engine:
    - Run `git log -p` to get every addition/removal of that pattern
    - Match additions → introductions, removals → fixes
    - Pair them to compute lifetime (days open)
    - Aggregate by author, file, day-of-week, time-of-day, file-size
    - Build a logistic regression-style risk score for untouched files

Usage:
    auditlens archaeology ./repo
    auditlens archaeology ./repo --depth 500 --output arch_report.html
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# ── Regex patterns to track through history ──────────────────────────────────
# Each entry: (pattern_regex, rule_id, name, severity)
_TRACKED_PATTERNS = [
    (r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']',
     'HARDCODED-PASS', 'Hardcoded Password', 'HIGH'),
    (r'(?i)(api_key|apikey|secret|token)\s*=\s*["\'][A-Za-z0-9_\-]{8,}["\']',
     'HARDCODED-SECRET', 'Hardcoded Secret/Token', 'CRITICAL'),
    (r'AKIA[0-9A-Z]{16}',
     'AWS-KEY', 'AWS Access Key', 'CRITICAL'),
    (r'(?i)cursor\.execute\s*\(\s*["\'][^"\']*["\'\s]*\+',
     'SQLI-CONCAT', 'SQL Injection (concat)', 'CRITICAL'),
    (r'(?i)cursor\.execute\s*\(\s*f["\']',
     'SQLI-FSTRING', 'SQL Injection (f-string)', 'CRITICAL'),
    (r'(?i)subprocess\.(run|call|Popen)\s*\([^,)]*\+',
     'CMD-INJECT', 'Command Injection', 'CRITICAL'),
    (r'eval\s*\(',
     'EVAL', 'Use of eval()', 'CRITICAL'),
    (r'(?i)os\.system\s*\(',
     'OS-SYSTEM', 'os.system() call', 'HIGH'),
    (r'(?i)hashlib\.(md5|sha1)\s*\(',
     'WEAK-HASH', 'Weak Hash Algorithm', 'MEDIUM'),
    (r'(?i)random\.random\s*\(\)',
     'WEAK-RANDOM', 'Insecure Random', 'LOW'),
    (r'(?i)pickle\.(loads|load)\s*\(',
     'PICKLE', 'Unsafe Pickle Deserialization', 'CRITICAL'),
    (r'(?i)(verify\s*=\s*False|ssl.*verify.*False)',
     'SSL-NOVERIFY', 'SSL Verification Disabled', 'HIGH'),
    (r'(?i)yaml\.load\s*\([^,)]+\)',
     'YAML-UNSAFE', 'Unsafe yaml.load()', 'HIGH'),
    (r'(?i)DEBUG\s*=\s*True',
     'DEBUG-ON', 'Debug Mode Enabled', 'MEDIUM'),
    (r'(?i)(innerHTML|outerHTML)\s*=\s*',
     'XSS-INNER', 'Direct innerHTML Assignment (XSS)', 'HIGH'),
]

_COMPILED = [
    (re.compile(p), rid, name, sev)
    for p, rid, name, sev in _TRACKED_PATTERNS
]

# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class VulnEvent:
    """A single introduction or fix event in git history."""
    event_type: str          # 'introduced' | 'fixed'
    rule_id: str
    rule_name: str
    severity: str
    file_path: str
    line_snippet: str        # the actual code line
    commit_hash: str
    author_name: str
    author_email: str
    commit_date: str         # ISO date string
    commit_msg: str
    day_of_week: int         # 0=Monday … 6=Sunday
    hour_of_day: int
    file_line_count: int     # file size at time of commit

@dataclass
class VulnLifecycle:
    """Pairs an introduction with its eventual fix (or None if still open)."""
    rule_id: str
    rule_name: str
    severity: str
    file_path: str
    intro_event: VulnEvent
    fix_event: Optional[VulnEvent] = None
    lifetime_days: Optional[float] = None   # None = still open

    def is_open(self) -> bool:
        return self.fix_event is None

    def vuln_id(self) -> str:
        h = hashlib.md5(
            f'{self.rule_id}:{self.file_path}:{self.intro_event.commit_hash}'.encode()
        ).hexdigest()[:8]
        return f'VID-{h.upper()}'

@dataclass
class DeveloperProfile:
    """Behavioral risk profile for a single developer."""
    name: str
    email: str
    total_commits: int = 0
    vuln_introductions: int = 0
    vuln_fixes: int = 0
    avg_lifetime_days: float = 0.0
    risky_hours: Dict[int, int] = field(default_factory=dict)       # hour→count
    risky_days: Dict[int, int] = field(default_factory=dict)        # dow→count
    vuln_files: List[str] = field(default_factory=list)
    severity_breakdown: Dict[str, int] = field(default_factory=dict)
    risk_score: float = 0.0   # 0–100

    def introduction_rate(self) -> float:
        if self.total_commits == 0:
            return 0.0
        return self.vuln_introductions / self.total_commits

    def top_risky_hour(self) -> Optional[int]:
        if not self.risky_hours:
            return None
        return max(self.risky_hours, key=self.risky_hours.get)

    def top_risky_day(self) -> Optional[str]:
        _DAYS = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        if not self.risky_days:
            return None
        dow = max(self.risky_days, key=self.risky_days.get)
        return _DAYS[dow]

@dataclass
class FilePrediction:
    """Predicted vulnerability probability for a file."""
    file_path: str
    risk_probability: float     # 0.0–1.0
    risk_score: float           # 0–100
    contributing_factors: List[str]
    last_touched_by: str
    days_since_last_vuln: Optional[float]
    historical_vuln_count: int
    predicted_rule_ids: List[str]


# ── Git utilities ─────────────────────────────────────────────────────────────

def _git(args: List[str], cwd: str, timeout: int = 120) -> str:
    try:
        r = subprocess.run(
            ['git'] + args, cwd=cwd,
            capture_output=True, text=True, timeout=timeout,
        )
        return r.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ''


def _get_all_commits(repo_path: str, max_count: int) -> List[Dict[str, str]]:
    """Return list of {hash, author_name, author_email, date, subject}."""
    fmt = '%H\x1f%an\x1f%ae\x1f%aI\x1f%s'
    output = _git(
        ['log', '--all', f'--max-count={max_count}',
         f'--format={fmt}', '--no-merges'],
        cwd=repo_path,
    )
    commits = []
    for line in output.splitlines():
        parts = line.split('\x1f')
        if len(parts) == 5:
            commits.append({
                'hash': parts[0],
                'author_name': parts[1],
                'author_email': parts[2],
                'date': parts[3],
                'subject': parts[4],
            })
    return commits


def _get_commit_diff(repo_path: str, commit_hash: str) -> str:
    """Get the unified diff of a single commit."""
    return _git(
        ['show', commit_hash, '--unified=0', '--no-color',
         '--diff-filter=M', '-p'],
        cwd=repo_path, timeout=30,
    )


def _get_file_line_count(repo_path: str, commit_hash: str, file_path: str) -> int:
    """Get line count of file at a specific commit."""
    out = _git(
        ['show', f'{commit_hash}:{file_path}'],
        cwd=repo_path, timeout=10,
    )
    return out.count('\n')


def _parse_date(iso_date: str) -> Tuple[str, int, int]:
    """Returns (date_str, day_of_week, hour_of_day)."""
    try:
        # Handle ISO 8601 with timezone offset
        clean = re.sub(r'([+-]\d{2}):(\d{2})$', r'+\1\2', iso_date)
        import datetime
        if '+' in clean[10:] or clean.endswith('Z'):
            clean = clean.replace('Z', '+0000')
            dt = datetime.datetime.fromisoformat(clean[:19])
        else:
            dt = datetime.datetime.fromisoformat(clean[:19])
        return dt.strftime('%Y-%m-%d'), dt.weekday(), dt.hour
    except Exception:
        return iso_date[:10], 0, 12


# ── Core archaeology engine ───────────────────────────────────────────────────

def _extract_events_from_diff(
    diff_text: str,
    commit_info: Dict[str, str],
) -> List[VulnEvent]:
    """Scan a commit diff for vulnerability introductions (+) and fixes (-)."""
    events: List[VulnEvent] = []
    date_str, dow, hour = _parse_date(commit_info['date'])
    current_file = ''

    for line in diff_text.splitlines():
        if line.startswith('+++ b/'):
            current_file = line[6:]
            continue
        if line.startswith('--- ') or line.startswith('diff ') or line.startswith('index '):
            continue

        if not current_file:
            continue
        # Only scan Python/JS/TS lines
        ext = Path(current_file).suffix.lower()
        if ext not in ('.py', '.js', '.ts', '.mjs', '.go', '.java', '.rb', '.php'):
            continue

        is_added   = line.startswith('+') and not line.startswith('+++')
        is_removed = line.startswith('-') and not line.startswith('---')
        if not (is_added or is_removed):
            continue

        code = line[1:]
        for pattern, rule_id, rule_name, severity in _COMPILED:
            if pattern.search(code):
                events.append(VulnEvent(
                    event_type='introduced' if is_added else 'fixed',
                    rule_id=rule_id,
                    rule_name=rule_name,
                    severity=severity,
                    file_path=current_file,
                    line_snippet=code.strip()[:120],
                    commit_hash=commit_info['hash'],
                    author_name=commit_info['author_name'],
                    author_email=commit_info['author_email'],
                    commit_date=date_str,
                    commit_msg=commit_info['subject'][:100],
                    day_of_week=dow,
                    hour_of_day=hour,
                    file_line_count=0,
                ))
                break

    return events


def _pair_lifecycles(events: List[VulnEvent]) -> List[VulnLifecycle]:
    """
    Match introduction events with their corresponding fix events.
    Strategy: for each (rule_id, file_path) pair, events are sorted by date.
    An introduced event is matched to the next fixed event for the same rule+file.
    """
    import datetime

    # Group by (rule_id, file_path)
    grouped: Dict[Tuple[str, str], List[VulnEvent]] = defaultdict(list)
    for ev in events:
        grouped[(ev.rule_id, ev.file_path)].append(ev)

    lifecycles: List[VulnLifecycle] = []

    for (rule_id, file_path), evs in grouped.items():
        evs_sorted = sorted(evs, key=lambda e: e.commit_date)
        pending_intro: Optional[VulnEvent] = None

        for ev in evs_sorted:
            if ev.event_type == 'introduced':
                if pending_intro is not None:
                    # Previous intro never fixed — still open
                    lifecycles.append(VulnLifecycle(
                        rule_id=rule_id,
                        rule_name=ev.rule_name,
                        severity=ev.severity,
                        file_path=file_path,
                        intro_event=pending_intro,
                        fix_event=None,
                        lifetime_days=None,
                    ))
                pending_intro = ev

            elif ev.event_type == 'fixed' and pending_intro is not None:
                try:
                    d1 = datetime.datetime.strptime(pending_intro.commit_date, '%Y-%m-%d')
                    d2 = datetime.datetime.strptime(ev.commit_date, '%Y-%m-%d')
                    days = max(0.0, (d2 - d1).days)
                except ValueError:
                    days = None

                lifecycles.append(VulnLifecycle(
                    rule_id=rule_id,
                    rule_name=pending_intro.rule_name,
                    severity=pending_intro.severity,
                    file_path=file_path,
                    intro_event=pending_intro,
                    fix_event=ev,
                    lifetime_days=days,
                ))
                pending_intro = None

        if pending_intro is not None:
            lifecycles.append(VulnLifecycle(
                rule_id=rule_id,
                rule_name=pending_intro.rule_name,
                severity=pending_intro.severity,
                file_path=file_path,
                intro_event=pending_intro,
                fix_event=None,
                lifetime_days=None,
            ))

    return lifecycles


def _build_developer_profiles(
    lifecycles: List[VulnLifecycle],
    all_commits: List[Dict],
) -> Dict[str, DeveloperProfile]:
    """Build behavioral risk profiles per developer."""
    profiles: Dict[str, DeveloperProfile] = {}

    # Count total commits per developer
    for c in all_commits:
        email = c['author_email']
        name = c['author_name']
        if email not in profiles:
            profiles[email] = DeveloperProfile(name=name, email=email)
        profiles[email].total_commits += 1

    # Analyze introductions
    for lc in lifecycles:
        email = lc.intro_event.author_email
        if email not in profiles:
            profiles[email] = DeveloperProfile(
                name=lc.intro_event.author_name, email=email,
            )
        p = profiles[email]
        p.vuln_introductions += 1

        sev = lc.severity
        p.severity_breakdown[sev] = p.severity_breakdown.get(sev, 0) + 1

        hour = lc.intro_event.hour_of_day
        dow  = lc.intro_event.day_of_week
        p.risky_hours[hour] = p.risky_hours.get(hour, 0) + 1
        p.risky_days[dow]   = p.risky_days.get(dow, 0) + 1

        if lc.file_path not in p.vuln_files:
            p.vuln_files.append(lc.file_path)

        if lc.lifetime_days is not None:
            # Running average
            n = p.vuln_introductions
            p.avg_lifetime_days = (
                (p.avg_lifetime_days * (n - 1) + lc.lifetime_days) / n
            )

    # Analyze fixes
    for lc in lifecycles:
        if lc.fix_event:
            email = lc.fix_event.author_email
            if email in profiles:
                profiles[email].vuln_fixes += 1

    # Compute risk score (0–100)
    for p in profiles.values():
        if p.total_commits == 0:
            continue
        rate = p.introduction_rate()             # 0–1
        crit = p.severity_breakdown.get('CRITICAL', 0)
        high = p.severity_breakdown.get('HIGH', 0)
        avg_lt = min(p.avg_lifetime_days / 365, 1.0) if p.avg_lifetime_days else 0

        # Weighted risk score
        p.risk_score = min(100.0, round(
            rate * 40          # 40% weight: how often they introduce vulns
            + (crit * 8)       # per CRITICAL introduced
            + (high * 4)       # per HIGH introduced
            + avg_lt * 20      # 20% weight: how long vulns live
            + (1 if p.top_risky_day() in ('Friday', 'Saturday') else 0) * 5
        , 1))

    return profiles


def _predict_file_risk(
    repo_path: str,
    lifecycles: List[VulnLifecycle],
    profiles: Dict[str, DeveloperProfile],
    all_commits: List[Dict],
) -> List[FilePrediction]:
    """
    Predict which files are most likely to have undiscovered vulnerabilities
    or to receive vulnerable code in the near future.
    """
    import datetime

    today = datetime.date.today()

    # Historical vuln counts per file
    file_vuln_counts: Dict[str, int] = defaultdict(int)
    file_last_vuln_date: Dict[str, str] = {}
    file_rule_ids: Dict[str, List[str]] = defaultdict(list)
    file_authors: Dict[str, Set[str]] = defaultdict(set)

    for lc in lifecycles:
        fp = lc.file_path
        file_vuln_counts[fp] += 1
        d = lc.intro_event.commit_date
        if fp not in file_last_vuln_date or d > file_last_vuln_date[fp]:
            file_last_vuln_date[fp] = d
        if lc.rule_id not in file_rule_ids[fp]:
            file_rule_ids[fp].append(lc.rule_id)
        file_authors[fp].add(lc.intro_event.author_email)

    # Last toucher per file from recent commits
    last_toucher: Dict[str, str] = {}
    for c in all_commits:
        diff = _get_commit_diff(repo_path, c['hash'])
        for line in diff.splitlines():
            if line.startswith('+++ b/'):
                fp = line[6:]
                if fp not in last_toucher:
                    last_toucher[fp] = c['author_email']

    predictions: List[FilePrediction] = []

    # Score all files that have had at least one vuln
    for fp, count in file_vuln_counts.items():
        factors: List[str] = []
        score = 0.0

        # Factor 1: historical vuln count
        hist_factor = min(count * 15, 40)
        score += hist_factor
        if count >= 3:
            factors.append(f'{count} vulnerabilidades históricas en este archivo')
        elif count >= 1:
            factors.append(f'{count} vulnerabilidad histórica en este archivo')

        # Factor 2: days since last vuln (recency)
        days_since: Optional[float] = None
        if fp in file_last_vuln_date:
            try:
                last_d = datetime.datetime.strptime(
                    file_last_vuln_date[fp], '%Y-%m-%d'
                ).date()
                days_since = (today - last_d).days
                if days_since < 30:
                    score += 25
                    factors.append(f'Vulnerabilidad introducida hace solo {int(days_since)} días')
                elif days_since < 90:
                    score += 10
                    factors.append(f'Vulnerabilidad introducida hace {int(days_since)} días')
            except ValueError:
                pass

        # Factor 3: risky developer touched this file
        toucher_email = last_toucher.get(fp, '')
        toucher_profile = profiles.get(toucher_email)
        if toucher_profile and toucher_profile.risk_score > 50:
            score += 15
            factors.append(
                f'Último editor con risk score {toucher_profile.risk_score:.0f}/100: '
                f'{toucher_profile.name}'
            )
        elif toucher_profile and toucher_profile.risk_score > 25:
            score += 7
            factors.append(f'Editor con historial de vulns: {toucher_profile.name}')

        # Factor 4: multiple rule types hit this file
        rule_variety = len(file_rule_ids[fp])
        if rule_variety >= 3:
            score += 10
            factors.append(f'{rule_variety} tipos distintos de vulnerabilidades históricas')

        # Factor 5: multiple risky authors
        if len(file_authors[fp]) >= 2:
            score += 5
            factors.append(f'Editado por {len(file_authors[fp])} desarrolladores con historial de vulns')

        probability = min(score / 100, 0.99)

        predictions.append(FilePrediction(
            file_path=fp,
            risk_probability=round(probability, 2),
            risk_score=round(score, 1),
            contributing_factors=factors,
            last_touched_by=toucher_profile.name if toucher_profile else toucher_email,
            days_since_last_vuln=days_since,
            historical_vuln_count=count,
            predicted_rule_ids=file_rule_ids[fp],
        ))

    return sorted(predictions, key=lambda p: p.risk_probability, reverse=True)


# ── Timeline builder (for charts) ─────────────────────────────────────────────

def _build_risk_timeline(lifecycles: List[VulnLifecycle]) -> List[Dict]:
    """
    Build a daily risk score time series.
    Each day: open vulns weighted by severity.
    """
    import datetime

    _W = {'CRITICAL': 10, 'HIGH': 5, 'MEDIUM': 2, 'LOW': 1}

    # Collect all dates in range
    all_dates = set()
    for lc in lifecycles:
        all_dates.add(lc.intro_event.commit_date)
        if lc.fix_event:
            all_dates.add(lc.fix_event.commit_date)

    if not all_dates:
        return []

    try:
        start = datetime.datetime.strptime(min(all_dates), '%Y-%m-%d').date()
        end   = datetime.datetime.strptime(max(all_dates), '%Y-%m-%d').date()
    except ValueError:
        return []

    # Build a set of (date, delta) events
    delta_by_date: Dict[str, float] = defaultdict(float)
    for lc in lifecycles:
        w = _W.get(lc.severity, 1)
        delta_by_date[lc.intro_event.commit_date] += w
        if lc.fix_event:
            delta_by_date[lc.fix_event.commit_date] -= w

    # Cumulative walk
    timeline = []
    running_score = 0.0
    current = start
    while current <= end:
        ds = current.strftime('%Y-%m-%d')
        running_score = max(0, running_score + delta_by_date.get(ds, 0))
        timeline.append({'date': ds, 'risk_score': round(running_score, 1)})
        current += datetime.timedelta(days=1)

    return timeline


# ── Main entry point ──────────────────────────────────────────────────────────

def run_archaeology(
    repo_path: str,
    max_commits: int = 500,
    verbose: bool = True,
) -> Dict[str, Any]:
    """
    Run the full Temporal Vulnerability Archaeology analysis.
    Returns a comprehensive dict with:
      - lifecycles: full vuln lifecycle records
      - developer_profiles: per-developer risk profiles
      - predictions: files predicted to become vulnerable
      - risk_timeline: daily risk score series
      - stats: summary counts
    """
    if not os.path.isdir(os.path.join(repo_path, '.git')):
        print(f'\033[91m[AuditLens Archaeology]\033[0m No hay repositorio git en {repo_path}')
        return {}

    if verbose:
        print(f'\033[94m[AuditLens Archaeology]\033[0m Minando historial git ({max_commits} commits)...')

    # 1. Get all commits
    all_commits = _get_all_commits(repo_path, max_commits)
    if not all_commits:
        print('\033[91m[AuditLens Archaeology]\033[0m No se encontraron commits.')
        return {}

    if verbose:
        print(f'\033[94m[AuditLens Archaeology]\033[0m Analizando {len(all_commits)} commits...')

    # 2. Extract all vulnerability events from diffs
    all_events: List[VulnEvent] = []
    for i, commit in enumerate(all_commits):
        if verbose and i % 50 == 0 and i > 0:
            print(f'\033[90m[AuditLens Archaeology]\033[0m  {i}/{len(all_commits)} commits procesados...')
        diff = _get_commit_diff(repo_path, commit['hash'])
        events = _extract_events_from_diff(diff, commit)
        all_events.extend(events)

    if verbose:
        intro = sum(1 for e in all_events if e.event_type == 'introduced')
        fixed = sum(1 for e in all_events if e.event_type == 'fixed')
        print(
            f'\033[94m[AuditLens Archaeology]\033[0m '
            f'{len(all_events)} eventos: {intro} introducciones, {fixed} fixes'
        )

    # 3. Pair into lifecycles
    lifecycles = _pair_lifecycles(all_events)

    # 4. Developer profiles
    profiles = _build_developer_profiles(lifecycles, all_commits)

    # 5. File predictions
    predictions = _predict_file_risk(repo_path, lifecycles, profiles, all_commits[:100])

    # 6. Risk timeline
    timeline = _build_risk_timeline(lifecycles)

    # 7. Stats
    open_vulns = [lc for lc in lifecycles if lc.is_open()]
    fixed_vulns = [lc for lc in lifecycles if not lc.is_open()]
    avg_lifetime = (
        sum(lc.lifetime_days for lc in fixed_vulns if lc.lifetime_days is not None)
        / max(len(fixed_vulns), 1)
    )

    sev_counts: Dict[str, int] = defaultdict(int)
    for lc in lifecycles:
        sev_counts[lc.severity] += 1

    stats = {
        'total_commits_analyzed': len(all_commits),
        'total_vuln_events': len(all_events),
        'total_lifecycles': len(lifecycles),
        'open_vulnerabilities': len(open_vulns),
        'fixed_vulnerabilities': len(fixed_vulns),
        'avg_lifetime_days': round(avg_lifetime, 1),
        'severity_counts': dict(sev_counts),
        'unique_files_affected': len({lc.file_path for lc in lifecycles}),
        'unique_developers': len(profiles),
        'high_risk_developers': sum(
            1 for p in profiles.values() if p.risk_score >= 50
        ),
    }

    if verbose:
        _print_summary(lifecycles, profiles, predictions, stats)

    return {
        'lifecycles': [_lifecycle_to_dict(lc) for lc in lifecycles],
        'developer_profiles': [_profile_to_dict(p) for p in profiles.values()],
        'predictions': [_prediction_to_dict(p) for p in predictions[:20]],
        'risk_timeline': timeline,
        'stats': stats,
    }


# ── Serialization helpers ─────────────────────────────────────────────────────

def _lifecycle_to_dict(lc: VulnLifecycle) -> dict:
    return {
        'vuln_id': lc.vuln_id(),
        'rule_id': lc.rule_id,
        'rule_name': lc.rule_name,
        'severity': lc.severity,
        'file_path': lc.file_path,
        'status': 'open' if lc.is_open() else 'fixed',
        'lifetime_days': lc.lifetime_days,
        'introduced': {
            'commit': lc.intro_event.commit_hash[:8],
            'author': lc.intro_event.author_name,
            'date': lc.intro_event.commit_date,
            'message': lc.intro_event.commit_msg,
            'snippet': lc.intro_event.line_snippet,
            'day_of_week': lc.intro_event.day_of_week,
            'hour': lc.intro_event.hour_of_day,
        },
        'fixed': {
            'commit': lc.fix_event.commit_hash[:8],
            'author': lc.fix_event.author_name,
            'date': lc.fix_event.commit_date,
            'message': lc.fix_event.commit_msg,
        } if lc.fix_event else None,
    }


def _profile_to_dict(p: DeveloperProfile) -> dict:
    return {
        'name': p.name,
        'email': p.email,
        'total_commits': p.total_commits,
        'vuln_introductions': p.vuln_introductions,
        'vuln_fixes': p.vuln_fixes,
        'avg_lifetime_days': round(p.avg_lifetime_days, 1),
        'introduction_rate': round(p.introduction_rate(), 3),
        'risk_score': p.risk_score,
        'top_risky_hour': p.top_risky_hour(),
        'top_risky_day': p.top_risky_day(),
        'severity_breakdown': p.severity_breakdown,
        'vuln_files_count': len(p.vuln_files),
    }


def _prediction_to_dict(p: FilePrediction) -> dict:
    return {
        'file_path': p.file_path,
        'risk_probability': p.risk_probability,
        'risk_score': p.risk_score,
        'contributing_factors': p.contributing_factors,
        'last_touched_by': p.last_touched_by,
        'days_since_last_vuln': p.days_since_last_vuln,
        'historical_vuln_count': p.historical_vuln_count,
        'predicted_rule_ids': p.predicted_rule_ids,
    }


# ── Terminal printer ──────────────────────────────────────────────────────────

def _print_summary(
    lifecycles: List[VulnLifecycle],
    profiles: Dict[str, DeveloperProfile],
    predictions: List[FilePrediction],
    stats: Dict,
) -> None:
    C = {
        'RED': '\033[91m', 'YELLOW': '\033[93m', 'CYAN': '\033[94m',
        'GREEN': '\033[92m', 'GRAY': '\033[90m', 'BOLD': '\033[1m',
        'RESET': '\033[0m',
    }
    _DAYS = ['Lunes', 'Martes', 'Miércoles', 'Jueves', 'Viernes', 'Sábado', 'Domingo']
    _SEV_COLOR = {
        'CRITICAL': C['RED'], 'HIGH': C['YELLOW'],
        'MEDIUM': C['CYAN'], 'LOW': C['GREEN'],
    }

    print(f'\n{C["BOLD"]}{"=" * 60}')
    print(f' TEMPORAL VULNERABILITY ARCHAEOLOGY')
    print(f'{"=" * 60}{C["RESET"]}')
    print(f'  Commits analizados:        {stats["total_commits_analyzed"]}')
    print(f'  Vulnerabilidades abiertas: {C["RED"]}{stats["open_vulnerabilities"]}{C["RESET"]}')
    print(f'  Vulnerabilidades fijadas:  {C["GREEN"]}{stats["fixed_vulnerabilities"]}{C["RESET"]}')
    print(f'  Vida promedio:             {C["YELLOW"]}{stats["avg_lifetime_days"]} días{C["RESET"]}')
    print(f'  Archivos afectados:        {stats["unique_files_affected"]}')

    # Severity breakdown
    print(f'\n{C["BOLD"]}Por severidad:{C["RESET"]}')
    for sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
        n = stats["severity_counts"].get(sev, 0)
        if n:
            bar = '█' * min(n * 2, 30)
            color = _SEV_COLOR.get(sev, '')
            print(f'  {color}{sev:8}{C["RESET"]} {bar} {n}')

    # Top open vulnerabilities
    open_vulns = sorted(
        [lc for lc in lifecycles if lc.is_open()],
        key=lambda x: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}.get(x.severity, 4),
    )[:8]
    if open_vulns:
        print(f'\n{C["BOLD"]}Vulnerabilidades abiertas más críticas:{C["RESET"]}')
        for lc in open_vulns:
            sev_color = _SEV_COLOR.get(lc.severity, '')
            age = ''
            try:
                import datetime
                d = datetime.datetime.strptime(lc.intro_event.commit_date, '%Y-%m-%d').date()
                days = (datetime.date.today() - d).days
                age = f'{C["YELLOW"]}{days}d abierta{C["RESET"]}'
            except Exception:
                pass
            print(
                f'  {sev_color}[{lc.severity}]{C["RESET"]} '
                f'{lc.rule_name:35} '
                f'{C["GRAY"]}{lc.file_path.split("/")[-1]}:{C["RESET"]} '
                f'{lc.intro_event.author_name} · {age}'
            )
            print(f'    {C["GRAY"]}snippet: {lc.intro_event.line_snippet[:80]}{C["RESET"]}')

    # Developer profiles
    risky_devs = sorted(
        profiles.values(),
        key=lambda p: p.risk_score,
        reverse=True,
    )[:5]
    if risky_devs and any(p.vuln_introductions > 0 for p in risky_devs):
        print(f'\n{C["BOLD"]}Perfiles de desarrolladores:{C["RESET"]}')
        print(f'  {"Nombre":<25} {"Commits":>7} {"Vulns":>6} {"Risk":>5} {"Patrón temporal"}')
        print(f'  {"-"*70}')
        for p in risky_devs:
            if p.vuln_introductions == 0:
                continue
            risk_color = C['RED'] if p.risk_score >= 50 else C['YELLOW'] if p.risk_score >= 25 else C['GREEN']
            day_str = p.top_risky_day() or 'N/A'
            hour = p.top_risky_hour()
            hour_str = f'{hour:02d}:00' if hour is not None else 'N/A'
            print(
                f'  {p.name[:24]:<25} {p.total_commits:>7} '
                f'{p.vuln_introductions:>6} '
                f'{risk_color}{p.risk_score:>4.0f}%{C["RESET"]} '
                f'{day_str} a las {hour_str}'
            )

    # Predictions
    top_preds = [p for p in predictions[:5] if p.risk_probability > 0.2]
    if top_preds:
        print(f'\n{C["BOLD"]}Archivos con mayor probabilidad de vulnerabilidad futura:{C["RESET"]}')
        for pred in top_preds:
            bar_len = int(pred.risk_probability * 20)
            bar = '█' * bar_len + '░' * (20 - bar_len)
            color = C['RED'] if pred.risk_probability > 0.7 else C['YELLOW'] if pred.risk_probability > 0.4 else C['CYAN']
            print(
                f'\n  {color}{pred.file_path.split("/")[-1]}{C["RESET"]} '
                f'[{bar}] {pred.risk_probability * 100:.0f}%'
            )
            for factor in pred.contributing_factors[:2]:
                print(f'    {C["GRAY"]}• {factor}{C["RESET"]}')
