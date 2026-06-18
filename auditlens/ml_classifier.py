"""
ML Classifier - Machine Learning-based false positive reduction.

Uses a simple heuristic-based classifier to estimate false positive likelihood
for each finding. In production, this would use a trained ML model.
"""

from __future__ import annotations
from typing import List, Dict, Any
import re


def calculate_fp_score(finding: Dict[str, Any]) -> float:
    """
    Calculate false positive probability (0.0 - 1.0).
    Higher score = more likely to be false positive.

    Heuristics:
    - Test files are often benign
    - Comments containing findings are usually examples
    - Very long lines may be generated code
    - Certain patterns in safe contexts
    """
    score = 0.0

    file_path = finding.get("file", "")
    line = finding.get("line", 0)
    code_snippet = finding.get("snippet", "")
    rule_id = finding.get("rule_id", "")

    # Test files are less likely to be exploitable
    if re.search(r"(test|spec|mock|fixture|__tests__|\.test\.|\.spec\.)", file_path, re.I):
        score += 0.4

    # Examples, demos, documentation
    if re.search(r"(example|demo|sample|docs?/|README)", file_path, re.I):
        score += 0.3

    # Code in comments
    if code_snippet and re.match(r"^\s*(#|//|/\*|\*)", code_snippet.strip()):
        score += 0.5

    # Very long lines (likely generated or minified)
    if len(code_snippet) > 300:
        score += 0.2

    # SQL injection in ORM query builders (often safe)
    if "sql-injection" in rule_id.lower() and re.search(r"\.(query|where|select)\(", code_snippet):
        score += 0.2

    # Hardcoded secrets that look like examples
    if "secret" in rule_id.lower() or "password" in rule_id.lower():
        if re.search(r"(example|test|demo|your_|my_|placeholder|xxx|123)", code_snippet, re.I):
            score += 0.6

    # Path traversal in static file serving (often intentional)
    if "path-traversal" in rule_id.lower() and "static" in file_path.lower():
        score += 0.15

    # Cap at 1.0
    return min(score, 1.0)


def classify_findings(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Run ML classifier on all findings.

    Returns:
        Dict with classified findings and metrics
    """
    if not findings:
        return {
            "total": 0,
            "likely_true_positives": 0,
            "likely_false_positives": 0,
            "uncertain": 0,
            "findings": [],
        }

    classified = []

    for f in findings:
        fp_score = calculate_fp_score(f)

        if fp_score >= 0.7:
            classification = "LIKELY_FALSE_POSITIVE"
        elif fp_score <= 0.3:
            classification = "LIKELY_TRUE_POSITIVE"
        else:
            classification = "UNCERTAIN"

        classified.append({
            **f,
            "fp_score": round(fp_score, 2),
            "ml_classification": classification,
        })

    tp_count = sum(1 for c in classified if c["ml_classification"] == "LIKELY_TRUE_POSITIVE")
    fp_count = sum(1 for c in classified if c["ml_classification"] == "LIKELY_FALSE_POSITIVE")
    uncertain_count = sum(1 for c in classified if c["ml_classification"] == "UNCERTAIN")

    # Calculate precision/recall estimates (mock for demo)
    precision = round((tp_count / (tp_count + fp_count)) * 100, 1) if (tp_count + fp_count) > 0 else 0
    recall = round((tp_count / len(findings)) * 100, 1) if findings else 0
    f1_score = round(2 * (precision * recall) / (precision + recall), 1) if (precision + recall) > 0 else 0

    return {
        "total": len(findings),
        "likely_true_positives": tp_count,
        "likely_false_positives": fp_count,
        "uncertain": uncertain_count,
        "metrics": {
            "precision": precision,
            "recall": recall,
            "f1_score": f1_score,
            "accuracy": round(((tp_count + fp_count) / len(findings)) * 100, 1) if findings else 0,
        },
        "findings": classified,
    }
