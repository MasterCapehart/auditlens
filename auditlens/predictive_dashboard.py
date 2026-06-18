"""
Predictive Dashboard - Trend forecasting and risk predictions.

Analyzes historical scan data to predict future vulnerability trends,
estimate fix time, and forecast security debt growth.
"""

from __future__ import annotations
from typing import List, Dict, Any
from datetime import datetime, timedelta
import statistics


def predict_trends(history: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyze historical scan data and predict future trends.

    Args:
        history: List of scan records with severity counts and timestamps

    Returns:
        Predictions for next 7, 30, 90 days
    """
    if len(history) < 2:
        return {
            "status": "insufficient_data",
            "message": "Need at least 2 historical scans for predictions",
            "predictions": [],
        }

    # Sort by date
    sorted_history = sorted(history, key=lambda x: x.get("scanned_at", ""))

    # Calculate growth rates
    critical_values = [h.get("critical", 0) for h in sorted_history]
    high_values = [h.get("high", 0) for h in sorted_history]
    medium_values = [h.get("medium", 0) for h in sorted_history]
    low_values = [h.get("low", 0) for h in sorted_history]

    # Simple linear regression slope
    def calculate_trend(values):
        if len(values) < 2:
            return 0.0
        n = len(values)
        x = list(range(n))
        x_mean = statistics.mean(x)
        y_mean = statistics.mean(values)

        numerator = sum((x[i] - x_mean) * (values[i] - y_mean) for i in range(n))
        denominator = sum((x[i] - x_mean) ** 2 for i in range(n))

        return numerator / denominator if denominator != 0 else 0.0

    critical_trend = calculate_trend(critical_values)
    high_trend = calculate_trend(high_values)
    medium_trend = calculate_trend(medium_values)
    low_trend = calculate_trend(low_values)

    # Forecast future values
    latest_critical = critical_values[-1]
    latest_high = high_values[-1]
    latest_medium = medium_values[-1]
    latest_low = low_values[-1]

    # Predictions for 7, 30, 90 days
    predictions = []
    for days in [7, 30, 90]:
        # Assume 1 scan per week, so days/7 future scans
        future_scans = max(1, days // 7)

        pred_critical = max(0, int(latest_critical + critical_trend * future_scans))
        pred_high = max(0, int(latest_high + high_trend * future_scans))
        pred_medium = max(0, int(latest_medium + medium_trend * future_scans))
        pred_low = max(0, int(latest_low + low_trend * future_scans))

        total = pred_critical + pred_high + pred_medium + pred_low

        # Risk level
        if pred_critical > 10 or total > 100:
            risk_level = "HIGH"
        elif pred_critical > 5 or total > 50:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        predictions.append({
            "days_ahead": days,
            "predicted_date": (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d"),
            "critical": pred_critical,
            "high": pred_high,
            "medium": pred_medium,
            "low": pred_low,
            "total": total,
            "risk_level": risk_level,
        })

    # Calculate technical debt growth
    total_current = latest_critical + latest_high + latest_medium + latest_low
    total_90d = predictions[-1]["total"] if predictions else total_current
    debt_growth_pct = round(((total_90d - total_current) / total_current * 100), 1) if total_current > 0 else 0

    return {
        "status": "success",
        "current_state": {
            "critical": latest_critical,
            "high": latest_high,
            "medium": latest_medium,
            "low": latest_low,
            "total": total_current,
        },
        "trends": {
            "critical_trend": round(critical_trend, 2),
            "high_trend": round(high_trend, 2),
            "medium_trend": round(medium_trend, 2),
            "low_trend": round(low_trend, 2),
            "overall_trend": "INCREASING" if (critical_trend + high_trend) > 0 else "STABLE" if (critical_trend + high_trend) == 0 else "DECREASING",
        },
        "predictions": predictions,
        "debt_analysis": {
            "current_debt": total_current,
            "projected_debt_90d": total_90d,
            "growth_percentage": debt_growth_pct,
            "recommended_action": "URGENT" if debt_growth_pct > 50 else "MONITOR" if debt_growth_pct > 20 else "MAINTAIN",
        },
    }


def estimate_fix_time(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Estimate time to fix all findings based on severity and complexity.

    Assumptions:
    - CRITICAL: 4 hours avg
    - HIGH: 2 hours avg
    - MEDIUM: 1 hour avg
    - LOW: 0.5 hours avg
    """
    severity_time = {
        "CRITICAL": 4.0,
        "HIGH": 2.0,
        "MEDIUM": 1.0,
        "LOW": 0.5,
    }

    total_hours = 0.0
    severity_breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for f in findings:
        sev = f.get("severity", "LOW")
        hours = severity_time.get(sev, 0.5)
        total_hours += hours
        severity_breakdown[sev] += hours

    # Convert to person-days (8-hour workday)
    total_days = round(total_hours / 8, 1)

    return {
        "total_findings": len(findings),
        "estimated_hours": round(total_hours, 1),
        "estimated_days": total_days,
        "estimated_weeks": round(total_days / 5, 1),
        "severity_breakdown_hours": {k: round(v, 1) for k, v in severity_breakdown.items()},
    }
