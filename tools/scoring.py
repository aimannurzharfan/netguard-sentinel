"""Composite risk scoring: CVSS + EPSS + CISA KEV -> 0-100.

Formula:
    score = 0.30 * (cvss / 10) + 0.50 * epss + 0.20 * kev_flag

    CVSS contributes 30% (severity baseline).
    EPSS contributes 50% (real-world exploit probability, the strongest signal).
    KEV contributes 20% (active exploitation confirmed by CISA).

A CVSS 9.8 with no known exploits scores ~29.
The same bug on CISA KEV with EPSS 0.97 scores ~91.
"""

from __future__ import annotations


def composite(cvss: float, epss: float, kev: bool) -> int:
    """Return a 0-100 risk score combining severity, exploit probability, and active exploitation."""
    kev_flag = 1.0 if kev else 0.0
    raw = 0.30 * (cvss / 10.0) + 0.50 * epss + 0.20 * kev_flag
    return round(min(max(raw, 0.0), 1.0) * 100)


def contextual_severity(score: int, kev: bool = False) -> str:
    """Map a composite score to a contextual severity label."""
    if kev or score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"
