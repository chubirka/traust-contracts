"""The OWASP Risk Rating Methodology's arithmetic, implemented once.

Source: OWASP Foundation, "OWASP Risk Rating Methodology",
https://owasp.org/www-community/OWASP_Risk_Rating_Methodology (CC BY-SA 4.0).
This module reimplements the method in original code and wording; it copies no
text from the source.

A rating scores twelve factors (eight for likelihood, four for impact) from 0
to 9. Each score is the mean of its factors. A score below 3 is low, below 6 is
medium, and otherwise high. Severity then combines the impact and likelihood
levels through the method's 3x3 severity table.

Only the factor scores are judgment. Everything this module derives from them
(scores, levels, severity) is fixed arithmetic, so the same factors always give
the same rating. Producers call `rate()` to build a rating, and validators call
`problems()` to reject one whose derived values do not follow from its factors.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

METHOD = "owasp-risk-rating"
SOURCE = "https://owasp.org/www-community/OWASP_Risk_Rating_Methodology"

#: Threat-agent factors, then vulnerability factors. Higher means more likely.
LIKELIHOOD_FACTORS = (
    "skill_level",
    "motive",
    "opportunity",
    "population_size",
    "ease_of_discovery",
    "ease_of_exploit",
    "awareness",
    "intrusion_detection",
)
TECHNICAL_IMPACT_FACTORS = ("confidentiality", "integrity", "availability", "accountability")
BUSINESS_IMPACT_FACTORS = ("financial", "reputation", "non_compliance", "privacy")

LEVELS = ("low", "medium", "high")
SEVERITIES = ("note", "low", "medium", "high", "critical")

#: (impact level, likelihood level) -> severity.
SEVERITY_TABLE: Mapping[tuple[str, str], str] = {
    ("high", "low"): "medium",
    ("high", "medium"): "high",
    ("high", "high"): "critical",
    ("medium", "low"): "low",
    ("medium", "medium"): "medium",
    ("medium", "high"): "high",
    ("low", "low"): "note",
    ("low", "medium"): "low",
    ("low", "high"): "medium",
}

_PRECISION = 3


def level(score: float) -> str:
    """low below 3, medium below 6, otherwise high."""
    if score < 3:
        return "low"
    if score < 6:
        return "medium"
    return "high"


def severity(impact_level: str, likelihood_level: str) -> str:
    return SEVERITY_TABLE[(impact_level, likelihood_level)]


def severity_rank(value: str | None) -> int:
    """Position in SEVERITIES (note=0 .. critical=4); -1 for a missing value."""
    return SEVERITIES.index(value) if value in SEVERITIES else -1


def _factor_problems(where: str, factors: Any, names: tuple[str, ...]) -> list[str]:
    if not isinstance(factors, Mapping):
        return [f"{where}: factors must be an object"]
    out = []
    missing = [n for n in names if n not in factors]
    extra = sorted(set(factors) - set(names))
    if missing or extra:
        out.append(f"{where}: missing factors {missing}, unknown factors {extra}")
    for name in names:
        value = factors.get(name)
        if name in factors and (
            isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 9
        ):
            out.append(f"{where}.{name}: must be an integer from 0 to 9, got {value!r}")
    return out


def _mean(factors: Mapping[str, int], names: tuple[str, ...]) -> float:
    return sum(factors[n] for n in names) / len(names)


def rate(
    likelihood: Mapping[str, int],
    technical: Mapping[str, int],
    business: Mapping[str, int] | None = None,
    *,
    basis: str | None = None,
    rationale: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Build a schema-conformant risk_rating from factor scores.

    The impact basis defaults to business when business factors are given (the
    method prefers business impact when it is known), and technical otherwise.
    """
    basis = basis or ("business" if business is not None else "technical")
    found = _factor_problems("likelihood", likelihood, LIKELIHOOD_FACTORS)
    found += _factor_problems("impact.technical", technical, TECHNICAL_IMPACT_FACTORS)
    if business is not None:
        found += _factor_problems("impact.business", business, BUSINESS_IMPACT_FACTORS)
    if basis not in ("technical", "business") or (basis == "business" and business is None):
        found.append(f"impact.basis {basis!r} needs its factor set")
    if found:
        raise ValueError("; ".join(found))

    l_mean = _mean(likelihood, LIKELIHOOD_FACTORS)
    i_mean = (
        _mean(business, BUSINESS_IMPACT_FACTORS)
        if basis == "business"
        else _mean(technical, TECHNICAL_IMPACT_FACTORS)
    )
    impact: dict[str, Any] = {
        "basis": basis,
        "technical": dict(technical),
        "score": round(i_mean, _PRECISION),
        "level": level(i_mean),
    }
    if business is not None:
        impact["business"] = dict(business)
    rating: dict[str, Any] = {
        "method": METHOD,
        "likelihood": {
            "factors": dict(likelihood),
            "score": round(l_mean, _PRECISION),
            "level": level(l_mean),
        },
        "impact": impact,
        "severity": severity(impact["level"], level(l_mean)),
    }
    if rationale:
        rating["rationale"] = dict(rationale)
    return rating


def problems(rating: Any) -> list[str]:
    """Every way a stored rating's derived values disagree with its factors."""
    if not isinstance(rating, Mapping):
        return ["risk_rating must be an object"]
    if rating.get("method") != METHOD:
        return [f"risk_rating.method must be {METHOD!r}"]
    likelihood = rating.get("likelihood") or {}
    impact = rating.get("impact") or {}
    business = impact.get("business")
    try:
        expected = rate(
            likelihood.get("factors") or {},
            impact.get("technical") or {},
            business,
            basis=impact.get("basis"),
        )
    except ValueError as err:
        return [f"risk_rating: {err}"]
    out = []
    for part in ("likelihood", "impact"):
        stored, want = rating.get(part) or {}, expected[part]
        score = stored.get("score")
        if not isinstance(score, (int, float)) or abs(score - want["score"]) > 10**-_PRECISION:
            out.append(f"risk_rating.{part}.score is {score!r}; its factors give {want['score']}")
        if stored.get("level") != want["level"]:
            out.append(
                f"risk_rating.{part}.level is {stored.get('level')!r}; "
                f"its factors give {want['level']!r}"
            )
    if rating.get("severity") != expected["severity"]:
        out.append(
            f"risk_rating.severity is {rating.get('severity')!r}; "
            f"its levels give {expected['severity']!r}"
        )
    return out
