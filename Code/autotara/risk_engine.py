"""Deterministic Risk Scoring Engine for AutoTARA AI.

Calculates Risk Score = Impact (1-5) x Attack Feasibility (1-5),
maps score to educational prototype risk bands:
- Low: 1 - 5
- Medium: 6 - 12
- High: 13 - 19
- Critical: 20 - 25

Enforces strict input validation on scale boundaries.
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional, Union

RISK_BANDS = [
    {"range": (1, 5), "label": "Low", "color": "#4caf50"},
    {"range": (6, 12), "label": "Medium", "color": "#ff9800"},
    {"range": (13, 19), "label": "High", "color": "#f44336"},
    {"range": (20, 25), "label": "Critical", "color": "#9c27b0"},
]

IMPACT_LABELS = {
    1: "Negligible",
    2: "Minor",
    3: "Moderate",
    4: "Major",
    5: "Critical",
}

FEASIBILITY_LABELS = {
    1: "Very Low",
    2: "Low",
    3: "Moderate",
    4: "High",
    5: "Very High",
}


@dataclass
class RiskAssessment:
    impact: int
    attack_feasibility: int
    score: int
    band: str
    color: str
    impact_label: str
    feasibility_label: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "impact": self.impact,
            "attack_feasibility": self.attack_feasibility,
            "score": self.score,
            "band": self.band,
            "color": self.color,
            "impact_label": self.impact_label,
            "feasibility_label": self.feasibility_label,
        }


class RiskEngine:
    """Deterministic risk evaluator mapping impact and feasibility to risk bands."""

    @staticmethod
    def _validate_level(value: Any, name: str) -> int:
        if value is None:
            raise ValueError(f"{name} cannot be None; must be an integer between 1 and 5.")
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(f"{name} must be an integer, got {type(value).__name__} ({value}).")
        if value < 1 or value > 5:
            raise ValueError(f"{name} must be between 1 and 5 (inclusive), got {value}.")
        return value

    @classmethod
    def calculate_risk(cls, impact: Any, attack_feasibility: Any) -> RiskAssessment:
        """Calculate deterministic risk score and map to corresponding band.

        Score = Impact x Attack Feasibility
        """
        imp = cls._validate_level(impact, "Impact")
        feas = cls._validate_level(attack_feasibility, "Attack Feasibility")

        score = imp * feas

        # Determine band
        band_info = None
        for b in RISK_BANDS:
            low, high = b["range"]
            if low <= score <= high:
                band_info = b
                break

        if not band_info:
            raise ValueError(f"Calculated score {score} does not fall into any configured risk band.")

        return RiskAssessment(
            impact=imp,
            attack_feasibility=feas,
            score=score,
            band=band_info["label"],
            color=band_info["color"],
            impact_label=IMPACT_LABELS[imp],
            feasibility_label=FEASIBILITY_LABELS[feas],
        )

    @classmethod
    def get_all_matrix_combinations(cls) -> Dict[str, Dict[str, Any]]:
        """Return all 25 impact x feasibility combinations and their calculated bands."""
        combos = {}
        for imp in range(1, 6):
            for feas in range(1, 6):
                key = f"{imp}x{feas}"
                assessment = cls.calculate_risk(imp, feas)
                combos[key] = assessment.to_dict()
        return combos
