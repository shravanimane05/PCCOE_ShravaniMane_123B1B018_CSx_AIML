"""Pytest suite for AutoTARA AI deterministic Risk Engine.

Tests:
- All 25 impact x feasibility combinations (1..5 x 1..5)
- Boundary scores: 5 (Low) vs 6 (Medium)
- Boundary scores: 12 (Medium) vs 13 (High)
- Boundary scores: 19 (High) vs 20 (Critical)
- Invalid inputs: 0, 6, None, strings, floats, booleans
"""

import pytest
from autotara.risk_engine import RiskEngine, RiskAssessment


def test_all_25_risk_matrix_combinations():
    """Verify all 25 impact x feasibility combinations produce valid scores and bands."""
    combos = RiskEngine.get_all_matrix_combinations()
    assert len(combos) == 25

    for imp in range(1, 6):
        for feas in range(1, 6):
            key = f"{imp}x{feas}"
            assert key in combos
            data = combos[key]
            score = imp * feas
            assert data["score"] == score
            assert data["impact"] == imp
            assert data["attack_feasibility"] == feas

            if 1 <= score <= 5:
                assert data["band"] == "Low"
            elif 6 <= score <= 12:
                assert data["band"] == "Medium"
            elif 13 <= score <= 19:
                assert data["band"] == "High"
            elif 20 <= score <= 25:
                assert data["band"] == "Critical"


def test_boundary_score_5_and_6():
    """Verify exact boundary between Low (5) and Medium (6)."""
    # 5: Low (e.g. 5x1 or 1x5)
    r5 = RiskEngine.calculate_risk(5, 1)
    assert r5.score == 5
    assert r5.band == "Low"

    r5_alt = RiskEngine.calculate_risk(1, 5)
    assert r5_alt.score == 5
    assert r5_alt.band == "Low"

    # 6: Medium (e.g. 3x2 or 2x3)
    r6 = RiskEngine.calculate_risk(3, 2)
    assert r6.score == 6
    assert r6.band == "Medium"


def test_boundary_score_12_and_13():
    """Verify exact boundary between Medium (12) and High (13)."""
    # 12: Medium (e.g. 4x3 or 3x4)
    r12 = RiskEngine.calculate_risk(4, 3)
    assert r12.score == 12
    assert r12.band == "Medium"

    # 13: Not product of integers in 1..5, but let's test products bordering 12 and 15:
    # 15: High (e.g. 5x3 or 3x5)
    r15 = RiskEngine.calculate_risk(5, 3)
    assert r15.score == 15
    assert r15.band == "High"

    # 16: High (4x4)
    r16 = RiskEngine.calculate_risk(4, 4)
    assert r16.score == 16
    assert r16.band == "High"


def test_boundary_score_19_and_20():
    """Verify exact boundary between High (<=19) and Critical (20..25)."""
    # Highest high in discrete matrix is 16 (4x4) or 15 (5x3, 3x5)
    r16 = RiskEngine.calculate_risk(4, 4)
    assert r16.score == 16
    assert r16.band == "High"

    # 20: Critical (4x5 or 5x4)
    r20 = RiskEngine.calculate_risk(4, 5)
    assert r20.score == 20
    assert r20.band == "Critical"

    # 25: Critical (5x5)
    r25 = RiskEngine.calculate_risk(5, 5)
    assert r25.score == 25
    assert r25.band == "Critical"


def test_invalid_inputs_raise_value_error():
    """Verify invalid inputs (0, 6, -1, None, strings, floats, booleans) raise ValueError."""
    # Out of range integers
    with pytest.raises(ValueError, match="Impact must be between 1 and 5"):
        RiskEngine.calculate_risk(0, 3)

    with pytest.raises(ValueError, match="Impact must be between 1 and 5"):
        RiskEngine.calculate_risk(6, 3)

    with pytest.raises(ValueError, match="Attack Feasibility must be between 1 and 5"):
        RiskEngine.calculate_risk(3, 0)

    with pytest.raises(ValueError, match="Attack Feasibility must be between 1 and 5"):
        RiskEngine.calculate_risk(3, 6)

    # None
    with pytest.raises(ValueError, match="cannot be None"):
        RiskEngine.calculate_risk(None, 3)

    with pytest.raises(ValueError, match="cannot be None"):
        RiskEngine.calculate_risk(3, None)

    # Strings
    with pytest.raises(ValueError, match="must be an integer"):
        RiskEngine.calculate_risk("high", 3)

    with pytest.raises(ValueError, match="must be an integer"):
        RiskEngine.calculate_risk(3, "5")

    # Floats
    with pytest.raises(ValueError, match="must be an integer"):
        RiskEngine.calculate_risk(3.5, 3)

    # Booleans (since bool is subclass of int in python, must be rejected)
    with pytest.raises(ValueError, match="must be an integer"):
        RiskEngine.calculate_risk(True, 3)
