"""Validators cho Stage 3.

Flag 3A (CVE-2021-43105 SOoB reproduction) - award qua passive query loop khi
cache cua Technitium tra IP attacker.

Endpoint POST /api/v1/stage3/bailiwick-evidence cung available cho thuyet
minh chi tiet (optional, khong award flag).

Flag 3B (Algorithm 4 normalization concerns) validate qua POST
/api/v1/stage3/normalization-evidence:
  - test_results phai co >= 2 case ma naive_implementation_says khac
    correct_answer (chung minh implementation pitfall).
  - Cac case must cover >= 2 normalization concern: case sensitivity,
    separator dot, trailing dot, IDN.
  - analysis text >= 120 ky tu, dinh vi dung "implementation pitfall"
    chu khong phai "bug cua paper".
"""
from __future__ import annotations


# Flag 3A da bo khoi scope CTF. Stage 3 chi co flag 3B
# (Algorithm 4 normalization concerns).


_CONCERN_KEYWORDS = {
    "case_sensitivity": ("case", "uppercase", "lowercase", "mixed"),
    "separator_dot": ("separator", "dot", "suffix"),
    "trailing_dot": ("trailing", "fqdn"),
    "idn": ("idn", "punycode", "internationalized", "xn--"),
}


def _classify_concern(text: str) -> str | None:
    t = text.lower()
    for concern, kws in _CONCERN_KEYWORDS.items():
        if any(k in t for k in kws):
            return concern
    return None


def validate_normalization_evidence(payload: dict) -> dict:
    errors: list[str] = []

    cases = payload.get("test_results") or []
    if not isinstance(cases, list) or len(cases) < 2:
        errors.append("test_results phai la list >= 2 case")

    if not errors:
        # Each case must have minimal shape
        for i, c in enumerate(cases):
            if not isinstance(c, dict):
                errors.append(f"test_results[{i}] khong phai dict")
                continue
            for k in ("record_name", "query_name", "naive_implementation_says",
                      "correct_answer", "description"):
                if k not in c:
                    errors.append(f"test_results[{i}].{k} missing")

    if errors:
        return {
            "status_code": 400,
            "verdict": "invalid",
            "flag": "3B",
            "errors": errors,
        }

    differing_cases = [
        c for c in cases
        if c.get("naive_implementation_says") != c.get("correct_answer")
    ]
    if len(differing_cases) < 2:
        return {
            "status_code": 422,
            "verdict": "evidence_insufficient",
            "flag": "3B",
            "note": (
                "Can it nhat 2 case ma naive_implementation_says khac correct_answer "
                "de chung minh implementation pitfall."
            ),
            "differing_cases_found": len(differing_cases),
        }

    concerns_covered = set()
    for c in differing_cases:
        text = " ".join([
            str(c.get("record_name") or ""),
            str(c.get("query_name") or ""),
            str(c.get("description") or ""),
        ])
        cls = _classify_concern(text)
        if cls is not None:
            concerns_covered.add(cls)

    if len(concerns_covered) < 2:
        return {
            "status_code": 422,
            "verdict": "concerns_insufficient",
            "flag": "3B",
            "note": "Phai cover >= 2 normalization concern khac nhau.",
            "concerns_found": sorted(concerns_covered),
        }

    analysis = str(payload.get("analysis") or "")
    if len(analysis) < 120:
        return {
            "status_code": 422,
            "verdict": "analysis_too_short",
            "flag": "3B",
            "note": "analysis phai >= 120 ky tu.",
        }
    if "bug" in analysis.lower() and "paper" in analysis.lower():
        # Player nen dinh vi day la implementation pitfall, khong noi paper co bug.
        if "implementation" not in analysis.lower():
            return {
                "status_code": 422,
                "verdict": "framing_incorrect",
                "flag": "3B",
                "note": (
                    "Day la implementation pitfall (gap giua pseudo-code va "
                    "production code), khong phai bug cua paper. Vui long "
                    "viet lai analysis cho dung framing."
                ),
            }

    return {
        "status_code": 200,
        "verdict": "accepted",
        "stage": "stage3",
        "award_flag_id": "3B",
        "concerns_covered": sorted(concerns_covered),
        "differing_cases": len(differing_cases),
    }
