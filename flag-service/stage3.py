def validate_bailiwick_evidence(payload):
    return {
        "status_code": 501,
        "verdict": "not_implemented",
        "stage": "stage3",
        "flag": "3A",
        "expected_evidence": [
            "attacker_zone",
            "authority_section",
            "additional_section",
            "poisoned_delegation",
        ],
        "received_keys": sorted(payload.keys()),
    }


def validate_normalization_evidence(payload):
    return {
        "status_code": 501,
        "verdict": "not_implemented",
        "stage": "stage3",
        "flag": "3B",
        "expected_evidence": [
            "case_sensitivity_case",
            "separator_dot_case",
            "trailing_dot_case",
            "analysis",
        ],
        "received_keys": sorted(payload.keys()),
    }

