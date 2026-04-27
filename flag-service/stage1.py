def validate_reproduction(payload):
    return {
        "status_code": 501,
        "verdict": "not_implemented",
        "stage": "stage1",
        "flag": "1A",
        "expected_evidence": [
            "poisoned_target_domain",
            "resolver_cache_observation",
            "attack_attempt_summary",
        ],
        "received_keys": sorted(payload.keys()),
    }


def validate_window_evidence(payload):
    return {
        "status_code": 501,
        "verdict": "not_implemented",
        "stage": "stage1",
        "flag": "1B",
        "expected_evidence": [
            "timestamps",
            "pops_tau",
            "window_boundary_analysis",
        ],
        "received_keys": sorted(payload.keys()),
    }

