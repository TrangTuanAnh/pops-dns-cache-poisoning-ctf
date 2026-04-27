def validate_fragmentation_evidence(payload):
    return {
        "status_code": 501,
        "verdict": "not_implemented",
        "stage": "stage2",
        "flag": "2A",
        "expected_evidence": [
            "fragment_offsets",
            "poisoned_rrset",
            "resolver_observation",
        ],
        "received_keys": sorted(payload.keys()),
    }


def validate_noncompliant_evidence(payload):
    return {
        "status_code": 501,
        "verdict": "not_implemented",
        "stage": "stage2",
        "flag": "2B",
        "expected_evidence": [
            "tc_response_seen",
            "tcp_retry_absent",
            "resolver_profile",
        ],
        "received_keys": sorted(payload.keys()),
    }

