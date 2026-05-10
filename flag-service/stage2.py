"""Validators cho Stage 2.

Flag 2A (SFrag reproduction) - award qua passive query loop khi cache poisoned.
Endpoint POST /api/v1/stage2/fragmentation-evidence cung available cho team
muon submit thuyet minh chi tiet (optional, khong award flag - flag value
duoc gui qua passive loop).

Flag 2B (TCP fallback compatibility) validate qua POST
/api/v1/stage2/noncompliant-evidence:
  - compliant_resolver result va non_compliant_resolver result deu phai co.
  - compliant_resolver phai resolve thanh cong (ips_returned chua DEFAULT_IP)
    sau khi POPS triggered, vi resolver tuan thu retry TCP.
  - non_compliant_resolver phai cho ket qua KHAC: timeout, no_answer, hoac
    error - chung minh limitation cua POPS voi resolver khong RFC-compliant.
  - analysis text >= 100 ky tu, mention "TCP", "TC=1", "compliance" hoac "APNIC".
"""
from __future__ import annotations


# Flag 2A da bo khoi scope CTF. Stage 2 chi co flag 2B
# (TCP fallback compat).


def validate_noncompliant_evidence(payload: dict) -> dict:
    errors: list[str] = []

    compliant = payload.get("compliant_resolver") or {}
    non_compliant = payload.get("non_compliant_resolver") or {}
    if not compliant:
        errors.append("compliant_resolver missing")
    if not non_compliant:
        errors.append("non_compliant_resolver missing")

    if errors:
        return {
            "status_code": 400,
            "verdict": "invalid",
            "flag": "2B",
            "errors": errors,
        }

    compliant_resolution = str(compliant.get("resolution") or "").lower()
    non_compliant_resolution = str(non_compliant.get("resolution") or "").lower()

    semantic_errors: list[str] = []
    if compliant_resolution != "success":
        semantic_errors.append(
            "compliant_resolver phai resolution=success "
            "(POPS set TC=1 -> resolver retry TCP -> resolve dung)."
        )
    if non_compliant_resolution == "success" and non_compliant.get("is_legitimate", True):
        semantic_errors.append(
            "non_compliant_resolver khong nen resolution=success voi legit IP "
            "vi resolver khong retry TCP - day la limitation can document."
        )
    if non_compliant_resolution not in ("timeout", "no_answer", "error", "servfail"):
        semantic_errors.append(
            "non_compliant_resolver expected resolution in "
            "{timeout, no_answer, error, servfail}; got: " + non_compliant_resolution
        )

    analysis = str(payload.get("analysis") or "")
    if len(analysis) < 100:
        semantic_errors.append("analysis phai >= 100 ky tu mo ta phenomenon")
    keywords = ("tcp", "tc=1", "compliance", "apnic", "fallback", "retry")
    if not any(k in analysis.lower() for k in keywords):
        semantic_errors.append(
            "analysis can de cap TCP/TC=1/compliance/APNIC/fallback/retry"
        )

    if semantic_errors:
        return {
            "status_code": 422,
            "verdict": "evidence_inconsistent",
            "flag": "2B",
            "errors": semantic_errors,
        }

    return {
        "status_code": 200,
        "verdict": "accepted",
        "stage": "stage2",
        "award_flag_id": "2B",
    }
