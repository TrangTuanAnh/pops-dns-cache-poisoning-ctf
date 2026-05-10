"""Validators cho Stage 1.

Flag 1A (DNSpooq reproduction) được award qua passive query loop trong app.py
khi resolver trả IP attacker; KHÔNG validate qua endpoint POST.

Flag 1B (window-edge evaluation) validate qua POST /api/v1/stage1/window-evidence:
  - Evidence phải có hai experiment: within_window và across_window.
  - Mỗi experiment có timestamps, packets_sent, truncated/forwarded counter.
  - across_window phải có forwarded_count > within_window forwarded_count.
  - Timestamps phải trải đúng pattern (within: span < W; across: span > W).
  - Analysis text >= 80 ký tự, mention footnote 12 hoặc CMS reset.
"""
from __future__ import annotations


WINDOW_SECONDS = 1.0


def _check_experiment_shape(exp: dict, name: str) -> list[str]:
    errors: list[str] = []
    required = (
        "experiment",
        "send_timestamps",
        "truncated_responses",
        "forwarded_responses",
    )
    for k in required:
        if k not in exp:
            errors.append(f"{name}.{k} missing")
    if not errors:
        ts = exp.get("send_timestamps") or []
        if not isinstance(ts, list) or len(ts) < 5:
            errors.append(f"{name}.send_timestamps phai la list >= 5 phan tu")
    return errors


def _ts_span(ts: list[float]) -> float:
    if len(ts) < 2:
        return 0.0
    return float(max(ts)) - float(min(ts))


def validate_window_evidence(payload: dict) -> dict:
    errors: list[str] = []

    within = payload.get("within_window") or {}
    across = payload.get("across_window") or {}
    if not within:
        errors.append("within_window missing")
    if not across:
        errors.append("across_window missing")

    if not errors:
        errors.extend(_check_experiment_shape(within, "within_window"))
        errors.extend(_check_experiment_shape(across, "across_window"))

    analysis = str(payload.get("observation") or payload.get("analysis") or "")
    if len(analysis) < 80:
        errors.append("observation/analysis phai >= 80 ky tu, giai thich phenomenon")

    if errors:
        return {
            "status_code": 400,
            "verdict": "invalid",
            "flag": "1B",
            "errors": errors,
        }

    within_span = _ts_span(within.get("send_timestamps") or [])
    across_span = _ts_span(across.get("send_timestamps") or [])

    diagnostics = {
        "within_window_span_seconds": within_span,
        "across_window_span_seconds": across_span,
        "within_window_forwarded": within.get("forwarded_responses"),
        "across_window_forwarded": across.get("forwarded_responses"),
        "within_window_truncated": within.get("truncated_responses"),
        "across_window_truncated": across.get("truncated_responses"),
    }

    semantic_errors: list[str] = []
    if within_span >= WINDOW_SECONDS:
        semantic_errors.append(
            f"within_window span={within_span:.3f}s phai < W={WINDOW_SECONDS}s"
        )
    if across_span <= WINDOW_SECONDS:
        semantic_errors.append(
            f"across_window span={across_span:.3f}s phai > W={WINDOW_SECONDS}s"
        )
    forw_within = int(within.get("forwarded_responses") or 0)
    forw_across = int(across.get("forwarded_responses") or 0)
    if forw_across <= forw_within:
        semantic_errors.append(
            "across_window forwarded phai > within_window forwarded "
            "de demo CMS reset effect (footnote 12 paper POPS)."
        )

    keywords = ("footnote", "window", "cms", "reset")
    if not any(k in analysis.lower() for k in keywords):
        semantic_errors.append(
            "analysis can de cap footnote/window/CMS/reset de chung minh hieu phenomenon"
        )

    if semantic_errors:
        return {
            "status_code": 422,
            "verdict": "evidence_inconsistent",
            "flag": "1B",
            "errors": semantic_errors,
            "diagnostics": diagnostics,
        }

    return {
        "status_code": 200,
        "verdict": "accepted",
        "stage": "stage1",
        "award_flag_id": "1B",
        "diagnostics": diagnostics,
    }


# Flag 1A da bo khoi scope CTF. Stage 1 chi co flag 1B (window-edge).
