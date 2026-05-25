"""Evidence checker for Bailiwick Breakout 2: Trust Boundary."""
from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request


log = logging.getLogger("checker")
logging.basicConfig(
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    level=logging.INFO,
)


REQUIRED_FIELDS = (
    "victim_domain",
    "malicious_ns",
    "malicious_ns_ip",
    "trigger_qname",
    "poison_packet_number",
    "poison_dns_txid",
    "first_cache_seen",
    "first_victim_query",
)


def _norm_name(value: Any) -> str:
    return str(value).strip().lower().rstrip(".")


def _norm_txid(value: Any) -> str:
    raw = str(value).strip().lower()
    if raw.startswith("0x"):
        return f"0x{int(raw, 16):04x}"
    return f"0x{int(raw):04x}"


def _solution_paths() -> list[Path]:
    paths: list[Path] = []
    if os.environ.get("EXPECTED_SOLUTION_FILE"):
        paths.append(Path(os.environ["EXPECTED_SOLUTION_FILE"]))
    paths.extend(
        [
            Path("/app/expected_solution.json"),
            Path(__file__).resolve().parent / "expected_solution.json",
            Path(__file__).resolve().parent.parent / "challenge" / "expected_solution.json",
        ]
    )
    return paths


def _load_expected() -> dict[str, Any] | None:
    if os.environ.get("EXPECTED_SOLUTION_JSON"):
        return json.loads(os.environ["EXPECTED_SOLUTION_JSON"])

    env_solution = {
        field: os.environ.get(field.upper())
        for field in REQUIRED_FIELDS
        if os.environ.get(field.upper()) is not None
    }
    if len(env_solution) == len(REQUIRED_FIELDS):
        env_solution["poison_packet_number"] = int(env_solution["poison_packet_number"])
        return env_solution

    for path in _solution_paths():
        if path.exists():
            with path.open(encoding="utf-8") as handle:
                return json.load(handle)
    return None


def _validate(body: dict[str, Any], expected: dict[str, Any]) -> tuple[bool, str]:
    missing = [field for field in REQUIRED_FIELDS if field not in body]
    if missing:
        return False, "missing_fields:" + ",".join(missing)

    name_fields = ("victim_domain", "malicious_ns", "trigger_qname")
    for field in name_fields:
        if _norm_name(body.get(field)) != _norm_name(expected.get(field)):
            return False, "Evidence does not match incident timeline"

    if str(body.get("malicious_ns_ip", "")).strip() != str(expected.get("malicious_ns_ip", "")).strip():
        return False, "Evidence does not match incident timeline"

    try:
        packet_number = int(body.get("poison_packet_number"))
    except (TypeError, ValueError):
        return False, "poison_packet_number must be an integer"
    if packet_number != int(expected.get("poison_packet_number")):
        return False, "Evidence does not match incident timeline"

    try:
        submitted_txid = _norm_txid(body.get("poison_dns_txid"))
        expected_txid = _norm_txid(expected.get("poison_dns_txid"))
    except (TypeError, ValueError):
        return False, "poison_dns_txid must be hex like 0x4a91"
    if submitted_txid != expected_txid:
        return False, "Evidence does not match incident timeline"

    for field in ("first_cache_seen", "first_victim_query"):
        if str(body.get(field, "")).strip() != str(expected.get(field, "")).strip():
            return False, "Evidence does not match incident timeline"

    return True, "Evidence accepted. The poisoned delegation chain is complete."


app = Flask(__name__)


@app.get("/")
def index() -> tuple[str, int]:
    return (
        "<h1>Bailiwick Breakout 2</h1>"
        "<p>POST /submit with the evidence JSON described in submit_format.md.</p>"
    ), 200


@app.get("/health")
def health():
    expected = _load_expected()
    return jsonify(
        {
            "ok": True,
            "service": "bailiwick-breakout-2-checker",
            "expected_loaded": expected is not None,
        }
    )


_RATE_LIMIT_WINDOW = 10.0
_RATE_LIMIT_MAX = 20
_attempts: dict[str, list[float]] = {}


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _client_ip() -> str:
    if _env_flag("TRUST_PROXY"):
        forwarded_for = request.headers.get("X-Forwarded-For", "")
        if forwarded_for:
            first_hop = forwarded_for.split(",", 1)[0].strip()
            if first_hop:
                return first_hop[:128]
    return (request.remote_addr or "?")[:128]


def _rate_limit_ok(ip: str) -> bool:
    now = time.monotonic()
    queue = _attempts.setdefault(ip, [])
    queue[:] = [t for t in queue if t > now - _RATE_LIMIT_WINDOW]
    if len(queue) >= _RATE_LIMIT_MAX:
        return False
    queue.append(now)
    return True


@app.post("/submit")
def submit():
    expected = _load_expected()
    if expected is None:
        return jsonify({"error": "expected_solution_not_configured"}), 503

    client_ip = _client_ip()
    if not _rate_limit_ok(client_ip):
        return jsonify({"error": "rate_limited", "retry_after_seconds": int(_RATE_LIMIT_WINDOW)}), 429

    if not request.is_json:
        return jsonify({"error": "expected_application_json"}), 415

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "expected_json_object"}), 400

    ok, message = _validate(body, expected)
    log.info("submit ip=%s ok=%s", client_ip, ok)
    if ok:
        return jsonify({"verdict": "valid", "message": message})
    status = 400 if message.startswith("missing_fields") or "must be" in message else 401
    return jsonify({"verdict": "invalid", "message": message}), status


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
