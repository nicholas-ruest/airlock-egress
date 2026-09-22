from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .model import Contract, ContractError, parse_timestamp


@dataclass
class Simulation:
    decisions: list[dict[str, Any]]
    allowed: int
    denied: int
    allowed_bytes: int
    trace_digest: str

    def receipt(self, contract: Contract) -> dict[str, Any]:
        return {
            "schema": "airlock-egress-receipt/v1",
            "contract_digest": contract.digest,
            "trace_digest": self.trace_digest,
            "allowed": self.allowed,
            "denied": self.denied,
            "allowed_bytes": self.allowed_bytes,
            "decisions": self.decisions,
        }


def load_trace(path: str | Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ContractError(f"cannot read trace: {exc}") from exc
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ContractError(
                f"trace line {line_number} is not valid JSON: {exc}"
            ) from exc
        if not isinstance(event, dict):
            raise ContractError(f"trace line {line_number} must be an object")
        events.append(event)
    return events


def simulate(contract: Contract, events: Iterable[dict[str, Any]]) -> Simulation:
    event_list = list(events)
    canonical = "\n".join(
        json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        for event in event_list
    ).encode()
    trace_digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
    decisions: list[dict[str, Any]] = []
    allowed = 0
    denied = 0
    allowed_bytes = 0

    for index, event in enumerate(event_list):
        url = event.get("url")
        method = event.get("method", "GET")
        byte_count = event.get("bytes", 0)
        if not isinstance(url, str) or not url:
            raise ContractError(f"trace event {index} requires a non-empty url")
        if not isinstance(method, str) or not method:
            raise ContractError(
                f"trace event {index} method must be a non-empty string"
            )
        if (
            isinstance(byte_count, bool)
            or not isinstance(byte_count, int)
            or byte_count < 0
        ):
            raise ContractError(
                f"trace event {index} bytes must be a non-negative integer"
            )
        at = (
            parse_timestamp(event["at"], f"trace event {index}.at")
            if "at" in event
            else datetime.now(UTC)
        )
        is_allowed, reason, rule = contract.match(url, method, at)
        if is_allowed and allowed + 1 > contract.limits.max_requests:
            is_allowed, reason = False, "request_budget_exceeded"
        if is_allowed and allowed_bytes + byte_count > contract.limits.max_bytes:
            is_allowed, reason = False, "byte_budget_exceeded"
        if is_allowed:
            allowed += 1
            allowed_bytes += byte_count
        else:
            denied += 1
        decisions.append(
            {
                "index": index,
                "allowed": is_allowed,
                "reason": reason,
                "rule": rule,
                "bytes": byte_count,
            }
        )
    return Simulation(decisions, allowed, denied, allowed_bytes, trace_digest)
