from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


class ContractError(ValueError):
    """Raised when an egress contract is malformed."""


_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_KUBERNETES_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _reject_unknown(value: dict[str, Any], allowed: set[str], field: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ContractError(f"unknown {field} fields: {', '.join(unknown)}")


def _require_object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{field} must be an object")
    return value


def _require_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{field} must be a non-empty string")
    return value.strip()


def _require_positive_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ContractError(f"{field} must be a positive integer")
    return value


def parse_timestamp(value: Any, field: str) -> datetime:
    text = _require_string(value, field)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ContractError(f"{field} must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ContractError(f"{field} must include a timezone")
    return parsed.astimezone(UTC)


@dataclass(frozen=True)
class Workload:
    name: str
    namespace: str
    service_account: str


@dataclass(frozen=True)
class Limits:
    max_requests: int
    max_bytes: int


@dataclass(frozen=True)
class Destination:
    host: str
    protocol: str
    ports: tuple[int, ...]
    methods: tuple[str, ...]
    path_prefixes: tuple[str, ...]

    def host_matches(self, candidate: str) -> bool:
        candidate = candidate.lower().rstrip(".")
        if self.host.startswith("*."):
            suffix = self.host[1:]
            return candidate.endswith(suffix) and candidate != self.host[2:]
        return candidate == self.host


@dataclass(frozen=True)
class Contract:
    version: int
    workload: Workload
    expires_at: datetime
    limits: Limits
    destinations: tuple[Destination, ...]
    raw: dict[str, Any]

    @property
    def digest(self) -> str:
        encoded = json.dumps(
            self.raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        return "sha256:" + hashlib.sha256(encoded).hexdigest()

    def match(
        self, url: str, method: str, at: datetime
    ) -> tuple[bool, str, int | None]:
        if at.astimezone(UTC) >= self.expires_at:
            return False, "contract_expired", None
        try:
            parsed = urlsplit(url)
            host = parsed.hostname
            port = parsed.port
        except ValueError:
            return False, "invalid_url", None
        if not host or parsed.scheme not in {"http", "https"}:
            return False, "unsupported_url", None
        if parsed.username or parsed.password:
            return False, "userinfo_forbidden", None
        port = port or (443 if parsed.scheme == "https" else 80)
        normalized_method = method.upper()
        path = parsed.path or "/"
        segments = path.split("/")
        if (
            "%" in path
            or "\\" in path
            or "//" in path
            or any(segment in {".", ".."} for segment in segments)
        ):
            return False, "ambiguous_path", None
        for index, rule in enumerate(self.destinations):
            if not rule.host_matches(host):
                continue
            if rule.protocol != parsed.scheme:
                continue
            if port not in rule.ports:
                continue
            if normalized_method not in rule.methods:
                continue
            if not any(path.startswith(prefix) for prefix in rule.path_prefixes):
                continue
            return True, "matched", index
        return False, "no_matching_destination", None


def load_contract(path: str | Path) -> Contract:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise ContractError(f"cannot read contract: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ContractError(f"contract is not valid JSON: {exc}") from exc
    return parse_contract(raw)


def parse_contract(value: Any) -> Contract:
    raw = _require_object(value, "contract")
    allowed_top = {"version", "workload", "expires_at", "limits", "destinations"}
    _reject_unknown(raw, allowed_top, "top-level")
    if raw.get("version") != 1:
        raise ContractError("version must be 1")

    workload_raw = _require_object(raw.get("workload"), "workload")
    _reject_unknown(workload_raw, {"name", "namespace", "service_account"}, "workload")
    workload = Workload(
        name=_require_string(workload_raw.get("name"), "workload.name"),
        namespace=_require_string(workload_raw.get("namespace"), "workload.namespace"),
        service_account=_require_string(
            workload_raw.get("service_account"), "workload.service_account"
        ),
    )
    for field, item in (
        ("workload.name", workload.name),
        ("workload.namespace", workload.namespace),
        ("workload.service_account", workload.service_account),
    ):
        if not _KUBERNETES_NAME.fullmatch(item):
            raise ContractError(f"{field} must be a Kubernetes DNS label")

    limits_raw = _require_object(raw.get("limits"), "limits")
    _reject_unknown(limits_raw, {"max_requests", "max_bytes"}, "limits")
    limits = Limits(
        max_requests=_require_positive_int(
            limits_raw.get("max_requests"), "limits.max_requests"
        ),
        max_bytes=_require_positive_int(
            limits_raw.get("max_bytes"), "limits.max_bytes"
        ),
    )

    destinations_raw = raw.get("destinations")
    if not isinstance(destinations_raw, list) or not destinations_raw:
        raise ContractError("destinations must be a non-empty array")
    destinations: list[Destination] = []
    for index, item in enumerate(destinations_raw):
        prefix = f"destinations[{index}]"
        entry = _require_object(item, prefix)
        _reject_unknown(
            entry,
            {"host", "protocol", "ports", "methods", "path_prefixes"},
            prefix,
        )
        host = _require_string(entry.get("host"), f"{prefix}.host").lower().rstrip(".")
        if (
            host == "*"
            or "*" in host[2:]
            or ("*" in host and not host.startswith("*."))
        ):
            raise ContractError(f"{prefix}.host may only use one leading '*.' wildcard")
        if (
            ".." in host
            or "." not in host
            or any(part == "" for part in host.split("."))
        ):
            raise ContractError(f"{prefix}.host must be a fully qualified domain name")
        plain_host = host.removeprefix("*.")
        if len(plain_host) > 253 or not all(
            _DNS_LABEL.fullmatch(label) for label in plain_host.split(".")
        ):
            raise ContractError(f"{prefix}.host is not a valid ASCII domain name")
        protocol = _require_string(entry.get("protocol"), f"{prefix}.protocol").lower()
        if protocol not in {"http", "https"}:
            raise ContractError(f"{prefix}.protocol must be http or https")

        ports_raw = entry.get("ports")
        if not isinstance(ports_raw, list) or not ports_raw:
            raise ContractError(f"{prefix}.ports must be a non-empty array")
        ports = tuple(
            sorted(
                {_require_positive_int(port, f"{prefix}.ports") for port in ports_raw}
            )
        )
        if any(port > 65535 for port in ports):
            raise ContractError(f"{prefix}.ports contains a port above 65535")

        methods_raw = entry.get("methods")
        if not isinstance(methods_raw, list) or not methods_raw:
            raise ContractError(f"{prefix}.methods must be a non-empty array")
        methods = tuple(
            sorted(
                {_require_string(m, f"{prefix}.methods").upper() for m in methods_raw}
            )
        )
        supported_methods = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
        if not set(methods) <= supported_methods:
            raise ContractError(f"{prefix}.methods contains an unsupported HTTP method")

        paths_raw = entry.get("path_prefixes")
        if not isinstance(paths_raw, list) or not paths_raw:
            raise ContractError(f"{prefix}.path_prefixes must be a non-empty array")
        paths = tuple(
            sorted({_require_string(p, f"{prefix}.path_prefixes") for p in paths_raw})
        )
        if any(
            not path.startswith("/") or "?" in path or "#" in path for path in paths
        ):
            raise ContractError(
                f"{prefix}.path_prefixes entries must start with '/' and exclude query/fragment"
            )
        destinations.append(Destination(host, protocol, ports, methods, paths))

    return Contract(
        version=1,
        workload=workload,
        expires_at=parse_timestamp(raw.get("expires_at"), "expires_at"),
        limits=limits,
        destinations=tuple(destinations),
        raw=raw,
    )
