from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .model import ContractError, load_contract, parse_timestamp
from .policy import compile_cilium_policy
from .simulator import load_trace, simulate


def _write_json(value: Any, output: str | None = None) -> None:
    rendered = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if output:
        Path(output).write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="airlock-egress",
        description="Validate, simulate, and compile narrow egress contracts.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)

    validate = commands.add_parser("validate", help="validate a contract")
    validate.add_argument("contract")

    check = commands.add_parser("check", help="check one HTTP request")
    check.add_argument("contract")
    check.add_argument("url")
    check.add_argument("--method", default="GET")
    check.add_argument("--at", help="ISO 8601 decision time (default: now)")

    compile_command = commands.add_parser(
        "compile", help="compile the network-enforceable subset to Cilium JSON"
    )
    compile_command.add_argument("contract")
    compile_command.add_argument("--output", "-o")

    simulate_command = commands.add_parser(
        "simulate", help="evaluate a JSONL request trace and emit a receipt"
    )
    simulate_command.add_argument("contract")
    simulate_command.add_argument("trace")
    simulate_command.add_argument("--output", "-o")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        contract = load_contract(args.contract)
        if args.command == "validate":
            _write_json(
                {
                    "valid": True,
                    "contract_digest": contract.digest,
                    "destinations": len(contract.destinations),
                    "expires_at": contract.expires_at.isoformat().replace(
                        "+00:00", "Z"
                    ),
                }
            )
            return 0
        if args.command == "check":
            at = parse_timestamp(args.at, "--at") if args.at else datetime.now(UTC)
            allowed, reason, rule = contract.match(args.url, args.method, at)
            _write_json({"allowed": allowed, "reason": reason, "rule": rule})
            return 0 if allowed else 3
        if args.command == "compile":
            _write_json(compile_cilium_policy(contract), args.output)
            return 0
        simulation = simulate(contract, load_trace(args.trace))
        _write_json(simulation.receipt(contract), args.output)
        return 0 if simulation.denied == 0 else 4
    except ContractError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: cannot write output: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
