from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from airlock_egress.model import ContractError, parse_contract
from airlock_egress.policy import compile_cilium_policy
from airlock_egress.simulator import simulate


def sample_contract(**overrides):
    value = {
        "version": 1,
        "workload": {
            "name": "runner",
            "namespace": "airlock",
            "service_account": "runner",
        },
        "expires_at": "2030-01-01T00:00:00Z",
        "limits": {"max_requests": 2, "max_bytes": 100},
        "destinations": [
            {
                "host": "*.example.com",
                "protocol": "https",
                "ports": [443],
                "methods": ["GET", "POST"],
                "path_prefixes": ["/v1/"],
            }
        ],
    }
    value.update(overrides)
    return parse_contract(value)


class ContractTests(unittest.TestCase):
    def test_matching_subdomain_is_allowed(self):
        contract = sample_contract()
        allowed, reason, rule = contract.match(
            "https://api.example.com/v1/items",
            "GET",
            datetime(2027, 1, 1, tzinfo=UTC),
        )
        self.assertTrue(allowed)
        self.assertEqual("matched", reason)
        self.assertEqual(0, rule)

    def test_wildcard_does_not_match_apex(self):
        contract = sample_contract()
        allowed, reason, _ = contract.match(
            "https://example.com/v1/items",
            "GET",
            datetime(2027, 1, 1, tzinfo=UTC),
        )
        self.assertFalse(allowed)
        self.assertEqual("no_matching_destination", reason)

    def test_expired_contract_fails_closed(self):
        contract = sample_contract(expires_at="2026-01-01T00:00:00Z")
        allowed, reason, _ = contract.match(
            "https://api.example.com/v1/items",
            "GET",
            datetime(2027, 1, 1, tzinfo=UTC),
        )
        self.assertFalse(allowed)
        self.assertEqual("contract_expired", reason)

    def test_contract_expires_at_exact_boundary(self):
        contract = sample_contract(expires_at="2027-01-01T00:00:00Z")
        allowed, reason, _ = contract.match(
            "https://api.example.com/v1/items",
            "GET",
            datetime(2027, 1, 1, tzinfo=UTC),
        )
        self.assertFalse(allowed)
        self.assertEqual("contract_expired", reason)

    def test_ambiguous_encoded_path_fails_closed(self):
        contract = sample_contract()
        allowed, reason, _ = contract.match(
            "https://api.example.com/v1/%2e%2e/secret",
            "GET",
            datetime(2027, 1, 1, tzinfo=UTC),
        )
        self.assertFalse(allowed)
        self.assertEqual("ambiguous_path", reason)

    def test_rejects_global_wildcard(self):
        value = sample_contract().raw
        value["destinations"][0]["host"] = "*"
        with self.assertRaisesRegex(ContractError, "leading"):
            parse_contract(value)

    def test_rejects_unknown_top_level_field(self):
        value = sample_contract().raw
        value["surprise"] = True
        with self.assertRaisesRegex(ContractError, "unknown"):
            parse_contract(value)

    def test_rejects_unknown_destination_field(self):
        value = sample_contract().raw
        value["destinations"][0]["headers"] = {"authorization": "*"}
        with self.assertRaisesRegex(ContractError, "unknown destinations"):
            parse_contract(value)

    def test_rejects_invalid_domain(self):
        value = sample_contract().raw
        value["destinations"][0]["host"] = "api example.com"
        with self.assertRaisesRegex(ContractError, "valid ASCII"):
            parse_contract(value)

    def test_digest_is_independent_of_json_key_order(self):
        first = sample_contract()
        reordered = json.loads(json.dumps(first.raw, sort_keys=True))
        second = parse_contract(reordered)
        self.assertEqual(first.digest, second.digest)


class SimulationTests(unittest.TestCase):
    def test_request_budget_is_fail_closed(self):
        contract = sample_contract()
        events = [
            {"url": "https://a.example.com/v1/x", "bytes": 1},
            {"url": "https://b.example.com/v1/x", "bytes": 1},
            {"url": "https://c.example.com/v1/x", "bytes": 1},
        ]
        result = simulate(contract, events)
        self.assertEqual(2, result.allowed)
        self.assertEqual(1, result.denied)
        self.assertEqual("request_budget_exceeded", result.decisions[2]["reason"])

    def test_byte_budget_is_fail_closed(self):
        contract = sample_contract()
        result = simulate(
            contract,
            [{"url": "https://a.example.com/v1/x", "bytes": 101}],
        )
        self.assertEqual("byte_budget_exceeded", result.decisions[0]["reason"])
        self.assertEqual(0, result.allowed_bytes)

    def test_denied_request_does_not_consume_budget(self):
        contract = sample_contract()
        result = simulate(
            contract,
            [
                {"url": "https://evil.invalid/v1/x", "bytes": 99},
                {"url": "https://a.example.com/v1/x", "bytes": 50},
            ],
        )
        self.assertFalse(result.decisions[0]["allowed"])
        self.assertTrue(result.decisions[1]["allowed"])


class PolicyTests(unittest.TestCase):
    def test_policy_contains_dns_and_fqdn_rules(self):
        policy = compile_cilium_policy(sample_contract())
        self.assertEqual("CiliumNetworkPolicy", policy["kind"])
        self.assertIn("rules", policy["spec"]["egress"][0]["toPorts"][0])
        self.assertEqual(
            "*.example.com", policy["spec"]["egress"][1]["toFQDNs"][0]["matchPattern"]
        )

    def test_policy_is_json_serializable(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "policy.json"
            output.write_text(json.dumps(compile_cilium_policy(sample_contract())))
            self.assertEqual(
                "cilium.io/v2", json.loads(output.read_text())["apiVersion"]
            )


if __name__ == "__main__":
    unittest.main()
