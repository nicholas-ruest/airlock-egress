from __future__ import annotations

from typing import Any

from .model import Contract


def compile_cilium_policy(contract: Contract) -> dict[str, Any]:
    """Compile network-enforceable portions of a contract to Cilium policy."""
    egress: list[dict[str, Any]] = [
        {
            "toEndpoints": [
                {
                    "matchLabels": {
                        "k8s:io.kubernetes.pod.namespace": "kube-system",
                        "k8s:k8s-app": "kube-dns",
                    }
                }
            ],
            "toPorts": [
                {
                    "ports": [
                        {"port": "53", "protocol": "UDP"},
                        {"port": "53", "protocol": "TCP"},
                    ],
                    "rules": {"dns": [{"matchPattern": "*"}]},
                }
            ],
        }
    ]
    for destination in contract.destinations:
        fqdn_key = "matchPattern" if destination.host.startswith("*.") else "matchName"
        egress.append(
            {
                "toFQDNs": [{fqdn_key: destination.host}],
                "toPorts": [
                    {
                        "ports": [
                            {"port": str(port), "protocol": "TCP"}
                            for port in destination.ports
                        ]
                    }
                ],
            }
        )
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {
            "name": f"airlock-egress-{contract.workload.name}",
            "namespace": contract.workload.namespace,
            "annotations": {
                "airlock-egress.dev/contract-digest": contract.digest,
                "airlock-egress.dev/expires-at": contract.expires_at.isoformat().replace(
                    "+00:00", "Z"
                ),
                "airlock-egress.dev/application-policy": "simulate-or-enforce-upstream",
            },
        },
        "spec": {
            "endpointSelector": {
                "matchLabels": {
                    "io.cilium.k8s.policy.serviceaccount": contract.workload.service_account
                }
            },
            "egress": egress,
        },
    }
