"""Export the public v1 handoff and required policy JSON Schemas."""

from __future__ import annotations

import json
from pathlib import Path

from remediation_agent.api.a2a_contracts import ProviderProbeRequestV1, ProviderProbeResultV1
from remediation_agent.domain.models import (
    ApprovalDecisionV1,
    ApprovalRequest,
    DiagnosisHandoffV1,
    DownstreamDeliveryReceiptV1,
    RemediationHandoffV1,
)
from remediation_agent.policy.models import PolicyConfig


def main() -> None:
    output = Path(__file__).parents[1] / "config" / "schemas"
    output.mkdir(parents=True, exist_ok=True)
    schemas = {
        "diagnosis-handoff-v1.schema.json": DiagnosisHandoffV1.model_json_schema(),
        "approval-decision-v1.schema.json": ApprovalDecisionV1.model_json_schema(),
        "approval-request-v1.schema.json": ApprovalRequest.model_json_schema(),
        "delivery-receipt-v1.schema.json": DownstreamDeliveryReceiptV1.model_json_schema(),
        "provider-probe-request-v1.schema.json": ProviderProbeRequestV1.model_json_schema(),
        "provider-probe-result-v1.schema.json": ProviderProbeResultV1.model_json_schema(),
        "remediation-handoff-v1.schema.json": RemediationHandoffV1.model_json_schema(),
        "remediation-policy.schema.json": PolicyConfig.model_json_schema(),
    }
    for name, schema in schemas.items():
        (output / name).write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
