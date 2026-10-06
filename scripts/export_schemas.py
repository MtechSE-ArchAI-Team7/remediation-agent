"""Export the public v1 handoff and required policy JSON Schemas."""

from __future__ import annotations

import json
from pathlib import Path

from remediation_agent.api.a2a_contracts import (
    ProviderProbeRequestV1,
    ProviderProbeResultV1,
    RemediationRunSummaryV1,
)
from remediation_agent.domain.models import (
    ApprovalDecisionV1,
    ApprovalRequest,
    DiagnosisHandoffV1,
    DownstreamDeliveryReceiptV1,
    ExplainabilityTraceV1,
    ReleaseProvenanceV1,
    RemediationHandoffV1,
    VerificationBriefV1,
)
from remediation_agent.evaluation import (
    EvaluationJudgeSuiteV1,
    EvaluationSuiteManifestV2,
    EvaluationSuiteResultV2,
    MemoryBenchmarkManifestV1,
    MemoryEvaluationResultV1,
)
from remediation_agent.policy.models import PolicyConfig


def main() -> None:
    output = Path(__file__).parents[1] / "config" / "schemas"
    output.mkdir(parents=True, exist_ok=True)
    schemas = {
        "verification-brief-v1.schema.json": VerificationBriefV1.model_json_schema(),
        "release-provenance-v1.schema.json": ReleaseProvenanceV1.model_json_schema(),
        "diagnosis-handoff-v1.schema.json": DiagnosisHandoffV1.model_json_schema(),
        "approval-decision-v1.schema.json": ApprovalDecisionV1.model_json_schema(),
        "approval-request-v1.schema.json": ApprovalRequest.model_json_schema(),
        "delivery-receipt-v1.schema.json": DownstreamDeliveryReceiptV1.model_json_schema(),
        "explainability-trace-v1.schema.json": ExplainabilityTraceV1.model_json_schema(),
        "provider-probe-request-v1.schema.json": ProviderProbeRequestV1.model_json_schema(),
        "provider-probe-result-v1.schema.json": ProviderProbeResultV1.model_json_schema(),
        "remediation-run-summary-v1.schema.json": RemediationRunSummaryV1.model_json_schema(),
        "remediation-handoff-v1.schema.json": RemediationHandoffV1.model_json_schema(),
        "remediation-policy.schema.json": PolicyConfig.model_json_schema(),
        "evaluation-suite-v2.schema.json": EvaluationSuiteManifestV2.model_json_schema(),
        "evaluation-result-v2.schema.json": EvaluationSuiteResultV2.model_json_schema(),
        "evaluation-judge-v1.schema.json": EvaluationJudgeSuiteV1.model_json_schema(),
        "memory-benchmark-v1.schema.json": MemoryBenchmarkManifestV1.model_json_schema(),
        "memory-evaluation-result-v1.schema.json": MemoryEvaluationResultV1.model_json_schema(),
    }
    for name, schema in schemas.items():
        (output / name).write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
