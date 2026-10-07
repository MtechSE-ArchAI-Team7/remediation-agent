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
    CapabilityReportV1,
    CompiledContractV1,
    DiagnosisHandoffV1,
    DownstreamDeliveryReceiptV1,
    EditProposal,
    ExecutionBindingV1,
    ExplainabilityTraceV1,
    PublicationJournalV1,
    PublicationRetryRequestV1,
    ReleaseProvenanceV1,
    RemediationHandoffV1,
    ValidationStorageEvidence,
    VerificationBriefV1,
)
from remediation_agent.domain.qualification import ReleaseQualificationV1
from remediation_agent.domain.runtime_qualification import RuntimeQualificationRequestV1, RuntimeQualificationResultV1
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
        "runtime-qualification-request-v1.schema.json": RuntimeQualificationRequestV1.model_json_schema(),
        "runtime-qualification-result-v1.schema.json": RuntimeQualificationResultV1.model_json_schema(),
        "validation-storage.schema.json": ValidationStorageEvidence.model_json_schema(),
        "release-qualification-v1.schema.json": ReleaseQualificationV1.model_json_schema(),
        "compiled-contract-v1.schema.json": CompiledContractV1.model_json_schema(),
        "capability-report-v1.schema.json": CapabilityReportV1.model_json_schema(),
        "edit-proposal.schema.json": EditProposal.model_json_schema(),
        "execution-binding-v1.schema.json": ExecutionBindingV1.model_json_schema(),
        "publication-journal-v1.schema.json": PublicationJournalV1.model_json_schema(),
        "publication-retry-request-v1.schema.json": PublicationRetryRequestV1.model_json_schema(),
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
