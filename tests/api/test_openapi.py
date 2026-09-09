"""Contract tests for the committed OpenAPI document."""

from pathlib import Path

import yaml  # type: ignore[import-untyped]

from remediation_agent.api.app import create_app
from remediation_agent.api.openapi import (
    APPROVAL_DECISION_EXAMPLES,
    RUN_RESPONSE_EXAMPLES,
    START_REMEDIATION_EXAMPLES,
)
from remediation_agent.domain.models import ApprovalDecisionV1, DiagnosisHandoffV1, RemediationRunView


def test_committed_openapi_matches_application() -> None:
    openapi_path = Path(__file__).parents[2] / "openapi.yaml"
    committed: object = yaml.safe_load(openapi_path.read_text(encoding="utf-8"))

    assert committed == create_app().openapi()


def test_openapi_documents_stable_operations_errors_and_examples() -> None:
    document = create_app().openapi()
    paths = document["paths"]

    assert document["openapi"] == "3.1.0"
    assert [tag["name"] for tag in document["tags"]] == ["Service", "Tools", "Remediations"]
    assert "securitySchemes" not in document.get("components", {})
    assert paths["/"]["get"]["operationId"] == "get_service_info"
    assert paths["/healthz"]["get"]["operationId"] == "get_health"
    assert paths["/readyz"]["get"]["operationId"] == "get_readiness"
    assert paths["/v1/tools"]["get"]["operationId"] == "list_operational_tools"
    assert paths["/v1/remediations"]["post"]["operationId"] == "start_remediation"
    assert paths["/v1/remediations/{run_id}"]["get"]["operationId"] == "get_remediation"
    assert paths["/v1/remediations/{run_id}/approvals"]["post"]["operationId"] == "submit_remediation_approval"

    assert "503" in paths["/readyz"]["get"]["responses"]
    assert {"404", "422"}.issubset(paths["/v1/remediations/{run_id}"]["get"]["responses"])
    assert "422" in paths["/v1/remediations"]["post"]["responses"]
    approval_responses = paths["/v1/remediations/{run_id}/approvals"]["post"]["responses"]
    assert {"404", "409", "422"}.issubset(approval_responses)

    start_operation = paths["/v1/remediations"]["post"]
    request_examples = start_operation["requestBody"]["content"]["application/json"]["examples"]
    response_examples = start_operation["responses"]["202"]["content"]["application/json"]["examples"]
    assert "code_defect" in request_examples
    assert {"awaiting_approval", "terminal"}.issubset(response_examples)

    schemas = document["components"]["schemas"]
    assert {
        "ApprovalDecisionV1",
        "DiagnosisHandoffV1",
        "ErrorResponse",
        "HealthResponse",
        "ReadinessResponse",
        "RemediationHandoffV1",
        "RemediationRunView",
        "ServiceInfoResponse",
        "ToolCatalogResponse",
        "OperationalToolDescriptor",
    }.issubset(schemas)


def test_openapi_examples_validate_against_public_contracts() -> None:
    DiagnosisHandoffV1.model_validate(START_REMEDIATION_EXAMPLES["code_defect"]["value"])
    ApprovalDecisionV1.model_validate(APPROVAL_DECISION_EXAMPLES["approve_exact_scope"]["value"])

    for example in RUN_RESPONSE_EXAMPLES.values():
        RemediationRunView.model_validate(example["value"])
