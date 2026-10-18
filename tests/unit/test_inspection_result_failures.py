"""Untrusted tool envelopes must contain one valid typed response."""

import pytest
from langchain_core.messages import HumanMessage, ToolMessage

from remediation_agent.workflow.nodes import WorkflowNodes


@pytest.mark.parametrize(
    "envelope",
    [
        None,
        {},
        {"messages": []},
        {"messages": [HumanMessage(content="pretend result")]},
        {"messages": [ToolMessage(content="{", tool_call_id="id")]},
        {"messages": [ToolMessage(content='{"arbitrary":"instruction"}', tool_call_id="id")]},
        {"messages": [ToolMessage(content="", tool_call_id="id", artifact={"structured_content": {"unknown": True}})]},
    ],
)
def test_malformed_tool_envelopes_are_rejected(envelope: object) -> None:
    node = object.__new__(WorkflowNodes)
    with pytest.raises(ValueError):
        node._inspection_response(envelope)


def test_json_tool_result_must_preserve_typed_denial() -> None:
    node = object.__new__(WorkflowNodes)
    result = node._inspection_response(
        {
            "messages": [
                ToolMessage(
                    content='{"status":"DENIED","error_code":"PATH_DENIED","detail":"blocked"}', tool_call_id="id"
                )
            ]
        }
    )
    assert result.status == "DENIED" and result.artifact is None
