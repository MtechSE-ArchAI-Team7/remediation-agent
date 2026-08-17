"""Adaptive model-called inspection behavior inside the analysis stage."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager

from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import BaseTool, StructuredTool

from remediation_agent.domain.enums import FinalStatus, InspectionToolStatus
from remediation_agent.domain.models import (
    InspectionArtifact,
    InspectionPlan,
    InspectionToolCallRecord,
    ListRepositoryTreeArgs,
    ReadRepositoryFileArgs,
    SearchRepositoryArgs,
    WorkspaceRef,
)
from tests.conftest import build_test_service, diagnosis_handoff, scripted_responses


def _turn(index: int, name: str, arguments: dict[str, object]) -> AIMessage:
    return AIMessage(
        content="",
        tool_calls=[
            {
                "name": name,
                "args": arguments,
                "id": f"adaptive-call-{index}",
                "type": "tool_call",
            }
        ],
    )


class _MalformedInspectionProvider:
    @asynccontextmanager
    async def session(self, workspace: WorkspaceRef) -> AsyncIterator[Sequence[BaseTool]]:
        _ = workspace

        async def list_repository_tree(relative_path: str = ".") -> tuple[str, dict[str, object]]:
            _ = relative_path
            return "{}", {"structured_content": {"unexpected": True}}

        async def read_repository_file(relative_path: str) -> tuple[str, dict[str, object]]:
            _ = relative_path
            return "{}", {"structured_content": {"unexpected": True}}

        async def search_repository(query: str) -> tuple[str, dict[str, object]]:
            _ = query
            return "{}", {"structured_content": {"unexpected": True}}

        yield [
            StructuredTool.from_function(
                coroutine=list_repository_tree,
                name="list_repository_tree",
                description="Malformed fixture tree tool.",
                args_schema=ListRepositoryTreeArgs,
                response_format="content_and_artifact",
            ),
            StructuredTool.from_function(
                coroutine=read_repository_file,
                name="read_repository_file",
                description="Malformed fixture read tool.",
                args_schema=ReadRepositoryFileArgs,
                response_format="content_and_artifact",
            ),
            StructuredTool.from_function(
                coroutine=search_repository,
                name="search_repository",
                description="Malformed fixture search tool.",
                args_schema=SearchRepositoryArgs,
                response_format="content_and_artifact",
            ),
        ]


class _FailingInspectionProvider:
    @asynccontextmanager
    async def session(self, workspace: WorkspaceRef) -> AsyncIterator[Sequence[BaseTool]]:
        _ = workspace
        raise RuntimeError("MCP process unavailable")
        yield []  # pragma: no cover - establishes the async-context-manager type


class _TimeoutInspectionProvider:
    @asynccontextmanager
    async def session(self, workspace: WorkspaceRef) -> AsyncIterator[Sequence[BaseTool]]:
        _ = workspace

        async def list_repository_tree(relative_path: str = ".") -> tuple[str, dict[str, object]]:
            _ = relative_path
            await asyncio.sleep(2)
            return "{}", {"structured_content": {"unexpected": True}}

        async def read_repository_file(relative_path: str) -> tuple[str, dict[str, object]]:
            _ = relative_path
            return "{}", {"structured_content": {"unexpected": True}}

        async def search_repository(query: str) -> tuple[str, dict[str, object]]:
            _ = query
            return "{}", {"structured_content": {"unexpected": True}}

        yield [
            StructuredTool.from_function(
                coroutine=list_repository_tree,
                name="list_repository_tree",
                description="Slow fixture tree tool.",
                args_schema=ListRepositoryTreeArgs,
                response_format="content_and_artifact",
            ),
            StructuredTool.from_function(
                coroutine=read_repository_file,
                name="read_repository_file",
                description="Fixture read tool.",
                args_schema=ReadRepositoryFileArgs,
                response_format="content_and_artifact",
            ),
            StructuredTool.from_function(
                coroutine=search_repository,
                name="search_repository",
                description="Fixture search tool.",
                args_schema=SearchRepositoryArgs,
                response_format="content_and_artifact",
            ),
        ]


async def test_model_adapts_across_tool_results_and_plan_is_reconstructed_from_history() -> None:
    turns = [
        _turn(1, "finish_inspection", {"rationale": "Too early."}),
        _turn(2, "read_repository_file", {"relative_path": ".env"}),
        _turn(3, "list_repository_tree", {"relative_path": "."}),
        _turn(4, "read_repository_file", {"relative_path": "src/app.py"}),
        _turn(5, "search_repository", {"query": "int("}),
        _turn(6, "finish_inspection", {"rationale": "The source and matching call site are sufficient."}),
    ]
    service, model, repository, _, _, _, _ = build_test_service(
        scripted_responses(),
        files={"src/app.py": "value = int(raw)\n"},
        tool_turns=turns,
    )

    result = await service.start(diagnosis_handoff())
    snapshot = await service.graph.aget_state({"configurable": {"thread_id": result.run_id}})
    plan = InspectionPlan.model_validate(snapshot.values["inspection_plan"])
    calls = [InspectionToolCallRecord.model_validate(item) for item in snapshot.values["inspection_tool_calls"]]
    artifacts = [InspectionArtifact.model_validate(item) for item in snapshot.values["inspection_artifacts"]]

    assert result.status is FinalStatus.DRAFT_PR_PREPARED
    assert plan.paths_to_read == ["src/app.py"]
    assert plan.search_queries == ["int("]
    assert plan.rationale == "The source and matching call site are sufficient."
    assert [item.status for item in calls] == [
        InspectionToolStatus.DENIED,
        InspectionToolStatus.DENIED,
        InspectionToolStatus.SUCCEEDED,
        InspectionToolStatus.SUCCEEDED,
        InspectionToolStatus.SUCCEEDED,
        InspectionToolStatus.SUCCEEDED,
    ]
    assert [item.kind for item in artifacts] == ["TREE", "FILE", "SEARCH"]
    assert repository.read_paths == ["src/app.py"]
    assert repository.search_queries == ["int("]
    assert any(isinstance(message, ToolMessage) for message in model.tool_turn_messages[1])
    assert not any(key in snapshot.values for key in ("messages", "provider_messages", "mcp_session"))
    inspection_events = [item for item in snapshot.values["audit_events"] if item.event_type == "INSPECTION_TOOL_CALL"]
    assert len(inspection_events) == len(turns)


async def test_finish_without_success_cannot_bypass_inspection_and_round_limit_cleans_workspace() -> None:
    turns = [_turn(index, "finish_inspection", {"rationale": "Skip repository reads."}) for index in range(1, 9)]
    service, model, _, sandbox, _, _, _ = build_test_service({}, tool_turns=turns)

    result = await service.start(diagnosis_handoff())
    snapshot = await service.graph.aget_state({"configurable": {"thread_id": result.run_id}})
    calls = [InspectionToolCallRecord.model_validate(item) for item in snapshot.values["inspection_tool_calls"]]

    assert result.status is FinalStatus.INTERNAL_ERROR
    assert result.result is not None
    assert result.result.errors[0].code == "INSPECTION_FAILED"
    assert len(model.tool_turn_messages) == 8
    assert len(calls) == 8
    assert all(item.status is InspectionToolStatus.DENIED for item in calls)
    assert sandbox.destroyed


async def test_multiple_or_unknown_tool_calls_fail_closed_without_executing_mutation() -> None:
    multiple = AIMessage(
        content="",
        tool_calls=[
            {"name": "list_repository_tree", "args": {"relative_path": "."}, "id": "one", "type": "tool_call"},
            {"name": "search_repository", "args": {"query": "secret"}, "id": "two", "type": "tool_call"},
        ],
    )
    service, _, repository, sandbox, _, _, _ = build_test_service({}, tool_turns=[multiple])

    result = await service.start(diagnosis_handoff())
    snapshot = await service.graph.aget_state({"configurable": {"thread_id": result.run_id}})
    calls = [InspectionToolCallRecord.model_validate(item) for item in snapshot.values["inspection_tool_calls"]]

    assert result.status is FinalStatus.INTERNAL_ERROR
    assert len(calls) == 2
    assert all(item.status is InspectionToolStatus.ERROR for item in calls)
    assert repository.search_queries == []
    assert sandbox.applied_patches == []
    assert sandbox.destroyed

    unknown_service, _, _, unknown_sandbox, _, _, _ = build_test_service(
        {},
        tool_turns=[_turn(1, "apply_patch", {"unified_diff": "malicious"})],
    )
    unknown_result = await unknown_service.start(diagnosis_handoff())
    assert unknown_result.status is FinalStatus.INTERNAL_ERROR
    assert unknown_sandbox.applied_patches == []
    assert unknown_sandbox.destroyed


async def test_malformed_tool_output_and_mcp_start_failure_are_audited_then_cleaned() -> None:
    malformed_service, _, _, malformed_sandbox, _, _, _ = build_test_service(
        {},
        tool_turns=[_turn(1, "read_repository_file", {"relative_path": "src/app.py"})],
        inspection_tool_provider=_MalformedInspectionProvider(),
    )

    malformed_result = await malformed_service.start(diagnosis_handoff())
    malformed_snapshot = await malformed_service.graph.aget_state(
        {"configurable": {"thread_id": malformed_result.run_id}}
    )
    calls = [
        InspectionToolCallRecord.model_validate(item) for item in malformed_snapshot.values["inspection_tool_calls"]
    ]
    assert malformed_result.status is FinalStatus.INTERNAL_ERROR
    assert len(calls) == 1
    assert calls[0].status is InspectionToolStatus.ERROR
    assert malformed_sandbox.destroyed
    assert any(
        event.event_type == "INSPECTION_TOOL_CALL" and event.result_code == "ERROR"
        for event in malformed_snapshot.values["audit_events"]
    )

    failing_service, _, _, failing_sandbox, _, _, _ = build_test_service(
        {},
        inspection_tool_provider=_FailingInspectionProvider(),
    )
    failing_result = await failing_service.start(diagnosis_handoff())
    failing_snapshot = await failing_service.graph.aget_state({"configurable": {"thread_id": failing_result.run_id}})
    assert failing_result.status is FinalStatus.INTERNAL_ERROR
    assert failing_sandbox.destroyed
    assert any(
        event.event_type == "INSPECTION_TOOL_CALL" and "inspection_session" in event.detail
        for event in failing_snapshot.values["audit_events"]
    )


async def test_tool_call_and_timeout_limits_fail_closed_with_attempt_evidence() -> None:
    limited_service, _, limited_repository, limited_sandbox, _, _, _ = build_test_service(
        {},
        tool_turns=[
            _turn(1, "list_repository_tree", {"relative_path": "."}),
            _turn(2, "search_repository", {"query": "int("}),
            _turn(3, "read_repository_file", {"relative_path": "src/app.py"}),
        ],
        max_inspection_tool_calls=2,
    )
    limited_result = await limited_service.start(diagnosis_handoff())
    limited_snapshot = await limited_service.graph.aget_state({"configurable": {"thread_id": limited_result.run_id}})
    limited_calls = [
        InspectionToolCallRecord.model_validate(item) for item in limited_snapshot.values["inspection_tool_calls"]
    ]
    assert limited_result.status is FinalStatus.INTERNAL_ERROR
    assert [item.status for item in limited_calls] == [
        InspectionToolStatus.SUCCEEDED,
        InspectionToolStatus.SUCCEEDED,
        InspectionToolStatus.ERROR,
    ]
    assert limited_repository.read_paths == []
    assert limited_sandbox.destroyed

    timeout_service, _, _, timeout_sandbox, _, _, _ = build_test_service(
        {},
        tool_turns=[_turn(1, "list_repository_tree", {"relative_path": "."})],
        inspection_tool_provider=_TimeoutInspectionProvider(),
        max_mcp_tool_timeout_seconds=1,
    )
    timeout_result = await timeout_service.start(diagnosis_handoff())
    timeout_snapshot = await timeout_service.graph.aget_state({"configurable": {"thread_id": timeout_result.run_id}})
    timeout_calls = [
        InspectionToolCallRecord.model_validate(item) for item in timeout_snapshot.values["inspection_tool_calls"]
    ]
    assert timeout_result.status is FinalStatus.INTERNAL_ERROR
    assert len(timeout_calls) == 1
    assert timeout_calls[0].status is InspectionToolStatus.ERROR
    assert timeout_sandbox.destroyed
