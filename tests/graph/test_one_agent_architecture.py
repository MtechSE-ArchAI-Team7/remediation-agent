"""Architecture assertions for one-agent constraint."""

from __future__ import annotations

from tests.conftest import build_test_service, diagnosis_handoff, scripted_responses


async def test_workflow_subgraphs_share_one_identity_state_and_thread() -> None:
    service, *_ = build_test_service(scripted_responses())
    result = await service.start(diagnosis_handoff())
    snapshot = await service.graph.aget_state({"configurable": {"thread_id": result.run_id}})
    topology = service.graph.get_graph()

    assert {"analysis_workflow", "repair_workflow"}.issubset(topology.nodes)
    assert not {"planner_agent", "coder_agent", "reviewer_agent", "supervisor"}.intersection(topology.nodes)
    assert snapshot.values["agent_id"] == "resolution-remediation-agent"
    assert snapshot.values["thread_id"] == result.run_id
