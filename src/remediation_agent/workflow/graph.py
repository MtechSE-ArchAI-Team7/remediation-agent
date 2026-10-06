"""Build the one-agent parent graph and its two workflow subgraphs."""

from __future__ import annotations

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from remediation_agent.domain.enums import FinalStatus, ValidationOutcome, WorkspaceStatus
from remediation_agent.workflow.nodes import WorkflowNodes
from remediation_agent.workflow.state import RemediationState


def build_graph(
    nodes: WorkflowNodes,
    checkpointer: BaseCheckpointSaver[str] | None = None,
) -> CompiledStateGraph[RemediationState, None, RemediationState, RemediationState]:
    """Compile one remediation workflow; nested graphs are stages, not agents."""

    analysis_builder = StateGraph(RemediationState)
    analysis_builder.add_node("create_workspace", nodes.create_workspace)
    analysis_builder.add_node("retrieve_incident_memory", nodes.retrieve_incident_memory)
    analysis_builder.add_node("inspect_repository", nodes.inspect_repository)
    analysis_builder.add_node("create_plan", nodes.create_plan)
    analysis_builder.add_edge(START, "create_workspace")
    analysis_builder.add_edge("create_workspace", "retrieve_incident_memory")
    analysis_builder.add_edge("retrieve_incident_memory", "inspect_repository")
    analysis_builder.add_edge("inspect_repository", "create_plan")
    analysis_builder.add_edge("create_plan", END)
    analysis_workflow = analysis_builder.compile()

    repair_builder = StateGraph(RemediationState)
    repair_builder.add_node("generate_patch", nodes.generate_patch)
    repair_builder.add_node("preflight_patch", nodes.preflight_patch)
    repair_builder.add_node("patch_approval", nodes.patch_approval)
    repair_builder.add_node("apply_patch", nodes.apply_patch)
    repair_builder.add_node("select_validation_tasks", nodes.select_validation_tasks)
    repair_builder.add_node("run_validation", nodes.run_validation)
    repair_builder.add_node("evaluate_validation", nodes.evaluate_validation)
    repair_builder.add_node("restore_base", nodes.restore_base)
    repair_builder.add_node("prepare_revision", nodes.prepare_revision)
    repair_builder.add_edge(START, "generate_patch")
    repair_builder.add_edge("generate_patch", "preflight_patch")
    repair_builder.add_conditional_edges(
        "preflight_patch",
        _after_preflight,
        {"approve": "patch_approval", "apply": "apply_patch", "end": END},
    )
    repair_builder.add_conditional_edges(
        "patch_approval",
        _continue_if_pending,
        {"continue": "apply_patch", "end": END},
    )
    repair_builder.add_conditional_edges(
        "apply_patch",
        _after_patch_application,
        {"continue": "select_validation_tasks", "retry": "restore_base", "end": END},
    )
    repair_builder.add_conditional_edges(
        "select_validation_tasks", _continue_if_pending, {"continue": "run_validation", "end": END}
    )
    repair_builder.add_edge("run_validation", "evaluate_validation")
    repair_builder.add_conditional_edges(
        "evaluate_validation",
        _after_validation,
        {"retry": "restore_base", "end": END},
    )
    repair_builder.add_conditional_edges(
        "restore_base",
        _continue_if_pending,
        {"continue": "prepare_revision", "end": END},
    )
    repair_builder.add_edge("prepare_revision", "generate_patch")
    repair_workflow = repair_builder.compile()

    parent = StateGraph(RemediationState)
    parent.add_node("validate_intake", nodes.validate_intake)
    parent.add_node("verify_release_provenance", nodes.verify_release_provenance)
    parent.add_node("classify_scope", nodes.classify_scope)
    parent.add_node("analysis_workflow", analysis_workflow)
    parent.add_node("assess_risk", nodes.assess_risk)
    parent.add_node("plan_approval", nodes.plan_approval)
    parent.add_node("repair_workflow", repair_workflow)
    parent.add_node("build_evidence", nodes.build_evidence)
    parent.add_node("prepare_pr", nodes.prepare_pr)
    parent.add_node("cleanup", nodes.cleanup)
    parent.add_node("store_incident_memory", nodes.store_incident_memory)
    parent.add_node("finalize", nodes.finalize)

    parent.add_edge(START, "validate_intake")
    parent.add_edge("validate_intake", "verify_release_provenance")
    parent.add_conditional_edges(
        "verify_release_provenance",
        _after_release_provenance,
        {"classify": "classify_scope", "finalize": "finalize"},
    )
    parent.add_conditional_edges(
        "classify_scope",
        _after_scope,
        {"analysis": "analysis_workflow", "finalize": "finalize"},
    )
    parent.add_edge("analysis_workflow", "assess_risk")
    parent.add_conditional_edges(
        "assess_risk",
        _after_risk,
        {"approve": "plan_approval", "repair": "repair_workflow", "evidence": "build_evidence"},
    )
    parent.add_conditional_edges(
        "plan_approval",
        _after_plan_approval,
        {"repair": "repair_workflow", "evidence": "build_evidence"},
    )
    parent.add_edge("repair_workflow", "build_evidence")
    parent.add_conditional_edges(
        "build_evidence",
        _after_evidence,
        {"pr": "prepare_pr", "cleanup": "cleanup"},
    )
    parent.add_edge("prepare_pr", "cleanup")
    parent.add_edge("cleanup", "store_incident_memory")
    parent.add_edge("store_incident_memory", "finalize")
    parent.add_edge("finalize", END)
    return parent.compile(checkpointer=checkpointer)


def _after_scope(state: RemediationState) -> str:
    return "analysis" if state["final_status"] is FinalStatus.PENDING else "finalize"


def _after_release_provenance(state: RemediationState) -> str:
    return "classify" if state["final_status"] is FinalStatus.PENDING else "finalize"


def _after_risk(state: RemediationState) -> str:
    if state["final_status"] is FinalStatus.AWAITING_APPROVAL:
        return "approve"
    if state["final_status"] is FinalStatus.PENDING:
        return "repair"
    return "evidence"


def _after_plan_approval(state: RemediationState) -> str:
    return "repair" if state["final_status"] is FinalStatus.PENDING else "evidence"


def _after_preflight(state: RemediationState) -> str:
    if state["final_status"] is FinalStatus.AWAITING_APPROVAL:
        return "approve"
    if state["final_status"] is FinalStatus.PENDING:
        return "apply"
    return "end"


def _continue_if_pending(state: RemediationState) -> str:
    return "continue" if state["final_status"] is FinalStatus.PENDING else "end"


def _after_patch_application(state: RemediationState) -> str:
    if state["final_status"] is not FinalStatus.PENDING:
        return "end"
    if state.get("workspace_status") is WorkspaceStatus.PATCHED:
        return "continue"
    if (
        state.get("validation_outcome") is ValidationOutcome.ERROR
        and state["attempt_counter"] < state["max_validation_attempts"]
    ):
        return "retry"
    return "end"


def _after_validation(state: RemediationState) -> str:
    if (
        state["validation_outcome"] is not ValidationOutcome.PASSED
        and state["attempt_counter"] < state["max_validation_attempts"]
        and state["final_status"] is FinalStatus.PENDING
    ):
        return "retry"
    return "end"


def _after_evidence(state: RemediationState) -> str:
    return (
        "pr"
        if state.get("repair_outcome") is ValidationOutcome.PASSED and state.get("locally_verified", False)
        else "cleanup"
    )
