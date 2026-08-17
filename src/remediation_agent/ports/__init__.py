"""Narrow dependency-injection ports."""

from remediation_agent.ports.protocols import (
    ArtifactStore,
    AuditSink,
    InspectionToolProvider,
    PullRequestProvider,
    RepositoryInspectionPort,
    RepositoryPort,
    RepositoryWorkspacePort,
    SandboxExecutor,
    StructuredModel,
)

__all__ = [
    "ArtifactStore",
    "AuditSink",
    "InspectionToolProvider",
    "PullRequestProvider",
    "RepositoryInspectionPort",
    "RepositoryPort",
    "RepositoryWorkspacePort",
    "SandboxExecutor",
    "StructuredModel",
]
