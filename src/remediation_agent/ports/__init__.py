"""Narrow dependency-injection ports."""

from remediation_agent.ports.protocols import (
    ArtifactStore,
    AuditSink,
    PullRequestProvider,
    RepositoryPort,
    SandboxExecutor,
    StructuredModel,
)

__all__ = [
    "ArtifactStore",
    "AuditSink",
    "PullRequestProvider",
    "RepositoryPort",
    "SandboxExecutor",
    "StructuredModel",
]
