"""Opt-in proof that AgentCore validates the JavaScript demo in fresh managed sessions."""

from __future__ import annotations

import os
import tarfile
from pathlib import Path

import pytest

from remediation_agent.adapters.agentcore_sandbox import AgentCoreCodeInterpreterSandbox
from remediation_agent.domain.enums import ValidationBackend, ValidationCleanupStatus, ValidationOutcome
from remediation_agent.domain.models import WorkspaceRef
from remediation_agent.policy.models import ValidationTaskConfig
from remediation_agent.ports.models import ValidationTaskRequest

pytestmark = pytest.mark.live_code_interpreter


@pytest.mark.skipif(
    os.environ.get("AIOS_RUN_CODE_INTERPRETER_LIVE") != "1",
    reason="set AIOS_RUN_CODE_INTERPRETER_LIVE=1 to call AgentCore Code Interpreter",
)
async def test_agentcore_runs_node_syntax_and_regression_in_fresh_sessions(tmp_path: Path) -> None:
    region = os.environ.get("AIOS_AWS_REGION")
    if not region:
        pytest.skip("AIOS_AWS_REGION is required")
    workspace_root = tmp_path / "workspaces"
    workspace_path = workspace_root / "live-node"
    (workspace_path / "lib").mkdir(parents=True)
    (workspace_path / "tests").mkdir()
    (workspace_path / "server.js").write_text(
        "const { calculateAverage } = require('./lib/calculate-average');\ncalculateAverage(10, 2);\n",
        encoding="utf-8",
    )
    (workspace_path / "lib/calculate-average.js").write_text(
        "function calculateAverage(total, count) { if (count === 0) throw new RangeError('zero'); "
        "return total / count; }\nmodule.exports = { calculateAverage };\n",
        encoding="utf-8",
    )
    (workspace_path / "tests/calculate-average.test.js").write_text(
        "const test = require('node:test');\nconst assert = require('node:assert/strict');\n"
        "const { calculateAverage } = require('../lib/calculate-average');\n"
        "test('finite average', () => assert.equal(calculateAverage(10, 2), 5));\n"
        "test('zero rejected', () => assert.throws(() => calculateAverage(10, 0), RangeError));\n",
        encoding="utf-8",
    )
    bundle = tmp_path / "empty.tar.gz"
    with tarfile.open(bundle, "w:gz"):
        pass
    sandbox = AgentCoreCodeInterpreterSandbox(
        workspace_root,
        region_name=region,
        code_interpreter_identifier=os.environ.get(
            "AIOS_CODE_INTERPRETER_IDENTIFIER",
            "aws.codeinterpreter.v1",
        ),
        validation_bundle=bundle,
    )
    workspace = WorkspaceRef(
        workspace_id="live-node",
        path=str(workspace_path),
        base_commit="a" * 40,
    )
    commands = {
        "javascript_syntax": ["node", "--check", "server.js"],
        "average_regression": ["node", "--test", "tests/calculate-average.test.js"],
    }
    executions = []
    for name, argv in commands.items():
        executions.append(
            await sandbox.run_task(
                ValidationTaskRequest(
                    workspace=workspace,
                    task_name=name,
                    task=ValidationTaskConfig(
                        argv=argv,
                        cwd=".",
                        environment={},
                        timeout_seconds=60,
                        output_limit_bytes=262_144,
                        retryable=False,
                    ),
                )
            )
        )

    assert all(item.result.outcome is ValidationOutcome.PASSED for item in executions)
    assert all(item.execution.backend is ValidationBackend.AGENTCORE_CODE_INTERPRETER for item in executions)
    assert all(item.execution.cleanup_status is ValidationCleanupStatus.SUCCEEDED for item in executions)
    assert all(item.execution.session_digest for item in executions)
    assert executions[0].execution.session_digest != executions[1].execution.session_digest
