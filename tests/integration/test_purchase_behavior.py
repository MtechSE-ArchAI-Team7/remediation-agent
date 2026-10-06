"""Real offline Express/SQLite proof; no evaluation checkout or live target is used."""

from __future__ import annotations

import os
import tarfile
from pathlib import Path

import pytest

from remediation_agent.adapters.agentcore_sandbox import AgentCoreCodeInterpreterSandbox
from remediation_agent.adapters.sandbox import DockerSandboxExecutor
from remediation_agent.domain.models import WorkspaceRef
from remediation_agent.policy.loader import load_policy
from remediation_agent.ports.models import BehavioralTaskRequest
from tests.integration.test_docker_sandbox import _git, docker_executable  # noqa: F401

_APP = """
const express = require('express');
const sqlite3 = require('sqlite3');
const fs = require('fs');
const app = express();
app.use(express.json());
const db = new sqlite3.Database('ecommerce.db');
db.serialize(() => {
  db.exec(fs.readFileSync('schema.sql','utf8'));
  db.exec(fs.readFileSync('seed.sql','utf8'));
});
app.get('/products', (req,res) => db.all('SELECT * FROM products', (err,rows) => res.json(rows)));
app.post('/purchase', (req,res) => {
 const {productId, quantity} = req.body;
 if (!Number.isSafeInteger(productId) || !Number.isSafeInteger(quantity) || quantity <= 0)
   return res.status(400).json({error:'Invalid product ID or quantity'});
 // BEHAVIOR
});
app.listen(process.env.PORT, '127.0.0.1');
"""
_FIXED = """db.run('UPDATE products SET inventory = inventory - ? WHERE id = ? AND inventory >= ?',
 [quantity,productId,quantity], function(err) {
  if(err) return res.status(500).json({error:'Database error'});
  if(!this.changes) return res.status(400).json({error:'Insufficient inventory'});
  db.get('SELECT inventory FROM products WHERE id = ?', [productId], (err,row) => {
    if(err || !row) return res.status(500).json({error:'Database error'});
    res.json({success:true, remaining:row.inventory});
  });
 });"""


def purchase_workspace(tmp_path: Path) -> WorkspaceRef:
    root = tmp_path / "purchase"
    root.mkdir()
    (root / "package.json").write_text((Path(__file__).parents[2] / "validation/ecommerce/package.json").read_text())
    (root / "server.js").write_text(
        _APP.replace("// BEHAVIOR", "res.status(400).json({error:'Insufficient inventory'});")
    )
    (root / "schema.sql").write_text("CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY, inventory INTEGER);")
    (root / "seed.sql").write_text("INSERT OR IGNORE INTO products VALUES(1,10);")
    _git(root, "init", "-b", "main")
    _git(root, "config", "user.name", "AIOS disposable fixture")
    _git(root, "config", "user.email", "fixture@example.invalid")
    _git(root, "add", ".")
    _git(root, "commit", "-m", "isolated test fixture")
    commit = _git(root, "rev-parse", "HEAD")
    (root / "server.js").write_text(_APP.replace("// BEHAVIOR", _FIXED))
    return WorkspaceRef(workspace_id="purchase-proof", path=str(root), base_commit=commit)


async def qualify(sandbox: DockerSandboxExecutor, workspace: WorkspaceRef) -> None:
    task = load_policy(Path(__file__).parents[2] / "config/policies/demo.json").validation_tasks["purchase_regression"]
    before = (Path(workspace.path) / "server.js").read_bytes()
    result = await sandbox.run_behavior(
        BehavioralTaskRequest(
            workspace=workspace,
            task_name="purchase_regression",
            task=task,
            attempt=1,
            patch_digest="sha256:fixture",
        )
    )
    base = {case.test_id: case.outcome for case in result.evidence.base.cases}
    assert "purchase_below_stock" in base, result.evidence.model_dump_json()
    assert base["purchase_below_stock"] == "ASSERTION_FAILED"
    assert base["purchase_persistence"] == "ASSERTION_FAILED"
    assert all(case.outcome == "PASSED" for case in result.evidence.candidate.cases)
    assert set(base) == set(task.required_test_ids)
    assert result.evidence.cleanup_succeeded and len(result.executions) == 2
    assert (Path(workspace.path) / "server.js").read_bytes() == before
    assert not list(sandbox.workspace_root.glob("verification-*"))
    assert not list(Path(workspace.path).glob("*.db"))


@pytest.mark.integration
@pytest.mark.usefixtures("docker_executable")
async def test_purchase_real_express_sqlite_before_after(tmp_path: Path) -> None:
    bundle = Path(__file__).parents[2] / ".artifacts/validation/ecommerce"
    if not bundle.is_dir():
        pytest.skip("Build offline native assets with make validation-bundle first")
    sandbox = DockerSandboxExecutor(tmp_path, "aios-remediation-sandbox:local", behavioral_bundle=bundle)
    await qualify(sandbox, purchase_workspace(tmp_path))


@pytest.mark.live_code_interpreter
@pytest.mark.skipif(os.environ.get("AIOS_RUN_CODE_INTERPRETER_LIVE") != "1", reason="explicit live opt-in required")
async def test_purchase_code_interpreter_qualification(tmp_path: Path) -> None:
    region = os.environ.get("AIOS_AWS_REGION")
    bundle = os.environ.get("AIOS_BEHAVIORAL_BUNDLE")
    if not region or not bundle:
        pytest.skip("AIOS_AWS_REGION and a compatible AIOS_BEHAVIORAL_BUNDLE are required")
    vendor = tmp_path / "empty.tar.gz"
    with tarfile.open(vendor, "w:gz"):
        pass
    sandbox = AgentCoreCodeInterpreterSandbox(
        tmp_path,
        region_name=region,
        behavioral_bundle=Path(bundle),
        validation_bundle=vendor,
        code_interpreter_identifier=os.environ.get("AIOS_CODE_INTERPRETER_IDENTIFIER", "aws.codeinterpreter.v1"),
    )
    await qualify(sandbox, purchase_workspace(tmp_path))
