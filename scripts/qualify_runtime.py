"""Opt-in operator driver: fixed fixtures on managed session storage, stop, then cold resume."""

from __future__ import annotations

import argparse
import json
import os
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Protocol, cast
from uuid import uuid4

import boto3  # type: ignore[import-untyped]
from botocore.config import Config  # type: ignore[import-untyped]

from remediation_agent.api.a2a_contracts import RUNTIME_QUALIFICATION_REQUEST_MEDIA_TYPE
from remediation_agent.domain.runtime_qualification import RuntimeQualificationRequestV1, RuntimeQualificationResultV1

REGION = "ap-southeast-1"
ACCOUNT = "734849394833"
ARN = f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:runtime/remediation_agent-2425SXH9D3"


class Body(Protocol):
    def read(self, size: int = -1) -> bytes: ...


class Client(Protocol):
    def invoke_agent_runtime(self, **kwargs: object) -> Mapping[str, object]: ...
    def stop_runtime_session(self, **kwargs: object) -> Mapping[str, object]: ...


def invoke(client: Client, session: str, request: RuntimeQualificationRequestV1) -> RuntimeQualificationResultV1:
    response = client.invoke_agent_runtime(
        agentRuntimeArn=ARN,
        qualifier="DEFAULT",
        runtimeSessionId=session,
        contentType="application/json",
        accept="application/json",
        payload=json.dumps(
            {
                "jsonrpc": "2.0",
                "id": str(uuid4()),
                "method": "SendMessage",
                "params": {
                    "message": {
                        "messageId": str(uuid4()),
                        "role": "ROLE_USER",
                        "contextId": session,
                        "parts": [
                            {
                                "mediaType": RUNTIME_QUALIFICATION_REQUEST_MEDIA_TYPE,
                                "data": request.model_dump(mode="json"),
                            }
                        ],
                    }
                },
            }
        ).encode(),
    )
    raw = cast(Body, response["response"]).read(1048577)
    if len(raw) > 1048576:
        raise ValueError("QUALIFICATION_RESPONSE_OVERSIZED")
    payload = json.loads(raw)
    try:
        return RuntimeQualificationResultV1.model_validate(payload["result"]["message"]["parts"][0]["data"])
    except (KeyError, IndexError, ValueError) as exc:
        raise ValueError("QUALIFICATION_RESPONSE_INVALID") from exc


def require_result(
    result: RuntimeQualificationResultV1, *, source: str, image: str, version: str, release: str
) -> None:
    if (
        result.status != "PASSED"
        or not all(
            (
                result.managed_filesystem,
                result.process_restarted,
                result.git_integrity_verified,
                result.cleanup_verified,
            )
        )
        or result.failures
        or result.evidence is None
        or not result.evidence.cleanup_succeeded
        or result.storage is None
        or result.storage.failures
        or result.artifact_manifest is None
        or result.release.source_revision != source
        or result.release.image_digest != image
        or result.release.runtime_version != version
        or result.release.release_id != release
        or result.release.runtime_arn != ARN
        or result.release.region != REGION
    ):
        raise ValueError("HOSTED_RUNTIME_QUALIFICATION_FAILED")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--release", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get("AIOS_RUN_RUNTIME_QUALIFICATION") != "1":
        raise ValueError("Explicit AIOS_RUN_RUNTIME_QUALIFICATION=1 is required")
    if boto3.client("sts", region_name=REGION).get_caller_identity()["Account"] != ACCOUNT:
        raise ValueError("QUALIFICATION_ACCOUNT_MISMATCH")
    client = cast(
        Client,
        boto3.client(
            "bedrock-agentcore",
            region_name=REGION,
            config=Config(read_timeout=950, connect_timeout=15, retries={"total_max_attempts": 1}),
        ),
    )
    args.output.mkdir(parents=True, exist_ok=True)
    for fixture in ("ah54", "ah56"):
        request = RuntimeQualificationRequestV1(operation="prepare", fixture=fixture, qualification_id=str(uuid4()))
        session = str(uuid4())
        # Store correlation before any invocation; transport retries must never manufacture a new run.
        (args.output / (fixture + "-request.json")).write_text(
            json.dumps({"session": session, "request": request.model_dump(mode="json")})
        )
        try:
            prepared = invoke(client, session, request)
            (args.output / (fixture + "-prepared.json")).write_text(prepared.model_dump_json(indent=2))
            if prepared.status != "PREPARED":
                raise ValueError("QUALIFICATION_PREPARATION_FAILED")
            stopped = client.stop_runtime_session(
                agentRuntimeArn=ARN, runtimeSessionId=session, qualifier="DEFAULT", clientToken=str(uuid4())
            )
            if stopped.get("statusCode") not in {200, 202, 204}:
                raise ValueError("QUALIFICATION_SESSION_STOP_UNCONFIRMED")
            time.sleep(5)
            resumed = invoke(
                client,
                session,
                request.model_copy(update={"operation": "resume", "receipt_digest": prepared.receipt_digest}),
            )
            (args.output / (fixture + "-result.json")).write_text(resumed.model_dump_json(indent=2))
            require_result(resumed, source=args.source, image=args.image, version=args.version, release=args.release)
            print(f"{fixture}: hosted cold-resume, behavior, Git integrity and cleanup PASSED", flush=True)
        finally:
            client.stop_runtime_session(
                agentRuntimeArn=ARN, runtimeSessionId=session, qualifier="DEFAULT", clientToken=str(uuid4())
            )


if __name__ == "__main__":
    main()
