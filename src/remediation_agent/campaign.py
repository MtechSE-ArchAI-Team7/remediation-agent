"""Repeated operator evaluations with explicit denominators and conservative budget accounting."""

from __future__ import annotations

import asyncio
import hashlib
import math
import statistics
from collections import Counter
from collections.abc import Callable
from datetime import datetime
from decimal import Decimal
from uuid import NAMESPACE_URL, uuid5

from remediation_agent.domain.campaign import (
    CampaignCaseResultV1,
    CampaignCaseV1,
    CampaignManifestV1,
    CampaignObservationV1,
    CampaignResultV1,
    CampaignTrialV1,
)
from remediation_agent.ports.campaign import CampaignExecutor, CampaignStore


async def run_campaign(
    manifest: CampaignManifestV1, store: CampaignStore, executor: CampaignExecutor, *, clock: Callable[[], datetime]
) -> CampaignResultV1:
    digest = "sha256:" + hashlib.sha256(manifest.model_dump_json().encode()).hexdigest()
    records = [
        prior
        for case in manifest.cases
        for number in range(1, case.repetitions + 1)
        if (prior := store.read(case.case_id, number)) is not None
    ]
    charged = sum((r.charged_usd for r in records), Decimal(0))
    for case in manifest.cases:
        for number in range(1, case.repetitions + 1):
            if store.read(case.case_id, number) is not None:
                continue
            now = clock()
            allowed = charged + manifest.reservation_usd <= manifest.model_budget_usd
            start = CampaignTrialV1(
                campaign_id=manifest.campaign_id,
                manifest_digest=digest,
                case_id=case.case_id,
                trial_number=number,
                run_id=str(uuid5(NAMESPACE_URL, f"{digest}:{case.case_id}:{number}")),
                started_at=now,
                finished_at=None if allowed else now,
                state="STARTED" if allowed else "BUDGET_STOPPED",
                reserved_usd=manifest.reservation_usd if allowed else Decimal(0),
                charged_usd=manifest.reservation_usd if allowed else Decimal(0),
            )
            store.append(start)  # Durable reservation before the first external side effect.
            if not allowed:
                records.append(start)
                continue
            try:
                async with asyncio.timeout(manifest.trial_timeout_seconds):
                    observation = await executor.execute(case, start.run_id)
            except asyncio.CancelledError:
                # Keep the reservation and original identity. Resume cannot create a duplicate run.
                raise
            except Exception as exc:  # noqa: BLE001 - never persist arbitrary provider exception text
                observation = CampaignObservationV1(
                    status="FAILED",
                    failure_code="TRIAL_TIMEOUT" if isinstance(exc, TimeoutError) else "TRIAL_EXECUTION_ERROR",
                    remediation_latency_ms=max(0, int((clock() - now).total_seconds() * 1000)),
                )
            cost = (
                manifest.price.cost(observation.input_tokens, observation.output_tokens)
                if observation.usage_complete
                and observation.input_tokens is not None
                and observation.output_tokens is not None
                else None
            )
            # Release unused reservation only with complete receipts, including retry usage.
            debit = cost if cost is not None else start.reserved_usd
            final = CampaignTrialV1(
                **start.model_dump(
                    exclude={"state", "finished_at", "observation", "charged_usd", "estimated_cost_usd"}
                ),
                state="FINISHED",
                finished_at=clock(),
                observation=observation,
                charged_usd=debit,
                estimated_cost_usd=cost,
            )
            store.append(final)
            records.append(final)
            charged += debit
    return summarize_campaign(manifest, records)


def summarize_campaign(manifest: CampaignManifestV1, records: list[CampaignTrialV1]) -> CampaignResultV1:
    digest = "sha256:" + hashlib.sha256(manifest.model_dump_json().encode()).hexdigest()
    identities = {(r.case_id, r.trial_number) for r in records}
    if len(identities) != len(records) or any(r.manifest_digest != digest for r in records):
        raise ValueError("CAMPAIGN_RESULT_BINDING_MISMATCH")
    expected = {(c.case_id, n) for c in manifest.cases for n in range(1, c.repetitions + 1)}
    if not identities <= expected:
        raise ValueError("CAMPAIGN_UNKNOWN_TRIAL")
    results = []
    for case in manifest.cases:
        selected = [r for r in records if r.case_id == case.case_id]
        observations = [r.observation for r in selected if r.observation is not None]
        reasons = [_failure(case, o) for o in observations]
        successes = sum(reason is None for reason in reasons)
        latencies = sorted(o.remediation_latency_ms for o in observations)
        attempted = sum(r.state != "BUDGET_STOPPED" for r in selected)
        results.append(
            CampaignCaseResultV1(
                case_id=case.case_id,
                planned=case.repetitions,
                attempted=attempted,
                completed=len(observations),
                successful=successes,
                uncertain=sum(r.state == "STARTED" for r in selected),
                budget_stopped=sum(r.state == "BUDGET_STOPPED" for r in selected),
                failures=dict(Counter(reason for reason in reasons if reason is not None)),
                success_interval_95=_wilson(successes, attempted) if attempted else None,
                median_latency_ms=float(statistics.median(latencies)) if latencies else None,
                p95_latency_ms=float(latencies[math.ceil(len(latencies) * 0.95) - 1]) if latencies else None,
                input_tokens=_tokens(observations, "input_tokens"),
                output_tokens=_tokens(observations, "output_tokens"),
            )
        )
    measured = [r for r in records if r.state != "BUDGET_STOPPED"]
    return CampaignResultV1(
        campaign_id=manifest.campaign_id,
        manifest_digest=digest,
        cases=results,
        charged_usd=sum((r.charged_usd for r in records), Decimal(0)),
        estimated_cost_usd=(
            sum((r.estimated_cost_usd or Decimal(0) for r in measured), Decimal(0))
            if measured and all(r.estimated_cost_usd is not None for r in measured)
            else None
        ),
        complete=all(c.completed == c.planned for c in results),
    )


def _tokens(observations: list[CampaignObservationV1], field: str) -> int | None:
    values = [getattr(o, field) for o in observations]
    return sum(values) if values and all(v is not None for v in values) else None


def _wilson(successes: int, count: int) -> tuple[float, float]:
    z = 1.959963984540054
    proportion = successes / count
    divisor = 1 + z * z / count
    center = (proportion + z * z / (2 * count)) / divisor
    radius = z * math.sqrt(proportion * (1 - proportion) / count + z * z / (4 * count * count)) / divisor
    return max(0, center - radius), min(1, center + radius)


def _failure(case: CampaignCaseV1, observation: CampaignObservationV1) -> str | None:
    if observation.failure_code:
        return observation.failure_code
    if observation.status not in case.expected_statuses:
        return observation.status
    if not observation.cleanup_verified:
        return "CLEANUP_NOT_VERIFIED"
    if not observation.controls_verified:
        return "CONTROLS_NOT_VERIFIED"
    if case.require_draft and not observation.publication_verified:
        return "PUBLICATION_NOT_VERIFIED"
    if case.category == "attack" and observation.canary_leaked is not False:
        return "CANARY_LEAKED" if observation.canary_leaked else "CANARY_SCAN_INCOMPLETE"
    return None
