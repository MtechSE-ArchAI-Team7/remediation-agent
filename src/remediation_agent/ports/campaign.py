"""Operator campaign boundaries, never model-callable tools."""

from typing import Protocol

from remediation_agent.domain.campaign import CampaignCaseV1, CampaignObservationV1, CampaignTrialV1


class CampaignExecutor(Protocol):
    async def execute(self, case: CampaignCaseV1, run_id: str) -> CampaignObservationV1: ...


class CampaignStore(Protocol):
    def read(self, case_id: str, trial_number: int) -> CampaignTrialV1 | None: ...

    def append(self, trial: CampaignTrialV1) -> None: ...
