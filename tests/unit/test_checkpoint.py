"""Checkpoint serialization has an explicit allowlist and no pickle fallback."""

from __future__ import annotations

from remediation_agent.adapters.checkpoint import checkpoint_serializer, postgres_checkpointer
from tests.conftest import diagnosis_handoff


def test_domain_model_round_trip_uses_non_pickle_serializer() -> None:
    serializer = checkpoint_serializer()
    type_name, payload = serializer.dumps_typed(diagnosis_handoff())
    restored = serializer.loads_typed((type_name, payload))
    assert type_name == "msgpack"
    assert restored == diagnosis_handoff()
    assert serializer.pickle_fallback is False


async def test_invalid_checkpoint_encryption_key_fails_before_database_access() -> None:
    try:
        async with postgres_checkpointer("postgresql://unused", "too-short"):
            raise AssertionError("context should not be entered")
    except ValueError as exc:
        assert "16, 24, or 32" in str(exc)
