"""Every accepted checkout/purchase assertion has exactly one criterion mapping."""

import json
from pathlib import Path


def test_criterion_mapping_is_complete_without_expanding_checkout_contract() -> None:
    root = Path(__file__).parents[2]
    mapping = json.loads((root / "config/evaluation/gap-closure-criteria.json").read_text())
    profiles = json.loads((root / mapping["profiles_source"]).read_text())
    rows = mapping["criteria"]
    assert len({r["criterion_id"] for r in rows}) == len(rows)
    for profile in ("ecommerce_purchase", "ecommerce_checkout"):
        selected = [r for r in rows if r["profile"] == profile and r["scope"] != "out_of_scope"]
        mapped = [test for row in selected for test in row["test_ids"]]
        assert len(mapped) == len(set(mapped)) and set(mapped) == set(profiles[profile]["assertions"])
        assert {r["criterion_id"] for r in selected if r["scope"] == "regression"} == set(
            profiles[profile]["regression_test_ids"]
        )
    excluded = [r for r in rows if r["scope"] == "out_of_scope"]
    assert {r["criterion_id"] for r in excluded} == {
        "email_delivery",
        "user_association",
        "line_items",
        "checkout_inventory",
        "checkout_idempotency",
    }
    assert all(not r["test_ids"] and r["description"] for r in excluded)
