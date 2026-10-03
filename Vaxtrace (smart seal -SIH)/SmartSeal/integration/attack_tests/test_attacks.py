import pytest

from integration.attack_tests.harness import SCENARIOS, run_all

IDS = [s[0] for s in SCENARIOS if s[0] != 12]


@pytest.mark.parametrize("sid", IDS)
def test_attack_scenario(sid):
    r = run_all(only={sid})["results"][0]
    assert r["status"] == "PASS", r["observed"]


def test_validator_scenario_is_skipped_not_faked_without_besu():
    r = run_all(only={12})["results"][0]
    assert r["status"] == "SKIPPED" and "refuses to fake quorum" in r["observed"]["reason"]
