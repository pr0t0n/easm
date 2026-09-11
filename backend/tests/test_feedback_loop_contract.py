from app.services.pentest_outcome_learning import record_outcome
from app.services.scan_work_queue import update_skill_execution_score


def test_raw_candidate_does_not_make_skill_productive():
    state = {}
    update_skill_execution_score(state, "skill.sqli", "sqlmap", "unproductive", findings_count=3)
    row = state["skill_execution_scores"]["skill.sqli:sqlmap"]
    assert row["positives"] == 0
    assert row["utility_observations"] == 1


def test_confirmed_result_makes_skill_productive():
    state = {}
    update_skill_execution_score(state, "skill.sqli", "sqlmap", "productive", findings_count=1)
    row = state["skill_execution_scores"]["skill.sqli:sqlmap"]
    assert row["positives"] == 0
    assert row["utility_rate"] > 0
