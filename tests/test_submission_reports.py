import pytest

from agent.subagents.receipts import submission_report


@pytest.mark.parametrize("result,completed,outcome,correct", [
    ({"ok": True, "data": {"correct": True, "awarded": 100}}, True, "correct", True),
    ({"ok": True, "data": {"correct": True, "awarded": 50}}, False, "correct", True),
    ({"ok": True, "data": {"correct": False, "awarded": 0}}, False, "incorrect", False),
    ({"ok": False, "error": {"code": "duplicate"}}, True, "duplicate", None),
    ({"ok": False, "error": {"code": "transport_error"}}, False, "unknown", None),
    ({"ok": True, "data": {"reconciled": True}}, True, "unknown", None),
])
def test_report_does_not_conflate_submission_with_completion(result, completed, outcome, correct):
    report = submission_report("fixture", result, completed)
    assert report["outcome"] == outcome
    assert report["correct"] is correct
    assert report["challenge_completed"] is completed
    assert "accepted" not in report
    if not result.get("ok"):
        assert report["awarded"] is None
