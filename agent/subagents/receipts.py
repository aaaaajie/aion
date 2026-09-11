"""Submission reports preserve uncertainty independently of challenge completion."""

from collections.abc import Mapping


def submission_report(unique_code, result, completed):
    data = result.get("data")
    data = data if isinstance(data, Mapping) else {}
    error = result.get("error")
    error = error if isinstance(error, Mapping) else {}
    correct = data.get("correct") if result.get("ok") else None
    correct = correct if isinstance(correct, bool) else None
    duplicate = data.get("duplicate") is True or error.get("code") == "duplicate"
    return {
        "type": "challenge_flag",
        "unique_code": unique_code,
        "correct": correct,
        "challenge_completed": completed,
        "awarded": data.get("awarded") if result.get("ok") else None,
        "duplicate": duplicate,
        "error": error or None,
        "outcome": "duplicate" if duplicate else (
            "correct" if correct is True else "incorrect" if correct is False else "unknown"
        ),
    }
