"""Tests for _execute_error — the RPC result failure check that stops the
server reporting a handler/module as running when msfrpcd never started it.

Regression coverage for the observed bug: start_handler returned
status="listening" with a null job_id because msfrpcd rejected the
AutoLoadExtensions payload option ("must be a scalar") and returned an error
dict instead of raising, which the old code read job_id/uuid off and ignored.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from server import _execute_error  # noqa: E402


def test_successful_job_result_is_not_an_error():
    assert _execute_error({"job_id": 0, "uuid": "abc"}, expect_job=True) is None
    assert _execute_error({"job_id": 5}, expect_job=True) is None


def test_explicit_error_dict_is_surfaced():
    msg = _execute_error(
        {
            "error": True,
            "error_message": "Invalid module option value for "
            "AutoLoadExtensions: must be a scalar",
        },
        expect_job=True,
    )
    assert msg is not None
    assert "AutoLoadExtensions" in msg


def test_error_dict_without_job_flag_prefers_message_fields():
    assert _execute_error({"error": True, "error_message": "boom"}) == "boom"
    assert _execute_error({"error": True, "error_string": "bang"}) == "bang"


def test_null_job_id_is_a_failure_when_a_job_is_expected():
    # The silent case: no error flag, but no job either — handler never bound.
    msg = _execute_error({"job_id": None}, expect_job=True)
    assert msg is not None
    assert "job_id" in msg


def test_null_job_id_is_fine_when_no_job_is_expected():
    # run_module with as_job=False (aux/post run inline) legitimately has no
    # job_id — must not be flagged as a failure.
    assert _execute_error({"job_id": None, "result": "done"}) is None
    assert _execute_error({"result": "done"}) is None


def test_non_dict_result_is_an_error():
    assert _execute_error(None, expect_job=True) is not None
    assert _execute_error("listening") is not None
