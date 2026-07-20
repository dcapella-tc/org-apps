"""Tests for helper.otx_batch_status.batch_submit_succeeded."""

from helper.otx_batch_status import batch_submit_succeeded


def test_no_work_succeeds_even_if_empty_statuses():
    assert batch_submit_succeeded([], had_work=False) is True
    assert batch_submit_succeeded([{}], had_work=False) is True


def test_had_work_empty_list_fails():
    assert batch_submit_succeeded([], had_work=True) is False


def test_had_work_empty_dict_fails():
    assert batch_submit_succeeded([{}], had_work=True) is False
    assert batch_submit_succeeded([{}, {}], had_work=True) is False


def test_had_work_error_count_fails():
    assert (
        batch_submit_succeeded(
            [{'successCount': 10, 'errorCount': 1}],
            had_work=True,
        )
        is False
    )


def test_had_work_errors_list_fails():
    assert (
        batch_submit_succeeded(
            [{'successCount': 1, 'errors': [{'errorReason': 'nope'}]}],
            had_work=True,
        )
        is False
    )


def test_had_work_success_count_zero_fails():
    assert batch_submit_succeeded([{'successCount': 0}], had_work=True) is False


def test_had_work_success_status_ok():
    assert (
        batch_submit_succeeded(
            [{'id': 1, 'successCount': 5, 'errorCount': 0}],
            had_work=True,
        )
        is True
    )


def test_had_work_non_dict_fails():
    assert batch_submit_succeeded([None], had_work=True) is False
    assert batch_submit_succeeded('bad', had_work=True) is False
