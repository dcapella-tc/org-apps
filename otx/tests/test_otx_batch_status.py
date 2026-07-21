"""Tests for helper.otx_batch_status.summarize_batch_errors."""

from helper.otx_batch_status import summarize_batch_errors


def test_no_errors_returns_none():
    assert (
        summarize_batch_errors(
            [{'id': 1, 'successCount': 5, 'errorCount': 0}],
        )
        is None
    )


def test_partial_errors_summarized():
    summary = summarize_batch_errors(
        [
            {
                'status': 'Completed',
                'successCount': 4995,
                'errorCount': 50,
                'errors': [{'errorReason': 'URL invalid'}],
            },
            {
                'status': 'Completed',
                'successCount': 2070,
                'errorCount': 2,
                'errors': [{'errorReason': 'another bad url'}],
            },
        ]
    )
    assert summary is not None
    assert 'errors=52' in summary
    assert 'successCount=7065' in summary
    assert 'URL invalid' in summary


def test_empty_statuses():
    assert summarize_batch_errors([]) == 'batch returned no status entries'
    assert summarize_batch_errors([{}]) == 'batch returned empty or invalid status entry'
