"""Tests for helper.doc_analysis."""

from unittest.mock import MagicMock, patch

from helper.doc_analysis import (
    FEATURE_APPS,
    analyze_document,
    format_description,
    parse_app_data,
)


def test_format_description_bullets_and_summary():
    assert format_description(
        'Short summary.',
        ['Bullet one', 'Bullet two'],
    ) == '<ul><li>Bullet one</li><li>Bullet two</li></ul>Short summary.'


def test_format_description_summary_only():
    assert format_description('Only summary', None) == 'Only summary'
    assert format_description('Only summary', []) == 'Only summary'


def test_format_description_empty():
    assert format_description(None, None) == ''
    assert format_description(None, []) == ''


def test_parse_app_data():
    app_data = [
        {
            'app': 'TextSummarizer',
            'summary': 'First summary',
            'bullets': ['A', 'B'],
        },
        {
            'app': 'TextSummarizer',
            'summary': 'Second summary',
            'bullets': ['C'],
        },
        {
            'app': 'TextIndustrializer',
            'industry': ['Finance', 'Healthcare'],
        },
        {
            'objectType': 'attack pattern',
            'objectId': 'T1059',
        },
        {
            'objectType': 'attack pattern',
            'objectId': 'T1059',
        },
    ]
    result = parse_app_data(app_data)
    assert result['summary'] == 'First summary<br>Second summary'
    assert result['bullets'] == ['A', 'B', 'C']
    assert result['tags'] == ['Finance', 'Healthcare', 'T1059']


def test_analyze_document_posts_and_parses():
    response = MagicMock()
    response.status_code = 200
    response.raise_for_status = MagicMock()
    response.json.return_value = [
        {
            'appData': [
                {
                    'app': 'TextSummarizer',
                    'summary': 'AI summary',
                    'bullets': ['One'],
                }
            ]
        }
    ]

    with patch('helper.doc_analysis.requests.post', return_value=response) as post:
        result = analyze_document(
            'x' * 150_000,
            cal_token='HELIXTOKEN test',
            cal_timestamp=1234567890,
        )

    assert result['summary'] == 'AI summary'
    assert result['bullets'] == ['One']
    assert post.call_count == 1
    _, kwargs = post.call_args
    assert kwargs['params']['apps'] == FEATURE_APPS
    assert len(kwargs['json'][0]['text']) == 100_000
    assert kwargs['headers']['Authorization'] == 'HELIXTOKEN test'
    assert kwargs['headers']['Timestamp'] == '1234567890'
