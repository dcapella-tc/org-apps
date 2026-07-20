"""Tests for helper.otx_batch_pulse.import_pulse."""

from unittest.mock import MagicMock

from helper.otx_batch_pulse import import_pulse


def _make_batch():
    batch = MagicMock()
    batch.generate_xid.side_effect = lambda parts: 'xid-' + '-'.join(str(p) for p in parts)

    def _obj_factory(*_args, **_kwargs):
        return MagicMock()

    batch.report.side_effect = _obj_factory
    batch.adversary.side_effect = _obj_factory
    batch.malware.side_effect = _obj_factory
    batch.vulnerability.side_effect = _obj_factory
    batch.host.side_effect = _obj_factory
    batch.file.side_effect = _obj_factory
    batch.address.side_effect = _obj_factory
    batch.url.side_effect = _obj_factory
    batch.email_address.side_effect = _obj_factory
    return batch


def test_import_pulse_creates_report_adversary_malware_indicators():
    batch = _make_batch()
    pulse = {
        'id': 'pulse-1',
        'name': 'Test Pulse',
        'description': 'Desc',
        'tlp': 'white',
        'adversary': 'Poisson',
        'tags': ['alpha'],
        'attack_ids': ['T1001'],
        'targeted_countries': ['India'],
        'malware_families': ['Popa', 'Loopop'],
        'indicators': [
            {
                'id': 101,
                'type': 'hostname',
                'indicator': 'bad.example',
                'created': '2026-06-19T11:24:45',
            },
            {
                'id': 102,
                'type': 'FileHash-SHA256',
                'indicator': 'aa' * 32,
            },
            {
                'id': 103,
                'type': 'CVE',
                'indicator': 'CVE-2024-1',
            },
        ],
        'more_indicators': False,
    }

    stats = import_pulse(batch, pulse, rating='4.0', confidence='80')

    assert stats == {
        'adversaries': 1,
        'malware': 2,
        'vulnerabilities': 1,
        'indicators': 2,
        'skipped_indicators': 0,
    }

    batch.report.assert_called_once()
    report_name = batch.report.call_args[0][0]
    report_kwargs = batch.report.call_args[1]
    assert report_name == 'Test Pulse'
    assert report_kwargs['xid'] == 'xid-otx-pulse-pulse-1'

    report_obj = batch.save.call_args_list[0][0][0]
    report_obj.tag.assert_any_call('alpha')
    report_obj.tag.assert_any_call('T1001')
    report_obj.tag.assert_any_call('Target Country:India')
    report_obj.attribute.assert_any_call('Description', 'Desc', True)
    report_obj.security_label.assert_called_with('TLP:WHITE')

    batch.adversary.assert_called_once()
    assert batch.adversary.call_args[0][0] == 'Poisson'
    assert batch.malware.call_count == 2

    batch.vulnerability.assert_called_once()
    assert batch.vulnerability.call_args[0][0] == 'CVE-2024-1'
    assert batch.vulnerability.call_args[1]['xid'] == 'xid-otx-vulnerability-103'

    for saved in batch.save.call_args_list[1:]:
        obj = saved[0][0]
        obj.association.assert_called_with('xid-otx-pulse-pulse-1')

    batch.host.assert_called_once()
    assert batch.host.call_args[0][0] == 'bad.example'
    assert batch.host.call_args[1]['rating'] == '4.0'
    assert batch.host.call_args[1]['confidence'] == '80'

    batch.file.assert_called_once()
    assert batch.file.call_args[1]['sha256'] == 'aa' * 32


def test_import_pulse_skips_empty_cve():
    batch = _make_batch()
    log = MagicMock()
    stats = import_pulse(
        batch,
        {
            'id': 'p-cve',
            'name': 'Empty CVE',
            'indicators': [{'type': 'CVE', 'indicator': '  '}],
            'malware_families': [],
        },
        log=log,
    )
    assert stats['vulnerabilities'] == 0
    assert stats['skipped_indicators'] == 1
    batch.vulnerability.assert_not_called()


def test_import_pulse_skips_missing_id():
    batch = _make_batch()
    stats = import_pulse(batch, {'name': 'No Id'})
    assert stats['adversaries'] == 0
    assert stats['malware'] == 0
    assert stats['indicators'] == 0
    batch.report.assert_not_called()


def test_import_pulse_skips_empty_adversary():
    batch = _make_batch()
    stats = import_pulse(
        batch,
        {
            'id': 'p3',
            'name': 'No Adv',
            'adversary': '  ',
            'indicators': [],
            'malware_families': [],
        },
    )
    assert stats['adversaries'] == 0
    batch.adversary.assert_not_called()


def test_import_pulse_warns_on_more_indicators():
    batch = _make_batch()
    log = MagicMock()
    import_pulse(
        batch,
        {
            'id': 'p2',
            'name': 'Truncated',
            'more_indicators': True,
            'indicators': [],
            'malware_families': [],
        },
        log=log,
    )
    assert any('more_indicators=true' in str(c) for c in log.warning.call_args_list)
