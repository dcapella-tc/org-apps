"""Import one OTX pulse into a ThreatConnect v2 batch (Report hub)."""

from __future__ import annotations

from typing import Any, Protocol

from helper.otx_batch_attrs import build_pulse_attributes, tlp_security_label
from helper.otx_batch_tags import build_pulse_tags
from helper.otx_indicator_map import map_otx_indicator


class _Log(Protocol):
    def info(self, msg: str, *args: Any) -> None: ...

    def warning(self, msg: str, *args: Any) -> None: ...


def import_pulse(
    batch: Any,
    pulse: dict[str, Any],
    *,
    rating: str = '3.0',
    confidence: str = '50',
    log: _Log | None = None,
) -> dict[str, int]:
    """Create a Report plus associated malware, adversaries, and indicators.

    Returns:
        Counts: ``adversaries``, ``malware``, ``indicators``, ``skipped_indicators``.
    """
    stats = {
        'adversaries': 0,
        'malware': 0,
        'indicators': 0,
        'skipped_indicators': 0,
    }

    pulse_id = pulse.get('id')
    name = str(pulse.get('name') or '').strip() or f'OTX Pulse {pulse_id}'
    if pulse_id is None:
        if log:
            log.warning('otx-batch skipping pulse without id name=%s', name)
        return stats

    report_xid = batch.generate_xid(['otx', 'pulse', str(pulse_id)])
    report_kwargs: dict[str, Any] = {'xid': report_xid}
    created = pulse.get('created')
    if created:
        report_kwargs['publish_date'] = str(created)

    report = batch.report(name, **report_kwargs)

    for tag_name in build_pulse_tags(pulse):
        report.tag(tag_name)

    for attr_type, attr_value, displayed in build_pulse_attributes(pulse):
        report.attribute(attr_type, attr_value, displayed)

    label = tlp_security_label(pulse.get('tlp'))
    if label:
        report.security_label(label)

    batch.save(report)

    if pulse.get('more_indicators'):
        if log:
            log.warning(
                'otx-batch pulse_id=%s more_indicators=true; '
                'importing only indicators present in payload',
                pulse_id,
            )

    adversary_name = str(pulse.get('adversary') or '').strip()
    if adversary_name:
        adv_xid = batch.generate_xid(
            ['otx', 'adversary', str(pulse_id), adversary_name]
        )
        adversary = batch.adversary(adversary_name, xid=adv_xid)
        adversary.association(report_xid)
        batch.save(adversary)
        stats['adversaries'] += 1

    for family in pulse.get('malware_families') or []:
        family_name = str(family).strip()
        if not family_name:
            continue
        malware_xid = batch.generate_xid(
            ['otx', 'malware', str(pulse_id), family_name]
        )
        malware = batch.malware(family_name, xid=malware_xid)
        malware.association(report_xid)
        batch.save(malware)
        stats['malware'] += 1

    for raw_ind in pulse.get('indicators') or []:
        mapped = map_otx_indicator(raw_ind if isinstance(raw_ind, dict) else None)
        if mapped is None:
            otx_type = (
                raw_ind.get('type') if isinstance(raw_ind, dict) else type(raw_ind).__name__
            )
            if log:
                log.warning(
                    'otx-batch skipping unsupported indicator type=%s pulse_id=%s',
                    otx_type,
                    pulse_id,
                )
            stats['skipped_indicators'] += 1
            continue

        xid_parts = ['otx', 'indicator']
        if mapped.otx_id:
            xid_parts.append(mapped.otx_id)
        else:
            # Fall back to type + value for reproducibility when id is missing.
            xid_parts.extend([mapped.method, str(sorted(mapped.kwargs.items()))])
        ind_xid = batch.generate_xid(xid_parts)

        common: dict[str, Any] = {
            'rating': str(rating),
            'confidence': str(confidence),
            'xid': ind_xid,
        }
        if mapped.created:
            common['date_added'] = mapped.created

        indicator_obj = _create_indicator(batch, mapped.method, mapped.kwargs, common)
        if indicator_obj is None:
            stats['skipped_indicators'] += 1
            continue

        if mapped.description:
            indicator_obj.attribute('Description', mapped.description, True)

        indicator_obj.association(report_xid)
        batch.save(indicator_obj)
        stats['indicators'] += 1

    if log:
        log.info(
            'otx-batch pulse_id=%s report_xid=%s adversaries=%s malware=%s '
            'indicators=%s skipped=%s',
            pulse_id,
            report_xid,
            stats['adversaries'],
            stats['malware'],
            stats['indicators'],
            stats['skipped_indicators'],
        )

    return stats


def _create_indicator(
    batch: Any,
    method: str,
    value_kwargs: dict[str, Any],
    common: dict[str, Any],
) -> Any | None:
    """Invoke the appropriate batch indicator factory."""
    if method == 'address':
        return batch.address(value_kwargs['ip'], **common)
    if method == 'host':
        return batch.host(value_kwargs['hostname'], **common)
    if method == 'url':
        return batch.url(value_kwargs['text'], **common)
    if method == 'email_address':
        return batch.email_address(value_kwargs['address'], **common)
    if method == 'file':
        return batch.file(**value_kwargs, **common)
    return None
