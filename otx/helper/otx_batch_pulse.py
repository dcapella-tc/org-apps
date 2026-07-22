"""Import one OTX pulse into a ThreatConnect v2 batch (Report hub)."""

from __future__ import annotations

from typing import Any, Protocol

from helper.otx_batch_attrs import build_pulse_attributes, tlp_security_label
from helper.otx_batch_tags import build_pulse_tags
from helper.otx_indicator_map import map_otx_indicator
from helper.otx_target_country import resolve_targeted_countries


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
    """Create a Report plus associated malware, adversaries, CVEs, and indicators.

    Returns:
        Counts: ``adversaries``, ``malware``, ``vulnerabilities``, ``indicators``,
        ``skipped_indicators``.
    """
    stats = {
        'adversaries': 0,
        'malware': 0,
        'vulnerabilities': 0,
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
        created_text = str(created).strip()
        if created_text:
            report_kwargs['publish_date'] = created_text
            report_kwargs['external_date_created'] = created_text
    modified = pulse.get('modified')
    if modified:
        modified_text = str(modified).strip()
        if modified_text:
            report_kwargs['external_last_modified'] = modified_text

    report = batch.report(name, **report_kwargs)

    _mapped_countries, unmatched_countries = resolve_targeted_countries(pulse)
    if log:
        for country in unmatched_countries:
            log.warning(
                'otx-batch pulse_id=%s unmatched target country=%s; tagging instead',
                pulse_id,
                country,
            )

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
        if isinstance(raw_ind, dict) and str(raw_ind.get('type') or '').strip() == 'CVE':
            if _import_cve_vulnerability(batch, raw_ind, pulse_id, report_xid, log=log):
                stats['vulnerabilities'] += 1
            else:
                stats['skipped_indicators'] += 1
            continue

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
            'vulnerabilities=%s indicators=%s skipped=%s',
            pulse_id,
            report_xid,
            stats['adversaries'],
            stats['malware'],
            stats['vulnerabilities'],
            stats['indicators'],
            stats['skipped_indicators'],
        )

    return stats


def _import_cve_vulnerability(
    batch: Any,
    raw_ind: dict[str, Any],
    pulse_id: Any,
    report_xid: str,
    *,
    log: _Log | None = None,
) -> bool:
    """Create a Vulnerability group for an OTX CVE indicator. Return True if queued."""
    cve_name = str(raw_ind.get('indicator') or '').strip()
    if not cve_name:
        if log:
            log.warning(
                'otx-batch skipping CVE without value pulse_id=%s',
                pulse_id,
            )
        return False

    otx_id = raw_ind.get('id')
    if otx_id is not None:
        vuln_xid = batch.generate_xid(['otx', 'vulnerability', str(otx_id)])
    else:
        vuln_xid = batch.generate_xid(
            ['otx', 'vulnerability', str(pulse_id), cve_name]
        )

    vulnerability = batch.vulnerability(cve_name, xid=vuln_xid)
    vulnerability.association(report_xid)
    batch.save(vulnerability)
    return True


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
