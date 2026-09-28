"""Copy a ThreatConnect group into one or more owners."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

# Batch file summaries are ``md5 : sha1 : sha256``. A lone hash is classified by length.
_HASH_LENGTHS = {32: 0, 40: 1, 64: 2}
_SCALAR_FIELDS = (
    'status',
    'eventDate',
    'eventType',
    'firstSeen',
    'lastSeen',
    'fileName',
    'subject',
    'header',
    'body',
    'from',
    'publishDate',
)


class PublishError(Exception):
    """Raised when the request cannot be published."""


@dataclass
class PublishRequest:
    """Parsed security-export payload."""

    group_id: int
    owners: list[str]
    update: bool = False
    include_tags: bool = False
    include_attributes: bool = False
    include_indicators: bool = False
    include_groups: bool = False
    excluded_security_labels: set[str] = field(default_factory=set)


def parse_request(raw: str | dict) -> PublishRequest:
    """Parse the security-export JSON.

    ``update`` defaults to false when the key is omitted.
    """
    if isinstance(raw, dict):
        payload = raw
    else:
        try:
            payload = json.loads(str(raw))
        except json.JSONDecodeError as ex:
            raise PublishError('Request JSON is invalid') from ex
    if not isinstance(payload, dict):
        raise PublishError('Request JSON must be an object')

    custom = payload.get('custom') or {}
    if not isinstance(custom, dict) or custom.get('group_id') is None:
        raise PublishError('custom.group_id is required')
    owners = payload.get('owners')
    if not isinstance(owners, list) or not owners:
        raise PublishError('owners is required')

    return PublishRequest(
        group_id=int(custom['group_id']),
        owners=[str(owner) for owner in owners],
        update=_flag(payload.get('update', False)),
        include_tags=_flag(payload.get('includeTags', False)),
        include_attributes=_flag(payload.get('includeAttributes', False)),
        include_indicators=_flag(payload.get('includeAssociatedIndicators', False)),
        include_groups=_flag(payload.get('includeAssociatedGroups', False)),
        excluded_security_labels={
            str(name) for name in (payload.get('excludedSecurityLabels') or []) if name
        },
    )


def publish(
    session: Any,
    batch_factory: Callable[[str], Any],
    raw: str | dict,
    generate_xid: Callable[[list], str],
) -> list[dict[str, str]]:
    """Publish the source group into each owner that still needs it.

    ``generate_xid`` is ``Batch.generate_xid2``. Pass ``[owner, type, name]``.
    When ``update`` is false and that xid already exists in the owner, the owner
    is recorded as ``existing`` and no batch is opened.
    """
    request = parse_request(raw)
    source = fetch_group(session, request.group_id, request, include_associations=True)
    _require_identity(source)

    results: list[dict[str, str]] = []
    for owner in request.owners:
        xid = generate_xid([owner, source.get('type'), source.get('name')])
        if not request.update and group_exists(session, owner, xid):
            results.append({'owner': owner, 'xid': xid, 'status': 'existing'})
            continue

        batch = batch_factory(owner)
        try:
            batch.file_merge_mode('Merge')
            stage_group(
                batch,
                source,
                owner,
                request,
                generate_xid,
                session,
                xid=xid,
                parent_xid=None,
            )
            _raise_batch_errors(batch.submit_all())
            results.append({'owner': owner, 'xid': xid, 'status': 'published'})
        finally:
            batch.close()
    return results


def fetch_group(
    session: Any,
    group_id: int | str,
    request: PublishRequest,
    *,
    include_associations: bool,
) -> dict:
    """GET a v3 group, including only the fields this request will copy."""
    response = session.get(
        f'/v3/groups/{group_id}',
        params={'fields': _fields(request, include_associations=include_associations)},
    )
    if response.status_code == 404:
        raise PublishError(f'Group {group_id} was not found')
    response.raise_for_status()
    body = response.json()
    data = body.get('data', body) if isinstance(body, dict) else None
    if not isinstance(data, dict):
        raise PublishError(f'Group {group_id} was not found')
    return data


def group_exists(session: Any, owner: str, xid: str) -> bool:
    """Return whether ``GET /v3/groups/{xid}?owner=`` finds the group."""
    response = session.get(f'/v3/groups/{xid}', params={'owner': owner})
    if response.status_code == 200:
        return True
    if response.status_code == 404:
        return False
    response.raise_for_status()
    raise PublishError(f'Unable to look up xid {xid} in owner {owner}')


def stage_group(
    batch: Any,
    group: dict,
    owner: str,
    request: PublishRequest,
    generate_xid: Callable[[list], str],
    session: Any,
    *,
    xid: str,
    parent_xid: str | None,
) -> None:
    """Stage one group and the include flags that are on."""
    _require_identity(group)
    staged = batch.group(group.get('type'), group.get('name'), xid=xid)
    _apply_scalars(staged, group)
    _apply_labels(staged, group, request.excluded_security_labels)
    _apply_tags(staged, group, request.include_tags)
    _apply_attributes(staged, group, request.include_attributes)
    if parent_xid:
        staged.association(parent_xid)
    batch.save(staged)
    _stage_indicators(batch, group, xid, request)
    _stage_associated_groups(
        batch,
        group,
        owner,
        request,
        generate_xid,
        session,
        parent_xid=parent_xid,
        xid=xid,
    )


def stage_indicator(
    batch: Any,
    indicator: dict,
    group_xid: str,
    excluded_security_labels: set[str],
) -> None:
    """Stage an indicator and associate it to ``group_xid``.

    File indicators are upserted with ``batch.file`` (the batch job is in
    file-merge mode). Every other type is staged from its summary.
    """
    indicator_type = str(indicator.get('type') or '')
    if indicator_type.lower() == 'file':
        md5, sha1, sha256 = _file_hashes(indicator)
        if not any((md5, sha1, sha256)):
            return
        staged = batch.file(md5, sha1, sha256)
    else:
        summary = indicator.get('summary')
        if not indicator_type or not summary:
            return
        staged = batch.indicator(indicator_type, summary)

    if indicator.get('rating') is not None:
        staged.rating = indicator['rating']
    if indicator.get('confidence') is not None:
        staged.confidence = indicator['confidence']
    _apply_labels(staged, indicator, excluded_security_labels)
    staged.association(group_xid)
    batch.save(staged)


def _apply_scalars(staged: Any, group: dict) -> None:
    for key in _SCALAR_FIELDS:
        value = group.get(key)
        if value not in (None, ''):
            staged.add_key_value(key, value)


def _apply_tags(staged: Any, group: dict, include: bool) -> None:
    if not include:
        return
    for tag in _data_list(group, 'tags'):
        name = tag.get('name')
        if name:
            staged.tag(name)


def _apply_attributes(staged: Any, group: dict, include: bool) -> None:
    if not include:
        return
    for attr in _data_list(group, 'attributes'):
        attr_type = attr.get('type')
        value = attr.get('value')
        if attr_type and value is not None:
            staged.attribute(attr_type, str(value), bool(attr.get('default', False)))


def _stage_indicators(batch: Any, group: dict, xid: str, request: PublishRequest) -> None:
    if not request.include_indicators:
        return
    for indicator in _data_list(group, 'associatedIndicators'):
        stage_indicator(batch, indicator, xid, request.excluded_security_labels)


def _stage_associated_groups(
    batch: Any,
    group: dict,
    owner: str,
    request: PublishRequest,
    generate_xid: Callable[[list], str],
    session: Any,
    *,
    parent_xid: str | None,
    xid: str,
) -> None:
    if not request.include_groups or parent_xid is not None:
        return
    for child in _data_list(group, 'associatedGroups'):
        child_id = child.get('id')
        if child_id is None:
            continue
        full_child = fetch_group(session, child_id, request, include_associations=False)
        _require_identity(full_child)
        child_xid = generate_xid([owner, full_child.get('type'), full_child.get('name')])
        stage_group(
            batch,
            full_child,
            owner,
            request,
            generate_xid,
            session,
            xid=child_xid,
            parent_xid=xid,
        )


def _fields(request: PublishRequest, *, include_associations: bool) -> list[str]:
    fields = ['securityLabels']
    if request.include_tags:
        fields.append('tags')
    if request.include_attributes:
        fields.append('attributes')
    if request.include_indicators:
        fields.extend(['associatedIndicators', 'associatedIndicators.securityLabels'])
    if include_associations and request.include_groups:
        fields.append('associatedGroups')
    return fields


def _data_list(obj: dict, key: str) -> list[dict]:
    value = obj.get(key) or {}
    if isinstance(value, dict):
        return [item for item in (value.get('data') or []) if isinstance(item, dict)]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def _apply_labels(obj: Any, source: dict, excluded: set[str]) -> None:
    for label in _data_list(source, 'securityLabels'):
        name = label.get('name')
        if name and name not in excluded:
            obj.security_label(name)


def _file_hashes(indicator: dict) -> tuple[str | None, str | None, str | None]:
    hashes = [
        _text(indicator.get('md5')),
        _text(indicator.get('sha1')),
        _text(indicator.get('sha256')),
    ]
    if any(hashes):
        return hashes[0], hashes[1], hashes[2]

    parts = [part.strip() for part in str(indicator.get('summary') or '').split(' : ')]
    if len(parts) == 1:
        slot = _HASH_LENGTHS.get(len(parts[0]))
        if slot is None or not parts[0]:
            return None, None, None
        hashes[slot] = parts[0]
        return hashes[0], hashes[1], hashes[2]

    while len(parts) < 3:
        parts.append('')
    return _text(parts[0]), _text(parts[1]), _text(parts[2])


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _flag(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {'1', 'true', 'yes'}
    return bool(value)


def _require_identity(group: dict) -> None:
    if not group.get('type') or not group.get('name'):
        raise PublishError('Group type and name are required')


def _raise_batch_errors(batch_data: list | None) -> None:
    errors: list[Any] = []
    for item in batch_data or []:
        if not isinstance(item, dict):
            continue
        found = item.get('errors')
        if not found:
            continue
        if isinstance(found, list):
            errors.extend(found)
        else:
            errors.append(found)
    if errors:
        raise PublishError(f'Batch import failed: {errors}')
