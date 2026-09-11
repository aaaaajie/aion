"""Owned request replay and bounded, evidence-only response comparison."""
from __future__ import annotations

import difflib
import json
from http.cookies import SimpleCookie
from typing import Any

from pydantic import Field, create_model

from .models import HttpModel, HttpRequestInput, HttpRequestSpec

# A partial version of the existing input contract. Fields explicitly supplied
# are validated by HttpRequestSpec after replacement, never recursively merged.
HttpOverrides = create_model(
    'HttpOverrides', __base__=HttpModel,
    **{name: (field.annotation, None) for name, field in HttpRequestInput.model_fields.items()},
)


class HttpReference(HttpModel):
    interaction_id: str = Field(min_length=1)
    request_id: str = Field(min_length=1)


class HttpReplayArguments(HttpReference):
    overrides: HttpOverrides = Field(default_factory=HttpOverrides)
    wait_seconds: float = Field(default=20, ge=0, le=20)


class HttpCompareArguments(HttpModel):
    left: HttpReference
    right: HttpReference
    max_body_bytes: int = Field(default=30000, ge=1, le=100000)


async def replay(client, args: HttpReplayArguments):
    manager, agent = client.manager, client.agent_id
    await manager._owned(agent, args.interaction_id)
    try:
        original = next((r for r in manager._load_plan(agent, args.interaction_id)
                         if r.request_id == args.request_id), None)
    except (OSError, ValueError):
        original = None
    if original is None:
        raise manager._error('not_found', 'http_request_unavailable', 'Owned request plan is unavailable')
    values = original.spec.model_dump(mode='json')
    values.update(args.overrides.model_dump(mode='json', exclude_unset=True))
    values.update(parent_request_id=args.request_id, sequence_id=None, request_intent='http_replay')
    spec = HttpRequestSpec.model_validate(values)
    result = await manager.start_request(agent, request=spec, wait_seconds=args.wait_seconds, result_limit=1)
    result['replay'] = {'parent_interaction_id': args.interaction_id,
                        'parent_request_id': args.request_id,
                        'session_id': spec.session_id,
                        'session_state': 'current_cookie_jar' if spec.session_id else 'explicit_request'}
    return result


def cookie_attributes(headers, raw_headers=None):
    cookies = SimpleCookie()
    try:
        for raw in raw_headers if raw_headers is not None else [headers.get('set-cookie', '')]:
            cookies.load(raw)
    except Exception:
        return {'parse_status': 'unavailable'}
    return {key: {attr: value for attr, value in morsel.items() if value}
            for key, morsel in cookies.items()}


def json_changes(left: Any, right: Any, path: str = ''):
    if type(left) is type(right) and isinstance(left, dict):
        for key in sorted(left.keys() | right.keys()):
            child = path + '/' + key.replace('~', '~0').replace('/', '~1')
            if key not in left or key not in right:
                yield {'path': child, 'change': 'added' if key not in left else 'removed'}
            else:
                yield from json_changes(left[key], right[key], child)
    elif left != right or type(left) is not type(right):
        yield {'path': path, 'change': 'changed'}


async def compare(client, args: HttpCompareArguments):
    manager, agent = client.manager, client.agent_id
    summaries, bodies = [], []
    for ref in (args.left, args.right):
        await manager._owned(agent, ref.interaction_id)
        record = manager._response_record(agent, ref.interaction_id, ref.request_id)
        if record is None:
            raise manager._error('not_found', 'http_response_not_found', 'Owned response record is unavailable')
        body = None
        state = 'missing'
        if manager._response_body_available(agent, ref.interaction_id, record):
            path = manager._response_dir(agent, ref.interaction_id) / record['body_file']
            with path.open('rb') as stream:
                body = stream.read(args.max_body_bytes)
            state = 'complete' if record.get('body_complete') and path.stat().st_size <= len(body) else 'truncated'
        headers = {k.lower(): v for k, v in record.get('headers', {}).items()}
        summaries.append({**ref.model_dump(), 'status_code': record.get('status_code'),
                          'location': headers.get('location'), 'cookies': cookie_attributes(headers, record.get('set_cookie_headers')),
                          'body_bytes': record.get('body_bytes'), 'body_state': state,
                          'execution_source': record.get('execution_source', 'http'),
                          'outcome': record.get('outcome')})
        bodies.append(body)
    changes, diff = [], None
    if all(body is not None for body in bodies):
        texts = [body.decode('utf-8', errors='replace') for body in bodies]
        diff = ''.join(difflib.unified_diff(texts[0].splitlines(True), texts[1].splitlines(True), fromfile='left', tofile='right'))
        if all(s['body_state'] == 'complete' for s in summaries):
            try:
                import itertools
                changes = list(itertools.islice(json_changes(*map(json.loads, texts)), 201))
            except (ValueError, RecursionError):
                pass
    return {'left': summaries[0], 'right': summaries[1], 'body_diff': diff[:30000] if diff is not None else None,
            'body_diff_truncated': diff is not None and len(diff) > 30000,
            'body_equal': bodies[0] == bodies[1] if all(s['body_state'] == 'complete' for s in summaries) else None,
            'json_changes': changes[:200], 'json_changes_truncated': len(changes) > 200, 'comparison_limits': {'diff_chars': 30000, 'json_changes': 200},
            'business_equivalence': 'not_determined', 'requests_sent': 0}
