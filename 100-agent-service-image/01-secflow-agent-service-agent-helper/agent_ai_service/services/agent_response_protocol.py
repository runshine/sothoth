from __future__ import annotations

import json
import time
import uuid
from typing import Any, Dict


SENSITIVE_KEYWORDS = (
    'token',
    'secret',
    'password',
    'authorization',
    'cookie',
    'api_key',
    'apikey',
    'access_key',
    'private_key',
    'bearer',
)


def utc_now_ts() -> int:
    return int(time.time())


def rough_token_count(text: str) -> int:
    return len([item for item in str(text or '').strip().split() if item])


def redact_trace_payload(value: Any, key_hint: str = '') -> Any:
    lowered_key = str(key_hint or '').strip().lower()
    if any(marker in lowered_key for marker in SENSITIVE_KEYWORDS):
        return '***'
    if isinstance(value, dict):
        return {
            str(key): redact_trace_payload(item, str(key))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_trace_payload(item, key_hint) for item in value]
    if isinstance(value, str):
        text = value
        lowered = text.lower()
        if any(marker in lowered for marker in ('bearer ', 'authorization:', 'cookie:', 'api_key', 'token=')):
            return '***'
        return text
    return value


def trace_item(
    category: str,
    message: str = '',
    payload: Any = None,
    severity: str = 'info',
    source: str | None = None,
) -> Dict[str, Any]:
    item: Dict[str, Any] = {
        'id': f"trace_{uuid.uuid4().hex}",
        'category': str(category or 'agent.substep'),
        'message': str(message or ''),
        'severity': str(severity or 'info'),
        'created': utc_now_ts(),
    }
    if source:
        item['source'] = str(source)
    if payload is not None:
        item['payload'] = redact_trace_payload(payload)
    return item


def new_response_state(
    *,
    agent_id: str,
    backend: str,
    session_id: str | None,
    mode: str,
    prompt: str,
    include_trace: bool,
    max_trace_events: int,
    max_trace_bytes: int,
) -> Dict[str, Any]:
    response_id = f"resp_{uuid.uuid4().hex}"
    return {
        'id': response_id,
        'object': 'agent.response',
        'created': utc_now_ts(),
        'agent_id': str(agent_id or backend or ''),
        'backend': str(backend or agent_id or ''),
        'session_id': str(session_id or '') or None,
        'mode': str(mode or 'invoke'),
        'status': 'in_progress',
        'output_text': '',
        'output': [],
        'trace': [],
        'trace_truncated': False,
        'error': None,
        'usage': {
            'input_tokens': rough_token_count(prompt),
            'output_tokens': 0,
            'reasoning_tokens': 0,
            'total_tokens': rough_token_count(prompt),
        },
        'success': False,
        'partial_success': False,
        'agent_count': 1,
        'success_count': 0,
        'results': [],
        '_prompt': str(prompt or ''),
        '_output_parts': [],
        '_reasoning_parts': [],
        '_trace_enabled': bool(include_trace),
        '_trace_bytes': 0,
        '_max_trace_events': max(1, int(max_trace_events or 1)),
        '_max_trace_bytes': max(512, int(max_trace_bytes or 512)),
    }


def append_output_delta(state: Dict[str, Any], text: str) -> None:
    chunk = str(text or '')
    if not chunk:
        return
    state['_output_parts'].append(chunk)
    state['output_text'] = ''.join(state['_output_parts'])


def append_reasoning_delta(state: Dict[str, Any], text: str) -> None:
    chunk = str(text or '')
    if not chunk:
        return
    state['_reasoning_parts'].append(chunk)


def append_trace_item(state: Dict[str, Any], item: Dict[str, Any]) -> None:
    if not state.get('_trace_enabled'):
        return
    encoded = json.dumps(item, ensure_ascii=False)
    projected_size = int(state.get('_trace_bytes', 0)) + len(encoded.encode('utf-8'))
    if len(state.get('trace', [])) >= int(state.get('_max_trace_events', 0)) or projected_size > int(state.get('_max_trace_bytes', 0)):
        state['trace_truncated'] = True
        return
    state['trace'].append(item)
    state['_trace_bytes'] = projected_size


def _trace_summary_text(trace: list[Dict[str, Any]]) -> str:
    if not trace:
        return ''
    counts: Dict[str, int] = {}
    for item in trace:
        category = str(item.get('category') or 'agent.substep')
        counts[category] = counts.get(category, 0) + 1
    parts = [f"{key} x{counts[key]}" for key in sorted(counts.keys())]
    return ' | '.join(parts)


def finalize_response(
    state: Dict[str, Any],
    *,
    status: str,
    error_message: str = '',
    legacy_raw: Any = None,
) -> Dict[str, Any]:
    output_text = ''.join(state.get('_output_parts', []))
    reasoning_text = ''.join(state.get('_reasoning_parts', []))
    output_items = []
    if output_text:
        output_items.append({
            'type': 'message',
            'role': 'assistant',
            'text': output_text,
        })
    if reasoning_text:
        output_items.append({
            'type': 'reasoning',
            'text': reasoning_text,
        })
    summary_text = _trace_summary_text(state.get('trace', []))
    if summary_text:
        output_items.append({
            'type': 'trace_summary',
            'text': summary_text,
        })

    success = str(status) == 'completed'
    usage = {
        'input_tokens': rough_token_count(state.get('_prompt', '')),
        'output_tokens': rough_token_count(output_text),
        'reasoning_tokens': rough_token_count(reasoning_text),
    }
    usage['total_tokens'] = usage['input_tokens'] + usage['output_tokens'] + usage['reasoning_tokens']

    state['status'] = status
    state['output_text'] = output_text
    state['output'] = output_items
    state['error'] = str(error_message or '') or None
    state['usage'] = usage
    state['success'] = success
    state['success_count'] = 1 if success else 0
    state['results'] = [{
        'agent_id': state.get('agent_id'),
        'backend': state.get('backend'),
        'success': success,
        'output': output_text if success else '',
        'error': '' if success else str(error_message or ''),
        'raw': legacy_raw,
    }]
    return {
        key: value
        for key, value in state.items()
        if not str(key).startswith('_')
    }


def response_created_event(state: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'type': 'response.created',
        'response': {
            'id': state.get('id'),
            'object': state.get('object'),
            'created': state.get('created'),
            'agent_id': state.get('agent_id'),
            'backend': state.get('backend'),
            'session_id': state.get('session_id'),
            'mode': state.get('mode'),
            'status': state.get('status'),
        },
    }


def response_output_delta_event(state: Dict[str, Any], text: str) -> Dict[str, Any]:
    return {
        'type': 'response.output_text.delta',
        'response_id': state.get('id'),
        'session_id': state.get('session_id'),
        'agent_id': state.get('agent_id'),
        'delta': str(text or ''),
    }


def response_reasoning_delta_event(state: Dict[str, Any], text: str) -> Dict[str, Any]:
    return {
        'type': 'response.reasoning.delta',
        'response_id': state.get('id'),
        'session_id': state.get('session_id'),
        'agent_id': state.get('agent_id'),
        'delta': str(text or ''),
    }


def response_trace_item_event(state: Dict[str, Any], item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'type': 'response.trace.item',
        'response_id': state.get('id'),
        'session_id': state.get('session_id'),
        'agent_id': state.get('agent_id'),
        'item': item,
    }


def response_completed_event(response: Dict[str, Any], session: Dict[str, Any] | None = None) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        'type': 'response.completed',
        'response': response,
    }
    if session is not None:
        payload['session'] = session
    return payload


def response_failed_event(response: Dict[str, Any], error_message: str, session: Dict[str, Any] | None = None) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        'type': 'response.failed',
        'error_message': str(error_message or ''),
        'response': response,
    }
    if session is not None:
        payload['session'] = session
    return payload
