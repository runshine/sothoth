from __future__ import annotations

import json
import time
import uuid
from typing import Any, Dict, Generator, List

from flask import Blueprint, Response, current_app, jsonify, request

from agent_ai_service.api.a2a_api import a2a

bp = Blueprint('openai_compat', __name__)


def _error_payload(message: str, code: str, error_type: str = 'invalid_request_error') -> Dict[str, Any]:
    return {
        'error': {
            'message': message,
            'type': error_type,
            'code': code,
        }
    }


def _extract_text_from_content(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: List[str] = []
        for item in content:
            if isinstance(item, dict) and item.get('type') == 'text':
                parts.append(str(item.get('text') or ''))
        return '\n'.join([part for part in parts if part]).strip()
    return ''


def _resolve_prompt(messages: Any) -> str:
    if not isinstance(messages, list) or not messages:
        return ''
    # Prefer the latest user message, fallback to latest message.
    latest_user = None
    latest_any = None
    for item in messages:
        if not isinstance(item, dict):
            continue
        text = _extract_text_from_content(item.get('content'))
        if not text:
            continue
        latest_any = text
        if str(item.get('role') or '').strip() == 'user':
            latest_user = text
    return latest_user or latest_any or ''


def _count_tokens_rough(text: str) -> int:
    # OpenAI usage field compatible best-effort estimate.
    return len([x for x in str(text or '').strip().split() if x])


def _to_chat_completion_response(
    completion_id: str,
    model: str,
    prompt: str,
    output: str,
    success: bool,
    finish_reason: str = 'stop',
) -> Dict[str, Any]:
    prompt_tokens = _count_tokens_rough(prompt)
    completion_tokens = _count_tokens_rough(output)
    return {
        'id': completion_id,
        'object': 'chat.completion',
        'created': int(time.time()),
        'model': model,
        'choices': [
            {
                'index': 0,
                'message': {
                    'role': 'assistant',
                    'content': output,
                },
                'finish_reason': finish_reason,
            }
        ],
        'usage': {
            'prompt_tokens': prompt_tokens,
            'completion_tokens': completion_tokens,
            'total_tokens': prompt_tokens + completion_tokens,
        },
        'success': success,
    }


@bp.post('/<agent_name>/chat/completions')
def chat_completions(agent_name: str):
    payload = request.get_json(silent=True) or {}
    stream = bool(payload.get('stream', False))
    request_model = str(payload.get('model') or '').strip()
    if request_model and request_model != agent_name:
        current_app.logger.warning(
            "OpenAI compat model mismatch: path agent=%s, payload model=%s. Using path agent.",
            agent_name,
            request_model,
        )

    messages = payload.get('messages')
    if not isinstance(messages, list):
        return jsonify(_error_payload('messages is required and must be a list', 'messages_required')), 400

    prompt = _resolve_prompt(messages)
    if not prompt:
        return jsonify(_error_payload('messages must include textual content', 'empty_prompt')), 400

    try:
        detail = a2a.backend_runtime.get_backend(agent_name)
    except KeyError:
        return jsonify(_error_payload(f'backend not found: {agent_name}', 'backend_not_found')), 404

    if not bool(detail.get('enabled', True)):
        return jsonify(_error_payload(f'backend is disabled: {agent_name}', 'backend_disabled')), 400

    completion_id = f"chatcmpl-{uuid.uuid4().hex}"
    invoke_payload = {
        'agent_id': agent_name,
        'prompt': prompt,
        'task': prompt,
        'messages': messages,
        'include_trace': bool(payload.get('include_trace', True)),
    }

    if not stream:
        try:
            response = a2a.invoke(invoke_payload)
        except Exception as exc:
            return jsonify(_error_payload(str(exc), 'invoke_failed', 'server_error')), 500
        output = str(response.get('output_text') or response.get('error') or '')
        success = str(response.get('status') or '') == 'completed'
        response = _to_chat_completion_response(
            completion_id=completion_id,
            model=agent_name,
            prompt=prompt,
            output=output,
            success=success,
            finish_reason='stop' if success else 'error',
        )
        return jsonify(response)

    def _stream() -> Generator[str, None, None]:
        try:
            # First role chunk keeps compatibility with common OpenAI SSE parsers.
            first_chunk = {
                'id': completion_id,
                'object': 'chat.completion.chunk',
                'created': int(time.time()),
                'model': agent_name,
                'choices': [
                    {
                        'index': 0,
                        'delta': {'role': 'assistant'},
                        'finish_reason': None,
                    }
                ],
            }
            yield f"data: {json.dumps(first_chunk, ensure_ascii=False)}\n\n"

            for frame in a2a.invoke_sse(invoke_payload):
                text = str(frame or '')
                if not text.startswith('data:'):
                    continue
                raw_data = text[5:].strip()
                if not raw_data or raw_data == '[DONE]':
                    continue
                try:
                    event = json.loads(raw_data)
                except Exception:
                    continue
                event_type = str(event.get('type') or '')
                if event_type == 'response.output_text.delta':
                    delta = str(event.get('delta') or '')
                    if not delta:
                        continue
                    chunk_payload = {
                        'id': completion_id,
                        'object': 'chat.completion.chunk',
                        'created': int(time.time()),
                        'model': agent_name,
                        'choices': [
                            {
                                'index': 0,
                                'delta': {'content': delta},
                                'finish_reason': None,
                            }
                        ],
                    }
                    yield f"data: {json.dumps(chunk_payload, ensure_ascii=False)}\n\n"
                    continue

                if event_type == 'response.failed':
                    response_payload = event.get('response') if isinstance(event.get('response'), dict) else {}
                    error_payload = _error_payload(
                        str(event.get('error_message') or response_payload.get('error') or 'invoke_failed'),
                        'invoke_failed',
                        'server_error',
                    )
                    yield f"data: {json.dumps(error_payload, ensure_ascii=False)}\n\n"
                    yield "data: [DONE]\n\n"
                    return
                if event_type == 'response.completed':
                    response_payload = event.get('response') if isinstance(event.get('response'), dict) else {}
                    success = str(response_payload.get('status') or '') == 'completed'
                    final_chunk = {
                        'id': completion_id,
                        'object': 'chat.completion.chunk',
                        'created': int(time.time()),
                        'model': agent_name,
                        'choices': [
                            {
                                'index': 0,
                                'delta': {},
                                'finish_reason': 'stop' if success else 'error',
                            }
                        ],
                    }
                    yield f"data: {json.dumps(final_chunk, ensure_ascii=False)}\n\n"
                    yield "data: [DONE]\n\n"
                    return

            fallback_error = _error_payload('stream ended without completion event', 'stream_incomplete', 'server_error')
            yield f"data: {json.dumps(fallback_error, ensure_ascii=False)}\n\n"
            yield "data: [DONE]\n\n"
        except Exception as exc:
            error_payload = _error_payload(str(exc), 'stream_failed', 'server_error')
            yield f"data: {json.dumps(error_payload, ensure_ascii=False)}\n\n"
            yield "data: [DONE]\n\n"

    return Response(
        _stream(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no',
        },
    )
