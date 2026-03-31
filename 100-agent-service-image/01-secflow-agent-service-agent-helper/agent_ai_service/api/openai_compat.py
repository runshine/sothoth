from __future__ import annotations

import json
import time
import uuid
from typing import Any, Dict, Generator, List

from flask import Blueprint, Response, current_app, jsonify, request

from agent_ai_service.api.backends import runtime

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
        detail = runtime.get_backend(agent_name)
    except KeyError:
        return jsonify(_error_payload(f'backend not found: {agent_name}', 'backend_not_found')), 404

    if not bool(detail.get('enabled', True)):
        return jsonify(_error_payload(f'backend is disabled: {agent_name}', 'backend_disabled')), 400

    completion_id = f"chatcmpl-{uuid.uuid4().hex}"

    if not stream:
        try:
            result = runtime.invoke_backend(agent_name, prompt, messages)
        except Exception as exc:
            return jsonify(_error_payload(str(exc), 'invoke_failed', 'server_error')), 500
        output = str(result.get('stdout') or result.get('stderr') or result.get('error') or '')
        response = _to_chat_completion_response(
            completion_id=completion_id,
            model=agent_name,
            prompt=prompt,
            output=output,
            success=bool(result.get('success', False)),
            finish_reason='stop' if bool(result.get('success', False)) else 'error',
        )
        return jsonify(response)

    def _stream() -> Generator[str, None, None]:
        aggregated_output: List[str] = []
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

            done_event: Dict[str, Any] | None = None
            for event in runtime.invoke_backend_stream(agent_name, prompt, messages):
                event_type = str(event.get('type') or '')
                if event_type == 'chunk':
                    text = str(event.get('text') or '')
                    if not text:
                        continue
                    aggregated_output.append(text)
                    chunk_payload = {
                        'id': completion_id,
                        'object': 'chat.completion.chunk',
                        'created': int(time.time()),
                        'model': agent_name,
                        'choices': [
                            {
                                'index': 0,
                                'delta': {'content': text},
                                'finish_reason': None,
                            }
                        ],
                    }
                    yield f"data: {json.dumps(chunk_payload, ensure_ascii=False)}\n\n"
                    continue

                if event_type == 'done':
                    done_event = event
                    break

                if event_type == 'error':
                    error_payload = _error_payload(str(event.get('error') or 'invoke_failed'), 'invoke_failed', 'server_error')
                    yield f"data: {json.dumps(error_payload, ensure_ascii=False)}\n\n"
                    yield "data: [DONE]\n\n"
                    return

            output = ''.join(aggregated_output)
            if done_event and not output:
                output = str(done_event.get('stdout') or done_event.get('stderr') or '')
            final_chunk = {
                'id': completion_id,
                'object': 'chat.completion.chunk',
                'created': int(time.time()),
                'model': agent_name,
                'choices': [
                    {
                        'index': 0,
                        'delta': {},
                        'finish_reason': 'stop' if bool(done_event and done_event.get('success')) else 'error',
                    }
                ],
            }
            yield f"data: {json.dumps(final_chunk, ensure_ascii=False)}\n\n"
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
