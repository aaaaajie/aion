"""JSON stdin/--job CLI for the AION CyberChef subset."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import multiprocessing
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from .engine import OperationError, OPERATIONS, execute_recipe, operation_config

VERSION = '11.2.0-aion-python'
MAX_BYTES = 4 * 1024 * 1024
MAX_STEPS = 32


def _error(code: str, message: str, detail: Any = None, *, state: str = 'failed') -> dict[str, Any]:
    result: dict[str, Any] = {'state': state, 'code': code, 'error': message}
    if detail is not None:
        result['detail'] = detail
    return result


def _read_job(args: argparse.Namespace) -> dict[str, Any]:
    if args.job:
        try:
            return json.loads(Path(args.job).read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError) as exc:
            raise OperationError('invalid_input', f'Unable to read job: {exc}') from exc
    try:
        value = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        raise OperationError('invalid_input', 'stdin is not valid JSON') from exc
    if not isinstance(value, dict):
        raise OperationError('invalid_input', 'The JSON job must be an object')
    return value


def _input_bytes(job: dict[str, Any]) -> bytes:
    if 'input' not in job or not isinstance(job['input'], str):
        raise OperationError('invalid_input', 'bake requires a string input')
    value = job['input']
    encoding = job.get('input_encoding', 'utf8')
    try:
        if encoding == 'base64':
            value = base64.b64decode(value, validate=True)
        elif encoding == 'hex':
            value = bytes.fromhex(value)
        elif encoding == 'utf8':
            value = value.encode('utf-8')
        else:
            raise ValueError(f'unsupported input_encoding: {encoding}')
    except (ValueError, UnicodeError) as exc:
        raise OperationError('invalid_input', 'Invalid input encoding') from exc
    if len(value) > MAX_BYTES:
        raise OperationError('invalid_input', 'Input exceeds 4 MiB')
    return value


def _worker(connection, data: bytes, recipe: list[dict[str, Any]], result_path: str) -> None:
    try:
        output, steps = execute_recipe(data, recipe)
        Path(result_path).write_bytes(output)
        connection.send({'ok': True, 'output_length': len(output), 'steps': steps})
    except OperationError as exc:
        connection.send({'ok': False, 'code': exc.code, 'error': str(exc), 'detail': exc.detail})
    except Exception as exc:  # keep implementation errors inside the JSON protocol
        connection.send({'ok': False, 'code': 'recipe_failed', 'error': str(exc), 'detail': None})
    finally:
        connection.close()


def _bake(job: dict[str, Any]) -> tuple[bytes, list[dict[str, Any]]]:
    recipe = job.get('recipe')
    if not isinstance(recipe, list) or not recipe:
        raise OperationError('invalid_arguments', 'Provide a non-empty recipe')
    if len(recipe) > MAX_STEPS:
        raise OperationError('invalid_arguments', 'Recipe contains more than 32 steps')
    data = _input_bytes(job)
    timeout = float(job.get('timeout_seconds', 60))
    if timeout < 1 or timeout > 120:
        raise OperationError('invalid_arguments', 'timeout_seconds must be between 1 and 120')
    context = multiprocessing.get_context('spawn')
    parent, child = context.Pipe(False)
    fd, result_path = tempfile.mkstemp(prefix='aion-cyberchef-', suffix='.bin')
    os.close(fd)
    try:
        process = context.Process(target=_worker, args=(child, data, recipe, result_path))
        process.start()
        child.close()
        process.join(timeout)
        if process.is_alive():
            process.terminate()
            process.join(2)
            raise OperationError('recipe_timeout', 'Recipe exceeded timeout_seconds')
        if not parent.poll():
            raise OperationError('recipe_failed', 'Recipe worker exited without a result')
        result = parent.recv()
        if not result.get('ok'):
            raise OperationError(result.get('code', 'recipe_failed'), result.get('error', 'Recipe failed'), result.get('detail'))
        output = Path(result_path).read_bytes()
        if len(output) > MAX_BYTES or len(output) != result.get('output_length'):
            raise OperationError('recipe_failed', 'Output exceeds 4 MiB or was truncated')
        return output, result['steps']
    finally:
        try:
            Path(result_path).unlink()
        except FileNotFoundError:
            pass


def _write_artifacts(output: bytes, steps: list[dict[str, Any]], output_dir: str | None, job: dict[str, Any]) -> dict[str, Any]:
    if output_dir is None:
        return {
            'output_base64': base64.b64encode(output).decode('ascii'),
            'output_length': len(output),
            'sha256': hashlib.sha256(output).hexdigest(),
            'steps': steps,
        }
    directory = Path(output_dir)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    result_path = directory / 'result.bin'
    report_path = directory / 'report.json'
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(result_path, flags, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(output)
    report = {
        'state': 'completed', 'output_length': len(output), 'sha256': hashlib.sha256(output).hexdigest(),
        'steps': steps, 'cyberchef_version': VERSION, 'input_encoding': job.get('input_encoding', 'utf8'),
    }
    fd = os.open(report_path, flags, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
    return {
        'output_path': str(result_path), 'report_path': str(report_path),
        'output_length': len(output), 'sha256': report['sha256'], 'steps': steps,
    }


def _operations(job: dict[str, Any]) -> dict[str, Any]:
    query = job.get('query', '')
    if not isinstance(query, str):
        raise OperationError('invalid_arguments', 'query must be a string')
    names = [name for name in OPERATIONS if query.casefold() in name.casefold()]
    config = operation_config()
    return {
        'state': 'completed', 'cyberchef_version': VERSION, 'operations': names,
        'details': [{'name': name, 'description': config[name]['description'], 'args': config[name]['args']} for name in names[:10]] if query else [],
        'details_truncated': bool(query and len(names) > 10),
        'next_step': 'Use bake with exactly one of input/input_path and a recipe. Prefer named args; omit args for defaults.',
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='AION Python CyberChef crypto CLI')
    parser.add_argument('--job', help='JSON job file; stdin is used when omitted')
    parser.add_argument('--output-dir')
    parser.add_argument('--version', action='store_true')
    args = parser.parse_args(argv)
    if args.version:
        print(VERSION)
        return 0
    started = time.monotonic()
    try:
        job = _read_job(args)
        action = job.get('action', 'bake')
        if action == 'operations':
            result = _operations(job)
        elif action == 'bake':
            output, steps = _bake(job)
            result = {'state': 'completed', 'cyberchef_version': VERSION, **_write_artifacts(output, steps, args.output_dir, job)}
        else:
            raise OperationError('invalid_arguments', 'action must be operations or bake')
        result['duration_ms'] = round((time.monotonic() - started) * 1000, 3)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except OperationError as exc:
        result = _error(exc.code, str(exc), exc.detail)
    except Exception as exc:
        result = _error('recipe_failed', str(exc))
    print(json.dumps(result, ensure_ascii=False))
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
