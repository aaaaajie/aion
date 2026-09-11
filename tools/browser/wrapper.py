"""Agent-private Playwright sessions and durable bounded network evidence."""
from __future__ import annotations

import asyncio
import base64
import json
import os
from pathlib import Path
from typing import Literal
import uuid

from pydantic import Field, model_validator
from agent.tooling import AccessClaim, ToolSpec
from tools.binaries.layout import toolchain_for
from tools.http.models import HttpRequestArguments
from tools.system.models import ToolArguments
from tools.system.policy import WorkspacePolicy, SystemToolError

MAX_BODY = 100000
MAX_REQUESTS = 500


class BrowserOpenArguments(ToolArguments):
    url: str = Field(min_length=1)


class BrowserSessionArguments(ToolArguments):
    session_id: str = Field(pattern=r'^[a-f0-9]{32}$')


class BrowserActionArguments(BrowserSessionArguments):
    action: Literal['navigate', 'click', 'fill', 'select', 'wait', 'screenshot', 'upload']
    selector: str | None = None
    value: str | None = None
    timeout_seconds: float = Field(default=15, ge=1, le=30)

    @model_validator(mode='after')
    def fields_for_action(self):
        if self.action in {'click', 'fill', 'select', 'wait', 'upload'} and not self.selector:
            raise ValueError('this action requires a selector')
        if self.action in {'navigate', 'fill', 'select', 'upload'} and self.value is None:
            raise ValueError('this action requires a value')
        return self


class BrowserOutputArguments(BrowserSessionArguments):
    cursor: int = Field(default=0, ge=0)
    limit: int = Field(default=20, ge=1, le=100)


class BrowserExportArguments(BrowserSessionArguments):
    request_id: str = Field(pattern=r'^[a-f0-9]{32}$')


def error(code, message):
    return SystemToolError(error_type='validation', code=code, message=message)


def http_url(value):
    from urllib.parse import urlsplit
    url = urlsplit(value)
    if url.scheme not in {'http', 'https'} or not url.hostname:
        raise error('browser_invalid_url', 'Navigation requires an explicit HTTP(S) URL')
    return value


class BrowserTools:
    def __init__(self, root, *, toolchain_root=None, on_process_started=None):
        self.policy = WorkspacePolicy(root)
        self.root = self.policy.resolve('browser-evidence')
        self.root.mkdir(mode=0o700, exist_ok=True)
        self.toolchain = toolchain_for(toolchain_root)
        self.on_process_started = on_process_started
        self.playwright = self.browser = self.context = None
        self.sessions = {}
        self.locks = {}
        self.start_lock = asyncio.Lock()
        self.closed = False
        for path in self.root.glob('*/session.json'):
            if not path.is_symlink():
                value = json.loads(path.read_text())
                value['state'] = 'closed'
                self._write(path, value)

    @staticmethod
    def _write(path, value):
        temp = path.with_suffix('.tmp')
        with temp.open('w', encoding='utf-8') as stream:
            os.chmod(temp, 0o600)
            json.dump(value, stream, ensure_ascii=False)
        temp.replace(path)

    def tool_specs(self):
        definitions = [
            ('open', BrowserOpenArguments, self.open, '浏览器 浏览器抓包 正常请求 browser: open a page to establish normal login and business requests.'),
            ('action', BrowserActionArguments, self.action, '浏览器操作: navigate, click, fill, select, wait, screenshot or upload using a Playwright CSS selector.'),
            ('output', BrowserOutputArguments, self.output, 'Read browser page summary and captured request evidence; no network replay.'),
            ('export_request', BrowserExportArguments, self.export_request, '导出请求: export a complete captured HTTP request for system_http_request; sends no traffic.'),
            ('close', BrowserSessionArguments, self.close_session, 'Close a browser page while preserving evidence.'),
        ]
        return [ToolSpec('system_browser_' + name, description, model, handler,
                        lambda _: (AccessClaim('write', 'browser-context'),))
                for name, model, handler, description in definitions]

    async def _start(self):
        async with self.start_lock:
            if self.closed:
                raise error('browser_closed', 'Agent browser provider is closed')
            if self.context:
                return
            from playwright.async_api import async_playwright
            import psutil
            owner_marker = '--aion-owner=' + uuid.uuid4().hex
            self.playwright = await async_playwright().start()
            try:
                self.browser = await self.playwright.chromium.launch(
                    executable_path=self.toolchain.command('chromium'), headless=True,
                    downloads_path=str(self.root), args=[owner_marker])
                self.context = await self.browser.new_context(accept_downloads=True)
                if self.on_process_started:
                    owned = set()
                    for process in psutil.Process().children(recursive=True):
                        try:
                            if owner_marker in process.cmdline():
                                owned.add(process.pid)
                                owned.update(child.pid for child in process.children(recursive=True))
                                for parent in process.parents():
                                    if parent.pid == os.getpid():
                                        break
                                    owned.add(parent.pid)
                        except psutil.NoSuchProcess:
                            continue
                    for pid in owned:
                        await self.on_process_started(pid)
            except BaseException:
                await self.playwright.stop()
                self.playwright = None
                raise

    def _directory(self, session_id):
        directory = self.policy.resolve(self.root / session_id, must_exist=True)
        if not (directory / 'session.json').is_file():
            raise error('browser_session_missing', 'Owned browser session was not found')
        return directory

    async def open(self, args):
        http_url(args.url)
        await self._start()
        if sum(not s['page'].is_closed() for s in self.sessions.values()) >= 4:
            raise error('browser_session_limit', 'Close a page before opening another (limit 4)')
        session_id = uuid.uuid4().hex
        directory = self.root / session_id
        directory.mkdir(mode=0o700)
        page = await self.context.new_page()
        session = {'page': page, 'requests': [], 'pending': set(), 'dropped': 0, 'sequence': 0}
        self.sessions[session_id] = session
        self.locks[session_id] = asyncio.Lock()
        self._write(directory / 'session.json', {'session_id': session_id, 'state': 'open', 'url': args.url})

        def capture(response):
            if len(session['requests']) + len(session['pending']) >= MAX_REQUESTS:
                session['dropped'] += 1
                return
            session['sequence'] += 1
            task = asyncio.create_task(self._capture(session_id, response, session['sequence']))
            session['pending'].add(task)
            task.add_done_callback(session['pending'].discard)
        def failed(request):
            if len(session['requests']) >= MAX_REQUESTS:
                session['dropped'] += 1
                return
            session['sequence'] += 1
            request_id = uuid.uuid4().hex
            record = {'sequence': session['sequence'], 'request_id': request_id,
                      'url': request.url, 'method': request.method, 'page_url': page.url,
                      'execution_source': 'browser', 'status_code': None,
                      'capture_error': request.failure, 'failure_stage': 'unknown',
                      'replayable': False, 'replay_reason': 'request_failed', 'body_state': 'missing'}
            session['requests'].append(record)
            self._write(directory / (request_id + '.json'), record)
        page.on('requestfailed', failed)
        page.on('response', capture)
        page.on('download', lambda download: self._download_task(session_id, download))
        try:
            await page.goto(args.url, wait_until='domcontentloaded', timeout=30000)
        except Exception as exc:
            self._write(directory / 'navigation-error.json', {'error': type(exc).__name__})
        return await self.output(BrowserOutputArguments(session_id=session_id))

    def _download_task(self, session_id, download):
        session = self.sessions[session_id]
        async def save():
            try:
                await download.save_as(str(self.root / session_id / (uuid.uuid4().hex + '.download')))
            except Exception:
                pass
        task = asyncio.create_task(save())
        session['pending'].add(task)
        task.add_done_callback(session['pending'].discard)

    async def _capture(self, session_id, response, sequence):
        session = self.sessions[session_id]
        request = response.request
        request_id = uuid.uuid4().hex
        directory = self.root / session_id
        record = {'sequence': sequence, 'request_id': request_id, 'url': request.url, 'method': request.method,
                  'page_url': session['page'].url, 'execution_source': 'browser',
                  'status_code': response.status, 'replayable': False, 'body_state': 'missing'}
        try:
            headers = await request.all_headers()
            payload = request.post_data_buffer
            multipart = 'multipart/form-data' in headers.get('content-type', '').lower()
            record.update(headers=headers, response_headers=await response.all_headers(),
                          replayable=not multipart and (payload is None or len(payload) <= MAX_BODY),
                          replay_reason='multipart_not_preserved' if multipart else 'complete')
            if payload is not None and len(payload) <= MAX_BODY:
                record['body'] = {'type': 'base64', 'value': base64.b64encode(payload).decode(),
                                  'content_type': headers.get('content-type')}
            if payload is not None and len(payload) > MAX_BODY:
                record['replay_reason'] = 'request_body_too_large'
            # Only fetch response bodies with a known bounded Content-Length.
            # Playwright body() buffers the entire response, so unknown sizes
            # must not be fetched merely to truncate them afterwards.
            length = record['response_headers'].get('content-length')
            if length is not None and length.isdigit() and int(length) <= MAX_BODY:
                body = await asyncio.wait_for(response.body(), timeout=10)
                if len(body) <= MAX_BODY:
                    path = directory / (request_id + '.body')
                    path.write_bytes(body)
                    path.chmod(0o600)
                    record.update(body_state='complete', body_path=str(path), body_bytes=len(body))
                else:
                    record['body_state'] = 'omitted_size_limit'
            else:
                record['body_state'] = 'omitted_unknown_or_large_size'
        except asyncio.CancelledError:
            record['capture_error'] = 'capture_cancelled'
        except Exception as exc:
            record['capture_error'] = type(exc).__name__
        session['requests'].append(record)
        self._write(directory / (request_id + '.json'), record)

    async def action(self, args):
        session = self.sessions.get(args.session_id)
        if not session or session['page'].is_closed():
            raise error('browser_session_closed', 'Browser session is closed; captured evidence remains readable')
        async with self.locks[args.session_id]:
            page = session['page']
            timeout = args.timeout_seconds * 1000
            locator = page.locator(args.selector) if args.selector else None
            if args.action == 'navigate':
                await page.goto(http_url(args.value), wait_until='domcontentloaded', timeout=timeout)
            elif args.action == 'click':
                await locator.click(timeout=timeout)
            elif args.action == 'fill':
                await locator.fill(args.value, timeout=timeout)
            elif args.action == 'select':
                await locator.select_option(args.value, timeout=timeout)
            elif args.action == 'wait':
                await locator.wait_for(state='visible', timeout=timeout)
            elif args.action == 'upload':
                path = self.policy.resolve(args.value, must_exist=True, allow_root=False)
                if not path.is_file() or path.stat().st_size > 10000000:
                    raise error('browser_upload_invalid', 'Upload requires a workspace file of at most 10 MB')
                await locator.set_input_files(str(path), timeout=timeout)
            elif args.action == 'screenshot':
                await page.screenshot(path=str(self.root / args.session_id / 'screenshot.png'), timeout=timeout)
            return await self.output(BrowserOutputArguments(session_id=args.session_id))

    async def output(self, args):
        directory = self._directory(args.session_id)
        value = json.loads((directory / 'session.json').read_text())
        session = self.sessions.get(args.session_id)
        if session and not session['page'].is_closed():
            if session['pending']:
                await asyncio.wait(session['pending'], timeout=0.1)
            page = session['page']
            value.update(url=page.url, state='open')
            elements = page.locator('a,button,input,select,textarea')
            value['elements'] = []
            for index in range(min(await elements.count(), 50)):
                element = elements.nth(index)
                try:
                    value['elements'].append({
                        'id': await element.get_attribute('id', timeout=500),
                        'name': await element.get_attribute('name', timeout=500),
                        'type': await element.get_attribute('type', timeout=500),
                        'text': (await element.text_content(timeout=500) or '')[:200]})
                except Exception:
                    break
            value['dropped_requests'] = session['dropped']
            self._write(directory / 'session.json', value)
        else:
            value['state'] = 'closed'
        if (directory / 'navigation-error.json').is_file():
            value['navigation_error'] = json.loads((directory / 'navigation-error.json').read_text())
        records = [json.loads(p.read_text()) for p in sorted(directory.glob('*.json'))
                   if p.stem not in {'session', 'navigation-error'}]
        records.sort(key=lambda record: record['sequence'])
        value['requests'] = [{k: r.get(k) for k in ('request_id', 'url', 'method', 'status_code', 'replayable', 'replay_reason', 'body_state', 'capture_error')}
                             for r in records[args.cursor:args.cursor + args.limit]]
        value.update(next_cursor=args.cursor + len(value['requests']), total_requests=len(records),
                     artifact_directory=str(directory), downloads=[str(p) for p in directory.glob('*.download')])
        if (directory / 'screenshot.png').exists():
            value['screenshot_path'] = str(directory / 'screenshot.png')
        return value

    async def export_request(self, args):
        directory = self._directory(args.session_id)
        path = directory / (args.request_id + '.json')
        if not path.is_file() or path.is_symlink():
            raise error('browser_request_missing', 'Owned captured request was not found')
        record = json.loads(path.read_text())
        if not record['replayable']:
            raise error('browser_request_not_replayable', record.get('replay_reason', 'Incomplete request'))
        headers = {k: v for k, v in record['headers'].items()
                   if k.lower() not in {'host', 'content-length', 'connection', 'transfer-encoding', 'accept-encoding'} and not k.startswith(':')}
        request = HttpRequestArguments(method=record['method'], url=record['url'], headers=headers, body=record.get('body'))
        return {'arguments': request.model_dump(mode='json'), 'requests_sent': 0,
                'session_dependency': 'captured_credentials_may_expire', 'source_request_id': args.request_id}

    async def close_session(self, args):
        directory = self._directory(args.session_id)
        session = self.sessions.get(args.session_id)
        if session:
            async with self.locks[args.session_id]:
                await session['page'].close()
                if session['pending']:
                    _, pending = await asyncio.wait(session['pending'], timeout=1)
                    for task in pending:
                        task.cancel()
                    await asyncio.gather(*pending, return_exceptions=True)
        value = json.loads((directory / 'session.json').read_text())
        value['state'] = 'closed'
        self._write(directory / 'session.json', value)
        return {'session_id': args.session_id, 'state': 'closed', 'artifact_directory': str(directory)}

    async def close(self):
        self.closed = True
        for session_id in tuple(self.sessions):
            await self.close_session(BrowserSessionArguments(session_id=session_id))
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
        self.context = self.browser = self.playwright = None
