"""CyberChef recipes run as owned, resource-limited shell tasks."""
import base64
import json
import shlex
import re
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from pydantic import Field, model_validator
from agent.tooling import AccessClaim, ToolSpec
from tools.binaries.layout import toolchain_for
from tools.system.models import ToolArguments
from tools.system.policy import WorkspacePolicy, SystemToolError


class RecipeStep(ToolArguments):
    op: str = Field(min_length=1, max_length=100, description='Exact case-sensitive name returned by action=operations, e.g. From Base64.')
    args: list[Any] | dict[str, Any] | None = Field(default=None, description='Prefer named arguments from operations query. Omit for defaults; positional arrays must contain every argument for this version, not an empty array.')


class CyberChefArguments(ToolArguments):
    action: Literal['operations', 'bake'] = Field(default='bake', description='operations returns names/parameter schemas immediately; bake starts a background task.')
    query: str = Field(default='', max_length=200, description='Operation name substring, e.g. AES Decrypt; empty lists supported names. Used only by operations.')
    input: str | None = Field(default=None, max_length=8 * 1024 * 1024, description='Inline input, mutually exclusive with input_path. Ordinary Base64 text to decode stays utf8; select a From Base64 recipe step.')
    input_path: str | None = Field(default=None, description='Existing file in this Agent workspace, read as raw bytes. Do not specify input_encoding for files.')
    input_encoding: Literal['utf8', 'base64', 'hex'] = Field(default='utf8', description='Transport encoding of inline input, not an extra recipe step. base64/hex reconstruct bytes before the recipe.')
    recipe: list[RecipeStep] = Field(default_factory=list, max_length=32)
    timeout_seconds: float = Field(default=60, ge=1, le=120)

    @model_validator(mode='after')
    def check_input(self):
        if self.action == 'bake':
            if (self.input is None) == (self.input_path is None):
                raise ValueError('Provide exactly one of input or input_path')
            if not self.recipe:
                raise ValueError('Provide at least one recipe step')
            if self.input_path is not None and self.input_encoding != 'utf8':
                raise ValueError('input_path reads raw bytes; input_encoding applies only to inline input')
        elif self.input is not None or self.input_path is not None or self.recipe:
            raise ValueError('operations accepts query, not input or recipe')
        return self


class CyberChefTools:
    def __init__(self, shell, toolchain_root=None):
        self.shell = shell
        self.policy = WorkspacePolicy(shell.agent_work_root)
        self.toolchain = toolchain_for(toolchain_root)

    def tool_specs(self):
        return [ToolSpec('system_cyberchef',
            'CyberChef 解密 编解码 decode decrypt crypto recipe: offline Base64/hex/URL, XOR, AES/RSA with supplied keys, compression and hashes. Query action=operations for immediate exact operation arguments (no task); use skill cyberchef-recipes for workflow and error recovery; bake a JSON recipe with input or a workspace input_path. Not automatic password cracking. Poll system_task_output; exact bytes and report saved as artifacts.',
            CyberChefArguments, self.run, lambda _: (AccessClaim('write', 'cyberchef'),))]

    async def run(self, args):
        asset_root = self.toolchain.root / 'cyberchef'
        allowed = json.loads((asset_root / 'operations.json').read_text())
        config = json.loads((asset_root / 'operation-config.json').read_text())
        if args.action == 'operations':
            names = [name for name in allowed if args.query.casefold() in name.casefold()]
            return {'state': 'completed', 'cyberchef_version': '11.2.0-aion-python',
                'operations': names, 'details': [dict(name=name,
                    description=re.sub('<[^>]*>', ' ', config[name]['description']),
                    args=config[name]['args']) for name in names[:10]] if args.query else [],
                'details_truncated': bool(args.query and len(names) > 10),
                'next_step': 'Use bake with exactly one of input/input_path and a recipe. Prefer named args; omit args for defaults. Bake returns a task: poll system_task_output, do not resubmit to fetch output.'}
        for index, step in enumerate(args.recipe):
            correction = {'action': 'operations', 'query': step.op if step.op in allowed else ''}
            error = None
            if step.op not in allowed:
                error = 'unsupported_operation'
            else:
                schema = config[step.op]['args']
                normalize = lambda value: value.lower().replace(' ', '')
                if isinstance(step.args, dict) and any(normalize(key) not in {normalize(a['name']) for a in schema} for key in step.args):
                    error = 'invalid_arguments'
                if isinstance(step.args, list) and len(step.args) != len(schema):
                    error = 'invalid_arguments'
            if error:
                raise SystemToolError(error_type='validation', code=error,
                    message='Recipe needs correction before execution; query the operation schema. Omit args for defaults or supply named arguments.',
                    detail={'step_index': index, 'operation': step.op,
                            'next_tool': 'system_cyberchef', 'next_arguments': correction,
                            'repeat_unchanged': False})
        command = self.toolchain.command('cyberchef')
        job = args.model_dump(exclude={'input_path'}, exclude_none=True)
        if args.input_path is not None:
            path = self.policy.resolve(args.input_path, must_exist=True)
            if not path.is_file():
                raise ValueError('input_path must be a regular file')
            with path.open('rb') as stream:
                data = stream.read(4 * 1024 * 1024 + 1)
            if len(data) > 4 * 1024 * 1024:
                raise ValueError('Input exceeds 4 MiB')
            job['input'] = base64.b64encode(data).decode('ascii')
            job['input_encoding'] = 'base64'
        directory = self.policy.resolve(f'cyberchef-{uuid4().hex}')
        directory.mkdir(mode=0o700)
        request = directory / 'request.json'
        with request.open('x', encoding='utf8') as stream:
            request.chmod(0o600)
            json.dump(job, stream, ensure_ascii=False)
        return await self.shell.run_shell(shlex.join([command, '--job', str(request),
            '--output-dir', str(directory / 'result')]),
            timeout=args.timeout_seconds + 15, run_in_background=True,
            task_name='cyberchef', max_output_chars=30000)
