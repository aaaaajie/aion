"""Offline source review through the existing owned shell task lifecycle."""
from pathlib import Path
import shlex
import sys
from pydantic import Field
from agent.tooling import AccessClaim, ToolSpec
from tools.system.models import ToolArguments
from tools.system.policy import WorkspacePolicy


class SourceScanArguments(ToolArguments):
    path: str = Field(
        default='.',
        description="Logical workspace directory such as agent/src or shared/src; absolute paths and $TMPDIR belong in Shell only.",
    )
    timeout_seconds: float = Field(default=120, ge=1, le=600)


class SourceTools:
    def __init__(self, shell):
        self.shell = shell
        self.policy = WorkspacePolicy(shell.agent_work_root)

    def tool_specs(self):
        return [ToolSpec('system_source_scan',
            '源码扫描 源码审计 source audit: offline Semgrep Python/PHP/JavaScript/TypeScript review leads, not verified vulnerabilities. Poll system_task_output for findings and JSON artifact.',
            SourceScanArguments, self.scan, lambda _: (AccessClaim('read', 'source'),))]

    async def scan(self, args):
        path = self.policy.resolve(args.path, must_exist=True)
        if not path.is_dir():
            raise ValueError('source scan requires a directory')
        command = shlex.join([sys.executable, str(Path(__file__).with_name('scan.py')), str(path)])
        return await self.shell.run_shell(command, timeout=args.timeout_seconds,
            run_in_background=True, task_name='source-review', max_output_chars=30000)
