"""One local Runtime owns a Run; the kernel releases ownership on process exit."""

import fcntl
import os
from pathlib import Path
from agent.state.errors import StateConflict


class RunOwnership:
    def __init__(self, database_path: Path):
        path = database_path.with_name("runtime.lock")
        self.fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self.fd)
            self.fd = None
            raise StateConflict(
                "run_already_supervised", "Another Runtime currently owns this Run"
            ) from None

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
