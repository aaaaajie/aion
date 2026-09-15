"""Bounded waits that do not wait indefinitely for cancellation acknowledgement."""

import asyncio


def consume(task):
    if not task.cancelled():
        task.exception()


async def before(awaitable, deadline):
    task = asyncio.ensure_future(awaitable)
    try:
        done, _ = await asyncio.wait({task}, timeout=max(0, deadline - asyncio.get_running_loop().time()))
        if task not in done:
            raise TimeoutError("cleanup deadline exceeded")
        return task.result()
    finally:
        if not task.done():
            task.cancel()
            task.add_done_callback(consume)


async def cancel_before(tasks, deadline):
    pending = [task for task in tasks if task and not task.done() and task is not asyncio.current_task()]
    for task in pending:
        task.cancel()
        task.add_done_callback(consume)
    if pending:
        await asyncio.wait(pending, timeout=max(0, deadline - asyncio.get_running_loop().time()))
