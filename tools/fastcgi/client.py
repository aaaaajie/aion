"""Single-request FastCGI/1 Responder over an owned TCP connection.

Wire reference: https://fast-cgi.github.io/original/
No retries or multiplexing: uncertain execution is never replayed automatically.
"""
from __future__ import annotations

import asyncio
import base64
import struct
from time import monotonic

from agent.tooling import tool_error

HEADER = struct.Struct("!BBHHBB")
BEGIN, END, PARAMS, STDIN, STDOUT, STDERR = 1, 3, 4, 5, 6, 7
REQUEST_ID = 1


class ProtocolError(ValueError):
    pass


def record(kind: int, content: bytes) -> bytes:
    padding = (-len(content)) % 8
    return HEADER.pack(1, kind, REQUEST_ID, len(content), padding, 0) + content + bytes(padding)


def stream_records(kind: int, content: bytes):
    for start in range(0, len(content), 65535):
        yield record(kind, content[start:start + 65535])
    yield record(kind, b"")


def encode_params(params: dict[str, str]) -> bytes:
    def length(value):
        return bytes([value]) if value < 128 else struct.pack("!I", value | 0x80000000)
    output = bytearray()
    for name, value in params.items():
        key, data = name.encode("utf-8"), value.encode("utf-8")
        output.extend(length(len(key)) + length(len(data)) + key + data)
    return bytes(output)


def output_value(data: bytearray) -> dict:
    raw = bytes(data)
    try:
        return {"encoding": "utf-8", "content": raw.decode("utf-8"), "bytes": len(raw)}
    except UnicodeDecodeError:
        return {"encoding": "base64", "content": base64.b64encode(raw).decode("ascii"), "bytes": len(raw)}


class FastCGIClient:
    def __init__(self):
        self._writers: set[asyncio.StreamWriter] = set()
        self._closed = False

    async def request(self, args) -> dict:
        if self._closed:
            return tool_error("execution", "fastcgi_closed", "Provider is closed")
        started = monotonic()
        stdout, stderr = bytearray(), bytearray()
        writer = None
        end_received = False
        stdout_closed = stderr_closed = False
        app_status = protocol_status = None
        error = None
        sent = False
        raw_response = bytearray()
        transport_status = "not_connected"
        phase = "connect"
        error_type = None

        async def receive(size):
            # readexactly hides partial bytes on timeout/reset. Retain each read
            # before awaiting more, including incomplete headers and padding.
            data = bytearray()
            while len(data) < size:
                chunk = await reader.read(size - len(data))
                if not chunk:
                    raise asyncio.IncompleteReadError(bytes(data), size)
                raw_response.extend(chunk)
                data.extend(chunk)
            return bytes(data)

        try:
            async with asyncio.timeout(args.timeout_seconds):
                reader, writer = await asyncio.open_connection(args.host, args.port)
                transport_status = "open"
                phase = "send"
                if self._closed:
                    raise ProtocolError("Provider closed during connection establishment")
                self._writers.add(writer)
                writer.write(record(BEGIN, struct.pack("!HB5x", 1, 0)))
                sent = True
                for chunk in stream_records(PARAMS, encode_params(args.params)):
                    writer.write(chunk)
                    await writer.drain()
                for chunk in stream_records(STDIN, args.input_bytes()):
                    writer.write(chunk)
                    await writer.drain()
                # Count framing as well as content, so empty-record streams are bounded.
                phase = "receive"
                while True:
                    if len(raw_response) + 8 > args.max_output_bytes + 65536:
                        raise ProtocolError("Response framing exceeded its budget")
                    version, kind, request_id, size, padding, _ = HEADER.unpack(await receive(8))
                    if version != 1 or request_id != REQUEST_ID:
                        raise ProtocolError("Unexpected FastCGI version or request ID")
                    if len(raw_response) + size + padding > args.max_output_bytes + 65536:
                        raise ProtocolError("Response framing exceeded its budget")
                    content = await receive(size)
                    await receive(padding)
                    if kind in {STDOUT, STDERR}:
                        if (kind == STDOUT and stdout_closed) or (kind == STDERR and stderr_closed):
                            raise ProtocolError("Data received after stream termination")
                        target = stdout if kind == STDOUT else stderr
                        remaining = args.max_output_bytes - len(stdout) - len(stderr)
                        target.extend(content[:remaining])
                        if size > remaining:
                            error = ("fastcgi_output_limit", "Output limit reached; response is incomplete")
                            break
                        if not content:
                            if kind == STDOUT:
                                stdout_closed = True
                            else:
                                stderr_closed = True
                    elif kind == END:
                        if size != 8:
                            raise ProtocolError("Invalid END_REQUEST length")
                        app_status, protocol_status = struct.unpack("!IB3x", content)
                        end_received = True
                        transport_status = "end_request"
                        if protocol_status != 0:
                            error = ("fastcgi_protocol_status", "Server did not complete the requested role")
                        elif app_status != 0:
                            error = ("fastcgi_application_status", "Application returned a nonzero exit status")
                        break
                    else:
                        raise ProtocolError("Unexpected FastCGI response record type")
        except TimeoutError:
            transport_status = "timeout"
            error_type = "TimeoutError"
            error = ("fastcgi_timeout", "Request deadline exceeded; do not infer a negative application result")
        except asyncio.IncompleteReadError:
            transport_status = "eof"
            error_type = "IncompleteReadError"
            error = ("fastcgi_incomplete", "Connection ended before a complete FastCGI response")
        except ProtocolError as exc:
            error_type = type(exc).__name__
            error = ("fastcgi_protocol_error", str(exc))
        except OSError as exc:
            transport_status = "reset" if isinstance(exc, ConnectionResetError) else "connection_error"
            error_type = type(exc).__name__
            error = ("fastcgi_connection_error", f"Connection failed: {type(exc).__name__}")
        finally:
            if transport_status == "open":
                transport_status = "local_stop"
            if writer is not None:
                writer.close()
                self._writers.discard(writer)
                try:
                    await asyncio.wait_for(writer.wait_closed(), 1.0)
                except (OSError, TimeoutError):
                    pass
        # END_REQUEST ends this request. PHP's fcgi_flush may omit an empty
        # STDOUT record; do not discard a fully framed response for that reason.
        complete = end_received
        result = {
            "ok": error is None,
            "data": {
                "status": "completed" if error is None else "failed",
                "request_sent": sent, "complete": complete,
                "outcome_unknown": sent and not complete,
                "app_status": app_status, "protocol_status": protocol_status,
                "end_request_received": end_received,
                "stdout_terminated": stdout_closed, "stderr_terminated": stderr_closed,
                "stdout": output_value(stdout), "stderr": output_value(stderr),
                "raw_response": output_value(raw_response),
                "bytes_received": len(raw_response),
                "transport": {"status": transport_status, "phase": phase, "error_type": error_type},
                "elapsed_ms": int((monotonic() - started) * 1000),
            },
        }
        if error:
            result.update(tool_error("execution", error[0], error[1]))
        return result

    async def close(self):
        self._closed = True
        writers = list(self._writers)
        for writer in writers:
            writer.close()
        if writers:
            try:
                await asyncio.wait_for(asyncio.gather(*(w.wait_closed() for w in writers), return_exceptions=True), 1.0)
            except TimeoutError:
                pass
        self._writers.clear()
