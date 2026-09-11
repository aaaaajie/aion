"""Local HTTP and SSH servers for real transport lifecycle integration tests."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
import threading
import time
import paramiko


class LocalHttpTarget:
    def __init__(self):
        self.cookies = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                body = b"authorized"
                self.send_response(200)
                if self.path == "/login":
                    self.send_header("Set-Cookie", "sid=retained; Path=/")
                else:
                    owner.cookies.append(self.headers.get("Cookie"))
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_POST = do_GET

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)


class LocalSshTarget:
    def __init__(self):
        owner = self
        self.transport = None
        self.closed = threading.Event()
        self.commands = []
        self.key = paramiko.RSAKey.generate(2048)
        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(1)
        self.socket.settimeout(0.2)
        self.port = self.socket.getsockname()[1]

        class Server(paramiko.ServerInterface):
            def check_auth_password(self, username, password):
                return (
                    paramiko.AUTH_SUCCESSFUL
                    if (username, password) == ("player", "fixture")
                    else paramiko.AUTH_FAILED
                )

            def get_allowed_auths(self, username):
                return "password"

            def check_channel_request(self, kind, chanid):
                return (
                    paramiko.OPEN_SUCCEEDED
                    if kind == "session"
                    else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
                )

            def check_channel_exec_request(self, channel, command):
                owner.commands.append(command)

                def reply():
                    # Let Paramiko acknowledge exec before emitting the result.
                    time.sleep(0.01)
                    channel.sendall(b"uid=1000(player)\n")
                    channel.send_exit_status(0)
                    channel.shutdown_write()

                threading.Thread(target=reply, daemon=True).start()
                return True

        def serve():
            while not self.closed.is_set():
                try:
                    connection, _ = self.socket.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                self.transport = paramiko.Transport(connection)
                self.transport.add_server_key(self.key)
                self.transport.start_server(server=Server())
                channels = []
                while not self.closed.is_set() and self.transport.is_active():
                    channel = self.transport.accept(0.2)
                    if channel is not None:
                        channels.append(channel)
                return

        self.thread = threading.Thread(target=serve, daemon=True)
        self.thread.start()

    def close(self):
        self.closed.set()
        if self.transport:
            self.transport.close()
        self.socket.close()
        self.thread.join(2)
