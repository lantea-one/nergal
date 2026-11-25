"""Local SMTP fixture. Only STARTTLS sessions can store a synthetic message."""
import contextlib
import email.policy
from email.parser import BytesParser
from pathlib import Path
import queue
import socketserver
import ssl
import subprocess
import threading


class Relay(socketserver.BaseRequestHandler):
    def handle(self):
        connection = self.request
        connection.settimeout(8)
        def write(message):
            connection.sendall(message + b"\r\n")

        write(b"220 synthetic SMTP")
        reader = connection.makefile("rb")
        protected = False
        recipient = None
        try:
            while line := reader.readline(8192):
                command, _, argument = line.rstrip(b"\r\n").partition(b" ")
                command = command.upper()
                if command in (b"EHLO", b"HELO"):
                    if not protected and self.server.starttls:
                        write(b"250-synthetic SMTP\r\n250 STARTTLS")
                    else:
                        write(b"250 synthetic SMTP")
                elif command == b"STARTTLS" and not protected and self.server.starttls:
                    write(b"220 Ready for TLS")
                    reader.close()
                    connection = self.server.tls.wrap_socket(connection, server_side=True)
                    reader = connection.makefile("rb")
                    protected = True
                elif command == b"QUIT":
                    write(b"221 Goodbye")
                    break
                elif not protected:
                    self.server.plaintext_commands.put(command)
                    write(b"530 STARTTLS required")
                elif command == b"MAIL":
                    write(b"250 Sender accepted")
                elif command == b"RCPT":
                    recipient = argument.decode("ascii")
                    write(b"250 Recipient accepted")
                elif command == b"DATA" and recipient is not None:
                    write(b"354 Send message")
                    data = bytearray()
                    while len(data) < 8192:
                        line = reader.readline(8192)
                        if line == b".\r\n":
                            message = BytesParser(policy=email.policy.default).parsebytes(bytes(data))
                            self.server.messages.put((recipient, message))
                            break
                        if not line:
                            return
                        data.extend(line[1:] if line.startswith(b"..") else line)
                    else:
                        return
                    write(b"250 Message accepted")
                    recipient = None
                else:
                    write(b"500 Unexpected command")
        except (OSError, ssl.SSLError):
            # The client closes the connection when TLS or delivery is denied.
            pass
        finally:
            reader.close()
            connection.close()


@contextlib.contextmanager
def relay(directory: Path, *, starttls=True):
    """Start a loopback relay with a synthetic certificate and no mail forwarding."""
    certificate = directory / "smtp.crt"
    key = directory / "smtp.key"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=synthetic-smtp", "-addext", "subjectAltName=IP:127.0.0.1",
                    "-keyout", key, "-out", certificate], check=True, stderr=subprocess.DEVNULL)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(certificate, key)
    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), Relay) as server:
        server.tls = tls
        server.starttls = starttls
        server.messages = queue.Queue()
        server.plaintext_commands = queue.Queue()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server, certificate
        finally:
            server.shutdown()
            thread.join(timeout=5)
