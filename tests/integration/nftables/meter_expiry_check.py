"""Observe creation/idle expiry through real dual-stack UDP packets in disposable namespaces."""
import contextlib
import os
import selectors
import socket
import subprocess
import sys
import time


def main():
    if len(sys.argv) != 4 or os.readlink('/proc/self/ns/net') == sys.argv[2] or os.readlink('/proc/self/ns/user') == sys.argv[3]:
        raise AssertionError('Use the guarded launcher; refusing the parent namespaces')
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    subprocess.run(['nft', '--check', '-f', sys.argv[1]], check=True)
    subprocess.run(['nft', '-f', sys.argv[1]], check=True)
    # Continued denied attempts keep update entries alive. A creation-expiry entry
    # instead disappears at two seconds and grants a fresh initial burst.
    counts = [0] * 4
    with contextlib.ExitStack() as stack:
        selector = stack.enter_context(selectors.DefaultSelector())
        senders = []
        for index, port in enumerate(range(19101, 19105)):
            family, address = (socket.AF_INET, '127.0.0.1') if index < 2 else (socket.AF_INET6, '::1')
            receiver = stack.enter_context(socket.socket(family, socket.SOCK_DGRAM))
            receiver.bind((address, port))
            receiver.setblocking(False)
            selector.register(receiver, selectors.EVENT_READ, index)
            sender = stack.enter_context(socket.socket(family, socket.SOCK_DGRAM))
            senders.append((sender, (address, port)))
        start = time.monotonic()
        deadline, next_send = start + 4.5, start
        while time.monotonic() < deadline:
            now = time.monotonic()
            if now >= next_send:
                # Fail rather than report success if scheduling skipped an entire expiry.
                if now - next_send > 1:
                    raise AssertionError('Packet driver missed the expiry observation window')
                for sender, destination in senders:
                    sender.sendto(b'expiry-probe', destination)
                next_send = now + .2
            for key, _ in selector.select(max(0, min(next_send, deadline) - time.monotonic())):
                while True:
                    try:
                        key.fileobj.recv(128)
                        counts[key.data] += 1
                    except BlockingIOError:
                        break
        if counts[0] != 1 or counts[2] != 1 or counts[1] < 2 or counts[3] < 2:
            raise AssertionError(f'Dual-stack update/add expiry differed: {counts}')
    print('PASS: continued dual-stack attempts retain update buckets; add buckets expire and grant a fresh burst')


if __name__ == '__main__':
    main()
