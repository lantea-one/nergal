#!/usr/bin/env python3
"""Exercise two installed guests connected only by a private QEMU Unix socket."""

import argparse
from contextlib import ExitStack, closing
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import time


FIXTURE = Path(__file__).resolve().parent
MACS = {"controller": "52:54:00:4d:37:01", "agent": "52:54:00:4d:37:02"}


def execute(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, timeout=90)


def connect(path, process):
    deadline = time.monotonic() + 25
    while True:
        with closing(socket.socket(socket.AF_UNIX)) as candidate:
            try:
                candidate.connect(str(path))
            except (FileNotFoundError, ConnectionRefusedError):
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise
            else:
                connection = candidate.dup()
                connection.settimeout(100)
                return connection
        time.sleep(0.05)


def qmp_hotplug(path, process, mac):
    with connect(path, process) as connection, connection.makefile("rwb") as stream:
        assert "QMP" in json.loads(stream.readline())
        for command in ({"execute": "qmp_capabilities"}, {"execute": "device_add", "arguments": {
                "driver": "virtio-net-pci", "netdev": "lan", "id": "fixture-nic", "mac": mac,
        }}):
            stream.write(json.dumps(command).encode() + b"\r\n")
            stream.flush()
            while True:
                response = json.loads(stream.readline())
                if "event" not in response:
                    assert "return" in response, response
                    break


class Guest:
    def __init__(self, stack, root, stage, role, base, media, backup, lan, accelerator):
        self.role = role
        label = f"{stage}-{role}"
        overlay = root / f"{label}.qcow2"
        commands = root / f"{label}.control"
        self.qmp = root / f"{label}.qmp"
        execute("qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(base), str(overlay))
        self.log = root / f"{label}.log"
        backup_options = ",readonly=on" if stage == "restored" else ""
        with self.log.open("wb") as log:
            self.process = subprocess.Popen([
                "qemu-system-x86_64", "-machine", f"accel={accelerator}", "-cpu", "host" if accelerator == "kvm" else "max",
                "-smp", "2", "-m", "2048", "-nodefaults", "-no-user-config", "-display", "none", "-monitor", "none",
                "-serial", "stdio", "-nic", "none", "-no-reboot", "-qmp", f"unix:{self.qmp},server=on,wait=off",
                "-drive", f"if=none,id=system,format=qcow2,file={overlay}",
                "-device", "virtio-blk-pci,drive=system,bootindex=1", "-cdrom", str(media),
                "-drive", f"if=none,id=backup,format=raw,file={backup}{backup_options}",
                "-device", "virtio-blk-pci,drive=backup,serial=NERGAL_BACKUP",
                "-chardev", f"socket,id=commands,path={commands},server=on,wait=off",
                "-device", "virtio-serial-pci", "-device", "virtserialport,chardev=commands,name=nergal.fixture",
                "-netdev", f"stream,id=lan,addr.type=unix,addr.path={lan},server={'on' if role == 'agent' else 'off'}",
            ], stdout=log, stderr=subprocess.STDOUT)
        stack.callback(self.close)
        connection = stack.enter_context(connect(commands, self.process))
        self.stream = stack.enter_context(connection.makefile("rwb"))

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()

    def ready(self):
        assert self.stream.readline().strip() == b"READY", f"{self.role}: guest not ready; see {self.log}"
        qmp_hotplug(self.qmp, self.process, MACS[self.role])
        identity = self.run("network")
        self.boot_id = self.value("BOOT_ID", identity, r"[0-9a-f-]{36}")
        self.machine_id = self.value("MACHINE_ID", identity, r"[0-9a-f]{32}")

    def run(self, phase, *arguments):
        assert all(re.fullmatch(r"[a-zA-Z0-9-]+", word) for word in (phase, *arguments))
        print(f"{self.role}: {phase}", flush=True)
        self.stream.write((" ".join((phase, *arguments)) + "\n").encode())
        self.stream.flush()
        lines = []
        while line := self.stream.readline():
            line = line.decode(errors="replace").rstrip("\r\n")
            if line == "OK":
                return lines
            if not line.startswith("LOG "):
                break
            lines.append(line.removeprefix("LOG "))
        raise RuntimeError(f"{self.role}: {phase} failed; see {self.log}\n" + "\n".join(lines[-8:]))

    def shutdown(self):
        self.run("shutdown")
        assert self.process.wait(timeout=35) == 0

    @staticmethod
    def value(name, lines, pattern):
        value, = [line.split("=", 1)[1] for line in lines if line.startswith(name + "=")]
        assert re.fullmatch(pattern, value)
        return value

    def pin(self, lines, key="SERVER_PIN"):
        return self.value(key, lines, r"[0-9a-f]{64}")

    def register(self, name, pin):
        return self.value("HOST_ID", self.run("controller-register", name, pin), r"[0-9a-f-]{36}")


def make_media(root, role, arguments):
    media = root / f"{role}-media"
    media.mkdir()
    (media / "role").write_text(role + "\n")
    shutil.copyfile(FIXTURE / "multihost-guest.sh", media / "check-guest.sh")
    shutil.copyfile(FIXTURE / "multihost-backup.sh", media / "multihost-backup.sh")
    shutil.copyfile(arguments.baseline, media / "nergal.deb")
    shutil.copyfile(arguments.upgrade, media / "nergal-upgrade.deb")
    (media / "runtime-debs").mkdir()
    for artifact in sorted(arguments.runtimes.glob("*.deb")):
        shutil.copyfile(artifact, media / "runtime-debs" / artifact.name)
    if role == "controller":
        (media / "password").write_text(secrets.token_urlsafe(32) + "\n")
        for name in ("multihost-controller.sh", "multihost-controller.py", "multihost-oidc.py"):
            shutil.copyfile(FIXTURE / name, media / name)
        for group, names in {"oidc": ("check.py",), "local-sessions": ("check.py", "check-settings.py")}.items():
            destination = media / "reuse" / group
            destination.mkdir(parents=True)
            for name in names:
                shutil.copyfile(FIXTURE.parent / group / name, destination / name)
    else:
        shutil.copyfile(FIXTURE / "multihost-agent.sh", media / "multihost-agent.sh")
    image = root / f"{role}.iso"
    execute("xorriso", "-as", "mkisofs", "-quiet", "-R", "-V", "NERGAL_TEST", "-o", str(image), str(media))
    return image


def start_pair(stack, work, stage, bases, media, disks, accelerator):
    lan = work / f"{stage}.lan"
    agent = Guest(stack, work, stage, "agent", bases["agent"], media["agent"], disks["agent"], lan, accelerator)
    assert lan.is_socket(), f"QEMU failed to create the isolated guest link; see {agent.log}"
    controller = Guest(stack, work, stage, "controller", bases["controller"], media["controller"],
                       disks["controller"], lan, accelerator)
    agent.ready()
    controller.ready()
    assert agent.boot_id != controller.boot_id and agent.machine_id != controller.machine_id
    return controller, agent


def exercise(work, arguments):
    bases = {"controller": arguments.controller_base, "agent": arguments.agent_base}
    media = {role: make_media(work, role, arguments) for role in bases}
    disks = {role: work / f"{role}.backup" for role in bases}
    for disk in disks.values():
        with disk.open("xb") as backup:
            backup.truncate(64 * 1024 * 1024)

    with ExitStack() as stack:
        controller, agent = start_pair(stack, work, "installed", bases, media, disks, arguments.accelerator)
        installed = {guest.role: (guest.boot_id, guest.machine_id) for guest in (controller, agent)}
        controller.run("package", "baseline")
        agent.run("package", "baseline")
        clients = controller.run("controller-init")
        first = controller.pin(clients, "CLIENT_FIRST_PIN")
        second = controller.pin(clients, "CLIENT_SECOND_PIN")
        assert first != second
        first_server = agent.pin(agent.run("agent-init", first))
        original_id = controller.register("fixture-original", first_server)
        controller.run("controller-probe", original_id, "matched", "1")
        agent.run("agent-commit")
        controller.run("controller-probe", original_id, "matched", "2")
        controller.run("controller-save")
        controller.run("oidc-configure")

        for guest in (agent, controller):
            guest.run("upgrade")
        agent.run("agent-start")
        controller.run("controller-start")
        controller.run("controller-probe", original_id, "matched", "2")
        controller.run("oidc-verify")

        second_server = agent.pin(agent.run("agent-rotate", first))
        assert first_server != second_server
        controller.run("controller-probe", original_id, "unavailable", "none")
        replacement_id = controller.register("fixture-rotated", second_server)
        controller.run("controller-probe", replacement_id, "matched", "2")
        agent.run("agent-trust", first, second)
        controller.run("controller-client", "second")
        controller.run("controller-probe", replacement_id, "matched", "2")
        agent.run("agent-trust", second)
        controller.run("controller-client", "first")
        controller.run("controller-probe", replacement_id, "unavailable", "none")
        controller.run("controller-client", "second")
        controller.run("controller-retire", original_id)
        controller.run("controller-probe", replacement_id, "matched", "2")
        saved = controller.run("controller-verify", replacement_id, second_server)
        original_digest = controller.value("POLICY_DIGEST", saved, r"[0-9a-f]{64}")
        for guest in (controller, agent):
            guest.run("backup")
            guest.shutdown()

    with ExitStack() as stack:
        recovery_bases = {"controller": bases["agent"], "agent": bases["controller"]}
        controller, agent = start_pair(stack, work, "restored", recovery_bases, media, disks, arguments.accelerator)
        for guest in (controller, agent):
            old_boot, old_machine = installed[guest.role]
            assert guest.boot_id != old_boot and guest.machine_id != old_machine
        for guest in (controller, agent):
            guest.run("package", "upgrade")
            guest.run("restore")
        agent.run("agent-reconcile")
        controller.run("oidc-trust")
        controller.run("controller-start")
        saved = controller.run("controller-verify", replacement_id, second_server)
        assert controller.value("POLICY_DIGEST", saved, r"[0-9a-f]{64}") == original_digest
        controller.run("oidc-verify")
        agent.run("agent-drift")
        controller.run("controller-probe", replacement_id, "drift", "2")
        agent.run("agent-repair")
        controller.run("controller-probe", replacement_id, "matched", "2")
        for guest in (controller, agent):
            guest.shutdown()


def main():
    if not __debug__:
        raise SystemExit("Run this acceptance fixture with Python assertions enabled")
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("controller_base", "agent_base", "baseline", "upgrade", "runtimes"):
        parser.add_argument(name, type=lambda path: Path(path).resolve(strict=True))
    parser.add_argument("--accelerator", choices=("tcg", "kvm"), default="tcg")
    arguments = parser.parse_args()
    if arguments.controller_base.samefile(arguments.agent_base):
        parser.error("Supply two independently installed Debian fixture base disks")
    if not list(arguments.runtimes.glob("*.deb")):
        parser.error("Runtime package directory must contain .deb files")
    versions = []
    for package in (arguments.baseline, arguments.upgrade):
        name, version = (subprocess.check_output(["dpkg-deb", "-f", str(package), field], text=True).strip()
                         for field in ("Package", "Version"))
        if name != "nergal":
            parser.error("Both packages must be Nergal .deb files")
        versions.append(version)
        with package.open("rb") as data:
            print(f"{name} {version} SHA-256 {hashlib.file_digest(data, 'sha256').hexdigest()}", flush=True)
    execute("dpkg", "--compare-versions", versions[0], "lt", versions[1])
    os.umask(0o077)
    work = Path(tempfile.mkdtemp(prefix="nergal-ops-", dir="/tmp"))
    print(f"Guest logs and disposable media: {work}", flush=True)
    exercise(work, arguments)
    print("PASS: separate guest installs, optional OIDC, same-schema upgrade, mutual TLS rotation and full restore")


if __name__ == "__main__":
    main()
