"""Exercise native backup and restore in disposable local database containers."""

import argparse
from contextlib import contextmanager
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
import tempfile
import time
import uuid


DOCKER = ("docker", "--host", "unix:///var/run/docker.sock")
HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "bin/Release/net10.0/Nergal.ControllerSql.Fixture.dll"
SOURCE = "fixture_source"
RESTORED = "fixture_restored"
USER = "fixture_controller"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(args, **options):
    return subprocess.run(args, timeout=120, check=True, **options)


class Engine:
    server_args = ()
    version_query = "SELECT VERSION();"

    def __init__(self):
        self.container = "nergal-controller-sql-" + uuid.uuid4().hex
        self.password = "Fixture!" + secrets.token_hex(24)
        self.admin_password = "Fixture!" + secrets.token_hex(24)

    @contextmanager
    def started(self):
        image = self.image or subprocess.run(
            [*DOCKER, "build", "--quiet", HERE / "mariadb"],
            check=True, stdout=subprocess.PIPE, text=True, timeout=300,
        ).stdout.strip()
        wiring = self.server_environment()
        env = {**os.environ, **wiring}
        network = self.container + "-net"
        args = [*DOCKER, "run", "--detach", "--rm", "--name", self.container, "--network", network,
                "--security-opt", "no-new-privileges", "--publish", f"127.0.0.1::{self.port}"]
        for key in wiring:
            args.extend(("--env", key))
        run([*DOCKER, "network", "create", "--driver", "bridge", network], stdout=subprocess.DEVNULL)
        try:
            run([*args, image, *self.server_args], env=env, stdout=subprocess.DEVNULL)
            address = run([*DOCKER, "port", self.container, f"{self.port}/tcp"],
                          stdout=subprocess.PIPE).stdout.decode().strip()
            require(re.fullmatch(r"127\.0\.0\.1:[0-9]+", address), "Expected a single loopback binding")
            self.host_port = int(address.split(":")[1])
            deadline = time.monotonic() + 90
            while not self.ready():
                require(time.monotonic() < deadline,
                        f"{self.provider} did not become ready: {self.readiness_error}")
                time.sleep(0.5)
            self.provision()
            version = self.query(SOURCE, self.version_query).decode().strip()
            require(re.match(rf"^{re.escape(self.expected_version)}(?:[\s-]|$)", version),
                    f"{self.provider}: expected version {self.expected_version}, received {version}")
            print(f"{self.provider}: started {version} on {address} ({image})", flush=True)
            yield
        finally:
            subprocess.run([*DOCKER, "rm", "--force", "--volumes", self.container],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            run([*DOCKER, "network", "rm", network], stdout=subprocess.DEVNULL)

    def client(self, args, *, auth, password, phase, input=None, stdin=None, output=None,
               denial=None, probe=False):
        result = subprocess.run(
            [*DOCKER, "exec", "--interactive", "--env", auth, self.container, *args],
            env={**os.environ, auth: password}, input=input, stdin=stdin,
            stdout=output if output is not None else subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=5 if probe else 120,
        )
        stderr = self.redact(result.stderr.decode(errors="replace"))
        if probe:
            self.readiness_error = stderr.strip() or f"client exited {result.returncode}"
            return result.returncode == 0
        if denial is not None:
            diagnostics = stderr + self.redact((result.stdout or b"").decode(errors="replace"))
            require(result.returncode != 0 and denial in diagnostics,
                    f"{self.provider} {phase}: expected {denial!r}, got {result.returncode}: {diagnostics}")
            return None
        if result.returncode != 0:
            stdout = self.redact((result.stdout or b"").decode(errors="replace"))
            raise RuntimeError(f"{self.provider} {phase} failed ({result.returncode}): {stderr}{stdout}")
        return result.stdout

    def immutability_error(self, table, message):
        return message

    def redact(self, message):
        return message.replace(self.password, "[redacted]").replace(self.admin_password, "[redacted]")

    def connection(self, database):
        return (f"Server=127.0.0.1;Port={self.host_port};Database={database};"
                f"User ID={USER};Password={self.password};Pooling=false")


class PostgreSql(Engine):
    provider = "PostgreSql"
    expected_version = "19.0"
    version_query = "SHOW server_version;"
    image = "postgres:19.0-bookworm@sha256:f8b826440669ad283328d2ac8326682539eddd91867904ad5abf4ec19269d241"
    port = 5432

    def immutability_error(self, table, message):
        return f"{table} is append-only"

    def server_environment(self):
        return {"POSTGRES_PASSWORD": self.admin_password}

    def psql(self, database, sql, *, admin=False, **options):
        user = "postgres" if admin else USER
        return self.client(
            ["psql", "-X", "-wAt", "-v", "ON_ERROR_STOP=1", "-h", "127.0.0.1",
             "-U", user, "-d", database],
            auth="PGPASSWORD", password=self.admin_password if admin else self.password,
            input=sql.encode(), phase="psql", **options,
        )

    def ready(self):
        return self.psql("postgres", "SELECT 1;", admin=True, probe=True)

    def provision(self):
        self.psql("postgres", f"""
            CREATE ROLE {USER} LOGIN PASSWORD '{self.password}';
            CREATE DATABASE {SOURCE} OWNER {USER};
            CREATE DATABASE {RESTORED} OWNER {USER};
            """, admin=True)

    def query(self, database, sql, **options):
        return self.psql(database, sql, **options)

    def empty(self, database):
        return self.query(database, "SELECT count(*) FROM pg_tables WHERE schemaname = 'public';").strip() == b"0"

    def backup_restore(self, archive):
        args = ["-h", "127.0.0.1", "-U", USER, "-w"]
        with archive.open("xb") as file:
            self.client(["pg_dump", *args, "--format=custom", "--no-owner", "--no-acl", SOURCE],
                        auth="PGPASSWORD", password=self.password, phase="pg_dump", output=file)
        with archive.open("rb") as file:
            self.client(["pg_restore", *args, "--exit-on-error", "--single-transaction",
                         "--no-owner", "--no-acl", "--dbname", RESTORED],
                        auth="PGPASSWORD", password=self.password, phase="pg_restore", stdin=file)


class MariaDb(Engine):
    provider = "MariaDb"
    expected_version = "13.1.2"
    image = None
    port = 3306
    env_prefix = "MARIADB"
    shell = "mariadb"
    dump = "mariadb-dump"
    dump_options = ()

    def server_environment(self):
        return {
            f"{self.env_prefix}_ROOT_PASSWORD": self.admin_password,
            f"{self.env_prefix}_ROOT_HOST": "localhost",
            f"{self.env_prefix}_DATABASE": SOURCE,
            f"{self.env_prefix}_USER": USER,
            f"{self.env_prefix}_PASSWORD": self.password,
        }

    def query(self, database, sql, *, admin=False, **options):
        connection = ["--user=root"] if admin else ["--host=127.0.0.1", "--protocol=TCP", f"--user={USER}"]
        return self.client(
            [self.shell, "--batch", "--skip-column-names", *connection, database],
            auth="MYSQL_PWD", password=self.admin_password if admin else self.password,
            input=sql.encode(), phase=self.shell, **options,
        )

    def ready(self):
        return self.query(SOURCE, "SELECT 1;", probe=True)

    def provision(self):
        self.query("mysql", f"""
            CREATE DATABASE {RESTORED};
            GRANT ALL PRIVILEGES ON {RESTORED}.* TO '{USER}'@'%';
            """, admin=True)

    def empty(self, database):
        return self.query(database, """
            SELECT count(*) FROM information_schema.tables WHERE table_schema=DATABASE();
            """).strip() == b"0"

    def backup_restore(self, archive):
        args = ["--host=127.0.0.1", "--protocol=TCP", f"--user={USER}"]
        with archive.open("xb") as file:
            self.client([self.dump, *args, "--single-transaction", "--skip-add-drop-table",
                         "--no-tablespaces", *self.dump_options, SOURCE],
                        auth="MYSQL_PWD", password=self.password, phase=self.dump, output=file)
        with archive.open("rb") as file:
            self.client([self.shell, *args, RESTORED], auth="MYSQL_PWD", password=self.password,
                        phase=f"{self.shell} restore", stdin=file)

    def connection(self, database):
        return f"{super().connection(database)};SslMode=Disabled;AllowPublicKeyRetrieval=true"


class MySql(MariaDb):
    provider = "MySql"
    expected_version = "26.10.0.1"
    version_query = "SELECT VERSION_WITH_UPDATE();"
    image = "mysql:26.10.0.1@sha256:9092489f49fb59c4ba6c1425c6a59f71f864f24bf4339a5a26b718adc7a8b343"
    env_prefix = "MYSQL"
    shell = "mysql"
    dump = "mysqldump"
    dump_options = ("--set-gtid-purged=OFF",)
    # MySQL requires server-level privileges to create triggers when binary
    # logging is enabled. This single-server logical-backup fixture needs neither.
    server_args = ("--skip-log-bin",)


class SqlServer(Engine):
    provider = "SqlServer"
    expected_version = "17.0.5065.9"
    version_query = "SELECT CONVERT(varchar(32), SERVERPROPERTY('ProductVersion'));"
    image = "mcr.microsoft.com/mssql/server:2025-CU11-ubuntu-24.04@sha256:05644dad1266ca3d445d1e8f6d2ebb9a6a03df9a39376e0f7b48917356dca9d9"
    port = 1433
    backup = "/var/opt/mssql/data/fixture.bak"

    def server_environment(self):
        return {"ACCEPT_EULA": "Y", "MSSQL_PID": "Developer",
                "MSSQL_SA_PASSWORD": self.admin_password, "MSSQL_MEMORY_LIMIT_MB": "2048"}

    def query(self, database, sql, *, admin=False, **options):
        return self.client(
            ["/opt/mssql-tools18/bin/sqlcmd", "-S", "127.0.0.1", "-C", "-b", "-I", "-r1",
             "-h", "-1", "-y", "8000", "-w", "65535", "-s", "|",
             "-U", "sa" if admin else USER, "-d", database],
            auth="SQLCMDPASSWORD", password=self.admin_password if admin else self.password,
            input=("SET NOCOUNT ON; SET ANSI_PADDING ON; SET ANSI_WARNINGS ON; SET ANSI_NULLS ON;\n"
                   "SET ARITHABORT ON; SET CONCAT_NULL_YIELDS_NULL ON; SET NUMERIC_ROUNDABORT OFF;\n" +
                   sql + "\nGO\n").encode(), phase="sqlcmd", **options,
        )

    def ready(self):
        return self.query("master", "SELECT 1;", admin=True, probe=True)

    def provision(self):
        self.query("master", f"""
            CREATE LOGIN {USER} WITH PASSWORD = '{self.password}';
            CREATE DATABASE {SOURCE};
            CREATE DATABASE {RESTORED};
            """, admin=True)
        for database in (SOURCE, RESTORED):
            self.query(database, f"""
                CREATE USER {USER} FOR LOGIN {USER};
                ALTER ROLE db_owner ADD MEMBER {USER};
                """, admin=True)

    def empty(self, database):
        return self.query(database, "SELECT count(*) FROM sys.tables;").strip() == b"0"

    def backup_restore(self, archive):
        self.query("master", f"""
            BACKUP DATABASE {SOURCE} TO DISK = '{self.backup}' WITH COPY_ONLY, CHECKSUM;
            RESTORE VERIFYONLY FROM DISK = '{self.backup}' WITH CHECKSUM;
            """, admin=True)
        # No REPLACE: drop only the verified-empty fixture recipient. MOVE gives the
        # restored files distinct paths, so the source stays online and unchanged.
        self.query("master", f"""
            DROP DATABASE {RESTORED};
            RESTORE DATABASE {RESTORED} FROM DISK = '{self.backup}'
                WITH CHECKSUM, MOVE '{SOURCE}' TO '/var/opt/mssql/data/{RESTORED}.mdf',
                MOVE '{SOURCE}_log' TO '/var/opt/mssql/data/{RESTORED}_log.ldf';
            """, admin=True)

    def connection(self, database):
        return (f"Server=127.0.0.1,{self.host_port};Database={database};User ID={USER};"
                f"Password={self.password};Pooling=false;Encrypt=true;TrustServerCertificate=true")


def fixture(engine, phase, manifest):
    result = subprocess.run(
        ["dotnet", str(FIXTURE), engine.provider, phase, str(manifest)],
        env={**os.environ, "NERGAL_SQL_FIXTURE_SOURCE": engine.connection(SOURCE),
             "NERGAL_SQL_FIXTURE_RESTORED": engine.connection(RESTORED)},
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120,
    )
    details = engine.redact((result.stdout + result.stderr).decode(errors="replace")).strip()
    require(result.returncode == 0, f"{engine.provider} fixture {phase} failed: {details}")
    print(details, flush=True)


def history(engine, database):
    return tuple(engine.query(database, f"SELECT * FROM {table} ORDER BY {key};")
                 for table, key in (("system_settings", "version"), ("audit_log", "sequence"),
                                    ("reusable_object_versions", "object_id, version"),
                                    ("policy_revisions", "revision")))


def check_immutable(engine):
    for table, predicate, column, message in (
        ("system_settings", "version = 1", "settings_json", "settings versions are immutable"),
        # The object event has no settings foreign key, so a delete reaches the audit trigger.
        ("audit_log", "action = 'object.create'", "outcome", "audit log is append-only"),
        ("reusable_object_versions", "version = 1", "description", "object history is immutable"),
        ("native_sources", "id IS NOT NULL", "name", "native sources are immutable"),
        ("policy_revisions", "revision = 1", "summary", "policy revisions are immutable"),
    ):
        for sql in (f"UPDATE {table} SET {column} = {column} WHERE {predicate};",
                    f"DELETE FROM {table} WHERE {predicate};"):
            engine.query(RESTORED, sql, denial=engine.immutability_error(table, message))


def check(engine, tools_only):
    with tempfile.TemporaryDirectory(prefix="nergal-controller-sql-") as root, engine.started():
        archive = Path(root) / "controller.backup"
        manifest = Path(root) / "store-snapshot.json"
        require(engine.empty(SOURCE) and engine.empty(RESTORED), "Expected two fresh fixture databases")

        if tools_only:
            engine.query(SOURCE, """
                CREATE TABLE fixture_marker (id int NOT NULL PRIMARY KEY);
                INSERT INTO fixture_marker VALUES (42);
                """)
        else:
            fixture(engine, "seed", manifest)
            source_snapshot = history(engine, SOURCE)
        require(engine.empty(RESTORED), "Source writes must leave the recipient empty")
        engine.backup_restore(archive)

        if tools_only:
            engine.query(RESTORED, "UPDATE fixture_marker SET id = 43 WHERE id = 42;")
            require(engine.query(SOURCE, "SELECT id FROM fixture_marker;").strip() == b"42"
                    and engine.query(RESTORED, "SELECT id FROM fixture_marker;").strip() == b"43",
                    "Expected restored marker and isolated writes")
        else:
            require(history(engine, RESTORED) == source_snapshot, "Restore must retain the exact history")
            require(history(engine, SOURCE) == source_snapshot, "Restore must leave the source unchanged")
            check_immutable(engine)
            require(history(engine, RESTORED) == source_snapshot, "Denied mutations must leave history intact")
            fixture(engine, "verify", manifest)
        scope = "native tooling and recipient isolation" if tools_only else "controller state and native backup/restore"
        print(f"PASS {engine.provider}: {scope}", flush=True)


def main():
    engines = {"postgresql": PostgreSql, "mariadb": MariaDb, "sqlserver": SqlServer, "mysql": MySql}
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", action="append", choices=engines, help="Select engines. Defaults to all.")
    parser.add_argument("--tools-only", action="store_true", help="Check images and native clients without .NET.")
    options = parser.parse_args()
    if not options.tools_only and not FIXTURE.is_file():
        parser.error("Build the Release controller SQL fixture first.")
    os.umask(0o077)
    failed = False
    for name in dict.fromkeys(options.engine or engines):
        try:
            check(engines[name](), options.tools_only)
        except (RuntimeError, subprocess.SubprocessError) as error:
            print(f"FAIL {name}: {error}", file=sys.stderr, flush=True)
            failed = True
    return int(failed)


def terminate(signum, _frame):
    raise SystemExit(128 + signum)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, terminate)
    sys.exit(main())
