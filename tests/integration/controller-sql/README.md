# Controller SQL backup and restore fixture

Run on Linux with Python 3, the repository-pinned .NET SDK and a local Docker
Engine on `/var/run/docker.sock`. The SQL Server image requires x86-64 and at
least 2 GiB of memory available to the engine. Running that case accepts the
SQL Server container license terms for the disposable Developer edition instance.

```sh
dotnet restore tests/integration/controller-sql/Nergal.ControllerSql.Fixture.csproj --locked-mode
dotnet build tests/integration/controller-sql/Nergal.ControllerSql.Fixture.csproj --configuration Release --no-restore
python3 -B tests/integration/controller-sql/check.py
```

The runner accepts repeated `--engine` arguments with `postgresql`, `mariadb`,
`mysql` and `sqlserver`. Use `--tools-only` to check the images, native backups,
restores and recipient isolation without building the .NET fixture.

Each case starts a digest-pinned container on a new Docker bridge with an
engine-assigned loopback port. Source and restore are different databases.
The fixture provisions its own database-scoped user and generates new synthetic
passwords for every run. The temporary directory, container, anonymous volumes
and bridge are removed on exit. SQL Server writes its backup within the
disposable container. The other engines stream their backups into the private
temporary directory.

The full fixture uses `ControllerStateStore` to check explicit initialization,
concurrent use of a settings token, immutable object versions, and settings
audit attribution. It compares settings, audit, object history, pinned policy
usage, and exact UTF-8 native source bytes before and after restore. It then
attempts direct updates and deletes against restored history. The source and
restore both continue writing from the backup point. Each rejects the other's
divergent token. The recipient's changes leave the source history intact.

PostgreSQL uses `pg_dump` in custom format and `pg_restore` in a single
transaction. MariaDB uses `mariadb-dump` and `mariadb`. MySQL uses
`mysqldump` and `mysql`. SQL Server uses `BACKUP DATABASE`, `RESTORE VERIFYONLY`
with checksums, and `RESTORE DATABASE` with distinct data and log paths.

The isolated MySQL engine runs with binary logging disabled so its
database-scoped controller user can install and restore immutable-history
triggers. This case exercises logical backups on a standalone server.
