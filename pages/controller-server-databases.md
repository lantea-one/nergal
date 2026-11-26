# Controller server databases

Choose the controller database when deploying a new controller. SQLite remains
the default. PostgreSQL, MariaDB, MySQL and Microsoft SQL Server each use a
fresh controller schema 5 in a dedicated database. MariaDB and MySQL share a
client library and have separate schemas and restore checks.
The controller restore fixture targets PostgreSQL 19.0, MariaDB 13.1.2,
MySQL 26.10.0.1 and SQL Server 2025 CU11 (17.0.5065.9).

The controller database contains managed hosts, desired policy revisions,
native sources and conversion plans, reusable objects, System settings and
controller audit. The local identity store, Data Protection keys and protected
agent journal retain their own persistence and recovery requirements. Restoring
a controller database does not reconcile the host's applied policy or authorize
dispatch to an agent.

## Initialize an empty database

1. Create an empty database on the chosen engine. Use the `public` schema on
   PostgreSQL and `dbo` on SQL Server. The account used to initialize the store
   needs permission to create the controller's tables, constraints, indexes and
   triggers. Keep other applications and extensions outside the controller
   namespace.
2. Set `ControllerState__ConnectionString` in the private process environment.
   Use the database driver's connection-string syntax with an explicit database
   name. Configure server identity verification using `SSL Mode=VerifyFull`
   on PostgreSQL, MariaDB and MySQL, or
   `Encrypt=True;TrustServerCertificate=False` on SQL Server, with the
   database server's CA trusted by the controller. Keep credentials in the
   service's protected environment or secret provider.
3. Run `nergal-admin controller init --provider PROVIDER`, substituting
   `postgresql`, `mariadb`, `mysql` or `sqlserver`. Initialization refuses
   a populated namespace. For MariaDB and MySQL, DDL commits independently.
   If initialization fails after creating some objects, investigate the failure
   and start again with a separate empty database.
4. Set `ControllerState__Enabled=true`, `ControllerState__Provider=PROVIDER`
   and `ControllerState__ConnectionString` for the web service. The Settings
   form records preferences. The deployment configuration selects the live
   connection.

Use database-scoped credentials without server-wide administrative privileges.
The runtime account needs data access and visibility into the controller schema
definitions. PostgreSQL additionally requires the privileges used by
`SELECT … FOR UPDATE` on `controller_metadata`. MariaDB and MySQL expose
trigger definitions only to an account with the database's `TRIGGER`
privilege. SQL Server needs definition visibility and a default schema of
`dbo`. Reserve database ownership, DDL and backup administration for
operators wherever the engine's metadata permissions permit it.
On MySQL with binary logging enabled, have the database administrator
authorize trigger creation during initialization and logical restore.

Controller writes serialize on a database row. Settings edits compare their
tokens within the write transaction and commit the settings snapshot and
audit event together. Startup and subsequent store operations check the
schema version and catalog definitions. A restore must preserve constraints,
indexes and triggers as part of the controller database.

## Back up and restore

Use the server's native client tools, a private destination and an independent
restore database. Use an account authorized for backup and restore with
credentials supplied through the tool's protected configuration. Keep the
controller schema unchanged while taking a logical backup. Examples assume
that the native clients have been configured to connect to the intended server.

| Engine | Backup | Restore |
| --- | --- | --- |
| PostgreSQL | `pg_dump --format=custom --no-owner --no-acl --file=controller.dump controller_source` | `pg_restore --exit-on-error --single-transaction --no-owner --no-acl --dbname=controller_restore controller.dump` |
| MariaDB | `mariadb-dump --single-transaction --skip-add-drop-table --no-tablespaces controller_source > controller.sql` | `mariadb controller_restore < controller.sql` |
| MySQL | `mysqldump --single-transaction --skip-add-drop-table --no-tablespaces --set-gtid-purged=OFF controller_source > controller.sql` | `mysql controller_restore < controller.sql` |
| SQL Server | `BACKUP DATABASE [controller_source] TO DISK = N'/private/controller.bak' WITH COPY_ONLY, CHECKSUM;` | Use `RESTORE FILELISTONLY` for the logical names. Restore as `[controller_restore]` with `CHECKSUM` and a separate `MOVE` destination for every file. |

For PostgreSQL, MariaDB and MySQL, create the empty restore database before
invoking the restore command. Recreate any required login or grants and retain
an authorized trigger definer when restoring into a different instance.
For SQL Server, give the server account access to the backup file and create
the restore database through `RESTORE DATABASE`. Use free target file paths.
Use `RESTORE VERIFYONLY … WITH CHECKSUM` to check a SQL Server archive and
complete a real restore to test recovery.

Start an isolated controller on the restore with agent dispatch unavailable.
Compare saved settings, sources, objects, revisions and audit to the expected
snapshot. Save an ordinary settings edit and verify the next version and audit
event. Keep the source untouched. Recovery of a production controller requires
a separate assessment of the agent journal and observed host state.
