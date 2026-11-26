-- Run fresh initialization with a separate provisioning principal. The caller
-- seeds settings version 0 and writes the metadata singleton after the schema.
--
-- The runtime principal needs database VIEW DEFINITION for the catalog check,
-- SELECT on the controller tables, INSERT on the data tables, UPDATE on
-- hosts.last_known_revision and host_observations, and DELETE on hosts. Keep it outside owner, DDL,
-- and bulk-administration roles and with no ALTER or CONTROL on these objects
-- or their containing schema/database. TRUNCATE bypasses DML triggers and
-- requires ALTER. The settings trigger also depends on ordinary DML firing.
--
-- The filtered indexes require these session options during creation and
-- subsequent writes to audit_log and system_settings.
SET ANSI_NULLS ON;
-- nergal:statement
SET ANSI_PADDING ON;
-- nergal:statement
SET ANSI_WARNINGS ON;
-- nergal:statement
SET ARITHABORT ON;
-- nergal:statement
SET CONCAT_NULL_YIELDS_NULL ON;
-- nergal:statement
SET QUOTED_IDENTIFIER ON;
-- nergal:statement
SET NUMERIC_ROUNDABORT OFF;
-- nergal:statement
CREATE TABLE dbo.hosts (
    id nvarchar(36) COLLATE Latin1_General_100_BIN2 NOT NULL,
    name nvarchar(128) COLLATE Latin1_General_100_BIN2 NOT NULL,
    transport_kind nvarchar(4) COLLATE Latin1_General_100_BIN2 NOT NULL,
    endpoint nvarchar(512) COLLATE Latin1_General_100_BIN2 NOT NULL,
    expected_uid bigint NULL,
    socket_gid bigint NULL,
    pinned_thumbprint nvarchar(64) COLLATE Latin1_General_100_BIN2 NULL,
    last_known_revision nvarchar(20) COLLATE Latin1_General_100_BIN2 NOT NULL,
    created_at_utc nvarchar(40) COLLATE Latin1_General_100_BIN2 NOT NULL,
    CONSTRAINT pk_hosts PRIMARY KEY (id),
    CONSTRAINT uq_hosts_name UNIQUE (name),
    CONSTRAINT ck_hosts_transport CHECK (
        (transport_kind = N'unix' AND DATALENGTH(transport_kind) = 8)
        OR (transport_kind = N'tls' AND DATALENGTH(transport_kind) = 6)
    )
);
-- nergal:statement
CREATE TABLE dbo.host_observations (
    host_id nvarchar(36) COLLATE Latin1_General_100_BIN2 NOT NULL PRIMARY KEY,
    state int NOT NULL CHECK (state BETWEEN 1 AND 5),
    reported_revision nvarchar(20),
    observed_at_utc nvarchar(40) NOT NULL,
    CONSTRAINT fk_host_observations_host FOREIGN KEY (host_id) REFERENCES dbo.hosts(id) ON DELETE CASCADE
);
-- nergal:statement
CREATE TABLE dbo.policy_revisions (
    revision bigint NOT NULL,
    policy_json nvarchar(max) NOT NULL,
    candidate_digest nvarchar(64) COLLATE Latin1_General_100_BIN2 NOT NULL,
    created_by_actor nvarchar(1024) COLLATE Latin1_General_100_BIN2 NOT NULL,
    created_at_utc nvarchar(40) COLLATE Latin1_General_100_BIN2 NOT NULL,
    summary nvarchar(256) COLLATE Latin1_General_100_BIN2 NULL,
    CONSTRAINT pk_policy_revisions PRIMARY KEY (revision),
    CONSTRAINT ck_policy_revisions_revision CHECK (revision >= 1)
);
-- nergal:statement
CREATE TABLE dbo.audit_log (
    sequence bigint NOT NULL,
    timestamp_utc nvarchar(40) COLLATE Latin1_General_100_BIN2 NOT NULL,
    actor_id nvarchar(1024) COLLATE Latin1_General_100_BIN2 NOT NULL,
    actor_role nvarchar(32) COLLATE Latin1_General_100_BIN2 NOT NULL,
    action nvarchar(128) COLLATE Latin1_General_100_BIN2 NOT NULL,
    target nvarchar(256) COLLATE Latin1_General_100_BIN2 NOT NULL,
    revision nvarchar(20) COLLATE Latin1_General_100_BIN2 NULL,
    outcome nvarchar(64) COLLATE Latin1_General_100_BIN2 NOT NULL,
    -- Settings audit details include a full SHA-256 binding and the version.
    detail_code nvarchar(128) COLLATE Latin1_General_100_BIN2 NULL,
    CONSTRAINT pk_audit_log PRIMARY KEY (sequence)
);
-- nergal:statement
CREATE TABLE dbo.native_sources (
    id nvarchar(36) COLLATE Latin1_General_100_BIN2 NOT NULL,
    name nvarchar(120) COLLATE Latin1_General_100_BIN2 NOT NULL,
    source_text varbinary(max) NOT NULL,
    source_sha256 nvarchar(64) COLLATE Latin1_General_100_BIN2 NOT NULL,
    byte_length int NOT NULL,
    imported_by_actor nvarchar(1024) COLLATE Latin1_General_100_BIN2 NOT NULL,
    imported_at_utc nvarchar(40) COLLATE Latin1_General_100_BIN2 NOT NULL,
    rowid bigint IDENTITY(1, 1) NOT NULL,
    CONSTRAINT pk_native_sources PRIMARY KEY (id),
    CONSTRAINT uq_native_sources_rowid UNIQUE (rowid),
    CONSTRAINT ck_native_sources_byte_length CHECK (byte_length BETWEEN 1 AND 524288)
);
-- nergal:statement
CREATE TABLE dbo.reusable_objects (
    id nvarchar(36) COLLATE Latin1_General_100_BIN2 NOT NULL,
    name nvarchar(64) COLLATE Latin1_General_100_BIN2 NOT NULL,
    kind nvarchar(4) COLLATE Latin1_General_100_BIN2 NOT NULL,
    CONSTRAINT pk_reusable_objects PRIMARY KEY (id),
    CONSTRAINT uq_reusable_objects_name UNIQUE (name),
    CONSTRAINT ck_reusable_objects_kind CHECK (kind IN (N'Ipv4', N'Ipv6', N'Port'))
);
-- nergal:statement
CREATE TABLE dbo.reusable_object_versions (
    object_id nvarchar(36) COLLATE Latin1_General_100_BIN2 NOT NULL,
    version int NOT NULL,
    description nvarchar(1000) COLLATE Latin1_General_100_BIN2 NOT NULL,
    entries_json nvarchar(max) NOT NULL,
    content_sha256 nvarchar(64) COLLATE Latin1_General_100_BIN2 NOT NULL,
    updated_by_actor nvarchar(1024) COLLATE Latin1_General_100_BIN2 NOT NULL,
    updated_at_utc nvarchar(40) COLLATE Latin1_General_100_BIN2 NOT NULL,
    CONSTRAINT pk_reusable_object_versions PRIMARY KEY (object_id, version),
    CONSTRAINT fk_reusable_object_versions_object FOREIGN KEY (object_id) REFERENCES dbo.reusable_objects (id),
    CONSTRAINT ck_reusable_object_versions_version CHECK (version BETWEEN 1 AND 64),
    -- SQLite counts Unicode code points and includes trailing spaces.
    CONSTRAINT ck_reusable_object_versions_description CHECK (
        LEN((description + N'#') COLLATE Latin1_General_100_CI_AS_SC) <= 501
    ),
    CONSTRAINT ck_reusable_object_versions_entries CHECK (
        LEN((entries_json + N'#') COLLATE Latin1_General_100_CI_AS_SC) <= 8193
    )
);
-- nergal:statement
CREATE TABLE dbo.native_conversion_plans (
    id nvarchar(36) COLLATE Latin1_General_100_BIN2 NOT NULL,
    root_source_id nvarchar(36) COLLATE Latin1_General_100_BIN2 NOT NULL,
    request_json nvarchar(max) NOT NULL,
    report_json nvarchar(max) NOT NULL,
    policy_json nvarchar(max) NULL,
    candidate_sha256 nvarchar(64) COLLATE Latin1_General_100_BIN2 NULL,
    content_sha256 nvarchar(64) COLLATE Latin1_General_100_BIN2 NOT NULL,
    created_by_actor nvarchar(1024) COLLATE Latin1_General_100_BIN2 NOT NULL,
    created_at_utc nvarchar(40) COLLATE Latin1_General_100_BIN2 NOT NULL,
    rowid bigint IDENTITY(1, 1) NOT NULL,
    CONSTRAINT pk_native_conversion_plans PRIMARY KEY (id),
    CONSTRAINT uq_native_conversion_plans_rowid UNIQUE (rowid),
    CONSTRAINT fk_native_conversion_plans_source FOREIGN KEY (root_source_id) REFERENCES dbo.native_sources (id)
);
-- nergal:statement
CREATE TABLE dbo.native_conversion_commits (
    plan_id nvarchar(36) COLLATE Latin1_General_100_BIN2 NOT NULL,
    revision bigint NOT NULL,
    CONSTRAINT pk_native_conversion_commits PRIMARY KEY (plan_id),
    CONSTRAINT uq_native_conversion_commits_revision UNIQUE (revision),
    CONSTRAINT fk_native_conversion_commits_plan FOREIGN KEY (plan_id) REFERENCES dbo.native_conversion_plans (id),
    CONSTRAINT fk_native_conversion_commits_revision FOREIGN KEY (revision) REFERENCES dbo.policy_revisions (revision)
);
-- nergal:statement
CREATE TABLE dbo.system_settings (
    version bigint NOT NULL,
    form_token nvarchar(33) COLLATE Latin1_General_100_BIN2 NOT NULL,
    settings_json nvarchar(max) NOT NULL,
    audit_sequence bigint NULL,
    CONSTRAINT pk_system_settings PRIMARY KEY (version),
    CONSTRAINT uq_system_settings_form_token UNIQUE (form_token),
    CONSTRAINT fk_system_settings_audit FOREIGN KEY (audit_sequence) REFERENCES dbo.audit_log (sequence),
    CONSTRAINT ck_system_settings_version CHECK (version >= 0),
    CONSTRAINT ck_system_settings_form_token CHECK (
        DATALENGTH(form_token) = 64 AND form_token NOT LIKE N'%[^0-9a-f]%'
        AND RIGHT(form_token, 1) <> N' '
    ),
    CONSTRAINT ck_system_settings_json CHECK (DATALENGTH(TRIM(settings_json)) > 0),
    CONSTRAINT ck_system_settings_audit CHECK (
        (version = 0 AND audit_sequence IS NULL) OR (version > 0 AND audit_sequence IS NOT NULL)
    )
);
-- nergal:statement
CREATE UNIQUE INDEX uq_system_settings_audit_sequence ON dbo.system_settings (audit_sequence)
WHERE audit_sequence IS NOT NULL;
-- nergal:statement
-- SQL Server pads operands for equality even under BIN2. The settings audit
-- lookup can also compare DATALENGTH(action) for an exact token match.
CREATE INDEX settings_audit_sequence ON dbo.audit_log (sequence)
WHERE action = N'settings.update';
-- nergal:statement
CREATE TABLE dbo.controller_metadata (
    id bigint NOT NULL,
    schema_version bigint NOT NULL,
    schema_fingerprint varchar(64) COLLATE Latin1_General_100_BIN2 NOT NULL,
    CONSTRAINT pk_controller_metadata PRIMARY KEY (id),
    CONSTRAINT ck_controller_metadata_singleton CHECK (id = 1)
);
-- nergal:statement
CREATE TRIGGER dbo.system_settings_append ON dbo.system_settings
INSTEAD OF INSERT
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @first bigint, @last bigint, @row_count bigint;
    SELECT @first = MIN(version), @last = MAX(version), @row_count = COUNT_BIG(*) FROM inserted;
    IF @row_count = 0
        RETURN;

    -- Reserve the top of the primary key range before inserting any versions.
    DECLARE @previous bigint = -1;
    SELECT TOP (1) @previous = version
    FROM dbo.system_settings WITH (UPDLOCK, HOLDLOCK)
    ORDER BY version DESC;

    IF @first <> CONVERT(decimal(20, 0), @previous) + 1
       OR CONVERT(decimal(20, 0), @last) - @first + 1 <> @row_count
        THROW 50001, 'settings versions must be consecutive and unique', 1;

    -- The inner INSERT enforces the primary key, unique keys and audit FK.
    INSERT INTO dbo.system_settings (version, form_token, settings_json, audit_sequence)
    SELECT version, form_token, settings_json, audit_sequence FROM inserted;
END;
-- nergal:statement
CREATE TRIGGER dbo.policy_revisions_no_update ON dbo.policy_revisions
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    THROW 50002, 'policy revisions are immutable', 1;
END;
-- nergal:statement
CREATE TRIGGER dbo.policy_revisions_no_delete ON dbo.policy_revisions
AFTER DELETE
AS
BEGIN
    SET NOCOUNT ON;
    THROW 50002, 'policy revisions are immutable', 1;
END;
-- nergal:statement
CREATE TRIGGER dbo.audit_no_update ON dbo.audit_log
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    THROW 50002, 'audit log is append-only', 1;
END;
-- nergal:statement
CREATE TRIGGER dbo.audit_no_delete ON dbo.audit_log
AFTER DELETE
AS
BEGIN
    SET NOCOUNT ON;
    THROW 50002, 'audit log is append-only', 1;
END;
-- nergal:statement
CREATE TRIGGER dbo.native_sources_no_update ON dbo.native_sources
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    THROW 50002, 'native sources are immutable', 1;
END;
-- nergal:statement
CREATE TRIGGER dbo.native_sources_no_delete ON dbo.native_sources
AFTER DELETE
AS
BEGIN
    SET NOCOUNT ON;
    THROW 50002, 'native sources are immutable', 1;
END;
-- nergal:statement
CREATE TRIGGER dbo.reusable_objects_no_update ON dbo.reusable_objects
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    THROW 50002, 'object history is immutable', 1;
END;
-- nergal:statement
CREATE TRIGGER dbo.reusable_objects_no_delete ON dbo.reusable_objects
AFTER DELETE
AS
BEGIN
    SET NOCOUNT ON;
    THROW 50002, 'object history is immutable', 1;
END;
-- nergal:statement
CREATE TRIGGER dbo.reusable_object_versions_no_update ON dbo.reusable_object_versions
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    THROW 50002, 'object history is immutable', 1;
END;
-- nergal:statement
CREATE TRIGGER dbo.reusable_object_versions_no_delete ON dbo.reusable_object_versions
AFTER DELETE
AS
BEGIN
    SET NOCOUNT ON;
    THROW 50002, 'object history is immutable', 1;
END;
-- nergal:statement
CREATE TRIGGER dbo.native_conversion_plans_no_update ON dbo.native_conversion_plans
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    THROW 50002, 'native conversion history is immutable', 1;
END;
-- nergal:statement
CREATE TRIGGER dbo.native_conversion_plans_no_delete ON dbo.native_conversion_plans
AFTER DELETE
AS
BEGIN
    SET NOCOUNT ON;
    THROW 50002, 'native conversion history is immutable', 1;
END;
-- nergal:statement
CREATE TRIGGER dbo.native_conversion_commits_no_update ON dbo.native_conversion_commits
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    THROW 50002, 'native conversion history is immutable', 1;
END;
-- nergal:statement
CREATE TRIGGER dbo.native_conversion_commits_no_delete ON dbo.native_conversion_commits
AFTER DELETE
AS
BEGIN
    SET NOCOUNT ON;
    THROW 50002, 'native conversion history is immutable', 1;
END;
-- nergal:statement
CREATE TRIGGER dbo.system_settings_no_update ON dbo.system_settings
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    THROW 50002, 'settings versions are immutable', 1;
END;
-- nergal:statement
CREATE TRIGGER dbo.system_settings_no_delete ON dbo.system_settings
AFTER DELETE
AS
BEGIN
    SET NOCOUNT ON;
    THROW 50002, 'settings versions are immutable', 1;
END;
