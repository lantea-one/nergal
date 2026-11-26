-- The application initializes the metadata row and settings version zero after DDL.
CREATE TABLE controller_metadata (
    id BIGINT NOT NULL PRIMARY KEY,
    schema_version BIGINT NOT NULL,
    schema_fingerprint VARCHAR(64) NOT NULL,
    CONSTRAINT controller_metadata_singleton CHECK (id = 1)
) ENGINE=InnoDB DEFAULT CHARACTER SET utf8mb4 COLLATE __NERGAL_BINARY_COLLATION__;
-- nergal:statement
CREATE TABLE hosts (
    id VARCHAR(36) NOT NULL PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    transport_kind VARCHAR(8) NOT NULL,
    endpoint TEXT NOT NULL,
    expected_uid BIGINT,
    socket_gid BIGINT,
    pinned_thumbprint TEXT,
    last_known_revision TEXT NOT NULL,
    created_at_utc TEXT NOT NULL,
    UNIQUE KEY hosts_name (name),
    CONSTRAINT hosts_transport_kind CHECK (transport_kind IN ('unix', 'tls'))
) ENGINE=InnoDB DEFAULT CHARACTER SET utf8mb4 COLLATE __NERGAL_BINARY_COLLATION__;
-- nergal:statement
CREATE TABLE policy_revisions (
    revision BIGINT NOT NULL PRIMARY KEY,
    policy_json LONGTEXT NOT NULL,
    candidate_digest TEXT NOT NULL,
    created_by_actor TEXT NOT NULL,
    created_at_utc TEXT NOT NULL,
    summary TEXT,
    CONSTRAINT policy_revisions_positive CHECK (revision >= 1)
) ENGINE=InnoDB DEFAULT CHARACTER SET utf8mb4 COLLATE __NERGAL_BINARY_COLLATION__;
-- nergal:statement
CREATE TABLE audit_log (
    sequence BIGINT NOT NULL PRIMARY KEY,
    timestamp_utc TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_role TEXT NOT NULL,
    action VARCHAR(128) NOT NULL,
    target TEXT NOT NULL,
    revision TEXT,
    outcome TEXT NOT NULL,
    detail_code TEXT,
    -- An action-leading index serves the lookup of the latest settings audit.
    KEY settings_audit_sequence (action, sequence)
) ENGINE=InnoDB DEFAULT CHARACTER SET utf8mb4 COLLATE __NERGAL_BINARY_COLLATION__;
-- nergal:statement
CREATE TABLE native_sources (
    id VARCHAR(36) NOT NULL PRIMARY KEY,
    rowid BIGINT NOT NULL AUTO_INCREMENT,
    name TEXT NOT NULL,
    source_text LONGBLOB NOT NULL,
    source_sha256 TEXT NOT NULL,
    byte_length INT NOT NULL,
    imported_by_actor TEXT NOT NULL,
    imported_at_utc TEXT NOT NULL,
    UNIQUE KEY native_sources_rowid (rowid),
    CONSTRAINT native_sources_byte_length CHECK (byte_length BETWEEN 1 AND 524288)
) ENGINE=InnoDB DEFAULT CHARACTER SET utf8mb4 COLLATE __NERGAL_BINARY_COLLATION__;
-- nergal:statement
CREATE TABLE reusable_objects (
    id VARCHAR(36) NOT NULL PRIMARY KEY,
    name VARCHAR(64) NOT NULL,
    kind VARCHAR(8) NOT NULL,
    UNIQUE KEY reusable_objects_name (name),
    CONSTRAINT reusable_objects_kind CHECK (kind IN ('Ipv4', 'Ipv6', 'Port'))
) ENGINE=InnoDB DEFAULT CHARACTER SET utf8mb4 COLLATE __NERGAL_BINARY_COLLATION__;
-- nergal:statement
CREATE TABLE reusable_object_versions (
    object_id VARCHAR(36) NOT NULL,
    version INT NOT NULL,
    description TEXT NOT NULL,
    entries_json LONGTEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    updated_by_actor TEXT NOT NULL,
    updated_at_utc TEXT NOT NULL,
    PRIMARY KEY (object_id, version),
    CONSTRAINT reusable_object_versions_object_fk FOREIGN KEY (object_id) REFERENCES reusable_objects (id),
    CONSTRAINT reusable_object_versions_supported CHECK (version BETWEEN 1 AND 64),
    CONSTRAINT reusable_object_versions_description_length CHECK (CHAR_LENGTH(description) <= 500),
    CONSTRAINT reusable_object_versions_entries_length CHECK (CHAR_LENGTH(entries_json) <= 8192)
) ENGINE=InnoDB DEFAULT CHARACTER SET utf8mb4 COLLATE __NERGAL_BINARY_COLLATION__;
-- nergal:statement
CREATE TABLE native_conversion_plans (
    id VARCHAR(36) NOT NULL PRIMARY KEY,
    rowid BIGINT NOT NULL AUTO_INCREMENT,
    root_source_id VARCHAR(36) NOT NULL,
    request_json LONGTEXT NOT NULL,
    report_json LONGTEXT NOT NULL,
    policy_json LONGTEXT,
    candidate_sha256 TEXT,
    content_sha256 TEXT NOT NULL,
    created_by_actor TEXT NOT NULL,
    created_at_utc TEXT NOT NULL,
    UNIQUE KEY native_conversion_plans_rowid (rowid),
    KEY native_conversion_plans_source (root_source_id),
    CONSTRAINT native_conversion_plans_source_fk FOREIGN KEY (root_source_id) REFERENCES native_sources (id)
) ENGINE=InnoDB DEFAULT CHARACTER SET utf8mb4 COLLATE __NERGAL_BINARY_COLLATION__;
-- nergal:statement
CREATE TABLE native_conversion_commits (
    plan_id VARCHAR(36) NOT NULL PRIMARY KEY,
    revision BIGINT NOT NULL,
    UNIQUE KEY native_conversion_commits_revision (revision),
    CONSTRAINT native_conversion_commits_plan_fk FOREIGN KEY (plan_id) REFERENCES native_conversion_plans (id),
    CONSTRAINT native_conversion_commits_revision_fk FOREIGN KEY (revision) REFERENCES policy_revisions (revision)
) ENGINE=InnoDB DEFAULT CHARACTER SET utf8mb4 COLLATE __NERGAL_BINARY_COLLATION__;
-- nergal:statement
CREATE TABLE system_settings (
    version BIGINT NOT NULL PRIMARY KEY,
    -- Allow one extra character so trailing-space truncation cannot produce a valid token.
    form_token VARCHAR(33) NOT NULL,
    settings_json LONGTEXT NOT NULL,
    audit_sequence BIGINT,
    UNIQUE KEY system_settings_form_token (form_token),
    UNIQUE KEY system_settings_audit_sequence (audit_sequence),
    CONSTRAINT system_settings_audit_fk FOREIGN KEY (audit_sequence) REFERENCES audit_log (sequence),
    CONSTRAINT system_settings_version CHECK (version >= 0),
    CONSTRAINT system_settings_token CHECK (
        CHAR_LENGTH(form_token) = 32 AND UNHEX(form_token) IS NOT NULL
        AND form_token = LOWER(HEX(UNHEX(form_token)))
    ),
    CONSTRAINT system_settings_json CHECK (CHAR_LENGTH(TRIM(settings_json)) > 0),
    CONSTRAINT system_settings_audit_binding CHECK (
        (version = 0 AND audit_sequence IS NULL) OR (version > 0 AND audit_sequence IS NOT NULL)
    )
) ENGINE=InnoDB DEFAULT CHARACTER SET utf8mb4 COLLATE __NERGAL_BINARY_COLLATION__;
-- nergal:statement
CREATE TRIGGER policy_revisions_no_update BEFORE UPDATE ON policy_revisions FOR EACH ROW
SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'policy revisions are immutable';
-- nergal:statement
CREATE TRIGGER policy_revisions_no_delete BEFORE DELETE ON policy_revisions FOR EACH ROW
SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'policy revisions are immutable';
-- nergal:statement
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_log FOR EACH ROW
SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit log is append-only';
-- nergal:statement
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_log FOR EACH ROW
SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit log is append-only';
-- nergal:statement
CREATE TRIGGER native_sources_no_update BEFORE UPDATE ON native_sources FOR EACH ROW
SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'native sources are immutable';
-- nergal:statement
CREATE TRIGGER native_sources_no_delete BEFORE DELETE ON native_sources FOR EACH ROW
SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'native sources are immutable';
-- nergal:statement
CREATE TRIGGER reusable_objects_no_update BEFORE UPDATE ON reusable_objects FOR EACH ROW
SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'object history is immutable';
-- nergal:statement
CREATE TRIGGER reusable_objects_no_delete BEFORE DELETE ON reusable_objects FOR EACH ROW
SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'object history is immutable';
-- nergal:statement
CREATE TRIGGER reusable_object_versions_no_update BEFORE UPDATE ON reusable_object_versions FOR EACH ROW
SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'object history is immutable';
-- nergal:statement
CREATE TRIGGER reusable_object_versions_no_delete BEFORE DELETE ON reusable_object_versions FOR EACH ROW
SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'object history is immutable';
-- nergal:statement
CREATE TRIGGER native_conversion_plans_no_update BEFORE UPDATE ON native_conversion_plans FOR EACH ROW
SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'native conversion history is immutable';
-- nergal:statement
CREATE TRIGGER native_conversion_plans_no_delete BEFORE DELETE ON native_conversion_plans FOR EACH ROW
SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'native conversion history is immutable';
-- nergal:statement
CREATE TRIGGER native_conversion_commits_no_update BEFORE UPDATE ON native_conversion_commits FOR EACH ROW
SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'native conversion history is immutable';
-- nergal:statement
CREATE TRIGGER native_conversion_commits_no_delete BEFORE DELETE ON native_conversion_commits FOR EACH ROW
SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'native conversion history is immutable';
-- nergal:statement
-- Check unique bindings before a REPLACE can attempt to delete an earlier version.
-- Application writers hold the controller_metadata row lock through commit.
CREATE TRIGGER system_settings_append BEFORE INSERT ON system_settings FOR EACH ROW
BEGIN
    IF NEW.version - 1 <> (SELECT COALESCE(MAX(version), -1) FROM system_settings)
       OR EXISTS (
           SELECT 1 FROM system_settings
           WHERE form_token = NEW.form_token OR audit_sequence = NEW.audit_sequence
       ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'settings versions must be consecutive and unique';
    END IF;
END;
-- nergal:statement
CREATE TRIGGER system_settings_no_update BEFORE UPDATE ON system_settings FOR EACH ROW
SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'settings versions are immutable';
-- nergal:statement
CREATE TRIGGER system_settings_no_delete BEFORE DELETE ON system_settings FOR EACH ROW
SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'settings versions are immutable';
