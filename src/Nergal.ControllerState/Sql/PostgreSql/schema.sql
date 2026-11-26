-- Apply all statements in one transaction against a dedicated database.
-- The controller inserts the metadata singleton and settings version zero.
DO $init$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_namespace AS ns
        WHERE ns.nspname = 'public'
          AND NOT EXISTS (
              SELECT 1
              FROM pg_catalog.pg_depend AS dep
              WHERE dep.refclassid = 'pg_catalog.pg_namespace'::pg_catalog.regclass
                AND dep.refobjid = ns.oid
          )
    ) THEN
        RAISE EXCEPTION 'controller requires an empty public schema';
    END IF;
END;
$init$ LANGUAGE plpgsql;
-- nergal:statement
CREATE TABLE public.controller_metadata (
    id BIGINT PRIMARY KEY CHECK (id = 1),
    schema_version BIGINT NOT NULL,
    schema_fingerprint VARCHAR(64) COLLATE pg_catalog."C" NOT NULL
);
-- nergal:statement
CREATE TABLE public.hosts (
    id TEXT COLLATE pg_catalog."C" PRIMARY KEY,
    name TEXT COLLATE pg_catalog."C" NOT NULL UNIQUE,
    transport_kind TEXT COLLATE pg_catalog."C" NOT NULL CHECK (transport_kind IN ('unix', 'tls')),
    endpoint TEXT COLLATE pg_catalog."C" NOT NULL,
    expected_uid BIGINT,
    socket_gid BIGINT,
    pinned_thumbprint TEXT COLLATE pg_catalog."C",
    last_known_revision TEXT COLLATE pg_catalog."C" NOT NULL,
    created_at_utc TEXT COLLATE pg_catalog."C" NOT NULL
);
-- nergal:statement
CREATE TABLE public.host_observations (
    host_id TEXT COLLATE pg_catalog."C" NOT NULL PRIMARY KEY REFERENCES public.hosts(id) ON DELETE CASCADE,
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 5),
    reported_revision TEXT,
    observed_at_utc TEXT NOT NULL
);
-- nergal:statement
CREATE TABLE public.policy_revisions (
    revision BIGINT PRIMARY KEY CHECK (revision >= 1),
    policy_json TEXT COLLATE pg_catalog."C" NOT NULL,
    candidate_digest TEXT COLLATE pg_catalog."C" NOT NULL,
    created_by_actor TEXT COLLATE pg_catalog."C" NOT NULL,
    created_at_utc TEXT COLLATE pg_catalog."C" NOT NULL,
    summary TEXT COLLATE pg_catalog."C"
);
-- nergal:statement
-- Writers allocate this key under the controller_metadata row lock.
CREATE TABLE public.audit_log (
    sequence BIGINT PRIMARY KEY,
    timestamp_utc TEXT COLLATE pg_catalog."C" NOT NULL,
    actor_id TEXT COLLATE pg_catalog."C" NOT NULL,
    actor_role TEXT COLLATE pg_catalog."C" NOT NULL,
    action TEXT COLLATE pg_catalog."C" NOT NULL,
    target TEXT COLLATE pg_catalog."C" NOT NULL,
    revision TEXT COLLATE pg_catalog."C",
    outcome TEXT COLLATE pg_catalog."C" NOT NULL,
    detail_code TEXT COLLATE pg_catalog."C"
);
-- nergal:statement
CREATE TABLE public.native_sources (
    id TEXT COLLATE pg_catalog."C" PRIMARY KEY,
    name TEXT COLLATE pg_catalog."C" NOT NULL,
    source_text BYTEA NOT NULL,
    source_sha256 TEXT COLLATE pg_catalog."C" NOT NULL,
    byte_length INT NOT NULL CHECK (byte_length BETWEEN 1 AND 524288),
    imported_by_actor TEXT COLLATE pg_catalog."C" NOT NULL,
    imported_at_utc TEXT COLLATE pg_catalog."C" NOT NULL,
    rowid BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE
);
-- nergal:statement
CREATE TABLE public.reusable_objects (
    id TEXT COLLATE pg_catalog."C" PRIMARY KEY,
    name TEXT COLLATE pg_catalog."C" NOT NULL UNIQUE,
    kind TEXT COLLATE pg_catalog."C" NOT NULL CHECK (kind IN ('Ipv4', 'Ipv6', 'Port'))
);
-- nergal:statement
CREATE TABLE public.reusable_object_versions (
    object_id TEXT COLLATE pg_catalog."C" NOT NULL REFERENCES public.reusable_objects(id),
    version INT NOT NULL CHECK (version BETWEEN 1 AND 64),
    description TEXT COLLATE pg_catalog."C" NOT NULL CHECK (length(description) <= 500),
    entries_json TEXT COLLATE pg_catalog."C" NOT NULL CHECK (length(entries_json) <= 8192),
    content_sha256 TEXT COLLATE pg_catalog."C" NOT NULL,
    updated_by_actor TEXT COLLATE pg_catalog."C" NOT NULL,
    updated_at_utc TEXT COLLATE pg_catalog."C" NOT NULL,
    PRIMARY KEY (object_id, version)
);
-- nergal:statement
CREATE TABLE public.native_conversion_plans (
    id TEXT COLLATE pg_catalog."C" PRIMARY KEY,
    root_source_id TEXT COLLATE pg_catalog."C" NOT NULL REFERENCES public.native_sources(id),
    request_json TEXT COLLATE pg_catalog."C" NOT NULL,
    report_json TEXT COLLATE pg_catalog."C" NOT NULL,
    policy_json TEXT COLLATE pg_catalog."C",
    candidate_sha256 TEXT COLLATE pg_catalog."C",
    content_sha256 TEXT COLLATE pg_catalog."C" NOT NULL,
    created_by_actor TEXT COLLATE pg_catalog."C" NOT NULL,
    created_at_utc TEXT COLLATE pg_catalog."C" NOT NULL,
    rowid BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE
);
-- nergal:statement
CREATE TABLE public.native_conversion_commits (
    plan_id TEXT COLLATE pg_catalog."C" PRIMARY KEY REFERENCES public.native_conversion_plans(id),
    revision BIGINT NOT NULL UNIQUE REFERENCES public.policy_revisions(revision)
);
-- nergal:statement
CREATE TABLE public.system_settings (
    version BIGINT PRIMARY KEY CHECK (version >= 0),
    form_token TEXT COLLATE pg_catalog."C" NOT NULL UNIQUE
        CHECK (length(form_token) = 32 AND form_token !~ '[^0-9a-f]'),
    settings_json TEXT COLLATE pg_catalog."C" NOT NULL CHECK (length(trim(settings_json)) > 0),
    audit_sequence BIGINT UNIQUE REFERENCES public.audit_log(sequence) ON DELETE RESTRICT,
    CHECK ((version = 0 AND audit_sequence IS NULL) OR (version > 0 AND audit_sequence IS NOT NULL))
);
-- nergal:statement
CREATE INDEX settings_audit_sequence ON public.audit_log(sequence) WHERE action = 'settings.update';
-- nergal:statement
CREATE FUNCTION public.reject_history_mutation() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pg_catalog
AS $function$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = '23514';
END;
$function$;
-- nergal:statement
-- Statement triggers protect history from TRUNCATE and reject even zero-row edits.
CREATE TRIGGER policy_revisions_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON public.policy_revisions
    FOR EACH STATEMENT EXECUTE FUNCTION public.reject_history_mutation();
-- nergal:statement
CREATE TRIGGER audit_log_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON public.audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION public.reject_history_mutation();
-- nergal:statement
CREATE TRIGGER native_sources_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON public.native_sources
    FOR EACH STATEMENT EXECUTE FUNCTION public.reject_history_mutation();
-- nergal:statement
CREATE TRIGGER reusable_objects_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON public.reusable_objects
    FOR EACH STATEMENT EXECUTE FUNCTION public.reject_history_mutation();
-- nergal:statement
CREATE TRIGGER reusable_object_versions_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON public.reusable_object_versions
    FOR EACH STATEMENT EXECUTE FUNCTION public.reject_history_mutation();
-- nergal:statement
CREATE TRIGGER native_conversion_plans_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON public.native_conversion_plans
    FOR EACH STATEMENT EXECUTE FUNCTION public.reject_history_mutation();
-- nergal:statement
CREATE TRIGGER native_conversion_commits_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON public.native_conversion_commits
    FOR EACH STATEMENT EXECUTE FUNCTION public.reject_history_mutation();
-- nergal:statement
CREATE TRIGGER system_settings_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON public.system_settings
    FOR EACH STATEMENT EXECUTE FUNCTION public.reject_history_mutation();
-- nergal:statement
CREATE FUNCTION public.require_next_settings_version() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pg_catalog
AS $function$
BEGIN
    IF NEW.version <> (SELECT coalesce(max(version) + 1, 0) FROM public.system_settings)
       OR EXISTS (
           SELECT 1
           FROM public.system_settings
           WHERE form_token = NEW.form_token OR audit_sequence = NEW.audit_sequence
       ) THEN
        RAISE EXCEPTION 'settings versions must be consecutive and unique' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$function$;
-- nergal:statement
CREATE TRIGGER system_settings_append BEFORE INSERT ON public.system_settings
    FOR EACH ROW EXECUTE FUNCTION public.require_next_settings_version();
