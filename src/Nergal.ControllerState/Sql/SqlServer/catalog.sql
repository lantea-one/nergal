-- Serialize catalog structure, not database names, object IDs, or current
-- IDENTITY values. Quote identifiers and keep free-form definitions last.
-- The caller needs database VIEW DEFINITION to see definitions and extra objects.
WITH user_tables AS (
    SELECT t.*, QUOTENAME(s.name) + N'.' + QUOTENAME(t.name) AS qualified_name
    FROM sys.tables AS t
    JOIN sys.schemas AS s ON s.schema_id = t.schema_id
    WHERE t.is_ms_shipped = 0
),
user_triggers AS (
    SELECT tr.*, COALESCE(t.qualified_name, N'<database>') AS parent_name
    FROM sys.triggers AS tr
    LEFT JOIN user_tables AS t ON tr.parent_class = 1 AND t.object_id = tr.parent_id
    WHERE tr.is_ms_shipped = 0 AND (tr.parent_class = 0 OR t.object_id IS NOT NULL)
),
catalog AS (
    SELECT CONCAT(CONVERT(nvarchar(max), N'TABLE|') COLLATE Latin1_General_100_BIN2, t.qualified_name,
                  N'|', t.temporal_type, N'|', t.is_memory_optimized, N'|', t.durability) AS schema_row
    FROM user_tables AS t

    UNION ALL

    SELECT CONCAT(N'COLUMN|' COLLATE Latin1_General_100_BIN2, t.qualified_name, N'|', c.column_id, N'|', QUOTENAME(c.name),
                  N'|', QUOTENAME(ts.name), N'.', QUOTENAME(ty.name), N'|', c.max_length,
                  N'|', c.precision, N'|', c.scale, N'|', c.is_nullable, N'|',
                  COALESCE(c.collation_name, N'<null>'), N'|', c.is_ansi_padded,
                  N'|', c.is_identity, N'|', CONVERT(nvarchar(100), ic.seed_value),
                  N'|', CONVERT(nvarchar(100), ic.increment_value), N'|', ic.is_not_for_replication,
                  N'|', c.generated_always_type, N'|', c.is_computed, N'|', cc.is_persisted,
                  N'|', COALESCE(cc.definition, N'<null>'))
    FROM user_tables AS t
    JOIN sys.columns AS c ON c.object_id = t.object_id
    JOIN sys.types AS ty ON ty.user_type_id = c.user_type_id
    JOIN sys.schemas AS ts ON ts.schema_id = ty.schema_id
    LEFT JOIN sys.identity_columns AS ic ON ic.object_id = c.object_id AND ic.column_id = c.column_id
    LEFT JOIN sys.computed_columns AS cc ON cc.object_id = c.object_id AND cc.column_id = c.column_id

    UNION ALL

    SELECT CONCAT(N'INDEX|' COLLATE Latin1_General_100_BIN2, t.qualified_name, N'|', QUOTENAME(i.name), N'|', i.type,
                  N'|', i.is_unique, N'|', i.is_primary_key, N'|', i.is_unique_constraint,
                  N'|', i.is_disabled, N'|', i.is_hypothetical, N'|', i.ignore_dup_key,
                  N'|', i.has_filter, N'|', COALESCE(i.filter_definition, N'<null>'))
    FROM user_tables AS t
    JOIN sys.indexes AS i ON i.object_id = t.object_id
    WHERE i.index_id > 0

    UNION ALL

    SELECT CONCAT(N'INDEX_COLUMN|' COLLATE Latin1_General_100_BIN2, t.qualified_name, N'|', QUOTENAME(i.name),
                  N'|', ix.index_column_id, N'|', ix.key_ordinal,
                  N'|', COALESCE(QUOTENAME(c.name), N'<row locator>'),
                  N'|', ix.is_descending_key, N'|', ix.is_included_column, N'|', ix.partition_ordinal)
    FROM user_tables AS t
    JOIN sys.indexes AS i ON i.object_id = t.object_id
    JOIN sys.index_columns AS ix ON ix.object_id = i.object_id AND ix.index_id = i.index_id
    LEFT JOIN sys.columns AS c ON c.object_id = ix.object_id AND c.column_id = ix.column_id
    WHERE i.index_id > 0

    UNION ALL

    SELECT CONCAT(N'CHECK|' COLLATE Latin1_General_100_BIN2, t.qualified_name, N'|', QUOTENAME(ck.name),
                  N'|', COALESCE(QUOTENAME(c.name), N'<table>'),
                  N'|', ck.is_disabled, N'|', ck.is_not_trusted, N'|', ck.is_not_for_replication,
                  N'|', ck.uses_database_collation, N'|', ck.definition)
    FROM user_tables AS t
    JOIN sys.check_constraints AS ck ON ck.parent_object_id = t.object_id
    LEFT JOIN sys.columns AS c ON c.object_id = t.object_id AND c.column_id = ck.parent_column_id

    UNION ALL

    SELECT CONCAT(N'DEFAULT|' COLLATE Latin1_General_100_BIN2, t.qualified_name, N'|', QUOTENAME(d.name),
                  N'|', QUOTENAME(c.name), N'|', d.definition)
    FROM user_tables AS t
    JOIN sys.default_constraints AS d ON d.parent_object_id = t.object_id
    JOIN sys.columns AS c ON c.object_id = t.object_id AND c.column_id = d.parent_column_id

    UNION ALL

    SELECT CONCAT(N'FOREIGN_KEY|' COLLATE Latin1_General_100_BIN2, t.qualified_name, N'|', QUOTENAME(fk.name),
                  N'|', QUOTENAME(rs.name), N'.', QUOTENAME(rt.name),
                  N'|', QUOTENAME(ri.name), N'|', fk.delete_referential_action,
                  N'|', fk.update_referential_action, N'|', fk.is_disabled,
                  N'|', fk.is_not_trusted, N'|', fk.is_not_for_replication)
    FROM user_tables AS t
    JOIN sys.foreign_keys AS fk ON fk.parent_object_id = t.object_id
    JOIN sys.tables AS rt ON rt.object_id = fk.referenced_object_id
    JOIN sys.schemas AS rs ON rs.schema_id = rt.schema_id
    JOIN sys.indexes AS ri ON ri.object_id = rt.object_id AND ri.index_id = fk.key_index_id

    UNION ALL

    SELECT CONCAT(N'FOREIGN_KEY_COLUMN|' COLLATE Latin1_General_100_BIN2, t.qualified_name, N'|', QUOTENAME(fk.name),
                  N'|', fc.constraint_column_id, N'|', QUOTENAME(pc.name), N'|', QUOTENAME(rc.name))
    FROM user_tables AS t
    JOIN sys.foreign_keys AS fk ON fk.parent_object_id = t.object_id
    JOIN sys.foreign_key_columns AS fc ON fc.constraint_object_id = fk.object_id
    JOIN sys.columns AS pc ON pc.object_id = fc.parent_object_id AND pc.column_id = fc.parent_column_id
    JOIN sys.columns AS rc ON rc.object_id = fc.referenced_object_id AND rc.column_id = fc.referenced_column_id

    UNION ALL

    SELECT CONCAT(N'TRIGGER|' COLLATE Latin1_General_100_BIN2, tr.parent_name, N'|', QUOTENAME(tr.name), N'|', tr.type,
                  N'|', tr.is_disabled, N'|', tr.is_instead_of_trigger, N'|', tr.is_not_for_replication,
                  N'|', m.uses_ansi_nulls, N'|', m.uses_quoted_identifier,
                  N'|', COALESCE(QUOTENAME(p.name), N'<caller>'),
                  N'|', CASE WHEN m.execute_as_principal_id = -2 THEN N'owner' ELSE N'' END,
                  N'|', COALESCE(m.definition, N'<null>'))
    FROM user_triggers AS tr
    LEFT JOIN sys.sql_modules AS m ON m.object_id = tr.object_id
    LEFT JOIN sys.database_principals AS p ON p.principal_id = m.execute_as_principal_id

    UNION ALL

    SELECT CONCAT(N'TRIGGER_EVENT|' COLLATE Latin1_General_100_BIN2, tr.parent_name, N'|', QUOTENAME(tr.name),
                  N'|', e.type_desc, N'|', e.is_first, N'|', e.is_last)
    FROM user_triggers AS tr
    JOIN sys.trigger_events AS e ON e.object_id = tr.object_id
)
SELECT encoded.schema_row
FROM catalog
CROSS APPLY (VALUES (STRING_ESCAPE(catalog.schema_row, 'json'))) AS encoded(schema_row)
ORDER BY encoded.schema_row COLLATE Latin1_General_100_BIN2, DATALENGTH(encoded.schema_row);
