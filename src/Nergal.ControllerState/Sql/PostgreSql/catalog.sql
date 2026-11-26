-- Run with the controller search_path (public, with pg_catalog implicit).
-- JSON arrays frame names and definitions without ambiguous delimiters. OIDs
-- are used for joins only so the same schema survives a native dump/restore.
WITH namespace AS (
    SELECT oid FROM pg_catalog.pg_namespace WHERE nspname = 'public'
), relations AS (
    SELECT c.*
    FROM pg_catalog.pg_class AS c
    JOIN namespace AS ns ON ns.oid = c.relnamespace
    WHERE c.relkind NOT IN ('i', 'I')
), definitions AS (
    SELECT pg_catalog.json_build_array(
        'relation', r.relname, r.relkind::text, r.relpersistence::text,
        am.amname, r.relrowsecurity, r.relforcerowsecurity, r.relreplident::text,
        CASE WHEN r.relkind IN ('v', 'm') THEN pg_catalog.pg_get_viewdef(r.oid, false) END,
        CASE WHEN r.relkind = 'p' THEN pg_catalog.pg_get_partkeydef(r.oid) END,
        pg_catalog.pg_get_expr(r.relpartbound, r.oid, false)
    )::text AS definition
    FROM relations AS r
    LEFT JOIN pg_catalog.pg_am AS am ON am.oid = r.relam

    UNION ALL

    SELECT pg_catalog.json_build_array(
        'inheritance', r.relname, parent_namespace.nspname, parent.relname, i.inhseqno
    )::text
    FROM relations AS r
    JOIN pg_catalog.pg_inherits AS i ON i.inhrelid = r.oid
    JOIN pg_catalog.pg_class AS parent ON parent.oid = i.inhparent
    JOIN pg_catalog.pg_namespace AS parent_namespace ON parent_namespace.oid = parent.relnamespace

    UNION ALL

    SELECT pg_catalog.json_build_array(
        'column', r.relname, a.attnum, a.attname,
        pg_catalog.format_type(a.atttypid, a.atttypmod), collation_namespace.nspname, col.collname,
        a.attnotnull, a.attidentity::text, a.attgenerated::text,
        pg_catalog.pg_get_expr(d.adbin, d.adrelid, false)
    )::text
    FROM relations AS r
    JOIN pg_catalog.pg_attribute AS a ON a.attrelid = r.oid AND a.attnum > 0 AND NOT a.attisdropped
    LEFT JOIN pg_catalog.pg_collation AS col ON col.oid = a.attcollation
    LEFT JOIN pg_catalog.pg_namespace AS collation_namespace ON collation_namespace.oid = col.collnamespace
    LEFT JOIN pg_catalog.pg_attrdef AS d ON d.adrelid = r.oid AND d.adnum = a.attnum

    UNION ALL

    SELECT pg_catalog.json_build_array(
        'constraint', r.relname, c.conname, c.contype::text, c.convalidated,
        c.condeferrable, c.condeferred, pg_catalog.pg_get_constraintdef(c.oid, false)
    )::text
    FROM relations AS r
    JOIN pg_catalog.pg_constraint AS c ON c.conrelid = r.oid

    UNION ALL

    SELECT pg_catalog.json_build_array(
        'index', r.relname, index_class.relname, i.indisvalid, i.indisready, i.indislive,
        i.indisclustered, i.indisreplident, pg_catalog.pg_get_indexdef(i.indexrelid, 0, false)
    )::text
    FROM relations AS r
    JOIN pg_catalog.pg_index AS i ON i.indrelid = r.oid
    JOIN pg_catalog.pg_class AS index_class ON index_class.oid = i.indexrelid

    UNION ALL

    SELECT pg_catalog.json_build_array(
        'sequence', r.relname, pg_catalog.format_type(s.seqtypid, NULL),
        s.seqstart, s.seqincrement, s.seqmin, s.seqmax, s.seqcache, s.seqcycle,
        owner_namespace.nspname, owner_table.relname, owner_column.attname, dep.deptype::text
    )::text
    FROM relations AS r
    JOIN pg_catalog.pg_sequence AS s ON s.seqrelid = r.oid
    LEFT JOIN pg_catalog.pg_depend AS dep
        ON dep.classid = 'pg_catalog.pg_class'::pg_catalog.regclass AND dep.objid = r.oid
        AND dep.refclassid = 'pg_catalog.pg_class'::pg_catalog.regclass AND dep.refobjsubid > 0
        AND dep.deptype IN ('a', 'i')
    LEFT JOIN pg_catalog.pg_class AS owner_table ON owner_table.oid = dep.refobjid
    LEFT JOIN pg_catalog.pg_namespace AS owner_namespace ON owner_namespace.oid = owner_table.relnamespace
    LEFT JOIN pg_catalog.pg_attribute AS owner_column
        ON owner_column.attrelid = dep.refobjid AND owner_column.attnum = dep.refobjsubid

    UNION ALL

    SELECT pg_catalog.json_build_array(
        'trigger', r.relname, t.tgname, t.tgenabled::text, pg_catalog.pg_get_triggerdef(t.oid, false)
    )::text
    FROM relations AS r
    JOIN pg_catalog.pg_trigger AS t ON t.tgrelid = r.oid AND NOT t.tgisinternal

    UNION ALL

    -- Internally generated foreign-key trigger names contain regenerated OIDs.
    SELECT pg_catalog.json_build_array(
        'internal trigger', r.relname, constrained_table.relname, c.conname,
        function_namespace.nspname, p.proname, t.tgtype, t.tgenabled::text,
        t.tgdeferrable, t.tginitdeferred
    )::text
    FROM relations AS r
    JOIN pg_catalog.pg_trigger AS t ON t.tgrelid = r.oid AND t.tgisinternal
    JOIN pg_catalog.pg_proc AS p ON p.oid = t.tgfoid
    JOIN pg_catalog.pg_namespace AS function_namespace ON function_namespace.oid = p.pronamespace
    LEFT JOIN pg_catalog.pg_constraint AS c ON c.oid = t.tgconstraint
    LEFT JOIN pg_catalog.pg_class AS constrained_table ON constrained_table.oid = c.conrelid

    UNION ALL

    SELECT pg_catalog.json_build_array(
        'routine', p.proname, p.prokind::text, pg_catalog.pg_get_function_identity_arguments(p.oid),
        CASE WHEN p.prokind <> 'a' THEN pg_catalog.pg_get_functiondef(p.oid) END
    )::text
    FROM pg_catalog.pg_proc AS p
    JOIN namespace AS ns ON ns.oid = p.pronamespace
)
SELECT definition FROM definitions ORDER BY definition COLLATE pg_catalog."C";
