# ADR 0019 — Local operator enrollment

Only the host operator may initiate enrollment, through a local command with
kernel administrative authority and a fresh private state directory. Enroll a
new fixed inet table and one empty input chain with default accept. Other base
chains still run. Filtering changes require a separate confirmed operation.

Generate all resource identifiers locally. Commit the intended baseline and
disable legacy operation insertion in the same transaction before invoking nft.
Validate the complete candidate and then submit it as one exclusive-create batch.
Derive expected handles from the successful native transaction echo. Compare a
separate full listing against that evidence and the protected baseline before
binding. A listing by itself cannot establish creation authority.

If creation collides, a process dies, or evidence is unavailable, preserve the
journal and any kernel state. Repeating enrollment with an existing journal
must stop before kernel access. Do not automatically delete, resume, or adopt
a same-name table. This first command supports offline bootstrap with other
agent writers stopped. Later replacements require independent rollback and
new crash-recovery semantics. No controller endpoint can initiate enrollment.
