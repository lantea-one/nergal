"""Reject unreviewed runner labels and heavy workloads on the short-task runner.

Labels are pinned to the organization's CI pool. Registration scope must also be
verified in Forgejo: an organization-owned runner with no repository binding.
A suffix alone does not establish that a runner is shared. This offline check
guards the reviewed workflow labels; it does not query private runner inventory.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APPROVED_LABELS = {"asgard-ci", "heimdall-ci", "vidar-ci"}
SHORT_TASK_WORKFLOWS = {"pages.yml"}
RUNNER = re.compile(r"^\s*runs-on:\s*(.*?)\s*$", re.MULTILINE)


def validate_workflows(workflows):
    """Return stable errors; runner expressions, private labels and unknown jobs fail closed."""
    errors = []
    for name, text in sorted(workflows.items()):
        labels = RUNNER.findall(text)
        # Only canonical literal block keys are supported. Reject flow mappings,
        # quoted keys, aliases and other layouts rather than overlooking a job.
        if len(re.findall(r"\bruns-on\b", text)) != len(labels):
            errors.append(f"{name}: runner.literalBlockRequired")
        if not labels:
            errors.append(f"{name}: runner.missing")
        for label in labels:
            if label not in APPROVED_LABELS:
                errors.append(f"{name}: runner.notApprovedSharedLabel")
            elif label == "vidar-ci" and name not in SHORT_TASK_WORKFLOWS:
                errors.append(f"{name}: runner.shortTasksOnly")
    return errors


def check_repository():
    """Check every tracked workflow's literal selection against the reviewed CI pool."""
    directory = ROOT / ".forgejo/workflows"
    workflows = {path.name: path.read_text() for path in sorted(directory.iterdir())
                 if path.suffix in (".yml", ".yaml")}
    return validate_workflows(workflows)
