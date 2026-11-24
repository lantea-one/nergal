"""Runner selection cannot fall back to infrastructure or use the small-task pool for full verification."""
import sys
import unittest
from ci_runner_policy import check_repository, validate_workflows


class RunnerPolicyTests(unittest.TestCase):
    def test_verified_build_labels_are_allowed(self):
        for label in ("asgard-ci", "heimdall-ci"):
            self.assertEqual([], validate_workflows({"ci.yml": f"jobs:\n  verify:\n    runs-on: {label}\n"}))

    def test_generic_private_unknown_and_expression_labels_are_denied(self):
        for label in ("infrastructure", "ubuntu-latest", "unknown-ci", "${{ vars.CI_RUNNER_LABEL }}", "[asgard-ci, ubuntu-latest]"):
            self.assertEqual(["ci.yml: runner.notApprovedSharedLabel"], validate_workflows({"ci.yml": f"runs-on: {label}\n"}))

    def test_vidar_is_limited_to_declared_short_workflows(self):
        self.assertEqual([], validate_workflows({"pages.yml": "runs-on: vidar-ci\n"}))
        for workflow in ("ci.yml", "new-heavy-job.yml"):
            self.assertEqual([f"{workflow}: runner.shortTasksOnly"], validate_workflows({workflow: "runs-on: vidar-ci\n"}))

    def test_all_runner_selections_must_pass(self):
        self.assertEqual(["ci.yml: runner.notApprovedSharedLabel"], validate_workflows({"ci.yml": "runs-on: asgard-ci\nruns-on: infrastructure\n"}))
        self.assertEqual(["ci.yml: runner.missing"], validate_workflows({"ci.yml": "jobs: {}\n"}))

    def test_noncanonical_keys_cannot_hide_a_runner(self):
        for hidden in ("other: {runs-on: infrastructure}", '"runs-on": infrastructure'):
            self.assertEqual(["ci.yml: runner.literalBlockRequired"], validate_workflows({"ci.yml": "runs-on: asgard-ci\n" + hidden + "\n"}))

    def test_repository_workflows_obey_policy(self):
        self.assertEqual([], check_repository())


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
