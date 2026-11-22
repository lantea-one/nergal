"""Source changes must refresh the sandbox; generated artifacts must not cause rebuild loops."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('dev_watch', Path(__file__).resolve().parents[1] / 'tools/dev-stack/watch.py')
watch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watch)


class FingerprintTests(unittest.TestCase):
    """A failed build must be retried after fixing a test, without watching its output."""

    def test_source_and_test_changes_are_detected(self):
        with tempfile.TemporaryDirectory() as root:
            previous_root = watch.ROOT
            watch.ROOT = Path(root)
            try:
                for directory in ('src', 'tests', 'tools/dev-stack'):
                    folder = Path(root) / directory
                    folder.mkdir(parents=True, exist_ok=True)
                    before = watch.fingerprint()
                    (folder / 'changed.py').write_text('changed')
                    self.assertNotEqual(before, watch.fingerprint())
            finally:
                watch.ROOT = previous_root

    def test_build_outputs_do_not_trigger_a_rebuild_loop(self):
        with tempfile.TemporaryDirectory() as root:
            previous_root = watch.ROOT
            watch.ROOT = Path(root)
            try:
                before = watch.fingerprint()
                for directory in ('tests/bin', 'src/obj', 'tools/dev-stack/__pycache__'):
                    folder = Path(root) / directory
                    folder.mkdir(parents=True)
                    (folder / 'generated').write_text('output')
                self.assertEqual(before, watch.fingerprint())
            finally:
                watch.ROOT = previous_root


if __name__ == '__main__':
    unittest.main()
