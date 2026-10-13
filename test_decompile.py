import json
from pathlib import Path
import stat
import tempfile
import unittest
import zipfile
from unittest.mock import patch
import decompile

class SafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
    def tearDown(self):
        self.temp.cleanup()
    def archive(self, entries):
        path = self.root / 'input.xapk'
        with zipfile.ZipFile(path, 'w') as z:
            for name, data in entries:
                z.writestr(name, data)
        return path
    def test_traversal_rejected(self):
        for name in ['../a.apk', '/a.apk', 'C:/a.apk', 'x/../a.apk', 'name ./a.apk']:
            with self.subTest(name=name):
                with self.assertRaises(ValueError): decompile.validate_zip(self.archive([(name, b'a')]))
    def test_case_collision_rejected(self):
        with self.assertRaises(ValueError): decompile.validate_zip(self.archive([('A.apk', b'a'), ('a.apk', b'b')]))
    def test_expansion_rejected(self):
        with self.assertRaises(ValueError): decompile.validate_zip(self.archive([('a.apk', b'1234')]), 3)
    def test_symlink_rejected(self):
        entry = zipfile.ZipInfo('a.apk'); entry.create_system = 3
        entry.external_attr = (stat.S_IFLNK | 0o777) << 16
        with self.assertRaises(ValueError): decompile.validate_zip(self.archive([(entry, b'target')]))
    def test_arbitrary_nested_apks(self):
        apk = self.root / 'tiny.apk'
        with zipfile.ZipFile(apk, 'w') as z: z.writestr('classes.dex', b'fixture')
        source = self.archive([('nested/base.apk', apk.read_bytes()), ('split.apk', apk.read_bytes()), ('metadata.json', b'{}')])
        outputs = decompile.prepare_inputs(source, self.root / 'inputs', 1024)
        self.assertEqual(len(outputs), 2)
        self.assertEqual(decompile.sha256(outputs[0]), decompile.sha256(apk))
    def test_existing_destination_preserved(self):
        target = self.root / 'inputs'; target.mkdir(); (target / 'keep').write_text('original')
        with self.assertRaises(FileExistsError): decompile.prepare_inputs(self.root / 'x.apk', target, 1024)
        self.assertEqual((target / 'keep').read_text(), 'original')
    def test_nonzero_command_recorded(self):
        import sys
        with self.assertRaises(RuntimeError):
            decompile.run_command([sys.executable, '-c', 'raise SystemExit(7)'], self.root, 'fail', 5)
        self.assertEqual(json.loads((self.root / 'fail.json').read_text())['exit_code'], 7)
    def test_timeout_recorded(self):
        import sys
        with self.assertRaises(RuntimeError):
            decompile.run_command([sys.executable, '-c', 'import time; time.sleep(5)'], self.root, 'timeout', .1)
        self.assertEqual(json.loads((self.root / 'timeout.json').read_text())['status'], 'timeout')
    def test_launch_failure_recorded(self):
        invalid = self.root / 'invalid-tool.exe'
        invalid.write_text('This is a synthetic non-executable fixture.')
        with self.assertRaises(RuntimeError):
            decompile.run_command([str(invalid)], self.root, 'launch-fail', 5)
        record = json.loads((self.root / 'launch-fail.json').read_text())
        self.assertEqual(record['status'], 'launch-failed')
        self.assertIsNone(record['exit_code'])
        self.assertIn('error', record)

if __name__ == '__main__': unittest.main()
