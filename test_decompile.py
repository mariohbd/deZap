import json
import contextlib
import io
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

    def test_smali_only_skips_java_tools_and_records_explicit_scope(self):
        source = self.root / 'tiny.apk'
        with zipfile.ZipFile(source, 'w') as z: z.writestr('classes.dex', b'own fixture')
        tools = {}
        for key in ('java', 'apktool'):
            tools[key] = self.root / key; tools[key].write_bytes(b'local tool fixture')
        output = self.root / 'export'
        called = []
        def decode(command, logs, label, timeout):
            called.append((command, label))
            self.assertEqual(label, 'decode-0000')
            self.assertIn('-jar', command)
            target = Path(command[command.index('-o') + 1]); target.mkdir()
            (target / 'AndroidManifest.xml').write_text('<manifest />')
            (target / 'smali').mkdir(); (target / 'smali/Own.smali').write_text('.class public LOwn;')
        with patch.object(decompile, 'resolve_tool', side_effect=lambda value: Path(value)) as resolve, \
             patch.object(decompile, 'run_command', side_effect=decode), contextlib.redirect_stdout(io.StringIO()):
            code = decompile.main([str(source), '--output', str(output), '--java', str(tools['java']),
                                   '--apktool-jar', str(tools['apktool']), '--smali-only',
                                   '--javac', 'missing-javac', '--jadx-jar', 'missing-jadx'])
        self.assertEqual(code, 0)
        self.assertEqual([c.args[0] for c in resolve.call_args_list], [str(tools['java']), str(tools['apktool'])])
        report = json.loads((output / 'run-summary.json').read_text())
        self.assertEqual(report['status'], 'export-completed')
        self.assertEqual(report['export_scope'], 'smali-and-resources')
        self.assertEqual(report['quality'], 'java-not-exported')
        self.assertIsNone(report['backend_sha256'])
        self.assertEqual(report['apks'][0]['java'], {'status': 'not-exported', 'reason': 'smali-only requested'})
        self.assertIn('AndroidManifest.xml', report['apks'][0]['preserved_decode_inventory'])
        self.assertEqual(len(called), 1)
        self.assertFalse((output / 'backend').exists())
        self.assertFalse((output / 'java-0000').exists())

    def test_default_export_requires_jadx_before_resolving_tools(self):
        with patch.object(decompile, 'resolve_tool') as resolve, contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            decompile.main(['input.apk', '--output', str(self.root / 'output'), '--apktool-jar', 'local.jar'])
        resolve.assert_not_called()

    def test_smali_only_without_jadx_does_not_claim_success_after_decode_failure(self):
        source = self.root / 'tiny.apk'
        with zipfile.ZipFile(source, 'w') as z: z.writestr('classes.dex', b'fixture')
        tool = self.root / 'local-tool'; tool.write_bytes(b'fixture')
        output = self.root / 'failed-export'
        with patch.object(decompile, 'resolve_tool', return_value=tool), \
             patch.object(decompile, 'run_command', side_effect=RuntimeError('decode failed')), contextlib.redirect_stdout(io.StringIO()):
            code = decompile.main([str(source), '--output', str(output), '--apktool-jar', str(tool), '--smali-only'])
        self.assertEqual(code, 1)
        report = json.loads((output / 'run-summary.json').read_text())
        self.assertEqual(report['status'], 'failed')
        self.assertEqual(report['quality'], 'java-not-exported')
        self.assertNotIn('preserved_decode_inventory', report['apks'][0])

if __name__ == '__main__': unittest.main()
