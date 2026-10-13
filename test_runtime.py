import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import runtime


class FakeADB:
    """Controlled ADB protocol replies; no emulator or connected device is used."""
    def __init__(self, failure=None):
        self.failure = failure
        self.commands = []
        self.taps = 0
        self.home = False
        self.starts = 0
        self.stopped = False
        self.boot_queries = 0

    def __call__(self, command, **kwargs):
        args = command[5:]
        self.commands.append(args)
        text, binary, code = '', None, 0
        if args == ['get-state']:
            text = 'device\n'
        elif args == ['emu', 'avd', 'name']:
            text = ('personal-avd' if self.failure == 'identity' else 'lab_avd') + '\nOK\n'
        elif args[:3] == ['emu', 'avd', 'snapshot']:
            text = 'KO: missing snapshot\n' if self.failure == 'snapshot' else 'OK\n'
        elif args == ['version']:
            text = 'Android Debug Bridge version test\n'
        elif args[:2] == ['shell', 'getprop']:
            text = '0\n' if self.failure == 'boot' and args[-1] == 'sys.boot_completed' else '1\n'
            if args[-1] == 'sys.boot_completed':
                self.boot_queries += 1
                if self.failure == 'permanent-offline' or (self.failure == 'temporary-offline' and self.boot_queries == 1):
                    return subprocess.CompletedProcess(command, 1, b'', b'error: device offline')
        elif args[:5] == ['shell', 'settings', 'get', 'global', 'airplane_mode_on']:
            text = '1\n'
        elif args[:4] == ['shell', 'settings', 'get', 'global']:
            text = '1\n' if self.failure == 'network' else '0\n'
        elif args == ['shell', 'dumpsys', 'account']:
            text = 'User UserInfo{0:Owner:13}:\n Accounts: ' + ('1' if self.failure == 'accounts' else '0') + '\n'
        elif args == ['shell', 'dumpsys', 'connectivity']:
            text = 'Active default network: ' + ('100' if self.failure == 'connectivity' else 'none') + '\n'
        elif args[:4] == ['shell', 'pm', 'list', 'packages']:
            text = 'package:example.tiny\n' if self.failure == 'installed' else ''
        elif args[0] == 'install-multiple':
            text = 'Failure [INSTALL_FAILED_INVALID_APK]\n' if self.failure == 'install' else 'Success\n'
        elif args[:3] == ['shell', 'pm', 'path']:
            text = 'package:/data/app/base.apk\n'
        elif args[:3] == ['shell', 'am', 'start']:
            self.home = False
            self.stopped = False
            self.starts += 1
            text = 'Status: ok\nActivity: example.tiny/.MainActivity\n'
            if self.failure == 'launch':
                text = 'Error type 3\nError: Activity does not exist\n'
        elif args == ['shell', 'dumpsys', 'activity', 'activities']:
            component = 'example.other/.MainActivity' if self.failure == 'activity' else 'example.tiny/.MainActivity'
            if self.failure == 'redirect': component = 'example.tiny/.Welcome'
            if self.home and self.failure != 'home': component = 'example.launcher/.Home'
            text = 'mResumedActivity: ActivityRecord{abc u0 ' + component + ' t1}\n'
        elif args[:2] == ['shell', 'pidof']:
            text = '' if self.failure == 'process' else '1234\n'
            if self.failure == 'coldstart' and self.starts > 1: text = '2345\n'
            if self.stopped: text, code = '', 1
        elif args[:3] == ['shell', 'uiautomator', 'dump']:
            text = 'UI hierchary dumped to: ' + args[-1] + '\n'
        elif args[:2] == ['exec-out', 'cat']:
            label = 'wrong' if self.failure == 'ui' else 'Fixture ready'
            dialog = ''
            if self.failure == 'dialog' and not self.taps:
                dialog = '<node package="example.tiny" text="Informational lab notice" />' + \
                    '<node package="example.tiny" resource-id="android:id/button2" text="OK" clickable="true" enabled="true" bounds="[0,0][20,20]" />'
            text = '<hierarchy><node package="example.tiny" text="' + label + '" />' + dialog + '</hierarchy>'
        elif args[:2] == ['exec-out', 'screencap']:
            binary = b'\x89PNG\r\n\x1a\nfixture'
        elif args[:4] == ['logcat', '-b', 'crash', '-d']:
            text = 'FATAL EXCEPTION: main\nProcess: example.tiny, PID: 1234\n' if self.failure == 'crash' else ''
        elif args == ['logcat', '-d', '-v', 'threadtime']:
            text = 'ANR in example.tiny\n' if self.failure == 'anr' else ''
        elif args[:3] == ['shell', 'input', 'tap']:
            self.taps += 1
        elif args[:3] == ['shell', 'input', 'keyevent']:
            self.home = True
        elif args[:3] == ['shell', 'am', 'force-stop']:
            if self.failure != 'force-stop': self.stopped = True
        elif args[:3] in (['shell', 'settings', 'put'], ['shell', 'svc', 'wifi'],
                          ['shell', 'svc', 'data'], ['shell', 'rm', '-f'],
                          ['shell', 'input', 'keyevent'], ['shell', 'am', 'force-stop']):
            pass
        elif args in (['logcat', '-b', 'crash', '-c'], ['logcat', '-c']):
            pass
        else:
            raise AssertionError('Unexpected fake command: ' + str(args))
        return subprocess.CompletedProcess(command, code, binary if binary is not None else text.encode(), b'')


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.adb = self.root / 'adb.exe'
        self.adb.write_bytes(b'fake executable')
        self.apk = self.root / 'base.apk'
        self.apk.write_bytes(b'fake artifact')
        self.summary = self.root / 'rebuild-summary.json'
        self.report = {'status': 'signed-set-completed', 'same_signer_verified': True,
                       'certificate_sha256': 'a' * 64, 'apks': [
                           {'metadata': {'package': 'example.tiny', 'version_code': '1', 'split': None},
                            'artifact': 'base.apk', 'sha256': runtime.digest(self.apk)}]}
        self.write_summary()
        self.output = self.root / 'evidence'

    def write_summary(self):
        self.summary.write_text(json.dumps(self.report), encoding='utf-8')

    def arguments(self):
        return [str(self.summary), '--output', str(self.output), '--adb', str(self.adb),
                '--server-port', '5047', '--serial', 'emulator-5580', '--avd', 'lab_avd',
                '--snapshot', 'clean_lab', '--package', 'example.tiny',
                '--activity', 'example.tiny/.MainActivity', '--expected-text', 'Fixture ready',
                '--observe-seconds', '0.001', '--boot-timeout', '0.001']

    def run_fake(self, failure=None, extra=None):
        fake = FakeADB(failure)
        with patch.object(runtime.subprocess, 'run', fake), patch.object(runtime.time, 'sleep'), contextlib.redirect_stdout(io.StringIO()):
            code = runtime.main(self.arguments() + (extra or []))
        report = json.loads((self.output / 'runtime-summary.json').read_text())
        return code, report, fake

    def test_three_scenarios_pass_and_all_commands_explicit(self):
        code, report, fake = self.run_fake()
        self.assertEqual(code, 0)
        self.assertEqual(report['status'], 'runtime-observed-pass')
        self.assertEqual([s['name'] for s in report['scenarios']], ['initial', 'home-resume', 'force-stop-relaunch'])
        for command in report['commands']:
            self.assertEqual(command['command'][1:5], ['-P', '5047', '-s', 'emulator-5580'])
        self.assertTrue((self.output / 'initial.png').exists())
        self.assertEqual(report['cleanup'], 'tested-package-force-stopped')
        self.assertFalse(any(c[0] in ('kill-server', 'devices') for c in fake.commands))

    def test_identity_refusal_prevents_snapshot_and_install(self):
        code, report, fake = self.run_fake('identity')
        self.assertEqual(code, 1)
        self.assertIn('identity', report['error'])
        self.assertFalse(any('snapshot' in c or 'install-multiple' in c or 'force-stop' in c for c in fake.commands))

    def test_snapshot_failure_prevents_install(self):
        code, _, fake = self.run_fake('snapshot')
        self.assertEqual(code, 1)
        self.assertFalse(any(c[0] == 'install-multiple' for c in fake.commands))

    def test_network_accounts_or_installed_package_refused(self):
        for failure in ('network', 'connectivity', 'accounts', 'installed'):
            with self.subTest(failure=failure):
                self.output = self.root / ('evidence-' + failure)
                code, report, fake = self.run_fake(failure)
                self.assertEqual(code, 1)
                self.assertEqual(report['status'], 'failed')
                self.assertFalse(any(c[0] == 'install-multiple' for c in fake.commands))

    def test_install_failure_does_not_claim_launch(self):
        code, report, _ = self.run_fake('install')
        self.assertEqual(code, 1)
        self.assertNotIn('installation', report['stages'])
        self.assertNotIn('launch_acknowledgment', report['stages'])

    def test_acknowledged_launch_is_not_runtime_pass(self):
        for failure in ('launch', 'activity', 'process', 'ui', 'crash', 'anr'):
            with self.subTest(failure=failure):
                self.output = self.root / ('evidence-' + failure)
                code, report, _ = self.run_fake(failure)
                self.assertEqual(code, 1)
                self.assertNotIn('runtime_observation', report['stages'])
                self.assertEqual(report['cleanup'], 'tested-package-force-stopped')
                if failure == 'crash':
                    self.assertTrue((self.output / 'initial-crash.txt').exists())

    def test_boot_timeout_recorded(self):
        code, report, _ = self.run_fake('boot')
        self.assertEqual(code, 1)
        self.assertIn('boot timeout', report['error'])

    def test_changed_apk_prevents_adb_interaction(self):
        self.apk.write_bytes(b'changed')
        code, report, fake = self.run_fake()
        self.assertEqual(code, 1)
        self.assertIn('hash differs', report['error'])
        self.assertEqual(fake.commands, [])

    def test_unexpected_package_and_incompatible_splits_refused(self):
        self.report['apks'][0]['metadata']['package'] = 'example.other'
        self.write_summary()
        with self.assertRaisesRegex(ValueError, 'Unexpected package'):
            runtime.load_set(self.summary, 'example.tiny')
        self.report['apks'][0]['metadata']['package'] = 'example.tiny'
        second = self.root / 'split.apk'; second.write_bytes(b'split')
        self.report['apks'].append({'metadata': {'package': 'example.tiny', 'version_code': '2', 'split': 'config.en'},
                                    'artifact': second.name, 'sha256': runtime.digest(second)})
        self.write_summary()
        with self.assertRaisesRegex(ValueError, 'Incompatible'):
            runtime.load_set(self.summary, 'example.tiny')

    def test_unsigned_and_artifact_escape_refused(self):
        self.report['status'] = 'unsigned-set-completed'; self.write_summary()
        with self.assertRaises(ValueError): runtime.load_set(self.summary, 'example.tiny')
        self.report['status'] = 'signed-set-completed'
        self.report['apks'][0]['artifact'] = '../base.apk'; self.write_summary()
        with self.assertRaises(ValueError): runtime.load_set(self.summary, 'example.tiny')

    def test_no_overwrite_and_physical_device_refused(self):
        self.output.mkdir(); marker = self.output / 'marker'; marker.write_text('keep')
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            runtime.main(self.arguments())
        self.assertEqual(marker.read_text(), 'keep')
        args = self.arguments(); args[args.index('emulator-5580')] = 'personal-phone'
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit): runtime.main(args)

    def test_subprocess_timeout_preserves_evidence(self):
        self.output.mkdir()
        adb = runtime.ADB(self.adb, 5047, 'emulator-5580', self.output, 0.05)
        def expire(*a, **kw): raise subprocess.TimeoutExpired(a[0], 0.05, output=b'partial', stderr=b'timed out')
        with patch.object(runtime.subprocess, 'run', expire), self.assertRaises(RuntimeError): adb.run('get-state')
        self.assertEqual(adb.commands[0]['status'], 'timeout')
        self.assertEqual((self.output / 'command-0000.stdout.txt').read_bytes(), b'partial')

    def test_conditional_dialog_requires_exact_button_then_captures_again(self):
        code, report, fake = self.run_fake('dialog', ['--dismiss-dialog-text', 'Informational lab notice',
                                                   '--dismiss-button-id', 'android:id/button2', '--dismiss-button-text', 'OK'])
        self.assertEqual(code, 0)
        self.assertEqual(fake.taps, 1)
        self.assertTrue(report['scenarios'][0]['dialog_dismissed'])
        self.assertTrue((self.output / 'initial-after-dialog.png').exists())

    def test_scoped_crash_excludes_similar_package(self):
        self.assertFalse(runtime.scoped_crash('Process: example.tinyish, PID: 2', 'example.tiny'))
        self.assertTrue(runtime.scoped_crash('Process: example.tiny:worker, PID: 2', 'example.tiny'))
        self.assertFalse(runtime.scoped_crash('Unrelated message about example.tiny', 'example.tiny'))
        self.assertTrue(runtime.scoped_crash('>>> example.tiny <<<', 'example.tiny'))
        self.assertTrue(runtime.scoped_crash('ANR in example.tiny', 'example.tiny'))
        self.assertFalse(runtime.scoped_crash('ANR in example.tinyish', 'example.tiny'))

    def test_unknown_connectivity_format_refused(self):
        with self.assertRaises(ValueError): runtime.no_default_network('')
        with self.assertRaises(ValueError): runtime.no_default_network('Active default network: 100\n')
        runtime.no_default_network('Active default network: none\n')

    def test_home_and_cold_restart_do_not_count_as_resume(self):
        for failure in ('home', 'coldstart'):
            with self.subTest(failure=failure):
                self.output = self.root / ('evidence-' + failure)
                code, report, _ = self.run_fake(failure)
                self.assertEqual(code, 1)
                self.assertNotIn('runtime_observation', report['stages'])
                self.assertFalse(any(s['name'] == 'home-resume' and s['status'] == 'observed-pass' for s in report['scenarios']))

    def test_inherited_adb_routing_overridden(self):
        with patch.dict(runtime.os.environ, {'ADB_SERVER_SOCKET': 'tcp:remote:5037',
                                           'ANDROID_ADB_SERVER_PORT': '5037', 'ANDROID_SERIAL': 'personal'}):
            adb = runtime.ADB(self.adb, 5047, 'emulator-5580', self.root, 1)
        self.assertEqual(adb.environment['ADB_SERVER_SOCKET'], 'tcp:127.0.0.1:5047')
        self.assertEqual(adb.environment['ANDROID_ADB_SERVER_PORT'], '5047')
        self.assertNotIn('ANDROID_SERIAL', adb.environment)

    def test_ignored_force_stop_cannot_pass_relaunch(self):
        code, report, _ = self.run_fake('force-stop')
        self.assertEqual(code, 1)
        self.assertIn('Force-stop', report['error'])
        self.assertNotIn('runtime_observation', report['stages'])
        self.assertIn('cleanup_error', report)
        self.assertTrue(any(s['name'] == 'force-stop-relaunch' and s['status'] == 'failed' for s in report['scenarios']))

    def test_snapshot_temporary_disconnect_recovers(self):
        # Give the retry loop enough time independent of filesystem speed.
        code, report, fake = self.run_fake('temporary-offline', ['--boot-timeout', '1'])
        self.assertEqual(code, 0)
        self.assertGreaterEqual(fake.boot_queries, 2)
        self.assertTrue(any(c['exit_code'] == 1 for c in report['commands']))
        self.assertEqual(sum(c == ['emu', 'avd', 'name'] for c in fake.commands), 2)

    def test_snapshot_permanent_disconnect_times_out_without_install(self):
        code, report, fake = self.run_fake('permanent-offline')
        self.assertEqual(code, 1)
        self.assertIn('boot timeout', report['error'])
        self.assertFalse(any(c[0] == 'install-multiple' for c in fake.commands))

    def test_redirect_requires_explicit_expected_activity(self):
        code, report, _ = self.run_fake('redirect')
        self.assertEqual(code, 1)
        self.assertIn('Unexpected resumed activity', report['error'])
        self.output = self.root / 'redirect-authorized'
        code, report, fake = self.run_fake('redirect', ['--expected-activity', 'example.tiny/.Welcome'])
        self.assertEqual(code, 0)
        self.assertEqual(report['expected_activity'], 'example.tiny/.Welcome')
        self.assertEqual(report['launch_activity'], 'example.tiny/.MainActivity')
        for command in fake.commands:
            if command[:3] == ['shell', 'am', 'start']:
                self.assertEqual(command[-1], 'example.tiny/.MainActivity')

    def test_expected_activity_from_another_package_refused(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            runtime.main(self.arguments() + ['--expected-activity', 'example.other/.Welcome'])
        self.assertFalse(self.output.exists())


if __name__ == '__main__':
    unittest.main()
