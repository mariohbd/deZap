#!/usr/bin/env python3
"""Observe a signed APK set on an explicitly selected, snapshot-restored emulator.

An observed pass is bounded runtime evidence, not a security audit. This runner
does not start/stop an emulator or register accounts. An optional explicit
selector can dismiss one informational dialog; other app buttons are untouched.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def load_set(summary_path, package):
    """Bind artifact identities to a completed signed reconstruction report."""
    report = json.loads(summary_path.read_text(encoding='utf-8'))
    if report.get('status') != 'signed-set-completed' or report.get('same_signer_verified') is not True:
        raise ValueError('A completed signed set with a verified common signer is required')
    certificate = report.get('certificate_sha256', '')
    if not re.fullmatch('[0-9a-fA-F]{64}', certificate):
        raise ValueError('Missing signing certificate identity')
    rows = report.get('apks')
    if not isinstance(rows, list) or not rows:
        raise ValueError('Empty APK set')
    versions, splits, artifacts = set(), [], []
    root = summary_path.parent.resolve()
    for row in rows:
        meta = row['metadata']
        if meta['package'] != package:
            raise ValueError('Unexpected package in reconstruction report')
        versions.add(meta['version_code'])
        splits.append(meta['split'])
        name = row['artifact']
        if not isinstance(name, str) or Path(name).name != name or '/' in name or '\\' in name or not name.endswith('.apk'):
            raise ValueError('Artifact must be an APK filename beside the summary')
        path = root / name
        if path.is_symlink() or not path.is_file() or path.resolve().parent != root:
            raise ValueError('Missing or unsafe APK artifact')
        if digest(path) != row['sha256']:
            raise ValueError('APK hash differs from signed reconstruction report')
        artifacts.append(path)
    if len(versions) != 1 or splits.count(None) != 1 or len(set(splits)) != len(splits):
        raise ValueError('Incompatible base/split set')
    if len(set(artifacts)) != len(artifacts):
        raise ValueError('Duplicate APK artifact')
    return report, artifacts


class ADB:
    def __init__(self, executable, port, serial, output, timeout):
        self.prefix = [str(executable), '-P', str(port), '-s', serial]
        self.output = output
        self.timeout = timeout
        self.commands = []
        self.environment = os.environ.copy()
        for key in ('ADB_SERVER_SOCKET', 'ANDROID_ADB_SERVER_PORT', 'ANDROID_ADB_SERVER_ADDRESS', 'ANDROID_SERIAL'):
            self.environment.pop(key, None)
        self.environment['ANDROID_ADB_SERVER_PORT'] = str(port)
        self.environment['ADB_SERVER_SOCKET'] = f'tcp:127.0.0.1:{port}'

    def run(self, *arguments, binary=False, timeout=None, allowed_exit_codes=(0,)):
        command = self.prefix + [str(x) for x in arguments]
        index = len(self.commands)
        record = {'command': command, 'status': 'running'}
        self.commands.append(record)
        started = time.monotonic()
        try:
            result = subprocess.run(command, capture_output=True, timeout=timeout or self.timeout,
                                    env=self.environment, check=False)
            record.update(status='completed', exit_code=result.returncode)
            stdout, stderr = result.stdout, result.stderr
        except subprocess.TimeoutExpired as error:
            record.update(status='timeout', exit_code=None)
            stdout, stderr = error.stdout or b'', error.stderr or b''
        except OSError as error:
            record.update(status='launch-failed', exit_code=None)
            stdout, stderr = b'', str(error).encode('utf-8')
        finally:
            record['seconds'] = time.monotonic() - started
        stem = self.output / f'command-{index:04d}'
        stem.with_suffix('.stdout.bin' if binary else '.stdout.txt').write_bytes(stdout)
        stem.with_suffix('.stderr.txt').write_bytes(stderr)
        record['stdout_file'] = stem.name + ('.stdout.bin' if binary else '.stdout.txt')
        record['stderr_file'] = stem.name + '.stderr.txt'
        record['stderr_present'] = bool(stderr.strip())
        if record['status'] != 'completed' or record['exit_code'] not in allowed_exit_codes:
            raise RuntimeError(f'ADB command {index} failed ({record["status"]}, exit {record["exit_code"]})')
        return stdout if binary else stdout.decode('utf-8', errors='replace')


def emulator_reply(text, expected=None):
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines or lines[-1] != 'OK' or any(line.startswith('KO') for line in lines):
        raise ValueError('Emulator console command refused or did not acknowledge success')
    if expected is not None and lines[:-1] != [expected]:
        raise ValueError('Emulator AVD identity does not match the requested laboratory')


def no_accounts(text):
    # dumpsys account prints an Accounts: N section for each user on supported AVDs.
    counts = re.findall(r'^\s*Accounts:\s*(\d+)\s*$', text, re.M)
    if not counts or any(int(value) for value in counts) or re.search(r'Account\s*\{', text):
        raise ValueError('Emulator accounts are present or account state cannot be determined')


def resumed_component(text):
    for line in text.splitlines():
        if re.search(r'(?:mResumedActivity|topResumedActivity|ResumedActivity):', line):
            match = re.search(r'\b([A-Za-z0-9_.]+/[A-Za-z0-9_.$]+)\b', line)
            if match:
                return match.group(1)
    raise ValueError('Cannot determine resumed activity')


def component_equal(actual, expected):
    def expand(value):
        package, activity = value.split('/', 1)
        return package, package + activity if activity.startswith('.') else activity
    return expand(actual) == expand(expected)


def scoped_crash(text, package):
    # The crash buffer has AndroidRuntime blocks. Match the explicit Process field,
    # not incidental mentions of a package elsewhere in unrelated diagnostics.
    identity = re.escape(package) + r'(?=[:,\s]|$)'
    return bool(re.search(r'\bProcess:\s*' + identity, text)
                or re.search(r'>>>\s*' + re.escape(package) + r'(?=[:\s])[^\n]*<<<', text)
                or re.search(r'\bANR in\s+' + identity, text))


def no_default_network(text):
    # Known Android ConnectivityService dumpsys format (including API 30).
    # Unknown formats fail closed; do not infer isolation from empty output.
    matches = re.findall(r'^\s*Active default network:\s*(\S+)\s*$', text, re.M | re.I)
    if matches != ['none']:
        raise ValueError('Active default network exists or connectivity state cannot be determined')


def connectivity_checkpoint(adb, output, label):
    text = adb.run('shell', 'dumpsys', 'connectivity')
    (output / f'{label}-connectivity.txt').write_text(text, encoding='utf-8')
    no_default_network(text)


def check_ui(xml, package, expected_text):
    root = ET.fromstring(xml)
    nodes = list(root.iter('node'))
    owned = [n for n in nodes if n.get('package') == package]
    if not owned:
        raise ValueError('Foreground UI does not contain nodes from the expected package')
    values = [n.get(key, '') for n in owned for key in ('text', 'content-desc')]
    for expected in expected_text:
        if not any(expected in value for value in values):
            raise ValueError('Expected UI text absent: ' + expected)


def capture_ui(adb, output, name):
    device_xml = '/data/local/tmp/dezap-runtime-ui.xml'
    try:
        dump = adb.run('shell', 'uiautomator', 'dump', device_xml)
        if 'dumped to:' not in dump:
            raise ValueError('UI hierarchy capture failed')
        xml = adb.run('exec-out', 'cat', device_xml)
        (output / f'{name}.xml').write_text(xml, encoding='utf-8')
    finally:
        adb.run('shell', 'rm', '-f', device_xml)
    png = adb.run('exec-out', 'screencap', '-p', binary=True)
    if not png.startswith(b'\x89PNG\r\n\x1a\n'):
        raise ValueError('Screenshot capture did not return PNG data')
    (output / f'{name}.png').write_bytes(png)
    return xml


def dismiss_dialog(adb, xml, args):
    if not args.dismiss_dialog_text:
        return False
    nodes = list(ET.fromstring(xml).iter('node'))
    if not any(args.dismiss_dialog_text in n.get('text', '') for n in nodes):
        return False
    matches = [n for n in nodes if n.get('resource-id') == args.dismiss_button_id
               and n.get('text') == args.dismiss_button_text
               and n.get('package') in (args.package, 'android')
               and n.get('enabled') == 'true' and n.get('clickable') == 'true']
    if len(matches) != 1:
        raise ValueError('Requested informational dialog button is absent or ambiguous')
    bounds = re.fullmatch(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', matches[0].get('bounds', ''))
    if not bounds:
        raise ValueError('Invalid dialog button bounds')
    left, top, right, bottom = map(int, bounds.groups())
    if right <= left or bottom <= top:
        raise ValueError('Empty dialog button bounds')
    adb.run('shell', 'input', 'tap', str((left + right) // 2), str((top + bottom) // 2))
    return True


def observe(adb, args, output, name):
    time.sleep(args.observe_seconds)
    xml = capture_ui(adb, output, name)
    dismissed = dismiss_dialog(adb, xml, args)
    if dismissed:
        time.sleep(args.observe_seconds)
        xml = capture_ui(adb, output, name + '-after-dialog')
    component = resumed_component(adb.run('shell', 'dumpsys', 'activity', 'activities'))
    if not component_equal(component, args.expected_activity):
        raise ValueError('Unexpected resumed activity: ' + component)
    pid = adb.run('shell', 'pidof', args.package).strip()
    if not re.fullmatch(r'\d+(?:\s+\d+)*', pid):
        raise ValueError('Expected app process is absent')
    crash = adb.run('logcat', '-b', 'crash', '-d', '-v', 'threadtime')
    (output / f'{name}-crash.txt').write_text(crash, encoding='utf-8')
    full_log = adb.run('logcat', '-d', '-v', 'threadtime')
    (output / f'{name}-logcat.txt').write_text(full_log, encoding='utf-8')
    if scoped_crash(crash + '\n' + full_log, args.package):
        raise ValueError('Crash recorded for the expected package')
    check_ui(xml, args.package, args.expected_text)
    evidence_name = name + '-after-dialog' if dismissed else name
    return {'name': name, 'status': 'observed-pass', 'component': component,
            'pid': pid, 'dialog_dismissed': dismissed,
            'ui_file': f'{evidence_name}.xml', 'screenshot_file': f'{evidence_name}.png'}


def launch(adb, args):
    text = adb.run('shell', 'am', 'start', '-W', '-n', args.activity)
    if not re.search(r'^Status:\s*ok\s*$', text, re.M) or re.search(r'^(?:Error|Exception)', text, re.M):
        raise ValueError('Activity launch was not acknowledged as successful')


def force_stop(adb, package):
    adb.run('shell', 'am', 'force-stop', package)
    pid = adb.run('shell', 'pidof', package, allowed_exit_codes=(0, 1))
    record = adb.commands[-1]
    if pid.strip() or record['exit_code'] != 1 or record['stderr_present']:
        raise ValueError('Force-stop did not establish process absence')


def execute(args, adb, output, report):
    source, artifacts = load_set(args.summary.resolve(), args.package)
    report['input'] = {'summary_sha256': digest(args.summary),
                       'certificate_sha256': source['certificate_sha256'],
                       'signature_evidence': 'Recorded by signed reconstruction; not independently reverified here',
                       'apks': [{'file': p.name, 'sha256': digest(p)} for p in artifacts]}
    report['stages']['artifact_validation'] = 'passed'
    if adb.run('get-state').strip() != 'device':
        raise ValueError('Explicit emulator is not connected')
    emulator_reply(adb.run('emu', 'avd', 'name'), args.avd)
    report['stages']['identity'] = 'passed'
    # Record runtime tools/environment before changing the snapshot.
    report['adb_version'] = adb.run('version').strip()
    emulator_reply(adb.run('emu', 'avd', 'snapshot', 'load', args.snapshot))
    deadline = time.monotonic() + args.boot_timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Snapshot boot timeout')
        try:
            booted = adb.run('shell', 'getprop', 'sys.boot_completed',
                            timeout=min(args.timeout, remaining)).strip() == '1'
        except RuntimeError:
            # Restoring a snapshot can temporarily disconnect the transport.
            # Retry only this non-mutating boot query, never installation or
            # identity validation. Every refused query remains in command logs.
            booted = False
        if booted:
            break
        if time.monotonic() >= deadline:
            raise TimeoutError('Snapshot boot timeout')
        time.sleep(min(1, max(0, deadline - time.monotonic())))
    emulator_reply(adb.run('emu', 'avd', 'name'), args.avd)
    report['environment'] = {key: adb.run('shell', 'getprop', prop).strip() for key, prop in (
        ('android_release', 'ro.build.version.release'), ('sdk', 'ro.build.version.sdk'),
        ('abi', 'ro.product.cpu.abi'), ('fingerprint', 'ro.build.fingerprint'))}
    adb.run('shell', 'settings', 'put', 'global', 'airplane_mode_on', '1')
    adb.run('shell', 'svc', 'wifi', 'disable')
    adb.run('shell', 'svc', 'data', 'disable')
    network = {key: adb.run('shell', 'settings', 'get', 'global', key).strip()
               for key in ('airplane_mode_on', 'wifi_on', 'mobile_data')}
    if network != {'airplane_mode_on': '1', 'wifi_on': '0', 'mobile_data': '0'}:
        raise ValueError('Radio configuration could not be confirmed disabled')
    report['radio_settings'] = network
    connectivity_checkpoint(adb, output, 'before-install')
    no_accounts(adb.run('shell', 'dumpsys', 'account'))
    # pm path can return a nonzero status for an absent package. Use list packages
    # instead; require exact package matching and reject any installed target.
    packages = adb.run('shell', 'pm', 'list', 'packages', args.package).splitlines()
    if 'package:' + args.package in [p.strip() for p in packages]:
        raise ValueError('Expected package already exists in restored snapshot')
    report['stages']['snapshot_preconditions'] = 'passed'
    (output / 'before-install-logcat.txt').write_text(adb.run('logcat', '-d', '-v', 'threadtime'), encoding='utf-8')
    adb.run('logcat', '-c')
    adb.run('logcat', '-b', 'crash', '-c')
    # Recheck immediately before installation to avoid stale report acceptance.
    load_set(args.summary.resolve(), args.package)
    result = adb.run('install-multiple', '-t', '--no-incremental', *artifacts, timeout=args.install_timeout)
    if result.strip() != 'Success':
        raise ValueError('APK set installation failed: ' + result.strip()[:500])
    report['stages']['installation'] = 'passed'
    installed = adb.run('shell', 'pm', 'path', args.package).splitlines()
    if len(installed) != len(artifacts) or not all(x.startswith('package:') for x in installed):
        raise ValueError('Installed APK count differs from supplied set')
    launch(adb, args)
    report['stages']['launch_acknowledgment'] = 'passed'
    def scenario(name, expected_pid=None):
        try:
            observed = observe(adb, args, output, name)
            if expected_pid is not None and observed['pid'].split() != expected_pid.split():
                raise ValueError('App process changed during HOME/resume; a cold start is not a resume pass')
            report['scenarios'].append(observed)
        except Exception as error:
            report['scenarios'].append({'name': name, 'status': 'failed', 'error': str(error)})
            raise
    scenario('initial')
    initial_pid = report['scenarios'][-1]['pid']
    try:
        adb.run('shell', 'input', 'keyevent', 'KEYCODE_HOME')
        time.sleep(args.observe_seconds)
        home_component = resumed_component(adb.run('shell', 'dumpsys', 'activity', 'activities'))
        if home_component.split('/', 1)[0] == args.package:
            raise ValueError('HOME did not leave the tested application')
        home_pid = adb.run('shell', 'pidof', args.package).strip()
        if home_pid.split() != initial_pid.split():
            raise ValueError('App process did not survive HOME')
        report['home_observation'] = {'component': home_component, 'pid': home_pid}
        launch(adb, args)
    except Exception as error:
        report['scenarios'].append({'name': 'home-resume', 'status': 'failed', 'error': str(error)})
        raise
    scenario('home-resume', expected_pid=initial_pid)
    try:
        force_stop(adb, args.package)
        launch(adb, args)
    except Exception as error:
        report['scenarios'].append({'name': 'force-stop-relaunch', 'status': 'failed', 'error': str(error)})
        raise
    scenario('force-stop-relaunch')
    no_accounts(adb.run('shell', 'dumpsys', 'account'))
    connectivity_checkpoint(adb, output, 'after-observation')
    report['stages']['connectivity_checkpoints'] = 'no-active-default-network-observed'
    report['stages']['runtime_observation'] = 'passed'
    report['status'] = 'runtime-observed-pass'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('summary', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--adb', type=Path, required=True)
    parser.add_argument('--server-port', type=int, required=True)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--avd', required=True)
    parser.add_argument('--snapshot', required=True)
    parser.add_argument('--package', required=True)
    parser.add_argument('--activity', required=True)
    parser.add_argument('--expected-activity', help='Explicit expected foreground activity after launch; defaults to --activity')
    parser.add_argument('--expected-text', action='append', required=True)
    parser.add_argument('--dismiss-dialog-text')
    parser.add_argument('--dismiss-button-id')
    parser.add_argument('--dismiss-button-text')
    parser.add_argument('--timeout', type=float, default=30)
    parser.add_argument('--boot-timeout', type=float, default=120)
    parser.add_argument('--install-timeout', type=float, default=180)
    parser.add_argument('--observe-seconds', type=float, default=5)
    args = parser.parse_args(argv)
    args.expected_activity = args.expected_activity or args.activity
    if not re.fullmatch(r'emulator-\d+', args.serial):
        parser.error('An explicit emulator-NNNN serial is required; physical devices are refused')
    if not 1 <= args.server_port <= 65535 or min(args.timeout, args.boot_timeout, args.install_timeout, args.observe_seconds) <= 0:
        parser.error('Valid port and positive time limits required')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', args.avd) or not re.fullmatch(r'[A-Za-z0-9_.-]+', args.snapshot):
        parser.error('AVD and snapshot names must contain only letters, digits, dot, dash or underscore')
    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+', args.package):
        parser.error('Invalid package identifier')
    if not re.fullmatch(re.escape(args.package) + r'/[A-Za-z0-9_.$]+', args.activity):
        parser.error('Activity must belong to the expected package')
    if not re.fullmatch(re.escape(args.package) + r'/[A-Za-z0-9_.$]+', args.expected_activity):
        parser.error('Expected activity must belong to the expected package')
    if any(not text for text in args.expected_text):
        parser.error('Expected UI text must be nonempty')
    dismissal = (args.dismiss_dialog_text, args.dismiss_button_id, args.dismiss_button_text)
    if any(dismissal) and not all(dismissal):
        parser.error('Dialog dismissal requires text, button resource ID and exact button text')
    output = args.output.resolve()
    if output == HERE or output.is_relative_to(HERE):
        parser.error('Runtime evidence must be outside the public source directory')
    if not args.adb.is_file() or not args.summary.is_file():
        parser.error('Explicit ADB executable and reconstruction summary must exist')
    try:
        output.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        parser.error('Output already exists; choose a new evidence directory')
    adb = ADB(args.adb.resolve(), args.server_port, args.serial, output, args.timeout)
    report = {'status': 'incomplete', 'serial': args.serial, 'server_port': args.server_port,
              'avd': args.avd, 'snapshot': args.snapshot, 'package': args.package,
              'activity': args.activity, 'expected_text': args.expected_text,
              'launch_activity': args.activity, 'expected_activity': args.expected_activity,
              'dialog_dismissal': dict(text=args.dismiss_dialog_text, button_id=args.dismiss_button_id, button_text=args.dismiss_button_text),
              'adb_sha256': digest(args.adb), 'stages': {}, 'scenarios': [],
              'limits': ['Only the specified UI and lifecycle scenarios were observed.',
                         'Radio settings and default network checkpoints are not proof of total network isolation.',
                         'No account registration, server acceptance, complete functionality or security audit.']}
    started = time.monotonic()
    try:
        execute(args, adb, output, report)
    except Exception as error:
        report.update(status='failed', error=str(error))
        if report['stages'].get('snapshot_preconditions') == 'passed':
            for label, command in (('failure-logcat', ('logcat', '-d', '-v', 'threadtime')),
                                   ('failure-activity', ('shell', 'dumpsys', 'activity', 'activities'))):
                try:
                    (output / (label + '.txt')).write_text(adb.run(*command), encoding='utf-8')
                except Exception as diagnostic_error:
                    report.setdefault('diagnostic_errors', []).append(str(diagnostic_error))
    finally:
        # Identity was established before any emulator mutation. Do not touch the
        # requested package when identity validation failed, and never stop ADB.
        if report['stages'].get('installation') == 'passed':
            try:
                force_stop(adb, args.package)
                report['cleanup'] = 'tested-package-force-stopped'
            except Exception as error:
                report.update(status='failed', cleanup_error=str(error))
        report['commands'] = adb.commands
        report['seconds'] = time.monotonic() - started
        (output / 'runtime-summary.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key: report[key] for key in ('status', 'error') if key in report}))
    return 0 if report['status'] == 'runtime-observed-pass' else 1


if __name__ == '__main__':
    raise SystemExit(main())
