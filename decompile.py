#!/usr/bin/env python3
"""Offline APK/XAPK export using explicitly supplied local tools."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import time
import zipfile

HERE = Path(__file__).resolve().parent

def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()

def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')

def preserved_decode_inventory(directory):
    """Track resources/manifest so preservation mode refuses silently ignored edits."""
    result = {}
    for child in directory.iterdir():
        if child.name.startswith('smali') or child.name in ('build', 'dist', 'java_src'):
            continue
        paths = child.rglob('*') if child.is_dir() else [child]
        for path in paths:
            if path.is_symlink():
                raise ValueError('Symlink in decoded tree')
            if path.is_file():
                result[path.relative_to(directory).as_posix()] = sha256(path)
    return result

def validate_zip(source, max_bytes=2 * 1024**3):
    """Validate every member before any extraction. Return APK member names."""
    with zipfile.ZipFile(source) as archive:
        seen, apks, total = set(), [], 0
        for member in archive.infolist():
            name = member.filename.replace('\\', '/')
            parts = PurePosixPath(name).parts
            if (not parts or name.startswith('/') or ':' in name or '..' in parts
                    or any(part.rstrip(' .') != part or not part for part in parts)
                    or stat.S_ISLNK(member.external_attr >> 16)):
                raise ValueError('Unsafe ZIP member')
            if name.casefold().rstrip('/') in seen:
                raise ValueError('Colliding ZIP members')
            seen.add(name.casefold().rstrip('/'))
            total += member.file_size
            if total > max_bytes:
                raise ValueError('ZIP expansion exceeds configured limit')
            if not member.is_dir() and name.lower().endswith('.apk'):
                apks.append(member.filename)
        return sorted(apks)

def prepare_inputs(source, destination, max_bytes):
    destination.mkdir()
    apks = []
    if source.suffix.lower() == '.apk':
        validate_zip(source, max_bytes)
        target = destination / '0000.apk'
        shutil.copyfile(source, target)
        apks.append(target)
    elif source.suffix.lower() == '.xapk':
        names = validate_zip(source, max_bytes)
        if not names:
            raise ValueError('XAPK contains no APK members')
        with zipfile.ZipFile(source) as archive:
            for index, name in enumerate(names):
                target = destination / f'{index:04d}.apk'
                with archive.open(name) as src, target.open('xb') as dst:
                    shutil.copyfileobj(src, dst)
                validate_zip(target, max_bytes)
                apks.append(target)
    else:
        raise ValueError('Input must be APK or XAPK')
    return apks

def resolve_tool(value):
    found = shutil.which(value) or value
    path = Path(found).resolve()
    if not path.is_file():
        raise ValueError(f'Local tool not found: {value}')
    return path

def run_command(command, directory, label, timeout):
    start = time.monotonic()
    record = {'command': [str(x) for x in command], 'status': 'running'}
    with (directory / f'{label}.stdout.txt').open('wb') as stdout, (directory / f'{label}.stderr.txt').open('wb') as stderr:
        try:
            result = subprocess.run(record['command'], stdout=stdout, stderr=stderr, timeout=timeout, check=False)
            record.update(status='completed', exit_code=result.returncode)
        except subprocess.TimeoutExpired:
            record.update(status='timeout', exit_code=None)
        except OSError as error:
            record.update(status='launch-failed', exit_code=None, error=str(error))
        finally:
            record['seconds'] = time.monotonic() - start
            write_json(directory / f'{label}.json', record)
    if record.get('exit_code') != 0:
        raise RuntimeError(f'{label} failed; inspect local command logs')

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--java', default='java')
    parser.add_argument('--javac', default='javac')
    parser.add_argument('--jadx-jar')
    parser.add_argument('--smali-only', action='store_true', help='Decode smali/resources without invoking JADX or exporting Java')
    parser.add_argument('--apktool-jar', required=True)
    parser.add_argument('--mode', choices=['AUTO', 'SIMPLE'], default='AUTO')
    parser.add_argument('--heap-gib', type=int, default=4)
    parser.add_argument('--timeout', type=float, default=1800)
    parser.add_argument('--max-expanded-gib', type=float, default=2)
    args = parser.parse_args(argv)
    if not args.smali_only and not args.jadx_jar:
        parser.error('--jadx-jar is required unless --smali-only is selected')
    if args.heap_gib < 1 or args.timeout <= 0 or args.max_expanded_gib <= 0:
        parser.error('Memory, timeout and expansion limits must be positive')
    source, output = args.input.resolve(), args.output.resolve()
    tool_keys = ['java', 'apktool_jar'] if args.smali_only else ['java', 'javac', 'jadx_jar', 'apktool_jar']
    tools = {key: resolve_tool(getattr(args, key)) for key in tool_keys}
    if not source.is_file():
        parser.error('Input file does not exist')
    # Never overwrite an existing output, including another process creating it.
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    report = {'status': 'failed', 'uses_llm': False, 'mode': args.mode,
              'export_scope': 'smali-and-resources' if args.smali_only else 'java-smali-and-resources',
              'input_sha256': sha256(source), 'tools_sha256': {key: sha256(path) for key, path in tools.items()},
              'backend_sha256': None if args.smali_only else sha256(HERE / 'Exporter.java'), 'apks': []}
    if args.smali_only:
        report['quality'] = 'java-not-exported'
    try:
        logs = output / 'logs'; logs.mkdir()
        apks = prepare_inputs(source, output / 'inputs', int(args.max_expanded_gib * 1024**3))
        if not args.smali_only:
            classes = output / 'backend'; classes.mkdir()
            run_command([tools['javac'], '-cp', tools['jadx_jar'], '-d', classes, HERE / 'Exporter.java'], logs, 'compile', args.timeout)
        for index, apk in enumerate(apks):
            if args.smali_only:
                summary = {'status': 'not-exported', 'reason': 'smali-only requested'}
            else:
                java_out = output / f'java-{index:04d}'
                run_command([tools['java'], f'-Xmx{args.heap_gib}g', '-cp', str(classes) + os.pathsep + str(tools['jadx_jar']), 'Exporter', apk, java_out, args.mode], logs, f'java-{index:04d}', args.timeout)
                summary = json.loads((java_out / 'summary.json').read_text(encoding='utf-8'))
            members = validate_zip(source, int(args.max_expanded_gib * 1024**3)) if source.suffix.lower() == '.xapk' else [source.name]
            report['apks'].append({'index': index, 'source_member': members[index], 'sha256': sha256(apk), 'java': summary})
            run_command([tools['java'], f'-Xmx{args.heap_gib}g', '-jar', tools['apktool_jar'], 'd', '-p', output / 'framework', '-o', output / f'decoded-{index:04d}', apk], logs, f'decode-{index:04d}', args.timeout)
            report['apks'][-1]['preserved_decode_inventory'] = preserved_decode_inventory(output / f'decoded-{index:04d}')
        report['status'] = 'export-completed'
        if not args.smali_only:
            report['quality'] = 'issues-detected' if any(item['java']['jadx_errors'] or item['java']['files_with_incomplete_markers'] for item in report['apks']) else 'no-java-issues-detected'
        report['limits'] = 'No proof of semantic equivalence, full recompilability, native-code recovery or security. Review Apktool logs separately.'
    except Exception as error:
        report['error'] = str(error)
    finally:
        report['seconds'] = time.monotonic() - started
        write_json(output / 'run-summary.json', report)
    print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'export-completed' else 1

if __name__ == '__main__':
    raise SystemExit(main())
