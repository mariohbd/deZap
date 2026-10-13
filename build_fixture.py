#!/usr/bin/env python3
"""Build the authored tiny fixture into a new directory outside this source tree."""
import argparse
from pathlib import Path
import shutil
import subprocess
import zipfile
from decompile import HERE, resolve_tool

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--java', default='java')
    parser.add_argument('--apktool-jar', required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.is_relative_to(HERE):
        parser.error('Fixture output must be outside the repository')
    java, apktool = resolve_tool(args.java), resolve_tool(args.apktool_jar)
    output.mkdir(parents=True, exist_ok=False)
    source = output / 'source'
    shutil.copytree(HERE / 'fixtures' / 'tiny', source)
    subprocess.run([str(java), '-jar', str(apktool), 'b', '-p', str(output / 'framework'), '-o', str(output / 'tiny.apk'), str(source)], check=True)
    with zipfile.ZipFile(output / 'tiny.xapk', 'w') as archive:
        archive.write(output / 'tiny.apk', 'nested/base.apk')
        archive.writestr('manifest.json', '{"name":"Tiny fixture"}')
    print(output / 'tiny.apk')

if __name__ == '__main__': main()
