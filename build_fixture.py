#!/usr/bin/env python3
"""Build the authored tiny fixture into a new directory outside this source tree."""
import argparse
import copy
import os
from pathlib import Path
import shutil
import subprocess
import zipfile
from decompile import HERE, resolve_tool

def store_resource_table(path):
    """API30+ requires resources.arsc stored; later signing flow aligns the ZIP."""
    temporary = path.with_suffix('.stored.apk')
    with zipfile.ZipFile(path) as source, zipfile.ZipFile(temporary, 'x') as target:
        for item in source.infolist():
            info = copy.copy(item)
            if info.filename == 'resources.arsc': info.compress_type = zipfile.ZIP_STORED
            target.writestr(info, source.read(item))
    temporary.replace(path)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--java', default='java')
    parser.add_argument('--javac', default='javac')
    parser.add_argument('--apktool-jar', required=True)
    parser.add_argument('--multidex', action='store_true')
    parser.add_argument('--with-resource-split', action='store_true')
    parser.add_argument('--modern-dex', choices=('038', '039'))
    parser.add_argument('--split-without-sdk', action='store_true')
    args = parser.parse_args()
    if args.split_without_sdk and not args.with_resource_split:
        parser.error('--split-without-sdk requires --with-resource-split')
    output = args.output.resolve()
    if output.is_relative_to(HERE):
        parser.error('Fixture output must be outside the repository')
    java, apktool = resolve_tool(args.java), resolve_tool(args.apktool_jar)
    output.mkdir(parents=True, exist_ok=False)
    source = output / 'source'
    shutil.copytree(HERE / 'fixtures' / 'tiny', source)
    if args.multidex:
        shutil.copytree(HERE / 'fixtures' / 'multidex' / 'smali_classes2', source / 'smali_classes2')
    if args.modern_dex:
        activity = source / 'smali/example/tiny/MainActivity.smali'
        activity.write_text(activity.read_text().replace('const-string v1, "Offline fixture"', 'invoke-static {}, Lexample/tiny/ModernFeatures;->label()Ljava/lang/String;\n    move-result-object v1'))
    subprocess.run([str(java), '-jar', str(apktool), 'b', '-p', str(output / 'framework'), '-o', str(output / 'tiny.apk'), str(source)], check=True)
    if args.modern_dex:
        modern = output / 'modern-source'
        shutil.copytree(HERE / 'fixtures/modern/smali_classes2', modern)
        method = modern / 'example/tiny/ModernFeatures.smali'
        if args.modern_dex == '039':
            text = method.read_text().replace('Offline fixture 038', 'Offline fixture 039')
            text = text.replace('    return-object v0', '    const-method-type v1, ()Ljava/lang/String;\n    invoke-virtual {v1}, Ljava/lang/invoke/MethodType;->toString()Ljava/lang/String;\n    move-result-object v1\n    invoke-virtual {v0, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v0\n    return-object v0')
            method.write_text(text)
        classes = output / 'assembler'; classes.mkdir()
        javac = resolve_tool(args.javac)
        subprocess.run([str(javac), '-cp', str(apktool), '-d', str(classes), str(HERE / 'Assembler.java')], check=True)
        dex = output / 'classes2.dex'
        subprocess.run([str(java), '-cp', str(classes) + os.pathsep + str(apktool), 'Assembler', str(modern), str(dex), '26' if args.modern_dex == '038' else '28'], check=True)
        if dex.read_bytes()[:8] != b'dex\n' + args.modern_dex.encode() + b'\0':
            raise ValueError('Unexpected fixture DEX version')
        original = output / 'tiny.apk'
        replaced = output / 'modern.apk'
        with zipfile.ZipFile(original) as a, zipfile.ZipFile(replaced, 'x') as b:
            for entry in a.infolist():
                if entry.filename != 'classes2.dex': b.writestr(entry, a.read(entry))
            b.writestr('classes2.dex', dex.read_bytes())
        replaced.replace(original)
    if args.with_resource_split:
        split = output / 'split-source'
        shutil.copytree(HERE / 'fixtures' / 'resource-split', split)
        if args.split_without_sdk:
            manifest = split / 'AndroidManifest.xml'
            manifest.write_text('\n'.join(line for line in manifest.read_text().splitlines() if '<uses-sdk ' not in line))
            config = split / 'apktool.yml'
            config.write_text(config.read_text().replace('sdkInfo:\n  minSdkVersion: 23\n  targetSdkVersion: 30\n', ''))
        subprocess.run([str(java), '-jar', str(apktool), 'b', '-p', str(output / 'framework'), '-o', str(output / 'config.en.apk'), str(split)], check=True)
    store_resource_table(output / 'tiny.apk')
    if args.with_resource_split: store_resource_table(output / 'config.en.apk')
    with zipfile.ZipFile(output / 'tiny.xapk', 'w') as archive:
        archive.write(output / 'tiny.apk', 'nested/base.apk')
        if args.with_resource_split:
            archive.write(output / 'config.en.apk', 'splits/config.en.apk')
        archive.writestr('manifest.json', '{"name":"Tiny fixture"}')
    print(output / 'tiny.apk')

if __name__ == '__main__': main()
