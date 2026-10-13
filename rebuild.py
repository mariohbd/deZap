"""Experimental DEX-only reconstruction; original binary resources are preserved."""
import argparse
import json
import os
from pathlib import Path
import re
import time
import zipfile
from decompile import HERE, sha256, resolve_tool, run_command, write_json, validate_zip, preserved_decode_inventory
from compare import signature_entry, dex_entry, compare_apks, assert_dex_only

def metadata(text):
    package=re.search(r"^package: name='([^']+)' versionCode='([^']+)'[^\n]*",text,re.M)
    if not package:raise ValueError('Cannot identify package/version from aapt2')
    split=re.search(r"\bsplit='([^']+)'",package.group())
    minimum=re.search(r"^(?:minSdkVersion|sdkVersion):'(\d+)'",text,re.M)
    if not minimum and re.search(r"^(?:minSdkVersion|sdkVersion):'",text,re.M):raise ValueError('Preview minimum SDK unsupported')
    return dict(package=package.group(1),version_code=package.group(2),split=split.group(1) if split else None,min_sdk=int(minimum.group(1)) if minimum else None)

def validate_set(records):
    if len({(r['package'],r['version_code']) for r in records})!=1:raise ValueError('APK set contains different packages or versions')
    if sum(r['split'] is None for r in records)!=1:raise ValueError('APK set must contain exactly one base')
    names=[r['split'] for r in records if r['split']]
    if len(names)!=len(set(names)):raise ValueError('Duplicate split identifiers')
    base=next(r for r in records if r['split'] is None)
    if base['min_sdk'] is None:raise ValueError('Base APK must declare numeric minimum SDK')
    for row in records:row['effective_min_sdk']=row['min_sdk'] if row['min_sdk'] is not None else base['min_sdk']

def dex_opcode_api(header):
    if not re.fullmatch(b'dex\\n0[0-9]{2}\\x00',header):raise ValueError('Invalid DEX header')
    version=int(header[4:7])
    supported={35:23,37:25,38:26,39:28}
    if version not in supported:raise ValueError('Unsupported DEX version; supported: 035, 037, 038, 039')
    return version,supported[version]

def smali_mapping(decoded, dex_names):
    mapping={}
    for folder in decoded.iterdir():
        if not folder.name.startswith('smali'):continue
        if not folder.is_dir() or folder.is_symlink():raise ValueError('Invalid smali directory')
        if folder.name=='smali':name='classes.dex'
        else:
            match=re.fullmatch(r'smali_classes([2-9]|[1-9][0-9]+)',folder.name)
            if not match:raise ValueError('Unsupported smali directory name')
            name='classes'+match.group(1)+'.dex'
        mapping[name]=folder
    if set(mapping)!=set(dex_names):raise ValueError('Missing or extra smali/DEX partition')
    return mapping

def package(original, output, replacements):
    validate_zip(original)
    with zipfile.ZipFile(original) as a,zipfile.ZipFile(output,'x') as b:
        for entry in a.infolist():
            if signature_entry(entry.filename):continue
            data=replacements[entry.filename].read_bytes() if entry.filename in replacements else a.read(entry)
            b.writestr(entry,data)
    comparison=compare_apks(original,output)
    assert_dex_only(comparison)
    return comparison

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('export',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--java',default='java');parser.add_argument('--javac',default='javac')
    parser.add_argument('--apktool-jar',required=True);parser.add_argument('--aapt2',required=True)
    parser.add_argument('--zipalign',required=True);parser.add_argument('--apksigner-jar')
    parser.add_argument('--keystore',type=Path);parser.add_argument('--key-alias')
    parser.add_argument('--ks-pass-env');parser.add_argument('--key-pass-env')
    parser.add_argument('--heap-gib',type=int,default=4);parser.add_argument('--timeout',type=float,default=1800)
    args=parser.parse_args(argv)
    if args.heap_gib<1 or args.timeout<=0:parser.error('Positive heap and timeout required')
    signing=args.keystore is not None
    if signing and not all((args.apksigner_jar,args.key_alias,args.ks_pass_env)):parser.error('Signing requires apksigner, alias and password environment variable name')
    if not signing and any((args.apksigner_jar,args.key_alias,args.ks_pass_env,args.key_pass_env)):parser.error('Signing options require a keystore')
    for key in (args.ks_pass_env,args.key_pass_env):
        if key and (not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',key) or key not in os.environ):parser.error('Password environment variable missing/invalid')
    if signing and not args.keystore.is_file():parser.error('Keystore not found')
    source=args.export.resolve();output=args.output.resolve()
    if output==source or output.is_relative_to(source):parser.error('Rebuild output must be outside export directory')
    tools={key:resolve_tool(getattr(args,key)) for key in ('java','javac','apktool_jar','aapt2','zipalign')}
    if signing:tools['apksigner_jar']=resolve_tool(args.apksigner_jar)
    export=json.loads((source/'run-summary.json').read_text())
    if export.get('status')!='export-completed' or not export.get('apks'):parser.error('A completed export is required')
    try:output.mkdir(parents=True,exist_ok=False)
    except FileExistsError:parser.error('Output already exists; choose a new directory')
    started=time.monotonic();report=dict(status='incomplete',preservation='DEX-only',signing_requested=signing,apks=[],tools_sha256={k:sha256(v) for k,v in tools.items()},limits='No Java rebuild, resource editing, runtime/semantic/security proof. Splits are not merged.')
    try:
        logs=output/'logs';logs.mkdir()
        classes=output/'backend';classes.mkdir()
        run_command([tools['javac'],'-encoding','UTF-8','-cp',tools['apktool_jar'],'-d',classes,HERE/'Assembler.java'],logs,'compile-assembler',args.timeout)
        inputs=[];set_meta=[]
        for row in export['apks']:
            index=row['index']
            if not isinstance(index,int) or index<0 or index>9999:raise ValueError('Invalid APK index')
            original=source/'inputs'/f'{index:04d}.apk';decoded=source/f'decoded-{index:04d}'
            if sha256(original)!=row['sha256']:raise ValueError('Original APK changed after export')
            if 'preserved_decode_inventory' not in row:raise ValueError('Export predates preservation inventory; create a new export')
            for p in decoded.rglob('*'):
                if p.is_symlink():raise ValueError('Symlink in decoded input')
            if preserved_decode_inventory(decoded)!=row['preserved_decode_inventory']:raise ValueError('Resource/manifest/config edits are unsupported in preservation mode')
            run_command([tools['aapt2'],'dump','badging',original],logs,f'metadata-{index}',args.timeout)
            info=metadata((logs/f'metadata-{index}.stdout.txt').read_text(encoding='utf-8',errors='replace'))
            inputs.append((index,original,decoded,row,info));set_meta.append(info)
        validate_set(set_meta)
        certificates=[]
        for index,original,decoded,row,info in inputs:
            with zipfile.ZipFile(original) as archive:
                if any(n.endswith('.dex') and '/' not in n and not dex_entry(n) for n in archive.namelist()):raise ValueError('Unsupported root DEX filename')
                dex_names=[n for n in archive.namelist() if dex_entry(n)]
                opcodes={n:dex_opcode_api(archive.read(n)[:8]) for n in dex_names}
            mapping=smali_mapping(decoded,dex_names);replacements={}
            for name,folder in mapping.items():
                dex=output/'dex'/f'{index:04d}'/name
                run_command([tools['java'],f'-Xmx{args.heap_gib}g','-cp',str(classes)+os.pathsep+str(tools['apktool_jar']),'Assembler',folder,dex,str(opcodes[name][1])],logs,f'assemble-{index}-{name}',args.timeout)
                if dex_opcode_api(dex.read_bytes()[:8])[0]!=opcodes[name][0]:raise ValueError('Assembler changed DEX version')
                replacements[name]=dex
            unsigned=output/f'{index:04d}-unsigned.apk'
            comparison=package(original,unsigned,replacements)
            aligned=output/f'{index:04d}-aligned.apk'
            run_command([tools['zipalign'],'-P','16','4',unsigned,aligned],logs,f'align-{index}',args.timeout)
            artifact=aligned
            if signing:
                artifact=output/f'{index:04d}-signed.apk'
                command=[tools['java'],'-jar',tools['apksigner_jar'],'sign','--ks',args.keystore,'--ks-key-alias',args.key_alias,'--ks-pass','env:'+args.ks_pass_env,'--min-sdk-version',str(info['effective_min_sdk']),'--out',artifact,aligned]
                if args.key_pass_env:command+=['--key-pass','env:'+args.key_pass_env]
                run_command(command,logs,f'sign-{index}',args.timeout)
                run_command([tools['java'],'-jar',tools['apksigner_jar'],'verify','--verbose','--print-certs','--min-sdk-version',str(info['effective_min_sdk']),artifact],logs,f'verify-{index}',args.timeout)
                text=(logs/f'verify-{index}.stdout.txt').read_text()
                if not re.search(r'Number of signers:\s*1\b',text):raise ValueError('Expected one laboratory signer')
                digests=set(re.findall(r'certificate SHA-256 digest:\s*([0-9a-fA-F]{64})',text))
                if len(digests)!=1:raise ValueError('Cannot identify unique signing certificate')
                certificates.append(next(iter(digests)))
            run_command([tools['zipalign'],'-c','-P','16','4',artifact],logs,f'check-align-{index}',args.timeout)
            final_comparison=compare_apks(original,artifact);assert_dex_only(final_comparison)
            run_command([tools['aapt2'],'dump','badging',artifact],logs,f'final-metadata-{index}',args.timeout)
            if metadata((logs/f'final-metadata-{index}.stdout.txt').read_text(encoding='utf-8',errors='replace'))!={k:v for k,v in info.items() if k!='effective_min_sdk'}:raise ValueError('Package metadata changed unexpectedly')
            if sha256(original)!=row['sha256']:raise ValueError('Original changed during rebuild')
            report['apks'].append(dict(index=index,source_member=row.get('source_member'),metadata=info,artifact=artifact.name,sha256=sha256(artifact),dex_count=len(mapping),dex_opcode_versions={n:dict(version=v[0],assembler_api=v[1]) for n,v in opcodes.items()},comparison=final_comparison))
        if signing and len(set(certificates))!=1:raise ValueError('APK signer mismatch')
        report.update(status='signed-set-completed' if signing else 'unsigned-set-completed',same_signer_verified=signing,certificate_sha256=certificates[0] if certificates else None,runtime_tested=False)
    except Exception as error:report['error']=str(error)
    finally:
        report['seconds']=time.monotonic()-started;write_json(output/'rebuild-summary.json',report)
    print(json.dumps({k:report[k] for k in ('status','error','same_signer_verified') if k in report}))
    return 0 if report['status'].endswith('-set-completed') else 1

if __name__=='__main__':raise SystemExit(main())
