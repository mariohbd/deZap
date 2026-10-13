"""Compare APK entry contents, not semantic behavior or publisher authenticity."""
import argparse
import hashlib
from pathlib import Path
import json
import re
import zipfile
from decompile import validate_zip, write_json

def signature_entry(name):
    upper=name.upper()
    return name in ('stamp-cert-sha256', 'META-INF/code_transparency_signed.jwt') or upper=='META-INF/MANIFEST.MF' or (upper.startswith('META-INF/') and upper.endswith(('.SF','.RSA','.DSA','.EC')))

def dex_entry(name):
    return re.fullmatch(r'classes(?:[2-9]|[1-9][0-9]+)?\.dex',name) is not None

def entries(apk):
    validate_zip(apk)
    with zipfile.ZipFile(apk) as archive:
        return {entry.filename:hashlib.sha256(archive.read(entry)).hexdigest() for entry in archive.infolist() if not entry.is_dir() and not signature_entry(entry.filename)}

def compare_apks(original, rebuilt):
    a,b=entries(original),entries(rebuilt)
    shared=a.keys() & b.keys()
    return dict(identical=sorted(n for n in shared if a[n]==b[n]),
                changed=[dict(path=n,original=a[n],rebuilt=b[n]) for n in sorted(shared) if a[n]!=b[n]],
                removed=sorted(a.keys()-b.keys()),added=sorted(b.keys()-a.keys()),
                scope='Uncompressed ZIP entry contents, known signing metadata excluded. No semantic proof.')

def assert_dex_only(comparison):
    unexpected=[r['path'] for r in comparison['changed'] if not dex_entry(r['path'])]
    if comparison['removed'] or comparison['added'] or unexpected:
        raise ValueError('Unexpected payload change: preservation check failed')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('original',type=Path);parser.add_argument('rebuilt',type=Path)
    parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args()
    result=compare_apks(args.original,args.rebuilt)
    # Exclusive creation prevents overwriting either an existing report or an APK.
    with args.report.open('x',encoding='utf-8') as stream:json.dump(result,stream,indent=2)
    print(json.dumps({key:len(result[key]) for key in ('identical','changed','removed','added')}))

if __name__=='__main__':main()
