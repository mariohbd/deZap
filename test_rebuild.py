import json
from pathlib import Path
import tempfile
import unittest
import zipfile
from compare import compare_apks, assert_dex_only
from rebuild import package, metadata, validate_set, smali_mapping, dex_opcode_api
from decompile import preserved_decode_inventory

class RebuildTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
    def apk(self,name,values):
        p=self.root/name
        with zipfile.ZipFile(p,'w') as z:
            for key,value in values.items():z.writestr(key,value)
        return p
    def test_dex_replacement_preserves_binary_payloads(self):
        original=self.apk('original.apk',{'classes.dex':b'old','AndroidManifest.xml':b'opaque','resources.arsc':b'table','lib/test.so':b'native','META-INF/CERT.RSA':b'signature'})
        dex=self.root/'replacement.dex';dex.write_bytes(b'new')
        result=package(original,self.root/'new.apk',{'classes.dex':dex})
        self.assertEqual([r['path'] for r in result['changed']],['classes.dex'])
        self.assertEqual(result['added'],[]);self.assertEqual(result['removed'],[])
    def test_resource_changes_rejected(self):
        a=self.apk('a.apk',{'classes.dex':b'code','resources.arsc':b'old'})
        b=self.apk('b.apk',{'classes.dex':b'code','resources.arsc':b'changed'})
        with self.assertRaises(ValueError):assert_dex_only(compare_apks(a,b))
    def test_added_removed_entries_rejected(self):
        a=self.apk('a.apk',{'classes.dex':b'code'})
        b=self.apk('b.apk',{'classes.dex':b'code','assets/extra':b'extra'})
        with self.assertRaises(ValueError):assert_dex_only(compare_apks(a,b))
    def test_existing_apk_not_overwritten(self):
        original=self.apk('a.apk',{'classes.dex':b'code'})
        with self.assertRaises(FileExistsError):package(original,original,{})
        self.assertEqual(compare_apks(original,original)['changed'],[])
    def test_base_and_split_metadata(self):
        base=metadata("package: name='example.tiny' versionCode='1' versionName='1.0'\nsdkVersion:'23'\n")
        split=metadata("package: name='example.tiny' versionCode='1' versionName='1.0' split='config.en'\nsdkVersion:'23'\n")
        validate_set([base,split])
        self.assertEqual(metadata("package: name='example.tiny' versionCode='1'\nminSdkVersion:'23'\n")['min_sdk'],23)
        with self.assertRaises(ValueError):validate_set([base,base])
        with self.assertRaises(ValueError):validate_set([base,{**split,'version_code':'2'}])
        with self.assertRaises(ValueError):validate_set([base,split,split])
    def test_missing_smali_partition_rejected(self):
        decoded=self.root/'decoded';decoded.mkdir();(decoded/'smali').mkdir()
        with self.assertRaises(ValueError):smali_mapping(decoded,['classes.dex','classes2.dex'])
        (decoded/'smali_classes2').mkdir()
        self.assertEqual(set(smali_mapping(decoded,['classes.dex','classes2.dex'])),{'classes.dex','classes2.dex'})
    def test_resource_inventory_detects_edits(self):
        p=self.root/'decoded';p.mkdir();(p/'res').mkdir();(p/'res/example.xml').write_text('original')
        before=preserved_decode_inventory(p)
        (p/'res/example.xml').write_text('edited')
        self.assertNotEqual(before,preserved_decode_inventory(p))
    def test_unknown_sdk_rejected(self):
        with self.assertRaises(ValueError):metadata("package: name='example' versionCode='1'\nsdkVersion:'Preview'\n")
    def test_split_inherits_base_sdk(self):
        base=metadata("package: name='example' versionCode='1'\nsdkVersion:'23'\n")
        split=metadata("package: name='example' versionCode='1' split='config.en'\n")
        validate_set([base,split])
        self.assertEqual(split['effective_min_sdk'],23)
    def test_opcodes_follow_dex_version_not_sdk_floor(self):
        self.assertEqual(dex_opcode_api(b'dex\n038\x00'),(38,26))
        self.assertEqual(dex_opcode_api(b'dex\n039\x00'),(39,28))
        with self.assertRaises(ValueError):dex_opcode_api(b'dex\n041\x00')

if __name__=='__main__':unittest.main()
