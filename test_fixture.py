import tempfile
from pathlib import Path
import unittest
import zipfile
from build_fixture import store_resource_table


class FixturePackagingTests(unittest.TestCase):
    def test_resource_table_stored_without_payload_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.apk'
            payloads = {'resources.arsc': b'original table', 'classes.dex': b'code'}
            with zipfile.ZipFile(path, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
                for name, data in payloads.items(): archive.writestr(name, data)
            store_resource_table(path)
            with zipfile.ZipFile(path) as archive:
                self.assertEqual(archive.getinfo('resources.arsc').compress_type, zipfile.ZIP_STORED)
                self.assertEqual(archive.getinfo('classes.dex').compress_type, zipfile.ZIP_DEFLATED)
                self.assertEqual({name: archive.read(name) for name in archive.namelist()}, payloads)

    def test_existing_temporary_archive_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.apk'
            with zipfile.ZipFile(path, 'x') as archive: archive.writestr('resources.arsc', b'table')
            temporary = path.with_suffix('.stored.apk'); temporary.write_bytes(b'keep')
            original = path.read_bytes()
            with self.assertRaises(FileExistsError): store_resource_table(path)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(temporary.read_bytes(), b'keep')


if __name__ == '__main__': unittest.main()
