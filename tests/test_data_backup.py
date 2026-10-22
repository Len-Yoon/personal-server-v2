"""DB 백업의 원자 게시·동시 실행·손상 거부·빈 대상 복구 경계."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1] / 'tools/data_backup/backup.py'
spec = importlib.util.spec_from_file_location('data_backup', MODULE)
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = backup.database_env('backup', {'PGHOST': 'postgres', 'PGDATABASE': 'notes', 'PGUSER': 'notes_backup'})
        self.restore_env = backup.database_env('restore', {'PGHOST': 'postgres-restore', 'PGDATABASE': 'notes_restore', 'PGUSER': 'notes_owner'})

    def fake_pg(self, command, env, **kwargs):
        if command[0] == 'psql':
            return '180000'
        fd = int(command[-1].split('/')[-1])
        os.write(fd, b'PGDMP\x01test-consistent-snapshot')
        return ''

    def make_backup(self):
        with patch.object(backup, 'pg', side_effect=self.fake_pg):
            return backup.backup(self.root, self.env)

    def test_success_publishes_only_complete_checksum_archive(self):
        manifest = self.make_backup()
        found, fd = backup.checked_archive(self.root, manifest['id'])
        os.close(fd)
        self.assertEqual(found, manifest)
        self.assertLessEqual(manifest['snapshot_window_start'], manifest['completed_at'])
        self.assertEqual([x.name for x in self.root.iterdir()], [manifest['id']])
        self.assertEqual((self.root / manifest['id']).stat().st_mode & 0o777, 0o700)

    def test_dump_failure_leaves_no_published_or_partial_backup(self):
        def fail(command, env, **kwargs):
            if command[0] == 'psql':
                return '180000'
            os.write(int(command[-1].split('/')[-1]), b'partial')
            raise RuntimeError('injected failure')
        with patch.object(backup, 'pg', side_effect=fail), self.assertRaises(RuntimeError):
            backup.backup(self.root, self.env)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_checksum_damage_stops_before_any_database_command(self):
        manifest = self.make_backup()
        (self.root / manifest['id'] / 'database.dump').write_bytes(b'damaged')
        with patch.object(backup, 'pg') as pg, self.assertRaisesRegex(RuntimeError, 'checksum'):
            backup.restore(self.root, self.restore_env, manifest['id'])
        pg.assert_not_called()

    def test_nonempty_target_never_runs_pg_restore(self):
        manifest = self.make_backup()
        with patch.object(backup, 'pg', return_value='2') as pg, self.assertRaisesRegex(RuntimeError, '비어'):
            backup.restore(self.root, self.restore_env, manifest['id'])
        self.assertEqual(pg.call_count, 1)
        self.assertEqual(pg.call_args.args[0][0], 'psql')

    def test_restore_uses_atomic_transaction_and_no_owner_acl(self):
        manifest = self.make_backup()
        with patch.object(backup, 'pg', side_effect=['0', '', '']) as pg:
            result = backup.restore(self.root, self.restore_env, manifest['id'])
        command = pg.call_args_list[1].args[0]
        self.assertIn('GRANT SELECT, INSERT, UPDATE, DELETE ON public.notes TO notes_app',pg.call_args.args[0])
        self.assertEqual(command[0], 'pg_restore')
        for flag in ['--single-transaction', '--exit-on-error', '--no-owner', '--no-acl', '--dbname=notes_restore']:
            self.assertIn(flag, command)
        self.assertEqual(result['sha256'], manifest['sha256'])

    def test_retention_keeps24_successes_and_ignores_partial(self):
        ids = []
        for _ in range(26):
            ids.append(self.make_backup()['id'])
        partial = self.root / '.partial-stale'
        partial.mkdir()
        (partial / 'sentinel').write_text('untouched')
        backup.prune(self.root)
        retained = [m['id'] for m in backup.inventory(self.root)]
        self.assertEqual(retained, sorted(ids)[-24:])
        self.assertTrue((partial / 'sentinel').exists())

    def test_corrupt_candidate_stops_retention_before_deletion(self):
        manifest = self.make_backup()
        (self.root / manifest['id'] / 'database.dump').write_bytes(b'corrupt')
        with self.assertRaises(RuntimeError):
            backup.prune(self.root)
        self.assertTrue((self.root / manifest['id']).exists())

    def test_symlink_archive_and_directory_are_rejected(self):
        manifest = self.make_backup()
        directory = self.root / manifest['id']
        dump = directory / 'database.dump'
        dump.rename(directory / 'real.dump')
        dump.symlink_to('real.dump')
        with self.assertRaises(OSError):
            backup.checked_archive(self.root, manifest['id'])
        directory.rename(self.root / 'original')
        directory.symlink_to('original', target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, '디렉터리'):
            backup.checked_archive(self.root, manifest['id'])

    def test_path_traversal_and_manifest_source_change_fail_closed(self):
        with self.assertRaises(RuntimeError):
            backup.checked_archive(self.root, '../outside')
        manifest = self.make_backup()
        path = self.root / manifest['id'] / 'manifest.json'
        altered = json.loads(path.read_text())
        altered['source_database'] = 'production'
        path.write_text(json.dumps(altered))
        with self.assertRaisesRegex(RuntimeError, '계약'):
            backup.checked_archive(self.root, manifest['id'])

    def test_restore_source_endpoint_and_ambient_pgoptions_are_rejected(self):
        with self.assertRaises(RuntimeError):
            backup.database_env('restore', {'PGHOST': 'postgres', 'PGDATABASE': 'notes', 'PGUSER': 'notes_owner'})
        env = backup.database_env('backup', {'PGHOST': 'postgres', 'PGDATABASE': 'notes', 'PGUSER': 'notes_backup', 'PGOPTIONS': 'unsafe', 'PGPASSWORD': 'sensitive'})
        self.assertNotIn('PGPASSWORD', env)
        self.assertNotEqual(env['PGOPTIONS'], 'unsafe')

    def test_lock_stops_second_operation_and_rejects_unsafe_root(self):
        self.root.chmod(0o700)
        with backup.locked_root(self.root):
            with self.assertRaisesRegex(RuntimeError, '진행 중'):
                with backup.locked_root(self.root):
                    self.fail('concurrent entry')
        self.root.chmod(0o755)
        with self.assertRaises(RuntimeError):
            with backup.locked_root(self.root):
                self.fail('unsafe root')

    def test_projected_password_is_escaped_in_private_pgpass_then_deleted(self):
        password = self.root / 'projected'
        password.write_text('a:b\\c')
        source = {'PGHOST': 'postgres', 'PGDATABASE': 'notes', 'PGUSER': 'notes_backup', 'PGPASSWORD_FILE': str(password)}
        with patch.dict(os.environ, source, clear=True):
            with backup.authenticated_env('backup') as env:
                path = Path(env['PGPASSFILE'])
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(path.read_text(), 'postgres:5432:notes:notes_backup:a\\:b\\\\c\n')
                self.assertNotIn('PGPASSWORD', env)
            self.assertFalse(path.exists())


if __name__ == '__main__':
    unittest.main()
