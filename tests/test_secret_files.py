"""자격 증명 유실·불일치·파일 경합에서 값 변경을 거부하는 계약 검증."""
import base64
from concurrent.futures import ThreadPoolExecutor
import contextlib
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import secret_files as files


def encoded(data):
    return {key: base64.b64encode(value.encode()).decode() for key, value in data.items()}


class SecretFileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.path = self.root / 'password'
        self.password = 'v2-synthetic-private-value'
        self.secret = encoded({'password': self.password})

    def tearDown(self):
        self.temporary.cleanup()

    def create(self, path=None, value=None):
        files.create_private(path or self.path, (value or self.password).encode())

    def test_preflight_is_read_only_and_new_commit_is_0600_without_rotation(self):
        plan = files.preflight_password(self.path, None, ['password'])
        self.assertFalse(self.path.exists())
        self.assertNotIn(plan.string_data['password'], repr(plan))
        files.commit_password(plan)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(files.read_private(self.path).decode().strip(), plan.string_data['password'])
        with self.assertRaises(files.SecretFileError):
            files.commit_password(plan)
        inode = self.path.stat().st_ino
        new_plan = files.preflight_password(self.path, encoded(plan.string_data), ['password'])
        files.commit_password(new_plan)
        self.assertEqual(self.path.stat().st_ino, inode)
        self.assertEqual(new_plan.string_data, plan.string_data)

    def test_existing_secret_missing_file_is_refused_without_file_or_value_output(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            with self.assertRaises(files.SecretFileError) as error:
                files.preflight_password(self.path, self.secret, ['password'])
        self.assertFalse(self.path.exists())
        self.assertEqual(output.getvalue(), '')
        self.assertNotIn(self.password, str(error.exception))
        with self.assertRaises(files.SecretFileError):
            files.preflight_password(self.path, {}, ['password'])

    def test_existing_mismatch_or_fields_are_refused_without_modification(self):
        self.create()
        original = self.path.read_bytes()
        for secret in (encoded({'password': 'different'}), encoded({'other': self.password}),
                       encoded({'password': self.password, 'extra': 'value'}), {'password': 'not base64!'}):
            with self.subTest(secret_keys=tuple(secret)):
                with self.assertRaises(files.SecretFileError) as error:
                    files.preflight_password(self.path, secret, ['password'])
                self.assertNotIn(self.password, str(error.exception))
                self.assertEqual(self.path.read_bytes(), original)

    def test_portal_and_grafana_field_mapping(self):
        self.create()
        portal_keys = ['FILE_MANAGER_ACCESS_PASSWORD', 'ADMIN_STATUS_PASSWORD', 'PORTFOLIO_ADMIN_PASSWORD', 'DELETE_PASSWORD']
        portal = files.preflight_password(self.path, encoded(dict.fromkeys(portal_keys, self.password)), portal_keys)
        self.assertEqual(portal.string_data, dict.fromkeys(portal_keys, self.password))
        grafana = {'admin-user': 'admin', 'admin-password': self.password}
        plan = files.preflight_password(self.path, encoded(grafana), ['admin-password'], {'admin-user': 'admin'})
        self.assertEqual(plan.string_data, grafana)
        with self.assertRaises(files.SecretFileError):
            files.preflight_password(self.path, encoded(grafana | {'admin-user': 'other'}), ['admin-password'], {'admin-user': 'admin'})

    def test_file_only_bootstrap_preserves_value_and_bytes(self):
        self.create(value=self.password + '\n')
        before = self.path.stat()
        plan = files.preflight_password(self.path, None, ['password'])
        files.commit_password(plan)
        self.assertEqual(plan.string_data['password'], self.password)
        self.assertEqual(self.path.read_bytes(), (self.password + '\n').encode())
        self.assertEqual(self.path.stat().st_ino, before.st_ino)

    def test_symlink_hardlink_fifo_directory_and_exposed_modes_are_rejected(self):
        target = self.root / 'target'
        self.create(path=target)
        self.path.symlink_to(target)
        with self.assertRaises(files.SecretFileError):
            files.preflight_password(self.path, None, ['password'])
        with self.assertRaises(files.SecretFileError):
            files.create_private(self.path, b'other')
        self.assertEqual(files.read_private(target), self.password.encode())
        self.path.unlink()
        os.link(target, self.path)
        with self.assertRaises(files.SecretFileError):
            files.read_private(self.path)
        self.path.unlink()
        os.mkfifo(self.path, 0o600)
        with self.assertRaises(files.SecretFileError):
            files.read_private(self.path)
        self.path.unlink()
        self.path.mkdir()
        with self.assertRaises(files.SecretFileError):
            files.read_private(self.path)
        self.path.rmdir()
        self.create()
        for mode in (0o644, 0o640, 0o400, 0o700):
            self.path.chmod(mode)
            with self.assertRaises(files.SecretFileError):
                files.preflight_password(self.path, None, ['password'])
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), mode)

    def test_foreign_owner_is_rejected_using_fstat_evidence(self):
        self.create()
        original = os.fstat
        def foreign_file(descriptor):
            result = original(descriptor)
            if stat.S_ISREG(result.st_mode):
                values = list(result)
                values[4] = result.st_uid + 1
                return os.stat_result(values)
            return result
        with patch.object(files.os, 'fstat', side_effect=foreign_file):
            with self.assertRaises(files.SecretFileError):
                files.read_private(self.path)

    def test_parent_symlink_or_writable_directory_is_rejected(self):
        parent = self.root / 'parent'
        parent.mkdir(mode=0o700)
        link = self.root / 'link'
        link.symlink_to(parent, target_is_directory=True)
        with self.assertRaises(files.SecretFileError):
            files.preflight_password(link / 'password', None, ['password'])
        parent.chmod(0o777)
        with self.assertRaises(files.SecretFileError):
            files.preflight_password(parent / 'password', None, ['password'])

    def test_full_preflight_failure_does_not_create_earlier_file(self):
        files.preflight_password(self.path, None, ['password'])
        with self.assertRaises(files.SecretFileError):
            files.preflight_password(self.root / 'lost', self.secret, ['password'])
        self.assertEqual(list(self.root.iterdir()), [])

    def test_two_new_plans_race_has_one_exclusive_winner(self):
        plans = [files.preflight_password(self.path, None, ['password']) for _ in range(2)]
        barrier = threading.Barrier(2)
        def commit(plan):
            barrier.wait()
            try:
                files.commit_password(plan)
                return plan.string_data['password']
            except files.SecretFileError:
                return None
        with ThreadPoolExecutor(max_workers=2) as pool:
            result = list(pool.map(commit, plans))
        winners = [value for value in result if value]
        self.assertEqual(len(winners), 1)
        self.assertEqual(files.read_private(self.path).decode().strip(), winners[0])

    def test_changes_after_preflight_are_refused(self):
        for change in ('replace', 'content', 'mode', 'delete', 'symlink'):
            with self.subTest(change=change):
                if self.path.exists() or self.path.is_symlink():
                    self.path.unlink()
                self.create()
                plan = files.preflight_password(self.path, self.secret, ['password'])
                if change == 'replace':
                    self.path.unlink()
                    self.create()
                elif change == 'content':
                    self.path.write_bytes(b'different')
                elif change == 'mode':
                    self.path.chmod(0o644)
                elif change == 'delete':
                    self.path.unlink()
                else:
                    self.path.unlink()
                    self.path.symlink_to(self.root / 'missing')
                with self.assertRaises(files.SecretFileError):
                    files.commit_password(plan)

    def test_parent_directory_replacement_after_preflight_is_refused(self):
        parent = self.root / 'credentials'
        parent.mkdir(mode=0o700)
        plan = files.preflight_password(parent / 'password', None, ['password'])
        parent.rename(self.root / 'old-credentials')
        parent.mkdir(mode=0o700)
        with self.assertRaises(files.SecretFileError):
            files.commit_password(plan)
        self.assertEqual(list(parent.iterdir()), [])

    def test_private_document_create_replace_and_unsafe_existing_refusal(self):
        files.replace_private(self.path, b'first synthetic document')
        self.assertEqual(files.read_private(self.path), b'first synthetic document')
        files.replace_private(self.path, b'second synthetic document')
        self.assertEqual(files.read_private(self.path), b'second synthetic document')
        self.assertEqual(list(self.root.iterdir()), [self.path])
        self.path.chmod(0o644)
        with self.assertRaises(files.SecretFileError):
            files.replace_private(self.path, b'forbidden')
        self.assertEqual(self.path.read_bytes(), b'second synthetic document')

    def test_failed_new_write_removes_only_its_partial_file(self):
        with patch.object(files.os, 'write', side_effect=OSError('synthetic write failure')):
            with self.assertRaises(files.SecretFileError):
                files.create_private(self.path, b'synthetic')
        self.assertFalse(self.path.exists())


if __name__ == '__main__':
    unittest.main()
