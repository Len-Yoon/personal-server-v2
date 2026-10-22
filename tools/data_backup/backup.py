#!/usr/bin/env python3
"""V2 메모 DB 전용 논리 백업·빈 복구 DB 복원. 인증 값과 SQL 오류는 출력하지 않음."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import uuid

ID_PATTERN = re.compile(r'^[0-9]{8}T[0-9]{12}Z-[0-9a-f]{8}$')
EMPTY_SQL = """SELECT
 (SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema') +
 (SELECT count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
   WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema') +
 (SELECT count(*) FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace
   WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema') +
 (SELECT count(*) FROM pg_catalog.pg_namespace
   WHERE nspname !~ '^pg_' AND nspname NOT IN ('public','information_schema'));"""


def now():
    return datetime.now(timezone.utc).isoformat()


def private_file(path, maximum=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or (maximum is not None and info.st_size > maximum)):
            raise RuntimeError('백업 파일 소유·권한·크기 불일치')
        return fd
    except BaseException:
        os.close(fd)
        raise


@contextmanager
def locked_root(root):
    root = Path(root)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    lock = None
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise RuntimeError('백업 디렉터리는 실행 계정 소유0700이어야 함')
        lock = os.open('.backup.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        lock_info = os.fstat(lock)
        if (not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != os.getuid()
                or stat.S_IMODE(lock_info.st_mode) != 0o600 or lock_info.st_nlink != 1):
            raise RuntimeError('백업 잠금 파일 소유·권한 불일치')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('다른 백업·복원·조회가 진행 중임') from None
        # 열린 directory FD를 사용하여 상위 경로 교체 후 다른 디렉터리에 쓰지 않음.
        yield Path('/proc/self/fd') / str(fd)
    finally:
        if lock is not None:
            os.close(lock)
        os.close(fd)


def database_env(mode, source=None):
    source = os.environ if source is None else source
    expected = ('postgres', 'notes', 'notes_backup') if mode == 'backup' else ('postgres-restore', 'notes_restore', 'notes_owner')
    if tuple(source.get(k) for k in ('PGHOST', 'PGDATABASE', 'PGUSER')) != expected or source.get('PGPORT', '5432') != '5432':
        raise RuntimeError('승인된 V2 백업/복구 DB endpoint·계정 불일치')
    return {'PATH': source.get('PATH', '/usr/local/bin:/usr/bin:/bin'), 'LANG': 'C.UTF-8',
            'PGHOST': expected[0], 'PGDATABASE': expected[1], 'PGUSER': expected[2],
            'PGPORT': '5432', 'PGCONNECT_TIMEOUT': '10', 'PGSSLMODE': 'disable',
            'PGOPTIONS': '-c statement_timeout=180000 -c lock_timeout=10000'}


@contextmanager
def authenticated_env(mode):
    env = database_env(mode)
    temp = None
    try:
        if os.environ.get('PGPASSWORD_FILE'):
            # projected Secret은 Kubernetes의 ..data symlink·0440을 사용함.
            # 이 경로는 배포 명세가 지정하며 값은 stdout·argv·PGPASSWORD로 전달하지 않음.
            with open(os.environ['PGPASSWORD_FILE'], 'rb') as secret:
                raw = secret.read(4097)
            if not raw or len(raw) > 4096 or any(x in raw for x in (b'\n', b'\r', b'\0')):
                raise RuntimeError('DB 비밀번호 파일 형식 불일치')
            password = raw.decode('utf-8').replace('\\', '\\\\').replace(':', '\\:')
            fd, temp = tempfile.mkstemp(prefix='v2-pgpass-')
            with os.fdopen(fd, 'w') as handle:
                handle.write(':'.join([env['PGHOST'], env['PGPORT'], env['PGDATABASE'], env['PGUSER'], password]) + '\n')
            env['PGPASSFILE'] = temp
        elif os.environ.get('PGPASSFILE'):
            password_fd = private_file(os.environ['PGPASSFILE'], 8192)
            os.close(password_fd)
            env['PGPASSFILE'] = os.environ['PGPASSFILE']
        else:
            raise RuntimeError('DB 비밀번호 파일이 필요함')
        yield env
    finally:
        if temp:
            Path(temp).unlink(missing_ok=True)


def pg(command, env, *, pass_fds=()):
    try:
        result = subprocess.run(command, env=env, capture_output=True, text=True,
                                timeout=240, pass_fds=pass_fds, check=False)
    except (OSError, subprocess.SubprocessError):
        raise RuntimeError('PostgreSQL 도구 실행 실패') from None
    if result.returncode:
        raise RuntimeError('PostgreSQL 작업 실패: 인증 값 보호를 위해 상세 출력 생략')
    return result.stdout.strip()


def checksum(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while data := os.read(fd, 1024 * 1024):
        digest.update(data)
    os.lseek(fd, 0, os.SEEK_SET)
    return digest.hexdigest()


def checked_archive(root, backup_id):
    if not ID_PATTERN.fullmatch(backup_id):
        raise RuntimeError('백업 ID 형식 불일치')
    directory = root / backup_id
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise RuntimeError('백업 항목 디렉터리 소유·권한 불일치')
    mfd = private_file(directory / 'manifest.json', 65536)
    try:
        with os.fdopen(mfd) as handle:
            manifest = json.load(handle)
    except (ValueError, UnicodeError):
        raise RuntimeError('백업 manifest 형식 오류') from None
    if (manifest.get('version') != 1 or manifest.get('id') != backup_id
            or manifest.get('source_database') != 'notes' or manifest.get('source_host') != 'postgres'
            or not isinstance(manifest.get('size'), int) or manifest['size'] <= 0
            or not isinstance(manifest.get('sha256'), str)
            or not re.fullmatch('[0-9a-f]{64}', manifest['sha256'])):
        raise RuntimeError('백업 manifest 계약 불일치')
    archive = private_file(directory / 'database.dump')
    try:
        if os.fstat(archive).st_size != manifest['size'] or checksum(archive) != manifest['sha256']:
            raise RuntimeError('백업 checksum/크기 불일치')
        return manifest, archive
    except BaseException:
        os.close(archive)
        raise


def inventory(root):
    items = []
    for path in sorted(root.iterdir()):
        if ID_PATTERN.fullmatch(path.name):
            manifest, fd = checked_archive(root, path.name)
            os.close(fd)
            items.append(manifest)
    return items


def prune(root, keep=24):
    if keep != 24:
        raise RuntimeError('승인된 성공 백업 보관 수는24개임')
    items = inventory(root)  # 모든 후보 검증 후에만 삭제함.
    for item in items[:-keep]:
        directory = root / item['id']
        # 승인된 두 일반 파일 외의 항목이 있으면 광역 삭제하지 않음.
        if {p.name for p in directory.iterdir()} != {'manifest.json', 'database.dump'}:
            raise RuntimeError('백업 보관 항목에 예상 밖 파일 존재')
    for item in items[:-keep]:
        directory = root / item['id']
        (directory / 'database.dump').unlink()
        (directory / 'manifest.json').unlink()
        directory.rmdir()


def backup(root, env):
    backup_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ-') + uuid.uuid4().hex[:8]
    staging = root / ('.partial-' + backup_id)
    staging.mkdir(mode=0o700)
    try:
        archive = staging / 'database.dump'
        fd = os.open(archive, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            start = now()
            version = pg(['psql', '-X', '--no-password', '-At', '-v', 'ON_ERROR_STOP=1', '-c', "SELECT current_setting('server_version_num')"], env)
            pg(['pg_dump', '--no-password', '--format=custom', '--no-owner', '--no-acl',
                '--file=/proc/self/fd/' + str(fd)], env, pass_fds=(fd,))
            os.fsync(fd)
            size = os.fstat(fd).st_size
            if size <= 0:
                raise RuntimeError('빈 백업 archive 거부')
            manifest = {'version': 1, 'id': backup_id, 'source_host': 'postgres', 'source_database': 'notes',
                'server_version_num': version, 'snapshot_window_start': start, 'completed_at': now(),
                'sha256': checksum(fd), 'size': size, 'format': 'pg_dump-custom'}
        finally:
            os.close(fd)
        manifest_fd = os.open(staging / 'manifest.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(manifest_fd, 'w') as handle:
            handle.write(json.dumps(manifest, sort_keys=True) + '\n')
            handle.flush()
            os.fsync(handle.fileno())
        dir_fd = os.open(staging, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        staging.rename(root / backup_id)
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(root_fd)
        finally:
            os.close(root_fd)
        prune(root)
        return manifest
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def restore(root, env, backup_id):
    manifest, fd = checked_archive(root, backup_id)
    try:
        count = pg(['psql', '-X', '--no-password', '-At', '-v', 'ON_ERROR_STOP=1', '-c', EMPTY_SQL], env)
        if count != '0':
            raise RuntimeError('복구 대상 DB가 비어 있지 않아 복원 거부')
        pg(['pg_restore', '--no-password', '--exit-on-error', '--single-transaction',
            '--no-owner', '--no-acl', '--dbname=' + env['PGDATABASE'], '/proc/self/fd/' + str(fd)],
            env, pass_fds=(fd,))
        pg(['psql', '-X', '--no-password', '-v', 'ON_ERROR_STOP=1', '-c', 'GRANT SELECT, INSERT, UPDATE, DELETE ON public.notes TO notes_app'], env)
        return {'backup_id': manifest['id'], 'sha256': manifest['sha256'],
                'target_database': 'notes_restore', 'restored_at': now()}
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('backup', 'restore', 'list'))
    parser.add_argument('--backup-id')
    args = parser.parse_args()
    if (args.action == 'restore') != bool(args.backup_id):
        parser.error('--backup-id는 restore에서만 필수임')
    try:
        with locked_root(os.environ.get('BACKUP_DIR', '/backups')) as root:
            if args.action == 'list':
                result = inventory(root)
            else:
                with authenticated_env(args.action) as env:
                    result = backup(root, env) if args.action == 'backup' else restore(root, env, args.backup_id)
        print(json.dumps(result, sort_keys=True))
    except (OSError, RuntimeError, ValueError, UnicodeError):
        # pgpass/Secret 및 libpq 오류 문자열을 stdout/stderr에 내보내지 않음.
        parser.exit(1, 'V2 DB 백업/복원 실패: endpoint·권한·checksum·빈 DB·도구 상태 확인 필요\n')


if __name__ == '__main__':
    main()
