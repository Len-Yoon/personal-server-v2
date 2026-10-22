"""V2 로컬 자격 증명의 사전 검사와 0600 파일 취급. 값은 오류/repr에 넣지 않음."""
import base64
from dataclasses import dataclass, field
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import stat
from typing import Mapping, Sequence


class SecretFileError(RuntimeError):
    """값을 노출하지 않는 자격 증명 검사 오류."""


@dataclass(frozen=True)
class _Snapshot:
    device: int
    inode: int
    ctime_ns: int
    digest: str


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _directory(path):
    path = Path(path).absolute()
    try:
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
            os.close(descriptor)
            raise SecretFileError('자격 증명 디렉터리 소유 또는 쓰기 권한 불일치')
        return path, descriptor, (info.st_dev, info.st_ino)
    except OSError:
        raise SecretFileError('자격 증명 디렉터리를 안전하게 열 수 없음') from None


def _read(descriptor, name):
    handle = None
    try:
        # FIFO/device도 open에서 대기하거나 부수 효과를 만들지 않도록 먼저 검사함.
        before = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode):
            raise SecretFileError('자격 증명은 symlink가 아닌 일반 파일이어야 함')
        handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        info = os.fstat(handle)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise SecretFileError('자격 증명은 단일 일반 파일이어야 함')
        if (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino):
            raise SecretFileError('자격 증명 파일이 검사 중 변경됨')
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise SecretFileError('자격 증명 파일 소유 또는 0600 권한 불일치')
        if info.st_size > 1024 * 1024:
            raise SecretFileError('자격 증명 파일 크기 제한 초과')
        chunks = []
        remaining = 1024 * 1024 + 1
        while remaining:
            chunk = os.read(handle, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b''.join(chunks)
        after = os.fstat(handle)
        if len(data) > 1024 * 1024 or (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise SecretFileError('자격 증명 파일이 검사 중 변경됨')
        return data, _Snapshot(info.st_dev, info.st_ino, info.st_ctime_ns, _digest(data))
    except FileNotFoundError:
        raise
    except OSError:
        raise SecretFileError('자격 증명 파일을 안전하게 읽을 수 없음') from None
    finally:
        if handle is not None:
            os.close(handle)


def read_private(path: Path) -> bytes:
    """0600·현재 사용자·일반 파일을 검사하고 원본 bytes를 반환함."""
    path, descriptor, _ = _directory(path)
    try:
        try:
            return _read(descriptor, path.name)[0]
        except FileNotFoundError:
            raise SecretFileError('자격 증명 파일 없음') from None
    finally:
        os.close(descriptor)


def _create(descriptor, name, data):
    handle = None
    identity = None
    complete = False
    try:
        handle = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=descriptor)
        info = os.fstat(handle)
        identity = (info.st_dev, info.st_ino)
        # umask에 관계없이 파일 생성 시점부터 최대0600이며 정확0600으로 고정함.
        os.fchmod(handle, 0o600)
        view = memoryview(data)
        while view:
            written = os.write(handle, view)
            if written <= 0:
                raise SecretFileError('자격 증명 파일 쓰기 실패')
            view = view[written:]
        os.fsync(handle)
        complete = True
        return identity
    except FileExistsError:
        raise SecretFileError('자격 증명 파일이 이미 존재하거나 생성 경합 발생') from None
    except OSError:
        raise SecretFileError('자격 증명 파일 생성 실패') from None
    finally:
        if handle is not None:
            os.close(handle)
        if not complete and identity is not None:
            try:
                current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if (current.st_dev, current.st_ino) == identity:
                    os.unlink(name, dir_fd=descriptor)
            except OSError:
                pass  # 다른 inode를 삭제하거나 원래 실패를 감추지 않음.


def create_private(path: Path, data: bytes) -> None:
    """기존 경로를 덮어쓰지 않고 0600으로 배타 생성함."""
    path, descriptor, _ = _directory(path)
    try:
        _create(descriptor, path.name, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def replace_private(path: Path, data: bytes) -> None:
    """로그인 안내 등 재작성 가능한 문서용. 기존 암호 회전 용도로 사용하지 않음.

    기존 파일을 안전하게 검사한 뒤 같은 디렉터리의0600 임시 파일을 rename함.
    현재 사용자 자체의 악의적 동시 경로 변경을 막는 OS 보안 경계는 아님.
    """
    path, descriptor, _ = _directory(path)
    temporary = '.v2-private-' + secrets.token_hex(16)
    created = False
    try:
        try:
            _, original = _read(descriptor, path.name)
        except FileNotFoundError:
            _create(descriptor, path.name, data)
            os.fsync(descriptor)
            return
        _create(descriptor, temporary, data)
        created = True
        _, current = _read(descriptor, path.name)
        if current != original:
            raise SecretFileError('자격 증명 파일이 검사 후 변경됨')
        os.replace(temporary, path.name, src_dir_fd=descriptor, dst_dir_fd=descriptor)
        created = False
        os.fsync(descriptor)
    except FileNotFoundError:
        raise SecretFileError('자격 증명 파일이 검사 후 유실됨') from None
    except OSError:
        raise SecretFileError('자격 증명 파일 교체 실패') from None
    finally:
        if created:
            os.unlink(temporary, dir_fd=descriptor)
        os.close(descriptor)


@dataclass(frozen=True)
class PasswordPlan:
    path: Path
    _parent_identity: tuple = field(repr=False)
    _snapshot: _Snapshot | None = field(repr=False)
    _password: str = field(repr=False)
    _password_keys: tuple = field(repr=False)
    _constants: tuple = field(repr=False)

    @property
    def string_data(self) -> dict[str, str]:
        """Kubernetes 적용 인자 전용. 출력/로그에 기록하지 않아야 함."""
        return dict(self._constants) | {key: self._password for key in self._password_keys}


def preflight_password(path: Path, existing_data: Mapping[str, str] | None,
                       password_keys: Sequence[str], constants: Mapping[str, str] | None = None) -> PasswordPlan:
    """파일을 쓰지 않고 기존 Secret과 일치를 검사함. data는 K8s base64 형식임.

    Secret 부재는 None, 존재하는 빈 Secret은 {}로 구분해야 함.
    모든 plan의 검사 성공 뒤 commit_password를 실행해야 함.
    """
    keys, constants = tuple(password_keys), dict(constants or {})
    if not keys or len(set(keys)) != len(keys) or set(keys) & set(constants):
        raise SecretFileError('자격 증명 필드 계약 불일치')
    path, descriptor, parent_identity = _directory(path)
    try:
        try:
            raw, snapshot = _read(descriptor, path.name)
        except FileNotFoundError:
            if existing_data is not None:
                raise SecretFileError('기존 Secret이 있으나 로컬 자격 증명 파일 유실: 자동 발급 거부') from None
            snapshot, password = None, secrets.token_urlsafe(24)
        else:
            try:
                password = raw.decode('utf-8').strip()
            except UnicodeError:
                raise SecretFileError('자격 증명 파일 형식 불일치') from None
            if not password or '\x00' in password:
                raise SecretFileError('자격 증명 파일 형식 불일치')
        expected = constants | {key: password for key in keys}
        if existing_data is not None:
            if set(existing_data) != set(expected):
                raise SecretFileError('기존 Secret 필드 불일치: 자동 변경 거부')
            for key, value in expected.items():
                try:
                    actual = base64.b64decode(existing_data[key], validate=True)
                except (ValueError, TypeError):
                    raise SecretFileError('기존 Secret 인코딩 불일치') from None
                if not hmac.compare_digest(_digest(actual), _digest(value.encode('utf-8'))):
                    raise SecretFileError('기존 Secret과 로컬 자격 증명 불일치: 자동 변경 거부')
        return PasswordPlan(path, parent_identity, snapshot, password, keys, tuple(constants.items()))
    finally:
        os.close(descriptor)


def commit_password(plan: PasswordPlan) -> None:
    """사전 검사한 동일 파일을 보존하거나 신규 파일만 배타 생성함. 회전하지 않음."""
    path, descriptor, parent_identity = _directory(plan.path)
    try:
        if parent_identity != plan._parent_identity:
            raise SecretFileError('자격 증명 디렉터리가 검사 후 변경됨')
        if plan._snapshot is None:
            _create(descriptor, path.name, (plan._password + '\n').encode('utf-8'))
            os.fsync(descriptor)
        else:
            try:
                _, current = _read(descriptor, path.name)
            except FileNotFoundError:
                raise SecretFileError('자격 증명 파일이 검사 후 유실됨') from None
            if current != plan._snapshot:
                raise SecretFileError('자격 증명 파일이 검사 후 변경됨')
    finally:
        os.close(descriptor)
