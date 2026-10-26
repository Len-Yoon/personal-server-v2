"""V2 ARM64 이미지 등록·검증 후 데이터 명세를 일괄 갱신함."""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import urllib.request

import lab

BASES = {
    'api': 'python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70',
    'postgres': 'postgres:17-bookworm@sha256:858bb5e98eed02eb8cafbcdc007f9a65d1b613972028944a8ec2133ccaf80d27',
}
SOURCES = {'api': ('apps/notes-api',), 'postgres': ('tools/data_image', 'tools/data_backup')}
REPOSITORIES = {'api': 'v2-notes-api', 'postgres': 'v2-data-postgres'}


def source_hash(kind):
    h = hashlib.sha256()
    for directory in SOURCES[kind]:
        for path in sorted((lab.ROOT / directory).rglob('*')):
            if '__pycache__' in path.parts:
                continue
            if path.is_symlink():
                raise RuntimeError('이미지 소스 symlink 거부')
            if path.is_file():
                h.update(str(path.relative_to(lab.ROOT)).encode() + b'\0' + path.read_bytes())
    return h.hexdigest()


def manifest_updates(previous, images):
    prepared = {}
    for environment in ('dev', 'restore', 'policies'):
        path = lab.ROOT / 'platforms/data' / environment / 'resources.yaml'
        if path.is_symlink():
            raise RuntimeError('명세 symlink 거부')
        content = path.read_text()
        for kind in ('api', 'postgres'):
            old = previous[kind]['image']
            if old not in content:
                raise RuntimeError('데이터 이미지 명세/lock 불일치')
            content = content.replace(old, images[kind]['image'])
        prepared[path] = content.encode()
    return prepared


def write_transaction(prepared, expected=None):
    """프로세스 내 실패 시 원본으로 복귀함. 강제 종료의 다중 파일 원자성은 보장하지 않음."""
    original = {path: path.read_bytes() for path in prepared}
    if expected is not None and original != expected:
        raise RuntimeError('빌드 중 데이터 명세 변경 감지')
    changed = {p: value for p, value in prepared.items() if value != original[p]}
    stages, backups, replaced = {}, {}, []
    def stage(path, data):
        fd, name = tempfile.mkstemp(prefix='.v2-release-', dir=path.parent)
        try:
            os.fchmod(fd, stat.S_IMODE(path.stat().st_mode))
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            os.unlink(name)
            raise
        return name
    try:
        for path, value in changed.items():
            stages[path] = stage(path, value)
            backups[path] = stage(path, original[path])
        if any(p.read_bytes() != original[p] for p in prepared):
            raise RuntimeError('명세 저장 직전 변경 감지')
        for path in changed:
            os.replace(stages[path], path)
            replaced.append(path)
    except BaseException:
        for path in reversed(replaced):
            os.replace(backups[path], path)
        raise
    finally:
        for name in [*stages.values(), *backups.values()]:
            if os.path.exists(name):
                os.unlink(name)
    return bool(changed)


def update_manifests(previous, images):
    # 기존 호출 계약을 유지하고 전체 명세를 검증한 다음 저장함.
    return write_transaction(manifest_updates(previous, images))


@contextlib.contextmanager
def release_lock():
    lab.LOCAL.mkdir(mode=0o700, exist_ok=True)
    if lab.LOCAL.is_symlink():
        raise RuntimeError('로컬 작업 디렉터리 symlink 거부')
    fd = os.open(lab.LOCAL / 'data-release.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise RuntimeError('배포 준비 잠금 파일 불일치')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('다른 데이터 배포 준비 실행 중') from None
        yield
    finally:
        os.close(fd)


def verify_image(kind, image):
    repository = 'localhost:5001/' + REPOSITORIES[kind]
    if not re.fullmatch(re.escape(repository) + r'@sha256:[0-9a-f]{64}', image):
        raise RuntimeError('V2 registry digest 경계 불일치')
    inspected = json.loads(lab.docker('image', 'inspect', image))[0]
    if inspected.get('Architecture') != 'arm64' or inspected.get('Os') != 'linux' or image not in inspected.get('RepoDigests', []):
        raise RuntimeError('ARM64 이미지/digest 불일치')
    digest = image.split('@')[1]
    # 프록시 환경에 위임하지 않고 고정 loopback registry의 실제 manifest를 대조함.
    request = urllib.request.Request('http://127.0.0.1:5001/v2/' + REPOSITORIES[kind] + '/manifests/' + digest,
        headers={'Accept': 'application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=10) as response:
        payload = response.read(1024 * 1024 + 1)
        if len(payload) > 1024 * 1024 or 'sha256:' + hashlib.sha256(payload).hexdigest() != digest:
            raise RuntimeError('registry manifest digest 불일치')


def build_images(previous, hashes):
    images = {}
    for kind in ('api', 'postgres'):
        old = previous[kind]
        if old.get('source_sha256') == hashes[kind] and old.get('base') == BASES[kind]:
            verify_image(kind, old['image'])
            images[kind] = dict(old)
            continue
        tag = 'localhost:5001/' + REPOSITORIES[kind] + ':' + hashes[kind][:16]
        dockerfile, context = ('apps/notes-api/Dockerfile', 'apps/notes-api') if kind == 'api' else ('tools/data_image/Dockerfile', '.')
        lab.docker('build', '--platform', 'linux/arm64', '--build-arg', ('PYTHON_BASE' if kind == 'api' else 'POSTGRES_BASE') + '=' + BASES[kind], '-f', dockerfile, '-t', tag, context, capture=False)
        lab.docker('push', tag, capture=False)
        inspected = json.loads(lab.docker('image', 'inspect', tag))[0]
        prefix = 'localhost:5001/' + REPOSITORIES[kind] + '@sha256:'
        candidates = [d for d in inspected.get('RepoDigests', []) if d.startswith(prefix)]
        if len(candidates) != 1:
            raise RuntimeError('유일한 registry 이미지 digest 필요')
        image = candidates[0]
        verify_image(kind, image)
        images[kind] = {'image': image, 'base': BASES[kind], 'source_sha256': hashes[kind], 'architecture': 'arm64'}
    return images


def prepare(run_tests=None):
    lab.guard()
    with release_lock():
        lockfile = lab.ROOT / 'platforms/data/images.lock.json'
        if lockfile.is_symlink():
            raise RuntimeError('이미지 lock symlink 거부')
        previous = json.loads(lockfile.read_text())
        prepared = manifest_updates(previous, previous)
        prepared[lockfile] = lockfile.read_bytes()
        original = dict(prepared)
        hashes = {kind: source_hash(kind) for kind in SOURCES}
        if run_tests is not None:
            run_tests()
        if hashes != {kind: source_hash(kind) for kind in SOURCES}:
            raise RuntimeError('테스트 중 이미지 소스 변경 감지')
        images = build_images(previous, hashes)
        if hashes != {kind: source_hash(kind) for kind in SOURCES}:
            raise RuntimeError('빌드 중 이미지 소스 변경 감지')
        prepared = manifest_updates(previous, images)
        prepared[lockfile] = (json.dumps(images, indent=2) + '\n').encode()
        changed = write_transaction(prepared, expected=original)
    print('V2 data 배포 준비 PASS (' + ('명세 갱신' if changed else '변경 없음') + ', 자동 commit·push·배포 없음)')
    return images


def main():
    prepare()


if __name__ == '__main__':
    main()
