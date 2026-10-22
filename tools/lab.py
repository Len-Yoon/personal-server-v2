#!/usr/bin/env python3
"""V2 로컬 실습 전용 제어 도구. 운영 context/호스트를 입력받지 않음."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / '.local'
STATE = LOCAL / 'state.json'
JOURNAL = LOCAL / 'creation.json'
KUBE = LOCAL / 'kubeconfig'
CONTEXT = 'k3d-ps-v2'
OWNER = 'lab.personal-server-v2/owner'
VALUE = 'personal-server-v2'
REPO = 'ssh://git@github.com/Len-Yoon/personal-server-v2.git'
SOURCE = '23572de06038341fc2ed11714cccde04e9967080'
MISSING_IMAGE = 'localhost:5001/v2-book@sha256:' + '0' * 64
REGISTRY = 'registry:2.8.3'  # dependencies.json의 digest로 실행
ENVIRONMENTS = {'dev': 'v2-dev', 'verify': 'v2-verify'}
APPLICATIONS = {
    'dev': ('book-dev', 'book-dev', 'apps/book/overlays/dev', 'v2-dev', ['deployment/book']),
    'verify': ('book-verify', 'book-verify', 'apps/book/overlays/verify', 'v2-verify', ['deployment/book']),
    **{f'{app}-{env}': (f'{app}-{env}', f'{app}-{env}', f'apps/{app}/overlays/{env}', ns, [f'deployment/{app}'])
       for app in ('youtube', 'portal') for env, ns in ENVIRONMENTS.items()},
    'root': ('v2-root', 'v2-root', 'platforms/gitops/root', 'argocd', []),
    'argocd': ('argocd-self', 'argocd-platform', 'platforms/argocd/chart', 'argocd',
               ['deployment/argocd-server', 'deployment/argocd-repo-server', 'deployment/argocd-redis', 'statefulset/argocd-application-controller']),
    'prometheus': ('prometheus', 'observability', 'platforms/observability/prometheus/chart', 'v2-observability', ['deployment/prometheus', 'deployment/prometheus-kube-state-metrics']),
    'grafana': ('grafana', 'observability', 'platforms/observability/grafana/chart', 'v2-observability', ['deployment/grafana']),
    'loki': ('loki', 'logging', 'platforms/observability/logging/loki', 'v2-observability', ['statefulset/loki']),
    'alloy': ('alloy', 'logging', 'platforms/observability/logging/alloy', 'v2-observability', ['deployment/alloy']),
    'tempo': ('tempo', 'logging', 'platforms/observability/tracing/tempo', 'v2-observability', ['statefulset/tempo']),
    'security': ('security', 'security', 'platforms/security/policies', 'v2-dev', []),
    'blackbox': ('blackbox', 'observability', 'platforms/observability/blackbox', 'v2-observability', ['deployment/blackbox']),
}


def run(args, *, stdin=None, capture=True, check=True):
    env = os.environ.copy()
    for key in list(env):
        if key.startswith('HELM_KUBE') or key in ('KUBECONFIG', 'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH'):
            env.pop(key, None)
    env['DOCKER_CONTEXT'] = 'orbstack'
    env['PATH'] = str(ROOT / '.tools/bin') + os.pathsep + env.get('PATH', '')
    result = subprocess.run([str(x) for x in args], input=stdin, text=True,
                            capture_output=capture, env=env, cwd=ROOT)
    if check and result.returncode:
        # Secret이 stdin/stdout에 있을 수 있어 command 출력과 stdout은 예외에 넣지 않음.
        detail = result.stderr if capture else '화면 출력 참조'
        if stdin and '"kind": "Secret"' in stdin:
            detail = 'Secret 입력을 포함한 오류 상세는 비밀값 보호를 위해 출력하지 않음'
        raise RuntimeError(f'{args[0]} 실패 (exit {result.returncode}): {detail}')
    return result.stdout if capture else result.returncode


def docker(*args, **kwargs):
    endpoint = run(['docker', 'context', 'inspect', 'orbstack', '--format', '{{.Endpoints.docker.Host}}']).strip()
    expected = f'unix://{Path.home()}/.orbstack/run/docker.sock'
    if endpoint != expected:
        raise RuntimeError('OrbStack 로컬 소켓 불일치. 실행 거부')
    return run(['docker', '--context', 'orbstack', *args], **kwargs)


def k(*args, **kwargs):
    return run(['kubectl', '--kubeconfig', KUBE, '--context', CONTEXT, '--request-timeout=20s', *args], **kwargs)


def save(state):
    LOCAL.mkdir(exist_ok=True, mode=0o700)
    STATE.write_text(json.dumps(state, indent=2) + '\n')
    STATE.chmod(0o600)


def journal_write(data):
    JOURNAL.write_text(json.dumps(data, indent=2) + '\n')
    JOURNAL.chmod(0o600)


def volume_identity(name):
    obj = json.loads(docker('volume', 'inspect', name))[0]
    return {key: obj.get(key) for key in ('Name', 'CreatedAt', 'Driver', 'Mountpoint', 'Labels', 'Options')}


def record_created(data):
    names = set(docker('ps', '-a', '--format', '{{.Names}}').splitlines())
    for name in ('ps-v2-registry', 'k3d-ps-v2-server-0', 'k3d-ps-v2-agent-0', 'k3d-ps-v2-agent-1', 'k3d-ps-v2-serverlb'):
        if name not in names:
            continue
        obj = container_owned(name)
        if obj['Config']['Labels'].get('lab.personal-server-v2/run') != data['run']:
            raise RuntimeError('생성 journal과 컨테이너 실행 표식 불일치')
        if name in data['containers'] and data['containers'][name] != obj['Id']:
            raise RuntimeError('생성 중 컨테이너 교체 감지')
        data['containers'][name] = obj['Id']
        for mount in obj.get('Mounts', []):
            if mount['Type'] == 'volume':
                identity = volume_identity(mount['Name'])
                if mount['Name'] in data['volumes'] and data['volumes'][mount['Name']] != identity:
                    raise RuntimeError('생성 중 볼륨 교체 감지')
                data['volumes'][mount['Name']] = identity
    journal_write(data)


def cleanup_resources(data):
    # k3d 이름/label selector에 삭제를 위임하지 않고 검증한 ID만 삭제함.
    current = set(docker('ps', '-a', '--format', '{{.Names}}').splitlines())
    for name, identity in data['containers'].items():
        if name in current and container_owned(name)['Id'] != identity:
            raise RuntimeError('삭제 전 컨테이너 교체 감지')
    network_names = docker('network', 'ls', '--format', '{{.Name}}').splitlines()
    if data.get('network') and 'ps-v2' in network_names:
        network = json.loads(docker('network', 'inspect', 'ps-v2'))[0]
        if network['Id'] != data['network'] or not set(network.get('Containers', {})) <= set(data['containers'].values()):
            raise RuntimeError('네트워크 ID 불일치 또는 타 소유 컨테이너 연결됨')
    volumes = set(docker('volume', 'ls', '--format', '{{.Name}}').splitlines())
    for name, identity in data['volumes'].items():
        if name in volumes and volume_identity(name) != identity:
            raise RuntimeError('삭제 전 볼륨 교체 감지')
        if name in volumes:
            users = set(docker('ps', '-a', '--filter', 'volume=' + name, '--no-trunc', '--format', '{{.ID}}').splitlines())
            if not users <= set(data['containers'].values()):
                raise RuntimeError('타 소유 컨테이너가 볼륨 사용 중')
    for name, identity in data['containers'].items():
        if name in current:
            docker('rm', '-f', identity)
    for name in data['volumes']:
        if name in volumes:
            docker('volume', 'rm', name)
    if data.get('network') and 'ps-v2' in network_names:
        docker('network', 'rm', data['network'])


def kube_config_valid(config):
    contexts = config.get('contexts', [])
    clusters = config.get('clusters', [])
    users = config.get('users', [])
    if len(contexts) != 1 or len(clusters) != 1 or len(users) != 1:
        return False
    ctx, cluster, user = contexts[0], clusters[0], users[0]
    return (ctx['name'] == CONTEXT and ctx['context']['cluster'] == cluster['name']
            and ctx['context']['user'] == user['name']
            and cluster['cluster'].get('server') == 'https://127.0.0.1:6550'
            and bool(cluster['cluster'].get('certificate-authority-data'))
            and set(cluster['cluster']) <= {'server', 'certificate-authority-data'}
            and set(user['user']) == {'client-certificate-data', 'client-key-data'})


def container_owned(name):
    obj = json.loads(docker('inspect', name))[0]
    if obj['Config'].get('Labels', {}).get(OWNER) != VALUE:
        raise RuntimeError(f'{name}: V2 소유 표식 없음')
    return obj


def guard():
    state = json.loads(STATE.read_text())
    if state.get('owner') != VALUE or hashlib.sha256(KUBE.read_bytes()).hexdigest() != state['kube_sha256']:
        raise RuntimeError('V2 state/kubeconfig 불일치')
    config = json.loads(k('config', 'view', '--raw', '-o', 'json'))
    if not kube_config_valid(config):
        raise RuntimeError('V2 전용 인증/loopback endpoint 불일치')
    for name, identity in state['containers'].items():
        if container_owned(name)['Id'] != identity:
            raise RuntimeError(f'{name}: 기록된 컨테이너 ID 불일치')
    ns = json.loads(k('get', 'namespace', 'kube-system', '-o', 'json'))
    if ns['metadata']['uid'] != state['cluster_uid']:
        raise RuntimeError('V2 cluster UID 불일치')
    return state


def namespace_guard(namespace):
    obj = json.loads(k('get', 'namespace', namespace, '-o', 'json'))
    if obj['metadata'].get('labels', {}).get(OWNER) != VALUE:
        raise RuntimeError('V2 namespace 소유 표식 없음')


def refuse_foreign(kind, name, namespace=None):
    args = ['get', kind, name, '--ignore-not-found', '-o', 'json']
    if namespace:
        args = ['-n', namespace, *args]
    existing = k(*args).strip()
    if existing and json.loads(existing)['metadata'].get('labels', {}).get(OWNER) != VALUE:
        raise RuntimeError(f'{kind}/{name}: 기존 타 소유 자원 인수 거부')


def doctor(_):
    print(run(['kubectl', 'version', '--client', '-o', 'json']))
    print(run(['k3d', 'version']))
    print(docker('info', '--format', 'Docker {{.ServerVersion}} / {{.Architecture}} / CPUs {{.NCPU}} / Memory {{.MemTotal}}'))


def up(_):
    if STATE.exists() or KUBE.exists():
        guard()
        print('기존 V2 클러스터 소유 검증 PASS')
        return
    if JOURNAL.exists():
        raise RuntimeError('생성 기록 존재. cleanup으로 미완성 V2 자원 정리 후 재시도')
    names = docker('ps', '-a', '--format', '{{.Names}}').splitlines()
    if any(n.startswith(('k3d-ps-v2-', 'ps-v2-registry')) for n in names):
        raise RuntimeError('동일 이름 자원이 이미 존재함. 자동 인수/삭제하지 않음')
    if 'ps-v2' in docker('network', 'ls', '--format', '{{.Name}}').splitlines():
        raise RuntimeError('동일 이름 network가 이미 존재함')
    if 'k3d-ps-v2-images' in docker('volume', 'ls', '--format', '{{.Name}}').splitlines():
        raise RuntimeError('동일 이름 image volume이 이미 존재함')
    LOCAL.mkdir(exist_ok=True, mode=0o700)
    dependency = json.loads((ROOT / 'dependencies.json').read_text())
    data = {'owner': VALUE, 'run': secrets.token_hex(16), 'containers': {}, 'volumes': {}, 'network': None}
    journal_write(data)
    label = 'lab.personal-server-v2/run=' + data['run']
    data['network'] = docker('network', 'create', '--label', f'{OWNER}={VALUE}', '--label', label, 'ps-v2').strip()
    journal_write(data)
    docker('volume', 'create', '--label', f'{OWNER}={VALUE}', '--label', label, 'k3d-ps-v2-images')
    data['volumes']['k3d-ps-v2-images'] = volume_identity('k3d-ps-v2-images')
    journal_write(data)
    docker('run', '-d', '--name', 'ps-v2-registry', '--label', f'{OWNER}={VALUE}', '--label', label,
           '--network', 'ps-v2', '-p', '127.0.0.1:5001:5000', '--memory', '256m', '--cpus', '0.5', dependency['registry'])
    record_created(data)
    config_text = (ROOT / 'platforms/k3d/cluster.yaml').read_text()
    config_text = config_text.replace('    labels:\n', '    labels:\n      - label: ' + label + '\n        nodeFilters: ["server:*", "agent:*", "loadbalancer"]\n')
    (LOCAL / 'cluster.yaml').write_text(config_text)
    try:
        run(['k3d', 'cluster', 'create', '--config', LOCAL / 'cluster.yaml'], capture=False)
    finally:
        record_created(data)
    KUBE.write_text(run(['k3d', 'kubeconfig', 'get', 'ps-v2']))
    KUBE.chmod(0o600)
    config = json.loads(k('config', 'view', '--raw', '-o', 'json'))
    if not kube_config_valid(config):
        raise RuntimeError('생성된 kubeconfig 검증 실패')
    ns = json.loads(k('get', 'namespace', 'kube-system', '-o', 'json'))
    containers = {}
    for name in ('ps-v2-registry', 'k3d-ps-v2-server-0', 'k3d-ps-v2-agent-0', 'k3d-ps-v2-agent-1', 'k3d-ps-v2-serverlb'):
        containers[name] = container_owned(name)['Id']
    save({**data, 'kube_sha256': hashlib.sha256(KUBE.read_bytes()).hexdigest(),
          'cluster_uid': ns['metadata']['uid'], 'containers': containers})
    guard()
    print('V2 클러스터 생성·전용 kubeconfig·소유 검증 PASS')


def build(args):
    guard()
    source = Path(args.source).resolve()
    app = getattr(args, 'app', 'book')
    source_dir = {'book': 'book-memo', 'youtube': 'youtube-memo', 'portal': 'portal-web'}[app]
    if run(['git', '-C', source, 'rev-parse', '--verify', SOURCE]).strip() != SOURCE:
        raise RuntimeError('고정 source commit 없음')
    # git archive는 바이너리이므로 별도 호출. worktree/실데이터/미추적 파일을 읽지 않음.
    archive = subprocess.run(['git', '-C', str(source), 'archive', SOURCE, source_dir], check=True, capture_output=True).stdout
    context = Path(tempfile.mkdtemp(prefix=app + '-source-', dir=LOCAL))
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        for member in tar.getmembers():
            parts = Path(member.name).parts
            if len(parts) < 2 or parts[0] != source_dir:
                continue
            relative = Path(*parts[1:])
            if member.isdir():
                continue
            if relative.name == '.gitkeep':
                continue
            if not member.isfile() or '..' in parts or relative.is_absolute():
                raise RuntimeError('허용되지 않은 source archive 경로')
            if any(p in {'.env', 'data', '.git'} for p in relative.parts) or relative.suffix in {'.sqlite3', '.db', '.pem', '.key'}:
                raise RuntimeError('앱 source에 데이터/자격 증명 의심 파일이 포함됨')
            dest = context / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(tar.extractfile(member).read())
    from v2_source_patch import apply as apply_source_patch, apply_telemetry
    patch_record = apply_source_patch(context)
    telemetry_dir = ROOT / 'tools/telemetry'
    telemetry_files = sorted(p for p in telemetry_dir.iterdir() if p.is_file() and p.suffix in ('.py', '.txt'))
    telemetry_hash = hashlib.sha256()
    for path in telemetry_files:
        telemetry_hash.update(path.name.encode() + b'\0' + path.read_bytes())
    (context / 'app/v2_telemetry.py').write_bytes((telemetry_dir / 'v2_telemetry.py').read_bytes())
    (context / 'v2-telemetry-requirements.txt').write_bytes((telemetry_dir / 'requirements.txt').read_bytes())
    dockerfile = context / 'Dockerfile'
    dockerfile.write_text(dockerfile.read_text() + '\nUSER root\nCOPY v2-telemetry-requirements.txt /tmp/v2-telemetry-requirements.txt\nRUN pip install --no-cache-dir -r /tmp/v2-telemetry-requirements.txt && rm /tmp/v2-telemetry-requirements.txt\nUSER 10001:10001\n')
    telemetry_changed = apply_telemetry(context)
    patch_record['telemetry_sha256'] = telemetry_hash.hexdigest()
    patch_record['files'].extend(['app/v2_telemetry.py', 'v2-telemetry-requirements.txt', 'Dockerfile'])
    patch_record['files'] = sorted(set(patch_record['files'] + telemetry_changed))
    patch_record['patch_sha256'] = hashlib.sha256((patch_record['patch_sha256'] + telemetry_hash.hexdigest()).encode()).hexdigest()
    tag = f'localhost:5001/v2-{app}:{SOURCE}-v2-{patch_record["patch_sha256"][:12]}'
    docker('build', '--platform', 'linux/arm64', '--label', f'org.opencontainers.image.revision={SOURCE}', '-t', tag, str(context), capture=False)
    docker('push', tag, capture=False)
    image = json.loads(docker('image', 'inspect', tag))[0]
    if image['Architecture'] != 'arm64':
        raise RuntimeError('ARM64 image 검증 실패')
    digest = next(x for x in image['RepoDigests'] if x.startswith(f'localhost:5001/v2-{app}@sha256:'))
    for env in ENVIRONMENTS:
        run(['kubectl', 'kustomize', f'apps/{app}/overlays/' + env])
        path = ROOT / f'apps/{app}/overlays' / env / 'kustomization.yaml'
        lines = path.read_text().splitlines()
        lines = [line for line in lines if not line.strip().startswith(('newTag:', 'digest:'))]
        # images newName 뒤 digest 삽입; agent와 합의한 image key 사용
        index = next(i for i, line in enumerate(lines) if line.strip().startswith('newName:'))
        indent = lines[index][:len(lines[index]) - len(lines[index].lstrip())]
        lines.insert(index + 1, indent + 'digest: ' + digest.split('@')[1])
        path.write_text('\n'.join(lines) + '\n')
        run(['kubectl', 'kustomize', f'apps/{app}/overlays/' + env])
    (LOCAL / ('image.json' if app == 'book' else f'{app}-image.json')).write_text(json.dumps({'source': SOURCE, 'source_archive_sha256': hashlib.sha256(archive).hexdigest(), 'patch': patch_record, 'image': digest, 'architecture': 'arm64'}, indent=2) + '\n')
    print(app + ' ARM64 이미지 빌드·digest 고정 완료:', digest)


def credential_secret(namespace, name):
    """값을 읽기 전에 소유 표식·UID 확인. 존재하지 않으면 None."""
    identity = k('-n', namespace, 'get', 'secret', name, '--ignore-not-found',
                 '-o=jsonpath={.metadata.uid}{"\\n"}{.metadata.labels.lab\\.personal-server-v2/owner}').splitlines()
    if not identity or not identity[0]:
        return None
    if len(identity) != 2 or identity[1] != VALUE:
        raise RuntimeError('기존 인증 Secret 소유 불일치')
    obj = json.loads(k('-n', namespace, 'get', 'secret', name, '-o', 'json'))
    if obj['metadata']['uid'] != identity[0] or obj['metadata'].get('labels', {}).get(OWNER) != VALUE:
        raise RuntimeError('인증 Secret 조회 중 교체 감지')
    return obj


def credentials(_):
    """전체 파일·기존 Secret을 먼저 검증하고 신규 실습 자격 증명만 생성함."""
    from secret_files import preflight_password, commit_password
    guard()
    namespaces = {}
    for namespace in [*ENVIRONMENTS.values(), 'v2-observability']:
        refuse_foreign('namespace', namespace)
        namespaces[namespace] = bool(k('get', 'namespace', namespace, '--ignore-not-found', '-o', 'name').strip())
    requests = []
    for env, namespace in ENVIRONMENTS.items():
        requests.extend([(namespace, 'book-auth', LOCAL / f'{env}-password', ('password',), {}),
            (namespace, 'youtube-auth', LOCAL / f'youtube-{env}-password', ('DELETE_PASSWORD',), {}),
            (namespace, 'portal-auth', LOCAL / f'portal-{env}-password',
             ('FILE_MANAGER_ACCESS_PASSWORD', 'ADMIN_STATUS_PASSWORD', 'PORTFOLIO_ADMIN_PASSWORD', 'DELETE_PASSWORD'), {})])
    requests.append(('v2-observability', 'grafana-admin', LOCAL / 'grafana-password', ('admin-password',), {'admin-user': 'admin'}))
    prepared = []
    for namespace, name, path, keys, constants in requests:
        existing = credential_secret(namespace, name) if namespaces[namespace] else None
        plan = preflight_password(path, existing.get('data', {}) if existing else None, keys, constants)
        prepared.append((namespace, name, existing, plan))
    # 어떤 파일/Secret도 모든 사전 검증을 통과하기 전에 쓰지 않음.
    for _, _, _, plan in prepared:
        commit_password(plan)
    for namespace, exists in namespaces.items():
        if not exists:
            k('create', '-f', '-', stdin=json.dumps({'apiVersion': 'v1', 'kind': 'Namespace',
                'metadata': {'name': namespace, 'labels': {OWNER: VALUE}}}))
        namespace_guard(namespace)
    for namespace, name, existing, plan in prepared:
        current = credential_secret(namespace, name)
        if existing:
            if not current or current['metadata']['uid'] != existing['metadata']['uid'] or current.get('data') != existing.get('data'):
                raise RuntimeError('사전 검증 후 기존 인증 Secret 변경 감지')
            continue
        if current:
            raise RuntimeError('검증 후 새 인증 Secret 경합 감지')
        k('create', '-f', '-', stdin=json.dumps({'apiVersion': 'v1', 'kind': 'Secret',
            'metadata': {'name': name, 'namespace': namespace, 'labels': {OWNER: VALUE}},
            'type': 'Opaque', 'stringData': plan.string_data}))
    print('V2 실습 Secret 준비 PASS (기존 값 보존·출력 없음)')
    login_info()


def login_info():
    """사용자가 승인한 로컬 로그인 안내. 값은 화면/Git에 출력하지 않음."""
    from secret_files import read_private, replace_private
    rows = [('Portal 개발', 'http://127.0.0.1:8000', 'portal-dev-password'),
            ('Portal 검증', 'http://127.0.0.1:8090', 'portal-verify-password'),
            ('YouTube 개발', 'http://127.0.0.1:8002', 'youtube-dev-password'),
            ('YouTube 검증', 'http://127.0.0.1:8092', 'youtube-verify-password'),
            ('Book 개발', 'http://127.0.0.1:8080', 'dev-password'),
            ('Book 검증', 'http://127.0.0.1:8081', 'verify-password'),
            ('Argo CD (admin)', 'http://localhost:8085', 'argocd-password'),
            ('Grafana (admin)', 'http://127.0.0.1:8083', 'grafana-password')]
    content = '# V2 로컬 로그인 정보\n\nGit에 올리지 않는 실습 전용 정보입니다.\n\n| 서비스 | 주소 | 비밀번호 |\n|---|---|---|\n'
    for name, url, filename in rows:
        path = LOCAL / filename
        if path.exists():
            content += f'| {name} | {url} | {read_private(path).decode().strip()} |\n'
    content += '\nPortal 비밀번호는 파일함·관리자·포트폴리오 편집에 사용합니다.\nPrometheus: http://127.0.0.1:8084 (로그인 없음)\nArgo 8085는 로컬 인증서 검증 프록시 실행 시 사용합니다.\n'
    path = LOCAL / 'V2_로그인정보.md'
    replace_private(path, content.encode())


def deploy(args):
    credentials(args)
    revision = getattr(args, 'revision', None) or run(['git', 'rev-parse', 'HEAD']).strip()
    from types import SimpleNamespace
    for environment in ENVIRONMENTS:
        sync(SimpleNamespace(environment=environment, revision=revision))
    print('Book dev/verify Argo 배포 PASS')


def seed(_):
    guard()
    code = "from app.services.book_service import create_or_get_book; create_or_get_book({'isbn':'v2-lab-001','title':'V2 Kubernetes 실습','authors':'V2 Lab','source':'manual'})"
    for namespace in ENVIRONMENTS.values():
        namespace_guard(namespace)
        k('-n', namespace, 'exec', 'deployment/book', '--', 'python', '-c', code)
    print('V2 고정 샘플 도서 생성 PASS')


def argocd(_):
    from secret_files import read_private, create_private
    guard()
    refuse_foreign('namespace', 'argocd')
    k('apply', '-f', 'platforms/argocd/namespace.yaml')
    namespace_guard('argocd')
    repo_key = LOCAL / 'argocd-repo-key'
    if repo_key.exists():
        refuse_foreign('secret', 'v2-repository', 'argocd')
        repo_secret = {'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': 'v2-repository', 'namespace': 'argocd',
                       'labels': {OWNER: VALUE, 'argocd.argoproj.io/secret-type': 'repository'}},
                       'stringData': {'type': 'git', 'url': REPO, 'sshPrivateKey': read_private(repo_key).decode()}}
        k('apply', '-f', '-', stdin=json.dumps(repo_secret))
    dependency = json.loads((ROOT / 'dependencies.json').read_text())
    chart = ROOT / 'platforms/argocd/chart/charts' / dependency['argocd_chart_file']
    if hashlib.sha256(chart.read_bytes()).hexdigest() != dependency['argocd_chart_sha256']:
        raise RuntimeError('Argo chart checksum 불일치')
    current = k('-n', 'argocd', 'get', 'deployment', 'argocd-server', '--ignore-not-found', '-o', 'json').strip()
    # Helm 3/4의 list 상태 필터 차이 없이 release 기록의 존재만 읽음. data는 조회하지 않음.
    releases = k('-n', 'argocd', 'get', 'secrets', '-l', 'owner=helm,name=argocd', '-o', 'name').strip()
    if current:
        refuse_foreign('deployment', 'argocd-server', 'argocd')
        print('기존 Argo CD 보존. Helm upgrade는 실행하지 않음')
    elif releases:
        raise RuntimeError('기존 Helm 기록이 있으나 Argo server가 없음. recover 절차 필요')
    else:
        run(['helm', 'install', 'argocd', ROOT / 'platforms/argocd/chart', '--namespace', 'argocd', '--kubeconfig', KUBE,
             '--kube-context', CONTEXT, '-f', 'platforms/argocd/values.yaml',
             '--set', 'argo-cd.redisSecretInit.enabled=true', '--set', 'argo-cd.configs.secret.createSecret=true',
             '--wait', '--timeout', '300s'], capture=False)
    for kind in ('appproject', 'application'):
        refuse_foreign(kind, 'v2-root', 'argocd')
    k('apply', '-f', 'platforms/gitops/bootstrap.yaml')
    import base64
    raw = k('-n', 'argocd', 'get', 'secret', 'argocd-initial-admin-secret', '--ignore-not-found', '-o', 'json').strip()
    if raw:
        password = LOCAL / 'argocd-password'
        if password.exists() or password.is_symlink():
            read_private(password)  # 오래된 initial Secret으로 기존 저장 값을 덮어쓰지 않음.
        else:
            create_private(password, base64.b64decode(json.loads(raw)['data']['password']))
    print('최소 bootstrap PASS. root → argocd → 각 서비스 순서로 Argo sync 실행')


def application_guard(environment):
    name, project, path, namespace, _ = APPLICATIONS[environment]
    app = json.loads(k('-n', 'argocd', 'get', 'application', name, '-o', 'json'))
    spec = app['spec']
    if (app['metadata'].get('labels', {}).get(OWNER) != VALUE
            or spec['project'] != project
            or spec['destination'] != {'server': 'https://kubernetes.default.svc', 'namespace': namespace}
            or spec['source']['repoURL'] != REPO
            or spec['source']['path'] != path
            or spec['source'].get('chart') or spec.get('sources')):
        raise RuntimeError('Application 소유/project/source/destination 불일치')
    if environment in ('argocd', 'prometheus', 'grafana'):
        release = 'argocd' if environment == 'argocd' else environment
        if spec['source'].get('helm', {}) != {'releaseName': release, 'valueFiles': ['../values.yaml']}:
            raise RuntimeError('고정 chart/values 계약 불일치')
    return app


def preflight_root(revision):
    if run(['git', 'rev-parse', 'HEAD']).strip() != revision or run(['git', 'status', '--porcelain', '--', 'platforms']).strip():
        raise RuntimeError('root sync는 검토할 SHA로 checkout하고 platforms 변경을 커밋한 상태에서 실행해야 함')
    rendered = k('kustomize', 'platforms/gitops/root')
    objects = decode_objects(k('create', '--dry-run=client', '--validate=false', '-f', '-', '-o', 'json', stdin=rendered))
    allowed = {'Namespace': {'argocd', 'v2-dev', 'v2-verify', 'v2-observability'},
               'Application': {data[0] for key, data in APPLICATIONS.items() if key != 'root'},
               'AppProject': {data[1] for data in APPLICATIONS.values() if data[0] != 'v2-root'}}
    for obj in objects:
        kind, meta = obj['kind'], obj['metadata']
        if meta['name'] not in allowed.get(kind, set()) or meta.get('labels', {}).get(OWNER) != VALUE:
            raise RuntimeError('root 선언 종류/이름/소유 불일치')
        if kind != 'Namespace' and meta.get('namespace') != 'argocd':
            raise RuntimeError('root 선언 namespace 불일치')
        refuse_foreign(kind, meta['name'], None if kind == 'Namespace' else 'argocd')


def preflight_logging(environment, revision):
    """신규 수집 권한/저장소가 타 namespace·타 소유 자원을 인수하지 않도록 검사함."""
    path = APPLICATIONS[environment][2]
    if run(['git', 'rev-parse', 'HEAD']).strip() != revision or run(['git', 'status', '--porcelain', '--', path]).strip():
        raise RuntimeError('로그 sync는 해당 SHA의 커밋된 명세로 실행해야 함')
    rendered = k('kustomize', path)
    objects = decode_objects(k('create', '--dry-run=client', '--validate=false', '-f', '-', '-o', 'json', stdin=rendered))
    allowed = ({'StatefulSet': {environment}, 'Service': {environment}, 'PersistentVolumeClaim': {environment + '-data'},
                'NetworkPolicy': {environment + '-isolation'}} if environment in ('loki', 'tempo') else
               {'Deployment': {'alloy'}, 'Service': {'alloy'}, 'ServiceAccount': {'v2-alloy'},
                'NetworkPolicy': {'alloy-isolation'}, 'Role': {'v2-alloy-logs'}, 'RoleBinding': {'v2-alloy-logs'}})
    for obj in objects:
        kind, meta = obj['kind'], obj['metadata']
        namespace = meta.get('namespace')
        expected_namespaces = {'v2-dev', 'v2-verify', 'argocd', 'v2-observability'} if kind in ('Role', 'RoleBinding') else {'v2-observability'}
        name_allowed = meta['name'] in allowed.get(kind, set())
        if kind == 'ConfigMap':
            import re
            name_allowed = bool(re.fullmatch(environment + r'-config-[a-z0-9]{10}', meta['name']))
        if not name_allowed or namespace not in expected_namespaces or meta.get('labels', {}).get(OWNER) != VALUE:
            raise RuntimeError('로그 선언 종류/이름/namespace/소유 불일치')
        namespace_guard(namespace)
        refuse_foreign(kind, meta['name'], namespace)


def sync(args):
    guard()
    if args.environment == 'root':
        preflight_root(args.revision)
    if args.environment in ('loki', 'alloy', 'tempo'):
        preflight_logging(args.environment, args.revision)
    if args.environment == 'security':
        from security_guard import preflight
        preflight(args.revision)
    before = application_guard(args.environment)
    if before.get('operation') or before.get('status', {}).get('operationState', {}).get('phase') == 'Running':
        raise RuntimeError('기존 sync 진행 중')
    app, _, _, namespace, workloads = APPLICATIONS[args.environment]
    request_info = [{'name': 'v2-request', 'value': secrets.token_hex(16)}]
    k('-n', 'argocd', 'patch', 'application', app, '--type=merge', '-p', json.dumps({'operation': {'info': request_info, 'sync': {'prune': False, 'revision': args.revision}}}))
    for _ in range(180):
        try:
            obj = application_guard(args.environment)
        except RuntimeError as error:
            # self 관리 중 API 일시 단절은 재시도하되 계약 불일치는 즉시 거부함.
            if '불일치' in str(error):
                raise
            time.sleep(2)
            continue
        op = obj.get('status', {}).get('operationState', {})
        if (op.get('operation', {}).get('sync', {}).get('revision') == args.revision
                and op.get('operation', {}).get('info') == request_info and not obj.get('operation')):
            if op.get('phase') == 'Succeeded':
                for workload in workloads:
                    k('-n', namespace, 'rollout', 'status', workload, '--timeout=240s')
                print('GitOps sync PASS:', args.revision)
                return
            if op.get('phase') in {'Failed', 'Error'}:
                raise RuntimeError('Argo sync 실패: ' + op.get('message', ''))
        time.sleep(2)
    raise RuntimeError('Argo sync 시간 초과')


def serve(_):
    guard()
    children = []
    logs = []
    try:
        endpoints = [('v2-dev', 'book', '8080:8003'), ('v2-verify', 'book', '8081:8003'), ('argocd', 'argocd-server', '8082:443')]
        exists = k('get', 'namespace', 'v2-observability', '--ignore-not-found', '-o', 'json').strip()
        if exists:
            namespace_guard('v2-observability')
            for service, port in [('grafana', '8083:80'), ('prometheus', '8084:80')]:
                if k('-n', 'v2-observability', 'get', 'service', service, '--ignore-not-found', '-o', 'json').strip():
                    endpoints.append(('v2-observability', service, port))
        for env, namespace in ENVIRONMENTS.items():
            for service, ports in [('portal', '8000:8000' if env == 'dev' else '8090:8000'),
                                   ('youtube', '8002:8002' if env == 'dev' else '8092:8002')]:
                if k('-n', namespace, 'get', 'service', service, '--ignore-not-found', '-o', 'json').strip():
                    endpoints.append((namespace, service, ports))
        endpoints.append(('v2-dev', 'book', '8003:8003'))
        for namespace, service, ports in endpoints:
            namespace_guard(namespace)
            log_path = LOCAL / ('forward-' + ports.split(':')[0] + '.log')
            log = log_path.open('w')
            logs.append(log)
            children.append(subprocess.Popen([str(ROOT / '.tools/bin/kubectl'), '--kubeconfig', str(KUBE), '--context', CONTEXT,
                                             '-n', namespace, 'port-forward', '--address', '127.0.0.1', 'service/' + service, ports], stdout=log, stderr=log))
            for _ in range(100):
                if children[-1].poll() is not None:
                    raise RuntimeError('port-forward 실패. ' + str(log_path) + ' 확인')
                if ('Forwarding from 127.0.0.1:' + ports.split(':')[0]) in log_path.read_text():
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError('port-forward 준비 시간 초과')
        print('Portal :8000/:8090 / YouTube :8002/:8092 / Book :8003,:8080/:8081 / Argo https://localhost:8082 / 설치 시 Grafana :8083 / Prometheus :8084 (모두 loopback)', flush=True)
        while all(p.poll() is None for p in children):
            time.sleep(1)
        raise RuntimeError('port-forward 중단됨. serve 재실행 필요')
    except KeyboardInterrupt:
        pass
    finally:
        for process in children:
            process.terminate()
        for process in children:
            process.wait()
        for log in logs:
            log.close()


def check(_):
    guard()
    for namespace in ENVIRONMENTS.values():
        namespace_guard(namespace)
        k('-n', namespace, 'rollout', 'status', 'deployment/book', '--timeout=120s')
        code = "import urllib.request,json; d=json.load(urllib.request.urlopen('http://127.0.0.1:8003/ready')); print(d)"
        print(k('-n', namespace, 'exec', 'deployment/book', '--', 'python', '-c', code).strip())
    print(k('get', 'nodes', '-o', 'wide'))


def status(_):
    guard()
    print(k('get', 'pods', '-A'))
    print(k('-n', 'argocd', 'get', 'applications'))


def exercise(args):
    guard()
    namespace = 'v2-verify'
    namespace_guard(namespace)
    obj = json.loads(k('-n', namespace, 'get', 'deployment', 'book', '-o', 'json'))
    if obj['metadata'].get('labels', {}).get(OWNER) != VALUE:
        raise RuntimeError('실습 Deployment 소유 표식 없음')
    app = application_guard('verify')
    if app.get('spec', {}).get('syncPolicy', {}).get('automated'):
        raise RuntimeError('자동 동기화를 끈 뒤 장애 실습 실행 필요')
    snapshot = LOCAL / 'exercise.json'
    if snapshot.exists():
        raise RuntimeError('미복구 실습 존재. restore 먼저 실행')
    save_snapshot = {'cluster_uid': json.loads(STATE.read_text())['cluster_uid'], 'deployment_uid': obj['metadata']['uid'], 'spec': obj['spec'], 'fault': args.fault}
    snapshot.write_text(json.dumps(save_snapshot))
    if args.fault == 'worker':
        docker('stop', 'k3d-ps-v2-agent-0')  # 노드 로컬 PVC를 다른 노드로 이동했다고 주장하지 않음
    else:
        container = {'name': 'book'}
        if args.fault == 'image':
            # digest 정책 통과 후 실제 registry NotFound를 관찰하는 기존 장애 실습을 유지함.
            container['image'] = MISSING_IMAGE
        elif args.fault == 'pending':
            k('-n', namespace, 'patch', 'deployment', 'book', '--type=strategic', '-p', json.dumps({'spec': {'template': {'spec': {'nodeSelector': {'lab.personal-server-v2/unavailable': 'true'}}}}}))
            print('장애 주입: Pending nodeSelector / 복구: python3 tools/lab.py restore')
            return
        elif args.fault == 'probe':
            container['readinessProbe'] = {'httpGet': {'path': '/missing-v2-lab', 'port': 8003}}
        elif args.fault == 'oom':
            container.update(command=['python', '-c', 'import time; time.sleep(5); x=bytearray(256*1024*1024); time.sleep(120)'], resources={'requests': {'memory': '32Mi'}, 'limits': {'memory': '64Mi'}})
        k('-n', namespace, 'patch', 'deployment', 'book', '--type=strategic', '-p', json.dumps({'spec': {'template': {'spec': {'containers': [container]}}}}))
    print('장애 주입:', args.fault, '/ 복구: python3 tools/lab.py restore / 자동 원인 판정은 수행하지 않음')


def restore(_):
    guard()
    path = LOCAL / 'exercise.json'
    snapshot = json.loads(path.read_text())
    if snapshot['cluster_uid'] != json.loads(STATE.read_text())['cluster_uid']:
        raise RuntimeError('다른 cluster의 snapshot')
    if snapshot['fault'] == 'worker':
        docker('start', 'k3d-ps-v2-agent-0')
        k('wait', '--for=condition=Ready', 'node/k3d-ps-v2-agent-0', '--timeout=180s')
    namespace_guard('v2-verify')
    current = json.loads(k('-n', 'v2-verify', 'get', 'deployment', 'book', '-o', 'json'))
    if current['metadata'].get('labels', {}).get(OWNER) != VALUE or current['metadata']['uid'] != snapshot['deployment_uid']:
        raise RuntimeError('복구 대상 Deployment UID/소유 표식 불일치')
    k('-n', 'v2-verify', 'patch', 'deployment', 'book', '--type=json', '-p', json.dumps([{'op': 'replace', 'path': '/spec', 'value': snapshot['spec']}]))
    k('-n', 'v2-verify', 'rollout', 'status', 'deployment/book', '--timeout=180s')
    path.unlink()
    print('장애 이전 spec 복구 PASS. GitOps 차이와 데이터는 별도 확인 필요')


def down(_):
    # API/노드 일부가 중지됐거나 이전 삭제가 중단돼도 남은 동일 ID만 정리 가능함.
    data = json.loads(STATE.read_text())
    if (data.get('owner') != VALUE or not data.get('cluster_uid')
            or hashlib.sha256(KUBE.read_bytes()).hexdigest() != data.get('kube_sha256')
            or not kube_config_valid(json.loads(k('config', 'view', '--raw', '-o', 'json')))):
        raise RuntimeError('정리용 state/kubeconfig 소유 검증 실패')
    if 'volumes' not in data or 'network' not in data:
        raise RuntimeError('전체 자원 inventory가 없는 초기 state. 자동 삭제 거부')
    data['phase'] = 'deleting'
    save(data)
    cleanup_resources(data)
    STATE.unlink()
    KUBE.unlink()
    JOURNAL.unlink(missing_ok=True)
    (LOCAL / 'exercise.json').unlink(missing_ok=True)
    print('V2 cluster/registry 삭제 완료. 로컬 비밀번호·source·cache 증거는 .local에 보존')


def cleanup(_):
    if STATE.exists():
        raise RuntimeError('완성된 cluster는 down 사용')
    data = json.loads(JOURNAL.read_text())
    if data.get('owner') != VALUE:
        raise RuntimeError('잘못된 생성 journal')
    record_created(data)
    cleanup_resources(data)
    JOURNAL.unlink()
    KUBE.unlink(missing_ok=True)
    print('미완성 V2 자원 정리 완료')


def gitops(args):
    """root 선언 등록 후 서비스를 수동 동기화함. Helm upgrade 경로 없음."""
    from types import SimpleNamespace
    revision = args.revision or run(['git', 'rev-parse', 'HEAD']).strip()
    credentials(args)
    for name in ('root', 'argocd', 'blackbox', 'loki', 'tempo', 'alloy', 'prometheus', 'grafana', 'dev', 'verify', 'youtube-dev', 'youtube-verify', 'portal-dev', 'portal-verify', 'security'):
        sync(SimpleNamespace(environment=name, revision=revision))


def recover(args):
    if not args.confirm_recovery:
        raise RuntimeError('비상 복구는 --confirm-recovery를 명시해야 함')
    guard()
    namespace_guard('argocd')
    lock = json.loads((ROOT / 'dependencies.json').read_text())
    archive = ROOT / 'platforms/argocd/chart/charts' / lock['argocd_chart_file']
    if hashlib.sha256(archive.read_bytes()).hexdigest() != lock['argocd_chart_sha256']:
        raise RuntimeError('복구 chart checksum 불일치')
    rendered = run(['helm', 'template', 'argocd', ROOT / 'platforms/argocd/chart', '-n', 'argocd', '-f', 'platforms/argocd/values.yaml'])
    objects = decode_objects(k('create', '--dry-run=client', '--validate=false', '-f', '-', '-o', 'json', stdin=rendered))
    allowed = {'ServiceAccount', 'ConfigMap', 'Service', 'Deployment', 'StatefulSet', 'Role', 'RoleBinding', 'ClusterRole', 'ClusterRoleBinding', 'CustomResourceDefinition', 'NetworkPolicy'}
    for obj in objects:
        kind, meta = obj['kind'], obj['metadata']
        if kind not in allowed or meta.get('labels', {}).get(OWNER) != VALUE:
            raise RuntimeError('복구 렌더 종류/소유 불일치')
        if kind == 'CustomResourceDefinition':
            if meta['name'] not in {'applications.argoproj.io', 'applicationsets.argoproj.io', 'appprojects.argoproj.io'}:
                raise RuntimeError('알 수 없는 복구 CRD')
        elif not meta['name'].startswith('argocd-'):
            raise RuntimeError('복구 자원 이름 불일치')
        if meta.get('namespace') not in (None, 'argocd'):
            raise RuntimeError('복구 namespace 불일치')
        ns = 'argocd' if kind not in {'ClusterRole', 'ClusterRoleBinding', 'CustomResourceDefinition'} else None
        # 이전 Helm CRD에는 owner가 없을 수 있어 검토된 3개 이름/Argo label만 예외로 인수함.
        if kind != 'CustomResourceDefinition':
            refuse_foreign(kind, meta['name'], ns)
        else:
            raw = k('get', kind, meta['name'], '--ignore-not-found', '-o', 'json').strip()
            labels = json.loads(raw)['metadata'].get('labels', {}) if raw else {}
            if raw and (labels.get('app.kubernetes.io/part-of') != 'argocd' or labels.get(OWNER) not in (None, VALUE)):
                raise RuntimeError('복구 CRD의 Argo 소유 label 불일치')
    k('apply', '--server-side', '--force-conflicts', '--field-manager=v2-breakglass', '-f', '-', stdin=json.dumps(objects_to_list(objects)))
    (LOCAL / 'recovery.json').write_text(json.dumps({'source_commit': run(['git', 'rev-parse', 'HEAD']).strip(), 'resources': len(objects), 'secret_changes': False}, indent=2) + '\n')
    print('동일 Git 명세로 Argo 비상 복구 적용. 이후 sync argocd 및 모든 서비스 상태 재확인 필요')


def objects_to_list(objects):
    return {'apiVersion': 'v1', 'kind': 'List', 'items': objects}


def decode_objects(output):
    """kubectl multi-document JSON은 버전에 따라 List 또는 연속 JSON 객체임."""
    decoder = json.JSONDecoder()
    objects = []
    remaining = output.lstrip()
    while remaining:
        obj, end = decoder.raw_decode(remaining)
        objects.extend(obj['items'] if obj.get('kind') == 'List' else [obj])
        remaining = remaining[end:].lstrip()
    if not objects:
        raise RuntimeError('비어 있는 렌더 결과')
    return objects


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    functions = {'doctor': doctor, 'up': up, 'build': build, 'deploy': deploy, 'seed': seed, 'argocd': argocd,
                 'sync': sync, 'gitops': gitops, 'credentials': credentials, 'recover': recover,
                 'serve': serve, 'check': check, 'status': status, 'exercise': exercise, 'restore': restore, 'down': down, 'cleanup': cleanup}
    for name in functions:
        p = sub.add_parser(name)
        if name == 'build':
            p.add_argument('--app', choices=['book', 'youtube', 'portal'], default='book')
            p.add_argument('--source', required=True, help='V1 로컬 Git 저장소. 앱 파일만 git archive로 추출')
        if name == 'sync':
            p.add_argument('environment', choices=APPLICATIONS)
        if name in ('sync', 'gitops', 'deploy'):
            p.add_argument('--revision', required=name == 'sync', help='GitHub에 push한 40자리 Git commit SHA, 기본 현재 HEAD')
        if name == 'recover':
            p.add_argument('--confirm-recovery', action='store_true', help='정상 Argo sync가 불가능할 때만 동일 명세 비상 적용')
        if name == 'exercise':
            p.add_argument('fault', choices=['image', 'pending', 'probe', 'oom', 'worker'])
    args = parser.parse_args()
    if getattr(args, 'revision', None) and (len(args.revision) != 40 or any(c not in '0123456789abcdef' for c in args.revision)):
        parser.error('revision은 40자리 lowercase commit SHA 필요')
    try:
        functions[args.command](args)
    except (RuntimeError, OSError, KeyError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    os.umask(0o077)
    if LOCAL.exists():
        LOCAL.chmod(0o700)
    sys.exit(main())
