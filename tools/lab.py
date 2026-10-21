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
REGISTRY = 'registry:2.8.3'  # dependencies.json의 digest로 실행
ENVIRONMENTS = {'dev': 'v2-dev', 'verify': 'v2-verify'}


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
    if run(['git', '-C', source, 'rev-parse', '--verify', SOURCE]).strip() != SOURCE:
        raise RuntimeError('고정 source commit 없음')
    # git archive는 바이너리이므로 별도 호출. worktree/실데이터/미추적 파일을 읽지 않음.
    archive = subprocess.run(['git', '-C', str(source), 'archive', SOURCE, 'book-memo'], check=True, capture_output=True).stdout
    context = Path(tempfile.mkdtemp(prefix='book-source-', dir=LOCAL))
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        for member in tar.getmembers():
            parts = Path(member.name).parts
            if len(parts) < 2 or parts[0] != 'book-memo':
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
    tag = f'localhost:5001/v2-book:{SOURCE}'
    docker('build', '--platform', 'linux/arm64', '--label', f'org.opencontainers.image.revision={SOURCE}', '-t', tag, str(context), capture=False)
    docker('push', tag, capture=False)
    image = json.loads(docker('image', 'inspect', tag))[0]
    if image['Architecture'] != 'arm64':
        raise RuntimeError('ARM64 image 검증 실패')
    digest = next(x for x in image['RepoDigests'] if x.startswith('localhost:5001/v2-book@sha256:'))
    for env in ENVIRONMENTS:
        run(['kubectl', 'kustomize', 'apps/book/overlays/' + env])
        path = ROOT / 'apps/book/overlays' / env / 'kustomization.yaml'
        lines = path.read_text().splitlines()
        lines = [line for line in lines if not line.strip().startswith(('newTag:', 'digest:'))]
        # images newName 뒤 digest 삽입; agent와 합의한 image key 사용
        index = next(i for i, line in enumerate(lines) if line.strip().startswith('newName:'))
        lines.insert(index + 1, '    digest: ' + digest.split('@')[1])
        path.write_text('\n'.join(lines) + '\n')
    (LOCAL / 'image.json').write_text(json.dumps({'source': SOURCE, 'source_archive_sha256': hashlib.sha256(archive).hexdigest(), 'image': digest, 'architecture': 'arm64'}, indent=2) + '\n')
    print('Book ARM64 이미지 빌드·digest 고정 완료:', digest)


def deploy(_):
    guard()
    if not (LOCAL / 'image.json').exists():
        raise RuntimeError('먼저 build를 실행해야 함')
    for namespace in ENVIRONMENTS.values():
        refuse_foreign('namespace', namespace)
    k('apply', '-f', 'platforms/namespaces.yaml')
    for env, namespace in ENVIRONMENTS.items():
        namespace_guard(namespace)
        for kind, name in [('deployment', 'book'), ('service', 'book'), ('pvc', 'book-data'), ('secret', 'book-auth'), ('resourcequota', 'book-budget'), ('limitrange', 'book-defaults')]:
            refuse_foreign(kind, name, namespace)
        k('apply', '-k', f'apps/book/overlays/{env}')
        secret_path = LOCAL / f'{env}-password'
        if not secret_path.exists():
            secret_path.write_text(secrets.token_urlsafe(24))
            secret_path.chmod(0o600)
        secret = {'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': 'book-auth', 'namespace': namespace, 'labels': {OWNER: VALUE}},
                  'type': 'Opaque', 'stringData': {'password': secret_path.read_text().strip()}}
        k('apply', '-f', '-', stdin=json.dumps(secret))
        k('-n', namespace, 'rollout', 'status', 'deployment/book', '--timeout=180s')
    print('Book dev/verify 배포 PASS')


def seed(_):
    guard()
    code = "from app.services.book_service import create_or_get_book; create_or_get_book({'isbn':'v2-lab-001','title':'V2 Kubernetes 실습','authors':'V2 Lab','source':'manual'})"
    for namespace in ENVIRONMENTS.values():
        namespace_guard(namespace)
        k('-n', namespace, 'exec', 'deployment/book', '--', 'python', '-c', code)
    print('V2 고정 샘플 도서 생성 PASS')


def argocd(_):
    guard()
    refuse_foreign('namespace', 'argocd')
    k('apply', '-f', 'platforms/argocd/namespace.yaml')
    namespace_guard('argocd')
    repo_key = LOCAL / 'argocd-repo-key'
    if repo_key.exists():
        refuse_foreign('secret', 'v2-repository', 'argocd')
        repo_secret = {'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': 'v2-repository', 'namespace': 'argocd',
                       'labels': {OWNER: VALUE, 'argocd.argoproj.io/secret-type': 'repository'}},
                       'stringData': {'type': 'git', 'url': REPO, 'sshPrivateKey': repo_key.read_text()}}
        k('apply', '-f', '-', stdin=json.dumps(repo_secret))
    dependency = json.loads((ROOT / 'dependencies.json').read_text())
    chart = LOCAL / 'cache' / dependency['argocd_chart_file']
    if hashlib.sha256(chart.read_bytes()).hexdigest() != dependency['argocd_chart_sha256']:
        raise RuntimeError('Argo chart checksum 불일치')
    run(['helm', 'upgrade', '--install', 'argocd', chart, '--namespace', 'argocd', '--kubeconfig', KUBE,
         '--kube-context', CONTEXT, '-f', 'platforms/argocd/values.yaml', '--wait', '--timeout', '300s'], capture=False)
    for kind in ('appproject', 'application'):
        for name in ('book-dev', 'book-verify'):
            refuse_foreign(kind, name, 'argocd')
    k('apply', '-f', 'platforms/argocd/applications.yaml')
    import base64
    secret = json.loads(k('-n', 'argocd', 'get', 'secret', 'argocd-initial-admin-secret', '-o', 'json'))
    password = LOCAL / 'argocd-password'
    password.write_bytes(base64.b64decode(secret['data']['password']))
    password.chmod(0o600)
    print('Argo CD 설치 PASS. Git main에 digest 명세가 반영된 뒤 sync 실행')


def application_guard(environment):
    app = json.loads(k('-n', 'argocd', 'get', 'application', 'book-' + environment, '-o', 'json'))
    spec = app['spec']
    if (app['metadata'].get('labels', {}).get(OWNER) != VALUE
            or spec['project'] != 'book-' + environment
            or spec['destination'] != {'server': 'https://kubernetes.default.svc', 'namespace': ENVIRONMENTS[environment]}
            or spec['source']['repoURL'] != REPO
            or spec['source']['path'] != 'apps/book/overlays/' + environment):
        raise RuntimeError('Application 소유/project/source/destination 불일치')
    return app


def sync(args):
    guard()
    before = application_guard(args.environment)
    if before.get('operation') or before.get('status', {}).get('operationState', {}).get('phase') == 'Running':
        raise RuntimeError('기존 sync 진행 중')
    app = 'book-' + args.environment
    request_info = [{'name': 'v2-request', 'value': secrets.token_hex(16)}]
    k('-n', 'argocd', 'patch', 'application', app, '--type=merge', '-p', json.dumps({'operation': {'info': request_info, 'sync': {'prune': False, 'revision': args.revision}}}))
    for _ in range(90):
        obj = json.loads(k('-n', 'argocd', 'get', 'application', app, '-o', 'json'))
        op = obj.get('status', {}).get('operationState', {})
        if (op.get('operation', {}).get('sync', {}).get('revision') == args.revision
                and op.get('operation', {}).get('info') == request_info and not obj.get('operation')):
            if op.get('phase') == 'Succeeded':
                k('-n', ENVIRONMENTS[args.environment], 'rollout', 'status', 'deployment/book', '--timeout=180s')
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
        for namespace, service, ports in [('v2-dev', 'book', '8080:8003'), ('v2-verify', 'book', '8081:8003'), ('argocd', 'argocd-server', '8082:443')]:
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
        print('Book http://localhost:8080 / http://localhost:8081 / Argo https://localhost:8082', flush=True)
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
            container['image'] = 'localhost:5001/v2-book:missing-v2-lab'
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    functions = {'doctor': doctor, 'up': up, 'build': build, 'deploy': deploy, 'seed': seed, 'argocd': argocd,
                 'sync': sync, 'serve': serve, 'check': check, 'status': status, 'exercise': exercise, 'restore': restore, 'down': down, 'cleanup': cleanup}
    for name in functions:
        p = sub.add_parser(name)
        if name == 'build':
            p.add_argument('--source', required=True, help='V1 로컬 Git 저장소. 앱 파일만 git archive로 추출')
        if name == 'sync':
            p.add_argument('environment', choices=ENVIRONMENTS)
            p.add_argument('--revision', required=True, help='Git commit SHA')
        if name == 'exercise':
            p.add_argument('fault', choices=['image', 'pending', 'probe', 'oom', 'worker'])
    args = parser.parse_args()
    if args.command == 'sync' and (len(args.revision) != 40 or any(c not in '0123456789abcdef' for c in args.revision)):
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
