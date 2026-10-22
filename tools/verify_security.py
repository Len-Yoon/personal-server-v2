#!/usr/bin/env python3
"""V2 전용 보안 정책·RBAC·패킷·canary Secret 검증. 실제 인증 값 비출력."""
import argparse
import base64
import copy
from datetime import datetime
import hashlib
import json
import ssl
import time
import urllib.error
import urllib.request
import uuid

import lab
import security_guard as boundary
from verify_logging import owned_object, application_snapshot
from verify_services import execute, book_snapshot, persisted_samples, owned_pod

JOURNAL = lab.LOCAL / 'security-fixture.json'
BREAKGLASS = lab.LOCAL / 'security-binding-recovery.json'


def pod_spec(name, namespace='v2-verify', secret=None):
    image = json.loads((lab.ROOT / 'apps/images.lock.json').read_text())['book']['image']
    spec = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': name, 'namespace': namespace,
        'labels': {lab.OWNER: lab.VALUE, 'app.kubernetes.io/name': 'v2-security-probe'}},
        'spec': {'serviceAccountName': 'v2-diagnostics', 'automountServiceAccountToken': False,
            'restartPolicy': 'Never', 'nodeSelector': {'kubernetes.io/hostname': 'k3d-ps-v2-agent-0'},
            'securityContext': {'runAsNonRoot': True, 'runAsUser': 10001, 'runAsGroup': 10001, 'fsGroup': 10001,
                                'seccompProfile': {'type': 'RuntimeDefault'}},
            'containers': [{'name': 'probe', 'image': image, 'command': ['python', '-c', 'import time; time.sleep(600)'],
                'resources': {'requests': {'cpu': '10m', 'memory': '32Mi'}, 'limits': {'cpu': '100m', 'memory': '64Mi'}},
                'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True, 'capabilities': {'drop': ['ALL']}}}]}}
    if secret:
        spec['spec']['volumes'] = [{'name': 'canary', 'secret': {'secretName': secret, 'defaultMode': 0o440}}]
        spec['spec']['containers'][0]['volumeMounts'] = [{'name': 'canary', 'mountPath': '/canary', 'readOnly': True}]
    return spec


def deployment_spec(pod):
    return {'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': copy.deepcopy(pod['metadata']),
        'spec': {'replicas': 1, 'selector': {'matchLabels': {'app.kubernetes.io/name': 'v2-security-probe'}},
            'template': {'metadata': {'labels': copy.deepcopy(pod['metadata']['labels'])},
                         'spec': {k: v for k, v in pod['spec'].items() if k != 'restartPolicy'}}}}


def dry_run(obj, reject=None, update=False):
    try:
        lab.k('replace' if update else 'create', '--dry-run=server', '-f', '-', '-o', 'json', stdin=json.dumps(obj))
    except RuntimeError as error:
        message = str(error)
        if reject and reject in message:
            return 'REJECTED'
        raise RuntimeError('server dry-run이 예상한 정책 결과와 다름') from None
    if reject:
        raise RuntimeError('금지된 명세가 server dry-run에서 허용됨')
    return 'ALLOWED'


def audit_bootstrap(revision):
    lab.guard()
    objects = boundary.preflight(revision)
    existing = lab.k('get', boundary.BINDING, boundary.NAME, '--ignore-not-found', '-o', 'json').strip()
    if existing and json.loads(existing)['spec']['validationActions'] != ['Warn', 'Audit']:
        raise RuntimeError('이미 집행 중인 Binding을 audit bootstrap으로 자동 완화하지 않음')
    audit = copy.deepcopy(objects)
    for obj in audit:
        if obj['kind'] == boundary.BINDING:
            obj['spec']['validationActions'] = ['Warn', 'Audit']
    lab.k('apply', '-f', '-', stdin=json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': audit}))
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        policy = boundary.owned_cluster(boundary.POLICY)
        if policy.get('status', {}).get('observedGeneration') == policy['metadata']['generation']:
            if policy.get('status', {}).get('typeChecking', {}).get('expressionWarnings'):
                raise RuntimeError('CEL 정책 typeChecking 경고 존재')
            break
        time.sleep(1)
    else:
        raise RuntimeError('CEL 정책 typeChecking 대기 시간 초과')
    normal = pod_spec('v2-security-audit-' + uuid.uuid4().hex[:10])
    dry_run(normal)
    violation = copy.deepcopy(normal)
    violation['spec']['containers'][0]['image'] = 'localhost:5001/v2-book:unfixed-security-test'
    dry_run(violation)
    binding = boundary.owned_cluster(boundary.BINDING)
    report = {'source_commit': revision, 'policy_uid': policy['metadata']['uid'], 'binding_uid': binding['metadata']['uid'],
        'validation_actions': binding['spec']['validationActions'], 'normal_allowed': True,
        'violation_allowed_before_deny': True, 'type_checking': 'PASS', 'result': 'PASS'}
    (lab.LOCAL / 'security-audit.json').write_text(json.dumps(report, indent=2) + '\n')
    print('Warn/Audit bootstrap·CEL typecheck·정상/위반 dry-run 사전 확인 PASS')


def admission_checks():
    policy = boundary.owned_cluster(boundary.POLICY)
    binding = boundary.owned_cluster(boundary.BINDING)
    if policy['spec'].get('matchConditions') != boundary.SCOPE or binding['spec']['validationActions'] != ['Deny']:
        raise RuntimeError('실제 정책의 scope/Deny 불일치')
    if policy.get('status', {}).get('typeChecking', {}).get('expressionWarnings'):
        raise RuntimeError('실제 정책에 CEL 경고 존재')
    checks = {}
    for ns in lab.ENVIRONMENTS.values():
        base = pod_spec('v2-security-admission-' + uuid.uuid4().hex[:10], ns)
        for kind in ('Pod', 'Deployment'):
            normal = base if kind == 'Pod' else deployment_spec(base)
            checks[ns + '/' + kind + '/valid'] = dry_run(normal)
            if kind == 'Deployment':
                fault = copy.deepcopy(normal)
                fault['spec']['template']['metadata']['labels']['app.kubernetes.io/name'] = 'book'
                fault['spec']['selector']['matchLabels']['app.kubernetes.io/name'] = 'book'
                fault['spec']['template']['spec']['serviceAccountName'] = 'v2-book'
                fault['spec']['template']['spec']['containers'][0]['image'] = lab.MISSING_IMAGE
                checks[ns + '/Deployment/image-pull-lab-compatible'] = dry_run(fault)
            for case in ('owner', 'service-account', 'token', 'tag', 'registry', 'init-image', 'projected-token', 'resource-zero'):
                obj = copy.deepcopy(normal)
                spec = obj['spec'] if kind == 'Pod' else obj['spec']['template']['spec']
                meta = obj['metadata'] if kind == 'Pod' else obj['spec']['template']['metadata']
                if case == 'owner': meta['labels'].pop(lab.OWNER)
                elif case == 'service-account': spec['serviceAccountName'] = 'default'
                elif case == 'token': spec['automountServiceAccountToken'] = True
                elif case == 'tag': spec['containers'][0]['image'] = 'localhost:5001/v2-book:latest'
                elif case == 'registry': spec['containers'][0]['image'] = 'other.invalid/v2-book@sha256:' + 'a' * 64
                elif case == 'init-image':
                    spec['initContainers'] = [copy.deepcopy(spec['containers'][0])]
                    spec['initContainers'][0]['name'] = 'init'
                    spec['initContainers'][0]['image'] = 'localhost:5001/v2-book:latest'
                elif case == 'resource-zero': spec['containers'][0]['resources']['requests']['cpu'] = '0'
                else: spec['volumes'] = [{'name': 'bypass', 'projected': {'sources': [{'serviceAccountToken': {'path': 'token'}}]}}]
                checks[ns + '/' + kind + '/' + case] = dry_run(obj, boundary.NAME)
        for case in ('privileged', 'hostPath', 'hostNetwork', 'root', 'escalation', 'capability', 'seccomp'):
            obj = copy.deepcopy(base)
            spec = obj['spec']; container = spec['containers'][0]
            if case == 'privileged':
                container['securityContext']['privileged'] = True
                # privileged=true와 escalation=false 조합은 API 구조 검증에서 먼저 거부됨.
                container['securityContext']['allowPrivilegeEscalation'] = True
            elif case == 'hostPath': spec['volumes'] = [{'name': 'host', 'hostPath': {'path': '/'}}]
            elif case == 'hostNetwork': spec['hostNetwork'] = True
            elif case == 'root': spec['securityContext']['runAsUser'] = 0
            elif case == 'escalation': container['securityContext']['allowPrivilegeEscalation'] = True
            elif case == 'capability': container['securityContext']['capabilities']['add'] = ['NET_ADMIN']
            else: spec['securityContext']['seccompProfile']['type'] = 'Unconfined'
            checks[ns + '/PSA/' + case] = dry_run(obj, 'violates PodSecurity')
        for case in ('owner', 'image'):
            obj = owned_object(ns, 'deployment', 'book')
            if case == 'owner': obj['spec']['template']['metadata']['labels'].pop(lab.OWNER)
            else: obj['spec']['template']['spec']['containers'][0]['image'] = 'localhost:5001/v2-book:latest'
            checks[ns + '/Deployment/UPDATE-' + case] = dry_run(obj, boundary.NAME, update=True)
    return checks


def api_client(namespace, service_account):
    lab.namespace_guard(namespace)
    sa = owned_object(namespace, 'serviceaccount', service_account)
    issued = json.loads(lab.k('create', '--raw', '/api/v1/namespaces/' + namespace + '/serviceaccounts/' + service_account + '/token',
        '-f', '-', stdin=json.dumps({'apiVersion': 'authentication.k8s.io/v1', 'kind': 'TokenRequest',
                                    'spec': {'expirationSeconds': 600}})))['status']
    token = issued['token']
    remaining = datetime.fromisoformat(issued['expirationTimestamp'].replace('Z', '+00:00')).timestamp() - time.time()
    if not 0 < remaining <= 660:
        raise RuntimeError('진단 토큰의 실제 유효기간이 허용 범위를 벗어남')
    # CA와 loopback API 주소는 guard가 검증한 kubeconfig만 사용함. 토큰은 argv/env/파일에 저장하지 않음.
    ca = lab.k('config', 'view', '--raw', '-o=jsonpath={.clusters[0].cluster.certificate-authority-data}')
    context = ssl.create_default_context(cadata=base64.b64decode(ca).decode())
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    def request(method, path, expected, body=None):
        if not path.startswith('/api/') and not path.startswith('/apis/'):
            raise RuntimeError('API 검증 경로 거부')
        req = urllib.request.Request('https://127.0.0.1:6550' + path, method=method,
            data=json.dumps(body).encode() if body else None,
            headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
        try:
            with opener.open(req, timeout=10) as response: status = response.status
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()
        if status != expected:
            raise RuntimeError('제한된 계정 API 응답이 예상 권한과 다름')
        return status
    request.expiry_seconds = int(remaining)
    return request


def rbac_checks():
    report = {}
    for ns in lab.ENVIRONMENTS.values():
        other = 'v2-verify' if ns == 'v2-dev' else 'v2-dev'
        diag = api_client(ns, 'v2-diagnostics')
        pod = owned_pod(ns, 'book')
        paths = [('pods', '/api/v1/namespaces/' + ns + '/pods?limit=1', 200),
            ('events', '/api/v1/namespaces/' + ns + '/events?limit=1', 200),
            ('logs', '/api/v1/namespaces/' + ns + '/pods/' + pod['metadata']['name'] + '/log?tailLines=1', 200),
            ('secrets', '/api/v1/namespaces/' + ns + '/secrets?limit=1', 403),
            ('other-environment', '/api/v1/namespaces/' + other + '/pods?limit=1', 403),
            ('exec', '/api/v1/namespaces/' + ns + '/pods/' + pod['metadata']['name'] + '/exec?command=true&stdout=true', 403)]
        result = {name: diag('GET', path, status) for name, path, status in paths}
        result['token_expiry_seconds_max'] = diag.expiry_seconds
        result['pod-create'] = diag('POST', '/api/v1/namespaces/' + ns + '/pods?dryRun=All', 403, pod_spec('v2-security-rbac', ns))
        result['role-write'] = diag('POST', '/apis/rbac.authorization.k8s.io/v1/namespaces/' + ns + '/roles?dryRun=All', 403,
            {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'Role', 'metadata': {'name': 'v2-security-denied'}, 'rules': []})
        result['token-create'] = diag('POST', '/api/v1/namespaces/' + ns + '/serviceaccounts/v2-diagnostics/token', 403,
            {'apiVersion': 'authentication.k8s.io/v1', 'kind': 'TokenRequest', 'spec': {'expirationSeconds': 600}})
        for app in ('book', 'portal', 'youtube'):
            actor = api_client(ns, 'v2-' + app)
            result[app + '-secrets'] = actor('GET', '/api/v1/namespaces/' + ns + '/secrets?limit=1', 403)
            result[app + '-pods'] = actor('GET', '/api/v1/namespaces/' + ns + '/pods?limit=1', 403)
        report[ns] = result
    return report


def network_checks():
    report = {}
    for ns in lab.ENVIRONMENTS.values():
        other = 'v2-verify' if ns == 'v2-dev' else 'v2-dev'
        for app in ('portal', 'book', 'youtube'):
            targets = [('node-api-observation', 'kubernetes.default.svc.cluster.local', 443, None),
                ('other-book', 'book.' + other + '.svc.cluster.local', 8003, False),
                ('otlp', 'alloy.v2-observability.svc.cluster.local', 4318, True)]
            if app == 'portal': targets += [('same-book', 'book', 8003, True), ('same-youtube', 'youtube', 8002, True)]
            else: targets += [('portal-denied', 'portal', 8000, False)]
            code = '''import socket,json
rows=TARGETS
out={'dns_resolution':'PASS'}
for name,host,port,allowed in rows:
 socket.getaddrinfo(host,port)
 try:
  with socket.create_connection((host,port),timeout=1.5): connected=True
 except (TimeoutError,OSError): connected=False
 if allowed is not None: assert connected==allowed, name+' packet expectation mismatch'
 out[name]='ALLOWED' if connected else 'BLOCKED'
print(json.dumps(out))
'''.replace('TARGETS', repr(targets))
            report[ns + '/' + app] = execute(ns, app, code)
        external = '''import json,urllib.request,urllib.error
url='https://www.googleapis.com/books/v1/volumes?q=isbn%3A9780132350884&maxResults=1'
try:
 with urllib.request.urlopen(url,timeout=15) as response:
  status=response.status; json.load(response)
except urllib.error.HTTPError as error: status=error.code
assert status in (200,403,429)
print(json.dumps({'https_connected':True,'http':status,'book_api_success':status==200}))
'''
        report[ns + '/book-external'] = execute(ns, 'book', external)
    return report


def save_journal(items, cluster):
    from secret_files import replace_private
    replace_private(JOURNAL, (json.dumps({'cluster_uid': cluster, 'items': items}, indent=2) + '\n').encode())


def cleanup():
    if not JOURNAL.exists(): return
    state = lab.guard(); journal = json.loads(JOURNAL.read_text())
    if journal['cluster_uid'] != state['cluster_uid']:
        raise RuntimeError('보안 실습 정리 cluster UID 불일치')
    for item in reversed(journal['items']):
        ns, kind, name = item['namespace'], item['kind'], item['name']
        if ns != 'v2-verify' or kind not in ('Pod', 'Secret') or not name.startswith('v2-security-'):
            raise RuntimeError('보안 실습 정리 범위 불일치')
        exists = lab.k('-n', ns, 'get', kind, name, '--ignore-not-found', '-o', 'name').strip()
        if not exists: continue
        current = owned_object(ns, kind, name)
        if current['metadata']['uid'] != item['uid']: raise RuntimeError('실습 자원 UID 변경')
        resource = 'pods' if kind == 'Pod' else 'secrets'
        lab.k('delete', '--raw', '/api/v1/namespaces/' + ns + '/' + resource + '/' + name, '-f', '-',
            stdin=json.dumps({'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': item['uid']}}))
    JOURNAL.unlink()


def canary_secret():
    state = lab.guard()
    if JOURNAL.exists(): raise RuntimeError('이전 보안 실습 journal 존재. --cleanup 필요')
    from secret_files import create_private
    create_private(JOURNAL, (json.dumps({'cluster_uid': state['cluster_uid'], 'items': []}) + '\n').encode())
    suffix = uuid.uuid4().hex[:10]; ns = 'v2-verify'
    name, pod_name = 'v2-security-secret-' + suffix, 'v2-security-probe-' + suffix
    items = []
    values = [uuid.uuid4().hex, uuid.uuid4().hex]
    secret = {'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': name, 'namespace': ns, 'labels': {lab.OWNER: lab.VALUE}},
              'type': 'Opaque', 'stringData': {'canary': values[0]}}
    try:
        current = json.loads(lab.k('create', '-f', '-', '-o', 'json', stdin=json.dumps(secret)))
        secret_uid = current['metadata']['uid']
        items.append({'namespace': ns, 'kind': 'Secret', 'name': name, 'uid': secret_uid});save_journal(items, state['cluster_uid'])
        for index, value in enumerate(values):
            if index:
                current = owned_object(ns, 'secret', name)
                assert current['metadata']['uid'] == secret_uid
                current['data'] = {'canary': base64.b64encode(value.encode()).decode()}
                lab.k('replace', '-f', '-', stdin=json.dumps(current))
            pod = pod_spec(pod_name, ns, name)
            made = json.loads(lab.k('create', '-f', '-', '-o', 'json', stdin=json.dumps(pod)))
            uid = made['metadata']['uid'];items.append({'namespace': ns, 'kind': 'Pod', 'name': pod_name, 'uid': uid});save_journal(items, state['cluster_uid'])
            lab.k('-n', ns, 'wait', '--for=condition=Ready', 'pod/' + pod_name, '--timeout=120s')
            # 실제 Service selector가 검증 Pod를 포함하지 않음을 확인함.
            services = json.loads(lab.k('-n', ns, 'get', 'services', '-o', 'json'))['items']
            assert all(not all(pod['metadata']['labels'].get(k) == v for k, v in service['spec'].get('selector', {}).items())
                       for service in services if service['spec'].get('selector'))
            digest = lab.k('-n', ns, 'exec', pod_name, '--', 'python', '-c', "import hashlib; print(hashlib.sha256(open('/canary/canary','rb').read()).hexdigest())").strip()
            assert digest == hashlib.sha256(value.encode()).hexdigest()
            if not index:
                update = owned_object(ns, 'pod', pod_name);update['metadata']['labels'].pop(lab.OWNER)
                dry_run(update, boundary.NAME, update=True)
                # UPDATE 이미지 우회와 ephemeral subresource를 실제 기존 Pod에 dry-run함.
                update = owned_object(ns, 'pod', pod_name);update['spec']['containers'][0]['image'] = 'localhost:5001/v2-book:latest'
                dry_run(update, boundary.NAME, update=True)
                update = owned_object(ns, 'pod', pod_name)
                update['spec']['ephemeralContainers'] = [{'name': 'bypass', 'image': pod['spec']['containers'][0]['image'],
                    'securityContext': {'runAsNonRoot': True, 'runAsUser': 10001, 'allowPrivilegeEscalation': False,
                                        'capabilities': {'drop': ['ALL']}}}]
                try:
                    lab.k('replace', '--raw', '/api/v1/namespaces/' + ns + '/pods/' + pod_name + '/ephemeralcontainers?dryRun=All',
                          '-f', '-', stdin=json.dumps(update))
                except RuntimeError as error:
                    if boundary.NAME not in str(error): raise RuntimeError('ephemeral API가 예상한 정책으로 거부되지 않음') from None
                else:
                    raise RuntimeError('ephemeral API 우회가 허용됨')
            lab.k('delete', '--raw', '/api/v1/namespaces/' + ns + '/pods/' + pod_name, '-f', '-',
                stdin=json.dumps({'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': uid}}))
            lab.k('-n', ns, 'wait', '--for=delete', 'pod/' + pod_name, '--timeout=120s')
            items.pop();save_journal(items, state['cluster_uid'])
        return {'canary_secret_uid_preserved': True, 'readbacks': 2, 'pod_recreated': True,
                'update_bypass_rejected': True, 'ephemeral_bypass_rejected': True, 'values_logged': False}
    finally:
        cleanup()


def binding_recovery(restore=False):
    """정확한 소유/UID Binding 한 개만 완화·복구함. journal은 복구 성공 후 제거함."""
    from secret_files import create_private
    state = lab.guard()
    application = lab.application_guard('security')
    if application['spec'].get('syncPolicy', {}).get('automated') or application.get('operation'):
        raise RuntimeError('자동/진행중 보안 sync가 있어 Binding 실습 거부')
    binding = boundary.owned_cluster(boundary.BINDING)
    policy = boundary.owned_cluster(boundary.POLICY)
    if restore:
        saved = json.loads(BREAKGLASS.read_text())
        if (saved['cluster_uid'] != state['cluster_uid'] or saved['binding_uid'] != binding['metadata']['uid']
                or saved['policy_uid'] != policy['metadata']['uid']):
            raise RuntimeError('Binding 복구 UID 불일치')
        actions = ['Deny']
    else:
        if BREAKGLASS.exists() or binding['spec']['validationActions'] != ['Deny']:
            raise RuntimeError('기존 복구 journal/예상 밖 Binding 상태')
        create_private(BREAKGLASS, (json.dumps({'cluster_uid': state['cluster_uid'],
            'binding_uid': binding['metadata']['uid'], 'policy_uid': policy['metadata']['uid']})+'\n').encode())
        actions = ['Warn', 'Audit']
    current = binding['spec']['validationActions']
    if current not in (['Deny'], ['Warn', 'Audit']):
        raise RuntimeError('예상 밖 Binding validationActions')
    lab.k('patch', boundary.BINDING, boundary.NAME, '--type=json', '-p', json.dumps([
        {'op': 'test', 'path': '/metadata/uid', 'value': binding['metadata']['uid']},
        {'op': 'test', 'path': '/spec/validationActions', 'value': current},
        {'op': 'replace', 'path': '/spec/validationActions', 'value': actions}]))
    # admission cache 반영 지연을 고려하되 정상/금지 판정이 확인되기 전에 journal을 지우지 않음.
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        obj = pod_spec('v2-security-recovery-' + uuid.uuid4().hex[:10])
        obj['spec']['containers'][0]['image'] = 'localhost:5001/v2-book:unfixed-security-test'
        try:
            dry_run(obj, boundary.NAME if restore else None)
            if restore: BREAKGLASS.unlink()
            return {'mode': 'Deny' if restore else 'Warn/Audit', 'uid_preserved': True}
        except RuntimeError:
            time.sleep(1)
    raise RuntimeError('Binding 변경 후 API 집행 확인 실패, 복구 journal 보존')


def recovery_exercise():
    try:
        binding_recovery()
    finally:
        if BREAKGLASS.exists(): binding_recovery(restore=True)
    return {'temporary_mode': 'Warn/Audit', 'restored': 'Deny', 'uid_guard': True}


def preserved():
    baseline = json.loads((lab.LOCAL / 'security-before.json').read_text())
    if baseline['cluster_uid'] != lab.guard()['cluster_uid']: raise RuntimeError('baseline cluster UID 불일치')
    for key, expected in baseline['resources'].items():
        ns, kind, name = key.split('/');obj = owned_object(ns, kind, name)
        actual = {'uid': obj['metadata']['uid']}
        if kind == 'Secret': actual['data_hash'] = hashlib.sha256(json.dumps(obj.get('data', {}), sort_keys=True).encode()).hexdigest()
        if actual != expected: raise RuntimeError('기존 자원 UID/Secret hash 변경')
    if application_snapshot() != baseline['apps']: raise RuntimeError('기존 앱 자원 변경')
    for ns in lab.ENVIRONMENTS.values():
        if book_snapshot(ns) != baseline['books'][ns] or persisted_samples(ns) != baseline['samples'][ns]:
            raise RuntimeError('기존 앱 샘플 변경')
    return len(baseline['resources'])


def verify(recovery=False):
    lab.guard()
    if any((lab.LOCAL / x).exists() for x in ('exercise.json', 'logging-collector-pause.json', 'security-binding-recovery.json')):
        raise RuntimeError('미복구 실습 상태 존재')
    report = {'source_commit': lab.run(['git', 'rev-parse', 'HEAD']).strip(), 'result': 'FAIL'}
    try:
        report['admission'] = admission_checks()
        report['rbac'] = rbac_checks()
        report['network'] = network_checks()
        report['secret_canary'] = canary_secret()
        if recovery: report['binding_recovery'] = recovery_exercise()
        report['preserved_resources'] = preserved()
        report['result'] = 'PASS'
        print('V2 admission·실제 제한 계정API·허용/차단 패킷·canary교체·기존자원 보존 PASS')
    finally:
        (lab.LOCAL / 'security-verification.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument('--audit-bootstrap', metavar='SHA')
    actions.add_argument('--cleanup', action='store_true')
    actions.add_argument('--restore-binding', action='store_true')
    parser.add_argument('--exercise-recovery', action='store_true')
    args = parser.parse_args()
    if args.audit_bootstrap: audit_bootstrap(args.audit_bootstrap)
    elif args.cleanup: cleanup()
    elif args.restore_binding: binding_recovery(restore=True)
    else: verify(args.exercise_recovery)
