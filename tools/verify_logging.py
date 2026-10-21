#!/usr/bin/env python3
"""V2 API 로그 수집·합성 값 마스킹·Loki Pod 재생성 후 데이터 조회 검증."""
import argparse
import base64
from contextlib import contextmanager
import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

import lab
from verify_services import execute


NAMESPACES = ('argocd', 'v2-dev', 'v2-verify', 'v2-observability')
SERVICES = {'book': 8003, 'portal': 8000, 'youtube': 8002}
LOKI_NAMESPACE = 'v2-observability'
LOKI_PVC = 'loki-data'
PAUSE = lab.LOCAL / 'logging-collector-pause.json'
SYNTHETIC_VALUE = 'v2-nonsecret-redaction-fixture'
DS_PROXY = 'http://127.0.0.1:8083/api/datasources/proxy/uid/v2-loki'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # 로컬 Grafana Basic 인증이 다른 목적지로 전송되지 않도록 함.
        return None


def grafana_json(path, parameters=None):
    if not path.startswith('/loki/api/v1/'):
        raise RuntimeError('허용되지 않은 Loki API 경로')
    credentials = 'admin:' + (lab.LOCAL / 'grafana-password').read_text().strip()
    url = DS_PROXY + path
    if parameters:
        url += '?' + urllib.parse.urlencode(parameters, doseq=True)
    request = urllib.request.Request(url, headers={
        'Authorization': 'Basic ' + base64.b64encode(credentials.encode()).decode()})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=20) as response:
            result = json.load(response)
    except urllib.error.HTTPError as error:
        # 응답 본문·인증 헤더·실제 로그 원문을 예외/증적으로 출력하지 않음.
        raise RuntimeError(f'로컬 Grafana Loki proxy HTTP {error.code}') from None
    if result.get('status') != 'success':
        raise RuntimeError('Loki API가 성공 상태를 반환하지 않음')
    return result['data']


def check_grafana_panels():
    """proxy 직접 조회에 더해 실제 Grafana datasource backend의 프레임 변환을 검증함."""
    dashboard = json.loads((lab.ROOT / 'platforms/observability/grafana/chart/files/v2-logs.json').read_text())
    queries = []
    for panel in dashboard['panels']:
        target = dict(panel['targets'][0])
        for variable in ('environment', 'namespace', 'service'):
            target['expr'] = target['expr'].replace('$' + variable, '.*')
        target.update(refId=str(panel['id']), intervalMs=15000, maxDataPoints=400)
        queries.append(target)
    credentials = 'admin:' + (lab.LOCAL / 'grafana-password').read_text().strip()
    request = urllib.request.Request('http://127.0.0.1:8083/api/ds/query',
        data=json.dumps({'from': 'now-30m', 'to': 'now', 'queries': queries}).encode(),
        headers={'Authorization': 'Basic ' + base64.b64encode(credentials.encode()).decode(),
                 'Content-Type': 'application/json'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=30) as response:
            result = json.load(response)
    except urllib.error.HTTPError as error:
        raise RuntimeError(f'로컬 Grafana 패널 query HTTP {error.code}') from None
    results = result.get('results', {})
    if len(results) != len(queries) or any(row.get('error') or row.get('status', 200) != 200 for row in results.values()):
        raise RuntimeError('Grafana 로그 패널 backend query 실패')
    if not results.get('2', {}).get('frames'):
        raise RuntimeError('Grafana 서비스 로그 프레임 누락')
    return {'queries': len(queries), 'frames': sum(len(row.get('frames', [])) for row in results.values())}


def query_lines(namespace, service, marker, start_ns):
    if namespace not in lab.ENVIRONMENTS.values() or service not in SERVICES:
        raise RuntimeError('V2 앱 로그 범위 불일치')
    if not marker.startswith('v2-log-canary-') or not marker[14:].isalnum():
        raise RuntimeError('허용되지 않은 합성 로그 식별자')
    query = '{cluster="ps-v2",namespace=' + json.dumps(namespace) + ',service=' + json.dumps(service) + '} |= ' + json.dumps(marker)
    data = grafana_json('/loki/api/v1/query_range', {'query': query, 'start': str(start_ns),
                         'end': str(time.time_ns()), 'limit': 1000, 'direction': 'forward'})
    if data.get('resultType') != 'streams':
        raise RuntimeError('예상하지 않은 Loki query 결과 유형')
    return [(stream['stream'], line) for stream in data.get('result', []) for _, line in stream.get('values', [])]


def canary_code(port, marker):
    if port not in SERVICES.values() or not marker.startswith('v2-log-canary-') or not marker[14:].isalnum():
        raise RuntimeError('합성 HTTP 요청 범위 불일치')
    endpoint = f'http://127.0.0.1:{port}/{marker}?token={SYNTHETIC_VALUE}'
    return """import json,urllib.request,urllib.error
try:
 with urllib.request.urlopen(ENDPOINT,timeout=10) as response:
  status=response.status
except urllib.error.HTTPError as error:
 status=error.code
assert status==404, '합성 경로는 404여야 함'
print(json.dumps({'http':status,'synthetic':True}))
""".replace('ENDPOINT', repr(endpoint))


def create_canaries():
    canaries = []
    for environment, namespace in lab.ENVIRONMENTS.items():
        for service, port in SERVICES.items():
            marker = 'v2-log-canary-' + uuid.uuid4().hex
            result = execute(namespace, service, canary_code(port, marker))
            if result.get('http') != 404:
                raise RuntimeError('합성 HTTP 요청 확인 실패')
            canaries.append({'namespace': namespace, 'environment': environment, 'service': service,
                             'marker': marker})
    return canaries


def observe_canaries(canaries, start_ns, timeout=180):
    results = []
    deadline = time.monotonic() + timeout
    for canary in canaries:
        while time.monotonic() < deadline:
            rows = query_lines(canary['namespace'], canary['service'], canary['marker'], start_ns)
            if rows:
                if any(SYNTHETIC_VALUE in line for _, line in rows):
                    raise RuntimeError('합성 token 값이 마스킹 없이 Loki에 저장됨')
                matches = [(labels, line) for labels, line in rows if '[REDACTED]' in line]
                if not matches:
                    raise RuntimeError('합성 token 마스킹 표식 누락')
                labels, line = matches[0]
                expected = {key: canary[key] for key in ('namespace', 'environment', 'service')}
                expected['cluster'] = 'ps-v2'
                if any(labels.get(key) != value for key, value in expected.items()) or not labels.get('pod') or not labels.get('container'):
                    raise RuntimeError('로그의 V2 namespace/service/environment/pod/container 표식 불일치')
                results.append({**canary, 'labels': labels, 'redacted': True,
                                'line_sha256': hashlib.sha256(line.encode()).hexdigest()})
                break
            time.sleep(3)
        else:
            raise RuntimeError('6개 V2 앱 합성 로그 수집 대기 시간 초과')
    return results


def check_namespace_scope(start_ns):
    data = grafana_json('/loki/api/v1/series', {'match[]': '{cluster="ps-v2"}',
                        'start': str(start_ns), 'end': str(time.time_ns())})
    namespaces = {stream.get('namespace') for stream in data}
    if not namespaces or not namespaces <= set(NAMESPACES):
        raise RuntimeError('허용한 4개 namespace 밖의 로그 표식 감지')
    return sorted(namespaces)


def check_rbac():
    identity = 'system:serviceaccount:v2-observability:v2-alloy'
    checks = {}
    for namespace in NAMESPACES:
        answer = lab.k('auth', 'can-i', 'get', 'pods', '--subresource=log', '-n', namespace,
                       '--as=' + identity, check=False).strip()
        checks[f'{namespace}:get:pods/log'] = answer
        if answer != 'yes':
            raise RuntimeError('Alloy의 허용 namespace Pod 로그 읽기 권한 누락')
    denied = [('get', 'pods', 'log', 'kube-system'), ('get', 'secrets', None, 'v2-dev'),
              ('get', 'secrets', None, 'v2-observability'), ('create', 'pods', 'exec', 'v2-dev'),
              ('get', 'nodes', 'proxy', None)]
    for verb, resource, subresource, namespace in denied:
        args = ['auth', 'can-i', verb, resource, '--as=' + identity]
        if subresource:
            args.append('--subresource=' + subresource)
        if namespace:
            args.extend(['-n', namespace])
        answer = lab.k(*args, check=False).strip()
        checks[f'{namespace or "cluster"}:{verb}:{resource}/{subresource or ""}'] = answer
        if answer != 'no':
            raise RuntimeError('Alloy에 범위 밖 logs/Secret/exec/node proxy 권한 존재')
    return checks


def owned_object(namespace, kind, name):
    lab.namespace_guard(namespace)
    # Secret 본문을 읽기 전에 UID·V2 소유 표식만 조회함.
    identity = lab.k('-n', namespace, 'get', kind, name,
                     '-o=jsonpath={.metadata.uid}{"\\n"}{.metadata.labels.lab\\.personal-server-v2/owner}').splitlines()
    if len(identity) != 2 or not identity[0] or identity[1] != lab.VALUE:
        raise RuntimeError('검증 대상 자원의 V2 UID/소유 표식 불일치')
    result = json.loads(lab.k('-n', namespace, 'get', kind, name, '-o', 'json'))
    if result['metadata']['uid'] != identity[0] or result['metadata'].get('labels', {}).get(lab.OWNER) != lab.VALUE:
        raise RuntimeError('검증 중 자원 교체 감지')
    return result


def application_snapshot():
    result = {}
    for namespace in lab.ENVIRONMENTS.values():
        objects = {}
        for service in SERVICES:
            deployment = owned_object(namespace, 'deployment', service)
            pvc = owned_object(namespace, 'pvc', service + '-data')
            secret = owned_object(namespace, 'secret', service + '-auth')
            objects[service] = {'deployment_uid': deployment['metadata']['uid'],
                                'pvc_uid': pvc['metadata']['uid'],
                                'secret_uid': secret['metadata']['uid'],
                                'secret_data_sha256': hashlib.sha256(json.dumps(secret.get('data', {}), sort_keys=True).encode()).hexdigest()}
        result[namespace] = objects
    return result


def loki_pod():
    stateful = owned_object(LOKI_NAMESPACE, 'statefulset', 'loki')
    pods = json.loads(lab.k('-n', LOKI_NAMESPACE, 'get', 'pods', '-o', 'json'))['items']
    matches = [pod for pod in pods if pod['metadata'].get('labels', {}).get(lab.OWNER) == lab.VALUE
               and not pod['metadata'].get('deletionTimestamp')
               and any(ref.get('uid') == stateful['metadata']['uid'] and ref.get('kind') == 'StatefulSet' for ref in pod['metadata'].get('ownerReferences', []))
               and any(condition.get('type') == 'Ready' and condition.get('status') == 'True' for condition in pod.get('status', {}).get('conditions', []))]
    if len(matches) != 1:
        return None
    return matches[0]


def recreate_loki():
    lab.guard()
    pod = loki_pod()
    if not pod:
        raise RuntimeError('Ready V2 Loki Pod 1개 필요')
    pvc = owned_object(LOKI_NAMESPACE, 'pvc', LOKI_PVC)
    if pvc.get('status', {}).get('phase') != 'Bound':
        raise RuntimeError('Loki PVC가 Bound 상태가 아님')
    path = '/api/v1/namespaces/' + LOKI_NAMESPACE + '/pods/' + pod['metadata']['name']
    body = {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': pod['metadata']['uid']}}
    lab.k('delete', '--raw', path, '-f', '-', stdin=json.dumps(body))
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        lab.guard()
        current = loki_pod()
        if current and current['metadata']['uid'] != pod['metadata']['uid']:
            after = owned_object(LOKI_NAMESPACE, 'pvc', LOKI_PVC)
            if after['metadata']['uid'] != pvc['metadata']['uid']:
                raise RuntimeError('Loki 재생성 후 PVC UID 변경')
            return {'old_pod_uid': pod['metadata']['uid'], 'new_pod_uid': current['metadata']['uid'],
                    'pvc_uid': pvc['metadata']['uid']}
        time.sleep(3)
    raise RuntimeError('Loki Pod 재생성 시간 초과')


def collector_is_paused(snapshot):
    deployment = owned_object(LOKI_NAMESPACE, 'deployment', 'alloy')
    if deployment['metadata']['uid'] != snapshot['deployment_uid'] or deployment['spec']['replicas'] != 0:
        raise RuntimeError('Alloy 중지 상태의 UID/replicas 변경 감지')
    pods = json.loads(lab.k('-n', LOKI_NAMESPACE, 'get', 'pods', '-l', 'app.kubernetes.io/name=alloy', '-o', 'json'))['items']
    return not pods


def restore_collector():
    state = lab.guard()
    snapshot = json.loads(PAUSE.read_text())
    if snapshot.get('cluster_uid') != state['cluster_uid'] or snapshot.get('replicas') != 1:
        raise RuntimeError('수집기 복구 snapshot의 cluster UID/replicas 불일치')
    deployment = owned_object(LOKI_NAMESPACE, 'deployment', 'alloy')
    if deployment['metadata']['uid'] != snapshot.get('deployment_uid'):
        raise RuntimeError('수집기 복구 대상 Deployment UID 불일치')
    current_replicas = deployment['spec']['replicas']
    if current_replicas not in (0, 1):
        raise RuntimeError('수집기 복구 전 예상하지 않은 replicas')
    operations = [{'op': 'test', 'path': '/metadata/uid', 'value': snapshot['deployment_uid']},
                  {'op': 'test', 'path': '/spec/replicas', 'value': current_replicas},
                  {'op': 'replace', 'path': '/spec/replicas', 'value': snapshot['replicas']}]
    lab.k('-n', LOKI_NAMESPACE, 'patch', 'deployment', 'alloy', '--type=json', '-p', json.dumps(operations))
    lab.k('-n', LOKI_NAMESPACE, 'rollout', 'status', 'deployment/alloy', '--timeout=180s')
    PAUSE.unlink()
    print('V2 Alloy 수집기 replicas1 복구·rollout PASS')


@contextmanager
def paused_collector():
    state = lab.guard()
    if PAUSE.exists():
        raise RuntimeError('기존 수집기 중지 기록 존재. --restore-collector 먼저 실행 필요')
    application = lab.application_guard('alloy')
    if application['spec'].get('syncPolicy', {}).get('automated'):
        raise RuntimeError('Alloy 자동 동기화를 끈 뒤 로그 영속성 검증 필요')
    deployment = owned_object(LOKI_NAMESPACE, 'deployment', 'alloy')
    if deployment['spec']['replicas'] != 1:
        raise RuntimeError('수집기 중지 전 replicas1 필요')
    snapshot = {'cluster_uid': state['cluster_uid'], 'deployment_uid': deployment['metadata']['uid'], 'replicas': 1}
    with PAUSE.open('x') as output:
        output.write(json.dumps(snapshot, indent=2) + '\n')
    PAUSE.chmod(0o600)
    try:
        operations = [{'op': 'test', 'path': '/metadata/uid', 'value': snapshot['deployment_uid']},
                      {'op': 'test', 'path': '/spec/replicas', 'value': 1},
                      {'op': 'replace', 'path': '/spec/replicas', 'value': 0}]
        lab.k('-n', LOKI_NAMESPACE, 'patch', 'deployment', 'alloy', '--type=json', '-p', json.dumps(operations))
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            if collector_is_paused(snapshot):
                break
            time.sleep(2)
        else:
            raise RuntimeError('Alloy 수집기 Pod 종료 대기 시간 초과')
        yield snapshot
    finally:
        # 조회·Loki 재생성 실패에도 원래 동일 Deployment만 복구함. 실패 시 snapshot 보존.
        restore_collector()


def verify_retention(canaries, start_ns):
    with paused_collector() as snapshot:
        recreation = recreate_loki()
        if not collector_is_paused(snapshot):
            raise RuntimeError('기존 로그 조회 전 Alloy 중지 확인 실패')
        retained = observe_canaries(canaries, start_ns)
        if not collector_is_paused(snapshot):
            raise RuntimeError('기존 로그 조회 중 Alloy 재실행 감지')
        if {item['marker'] for item in retained} != {item['marker'] for item in canaries}:
            raise RuntimeError('Loki Pod 재생성 후 기존 합성 로그 누락')
        return {'loki_recreation': recreation, 'retained_after_recreation': len(retained),
                'collector_paused_during_readback': True}


def verify(restart=False):
    state = lab.guard()
    if (lab.LOCAL / 'exercise.json').exists():
        raise RuntimeError('기존 장애 실습을 먼저 복구해야 함')
    if PAUSE.exists():
        raise RuntimeError('미복구 수집기 중지 기록 존재. python3 tools/verify_logging.py --restore-collector 실행 필요')
    report = {'scope': 'V2 synthetic log collection; not user diagnosis or delivery guarantee',
              'cluster_uid': state['cluster_uid'], 'source_commit': lab.run(['git', 'rev-parse', 'HEAD']).strip(), 'result': 'FAIL'}
    start_ns = time.time_ns() - 60 * 1_000_000_000
    try:
        before = application_snapshot()
        report['rbac'] = check_rbac()
        canaries = create_canaries()
        report['canaries'] = observe_canaries(canaries, start_ns)
        report['collected_namespaces'] = check_namespace_scope(start_ns)
        report['grafana_panels'] = check_grafana_panels()
        if restart:
            # Alloy가 중지된 동안 새 요청 없이 이전 UUID를 조회하여 재수집과 구분함.
            report.update(verify_retention(canaries, start_ns))
        after = application_snapshot()
        if after != before:
            raise RuntimeError('로그 검증 중 기존 앱·Secret·PVC UID/비밀값 hash 변경')
        report['existing_app_resources_preserved'] = after
        report['result'] = 'PASS'
        print('6개 앱 로그 수집·합성 token 마스킹·namespace/RBAC 경계' + ('·Loki Pod 재생성 후 조회' if restart else '') + ' PASS')
    finally:
        (lab.LOCAL / 'logging-verification.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument('--restart-loki', action='store_true', help='Alloy를 잠시 중지하고 Loki Pod를 UID 전제조건으로 재생성한 뒤 같은 PVC의 이전 로그 조회·수집기 복구 확인')
    actions.add_argument('--restore-collector', action='store_true', help='중단된 검증의 snapshot UID와 일치하는 Alloy Deployment를 원래 replicas1로 복구')
    args = parser.parse_args()
    if args.restore_collector:
        restore_collector()
    else:
        verify(args.restart_loki)
