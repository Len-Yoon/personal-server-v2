#!/usr/bin/env python3
"""V2 세 앱의 실제 trace·부모 관계·저장 속성·로그 상관관계 검증."""
import argparse
import base64
import json
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

import lab
from verify_logging import (NoRedirect, application_snapshot, grafana_json as loki_json,
                            owned_object, paused_collector, collector_is_paused)
from verify_services import execute, book_snapshot, persisted_samples

SYNTHETIC = 'v2-trace-private-fixture'
RESOURCE_KEYS = {'service.name', 'deployment.environment.name'}
SPAN_KEYS = {'http.request.method', 'http.route', 'http.response.status_code'}


def tempo_json(path):
    if not path.startswith('/api/traces/') or len(path) != len('/api/traces/') + 32:
        raise RuntimeError('허용되지 않은 Tempo trace API 경로')
    identity = 'admin:' + (lab.LOCAL / 'grafana-password').read_text().strip()
    request = urllib.request.Request('http://127.0.0.1:8083/api/datasources/proxy/uid/v2-tempo' + path,
        headers={'Authorization': 'Basic ' + base64.b64encode(identity.encode()).decode(), 'Accept': 'application/json'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=20) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise RuntimeError(f'로컬 Grafana Tempo proxy HTTP {error.code}') from None


def identifier(value, size):
    if not value:
        return ''
    if len(value) == size * 2 and all(c in '0123456789abcdefABCDEF' for c in value):
        return value.lower()
    return base64.b64decode(value, validate=True).hex()


def attributes(items):
    return {item['key']: next(iter(item['value'].values())) for item in items}


def inspect_trace(payload, trace_id, environment):
    encoded = json.dumps(payload)
    if SYNTHETIC in encoded:
        raise RuntimeError('합성 민감값이 저장 trace에 포함됨')
    rows = []
    for resource in payload.get('batches', payload.get('resourceSpans', [])):
        attrs = attributes(resource.get('resource', {}).get('attributes', []))
        if set(attrs) != RESOURCE_KEYS or attrs['deployment.environment.name'] != environment:
            raise RuntimeError('trace resource allowlist/환경 불일치')
        service = attrs['service.name']
        if service not in {'portal', 'book', 'youtube'}:
            raise RuntimeError('예상 밖 trace 서비스')
        for scope in resource.get('scopeSpans', resource.get('instrumentationLibrarySpans', [])):
            library = scope.get('scope', scope.get('instrumentationLibrary', {}))
            if library.get('name') != 'v2.http' or library.get('version') != '1' or library.get('attributes'):
                raise RuntimeError('trace scope allowlist 위반')
            for span in scope.get('spans', []):
                if identifier(span.get('traceId'), 16) != trace_id:
                    raise RuntimeError('trace ID 불일치')
                metadata = attributes(span.get('attributes', []))
                if set(metadata) != SPAN_KEYS or span.get('events') or span.get('links') or span.get('traceState') or span.get('status', {}).get('message'):
                    raise RuntimeError('trace span allowlist 위반')
                server = span.get('kind') in (2, 'SPAN_KIND_SERVER')
                client = span.get('kind') in (3, 'SPAN_KIND_CLIENT')
                expected_route = '/' if service == 'portal' and server else '/api/search'
                expected_name = 'HTTP ' + ('server' if server else 'client') + ' GET ' + expected_route
                if not (server or client) or metadata.get('http.request.method') != 'GET' or metadata.get('http.route') != expected_route or span.get('name') != expected_name:
                    raise RuntimeError('trace name/method/route allowlist 위반')
                if str(metadata.get('http.response.status_code')) != '200':
                    raise RuntimeError('내부 호출이 HTTP200이 아님')
                rows.append({'service': service, 'id': identifier(span['spanId'], 8),
                    'parent': identifier(span.get('parentSpanId'), 8), 'kind': span['kind'], 'name': span['name']})
    servers = {row['service']: row for row in rows if row['kind'] in (2, 'SPAN_KIND_SERVER')}
    clients = [row for row in rows if row['service'] == 'portal' and row['kind'] in (3, 'SPAN_KIND_CLIENT')]
    if set(servers) != {'portal', 'book', 'youtube'} or len(clients) != 2:
        raise RuntimeError('세 앱 server span 또는 Portal client span 누락')
    client_ids = {row['id'] for row in clients if row['parent'] == servers['portal']['id']}
    if len(client_ids) != 2 or any(servers[service]['parent'] not in client_ids for service in ('book', 'youtube')):
        raise RuntimeError('Portal→Book/YouTube 부모/자식 연결 불일치')
    return {'trace_id': trace_id, 'environment': environment, 'spans': rows, 'allowlist': 'PASS'}


def request_search(namespace, trace_id):
    parent = uuid.uuid4().hex[:16]
    code = '''import json,urllib.request,urllib.parse,time
url='http://127.0.0.1:8000/?'+urllib.parse.urlencode({'q':SYNTHETIC,'token':SYNTHETIC})
request=urllib.request.Request(url,headers={'traceparent':TRACEPARENT,'Authorization':'Bearer '+SYNTHETIC,'Cookie':'v2-fixture='+SYNTHETIC,'baggage':'private='+SYNTHETIC})
start=time.monotonic()
with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request,timeout=10) as response:
 assert response.status==200
 response.read()
print(json.dumps({'http':200,'elapsed_seconds':round(time.monotonic()-start,3)}))
'''.replace('TRACEPARENT', repr('00-' + trace_id + '-' + parent + '-01')).replace('SYNTHETIC', repr(SYNTHETIC))
    return execute(namespace, 'portal', code)


def observe(trace_id, environment):
    deadline = time.monotonic() + 100
    last = None
    while time.monotonic() < deadline:
        payload = tempo_json('/api/traces/' + trace_id)
        if payload:
            try:
                return inspect_trace(payload, trace_id, environment)
            except RuntimeError as error:
                last = str(error)
        time.sleep(2)
    raise RuntimeError('Tempo trace 연결 확인 시간 초과: ' + str(last))


def correlate(trace_id, environment, start_ns):
    expression = '{cluster="ps-v2",environment="' + environment + '"} |= "trace_id=' + trace_id + '"'
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        result = loki_json('/loki/api/v1/query_range', {'query': expression, 'start': start_ns, 'end': time.time_ns(), 'limit': 100})
        services = {stream['stream'].get('service') for stream in result.get('result', [])}
        if {'portal', 'book', 'youtube'} <= services:
            if any('trace_id' in stream['stream'] or 'span_id' in stream['stream'] for stream in result['result']):
                raise RuntimeError('trace ID가 Loki stream label로 추가됨')
            return sorted(services)
        time.sleep(2)
    raise RuntimeError('세 앱 Loki trace ID 로그 연결 시간 초과')


def tempo_pod():
    stateful = owned_object('v2-observability', 'statefulset', 'tempo')
    pods = json.loads(lab.k('-n', 'v2-observability', 'get', 'pods', '-l', 'app.kubernetes.io/name=tempo', '-o', 'json'))['items']
    candidates = [pod for pod in pods if not pod['metadata'].get('deletionTimestamp')
                  and pod['metadata'].get('labels', {}).get(lab.OWNER) == lab.VALUE
                  and any(ref.get('uid') == stateful['metadata']['uid'] for ref in pod['metadata'].get('ownerReferences', []))
                  and any(condition.get('type') == 'Ready' and condition.get('status') == 'True' for condition in pod.get('status', {}).get('conditions', []))]
    return candidates[0] if len(candidates) == 1 else None


def verify_retention(traces):
    """Alloy Pod가 없는 동안 Tempo 메모리를 재생성하여 exporter 재전송과 구분함."""
    lab.guard()
    application = lab.application_guard('tempo')
    if application['spec'].get('syncPolicy', {}).get('automated'):
        raise RuntimeError('Tempo 자동 sync 상태에서는 재생성 검증 거부')
    with paused_collector() as pause:
        before = tempo_pod()
        pvc = owned_object('v2-observability', 'pvc', 'tempo-data')
        if not before or pvc.get('status', {}).get('phase') != 'Bound':
            raise RuntimeError('Ready Tempo와 Bound PVC 필요')
        path = '/api/v1/namespaces/v2-observability/pods/' + before['metadata']['name']
        lab.k('delete', '--raw', path, '-f', '-', stdin=json.dumps({'apiVersion': 'v1', 'kind': 'DeleteOptions',
              'preconditions': {'uid': before['metadata']['uid']}}))
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            current = tempo_pod()
            if current and current['metadata']['uid'] != before['metadata']['uid']:
                break
            time.sleep(2)
        else:
            raise RuntimeError('Tempo 재생성 시간 초과')
        if owned_object('v2-observability', 'pvc', 'tempo-data')['metadata']['uid'] != pvc['metadata']['uid']:
            raise RuntimeError('Tempo PVC UID 변경')
        if not collector_is_paused(pause):
            raise RuntimeError('보존 조회 전 Alloy가 실행됨')
        for trace in traces:
            observe(trace['trace_id'], trace['environment'])
        if not collector_is_paused(pause):
            raise RuntimeError('보존 조회 중 Alloy가 실행됨')
        return {'old_pod_uid': before['metadata']['uid'], 'new_pod_uid': current['metadata']['uid'],
                'pvc_uid': pvc['metadata']['uid'], 'retained_traces': len(traces), 'alloy_absent_during_readback': True}


def verify(restart=False):
    state = lab.guard()
    if any((lab.LOCAL / name).exists() for name in ('exercise.json', 'logging-collector-pause.json')):
        raise RuntimeError('미복구 장애 실습/수집기 중지 기록 존재')
    before = application_snapshot()
    baseline_file = lab.LOCAL / 'tracing-before.json'
    baseline = json.loads(baseline_file.read_text()) if baseline_file.exists() else None
    if baseline and baseline['applications'] != before:
        raise RuntimeError('계측 전 기존 앱/PVC/Secret UID/hash와 불일치')
    report = {'source_commit': lab.run(['git', 'rev-parse', 'HEAD']).strip(), 'cluster_uid': state['cluster_uid'], 'result': 'FAIL'}
    try:
        start_ns = time.time_ns() - 60_000_000_000
        report['traces'] = []
        for environment, namespace in lab.ENVIRONMENTS.items():
            trace_id = uuid.uuid4().hex
            request = request_search(namespace, trace_id)
            trace = observe(trace_id, environment)
            trace.update(request=request, log_services=correlate(trace_id, environment, start_ns))
            report['traces'].append(trace)
        if restart:
            report['retention'] = verify_retention(report['traces'])
        if application_snapshot() != before:
            raise RuntimeError('검증 중 기존 앱 자원 변경')
        for namespace in lab.ENVIRONMENTS.values():
            if baseline and (book_snapshot(namespace) != baseline['book'][namespace] or persisted_samples(namespace) != baseline['samples'][namespace]):
                raise RuntimeError('기존 샘플 데이터 변경')
        report['existing_resources_and_samples'] = 'PASS'
        report['result'] = 'PASS'
        print('dev/verify 세 앱 trace 부모 연결·저장 속성 allowlist·Loki 상관 ID·기존 자원/샘플 보존 PASS')
    finally:
        (lab.LOCAL / 'tracing-verification.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--restart-tempo', action='store_true', help='Alloy를 잠시 멈추고 UID 전제조건으로 Tempo Pod만 재생성하여 동일 PVC의 이전 trace 조회')
    verify(parser.parse_args().restart_tempo)
