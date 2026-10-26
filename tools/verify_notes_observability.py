"""V2 메모 관측·정상 상태 유지·데이터 보존 검증. 읽기 요청만 생성함."""
import argparse
import base64
import hashlib
import json
import math
import time
import urllib.error
import urllib.parse
import urllib.request

import lab
import data_lab as data
import verify_data
from verify_security import preserved

BASELINE = lab.LOCAL / 'enhancement-before.json'
REPORT = lab.LOCAL / 'notes-enhancement-verification.json'
NAMESPACES = (*data.NAMESPACES, 'v2-observability', 'v2-dev', 'v2-verify')


def private_json(path, value):
    from secret_files import replace_private
    replace_private(path, (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode())


def snapshot():
    state = lab.guard()
    value = {'cluster_uid': state['cluster_uid'], 'preserved': preserved(), 'resources': {}, 'rows': {}}
    for ns in NAMESPACES:
        lab.namespace_guard(ns)
        kinds = 'pvc,secret,statefulset,deployment,service' if ns in data.NAMESPACES else 'pvc,secret'
        for obj in json.loads(lab.k('-n', ns, 'get', kinds, '-l', lab.OWNER + '=' + lab.VALUE, '-o', 'json'))['items']:
            kind = obj['kind'].lower()
            record = {'uid': obj['metadata']['uid']}
            if kind == 'secret':
                record['hash'] = hashlib.sha256(json.dumps(obj.get('data', {}), sort_keys=True).encode()).hexdigest()
            elif ns in data.NAMESPACES and kind != 'deployment':
                record['spec_hash'] = hashlib.sha256(json.dumps(obj.get('spec', {}), sort_keys=True).encode()).hexdigest()
            value['resources'][ns + '/' + kind + '/' + obj['metadata']['name']] = record
    for ns, database in zip(data.NAMESPACES, ('notes', 'notes_restore')):
        data.owned(ns, 'statefulset', 'postgres')
        output = lab.k('-n', ns, 'exec', 'postgres-0', '--', 'psql', '-U', 'notes_owner', '-d', database, '-At', '-c',
            'SELECT row_to_json(n)::text FROM (SELECT * FROM public.notes ORDER BY id) n;')
        value['rows'][ns] = {'count': len(output.splitlines()), 'hash': hashlib.sha256(output.encode()).hexdigest()}
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def http_json(url, headers=None, body=None):
    target = urllib.parse.urlsplit(url)
    if target.scheme != 'http' or target.netloc not in ('127.0.0.1:8083', '127.0.0.1:8084'):
        raise RuntimeError('고정 V2 loopback 관측 주소만 허용함')
    if headers and target.netloc != '127.0.0.1:8083':
        raise RuntimeError('Grafana 외 인증 헤더 전송 금지')
    request = urllib.request.Request(url, headers=headers or {},
        data=None if body is None else json.dumps(body).encode())
    if body is not None:
        request.add_header('Content-Type', 'application/json')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=15) as response:
        return json.load(response)


def grafana_panels(dashboard, auth):
    queries = []
    for panel in dashboard['panels']:
        for target in panel['targets']:
            queries.append({**target, 'refId': str(panel['id']), 'datasource': panel['datasource'],
                'instant': True, 'range': False, 'intervalMs': 15000, 'maxDataPoints': 30})
    value = http_json('http://127.0.0.1:8083/api/ds/query', auth,
        {'from': 'now-2m', 'to': 'now', 'queries': queries})
    results = value.get('results', {})
    if set(results) != {q['refId'] for q in queries}:
        raise RuntimeError('Grafana 패널 결과 누락')
    for row in results.values():
        if row.get('error') or row.get('status', 200) != 200:
            raise RuntimeError('Grafana 패널 backend 실패')
        numbers = []
        for frame in row.get('frames', []):
            for i, field in enumerate(frame['schema']['fields']):
                if field['type'] == 'number':
                    numbers.extend(v for v in frame['data']['values'][i] if isinstance(v, (int, float)) and math.isfinite(v))
        if not numbers:
            raise RuntimeError('Grafana 패널 수치 프레임 누락')
    return len(results)


def query(expression):
    value = http_json('http://127.0.0.1:8084/api/v1/query?' + urllib.parse.urlencode({'query': expression}))
    if value.get('status') != 'success':
        raise RuntimeError('PromQL 조회 실패')
    return value['data']['result']


def numeric(expression):
    rows = query(expression)
    if len(rows) != 1:
        raise RuntimeError('메모 API 단일 지표 필요')
    value = float(rows[0]['value'][1])
    if not math.isfinite(value):
        raise RuntimeError('메모 API 유한 지표 필요')
    return value


def workload_health():
    values = {}
    for ns in NAMESPACES:
        for pod in json.loads(lab.k('-n', ns, 'get', 'pods', '-l', lab.OWNER + '=' + lab.VALUE, '-o', 'json'))['items']:
            if not any(ref['kind'] in ('ReplicaSet', 'StatefulSet') for ref in pod['metadata'].get('ownerReferences', [])):
                continue
            if pod['metadata'].get('deletionTimestamp'):
                raise RuntimeError('안정화 중 종료 Pod 존재')
            statuses = pod['status'].get('containerStatuses', [])
            if pod['status'].get('phase') != 'Running' or not statuses or not all(c['ready'] for c in statuses):
                raise RuntimeError('안정화 중 준비되지 않은 서비스')
            values[ns + '/' + pod['metadata']['name']] = {'uid': pod['metadata']['uid'],
                'restarts': sum(c.get('restartCount', 0) for c in statuses)}
    if not values:
        raise RuntimeError('관측할 서비스 없음')
    return values


def verify(soak_seconds):
    state = lab.guard()
    before = json.loads(BASELINE.read_text())
    if before.get('cluster_uid') != state['cluster_uid']:
        raise RuntimeError('고도화 baseline cluster UID 불일치')
    report = {'result': 'FAIL', 'commit': lab.run(['git', 'rev-parse', 'HEAD']).strip(),
              'scope': '맥북 V2 자동 검증, 사용자 직접 실습·장기 안정성 보장과 구분', 'samples': []}
    try:
        for path, auth, status in [('/version', False, 200), ('/ready', False, 200),
                ('/notes', False, 401), ('/notes?limit=0', True, 422), ('/notes', True, 200)]:
            response = verify_data.api('v2-data-dev', path=path, auth=auth)
            if response['status'] != status:
                raise RuntimeError('메모 API 응답 계약 불일치')
        response = verify_data.api('v2-data-dev', path='/version', auth=False)
        assert response['body'] == {'service': 'v2-notes-api', 'version': '1.2.0'}
        lock = json.loads((lab.ROOT / 'platforms/data/images.lock.json').read_text())
        pod = json.loads(lab.k('-n', 'v2-data-dev', 'get', 'pod', data.pod('v2-data-dev', 'notes-api'), '-o', 'json'))
        assert pod['spec']['containers'][0]['image'] == lock['api']['image']
        assert pod['status']['containerStatuses'][0]['imageID'].endswith(lock['api']['image'].split('@')[1])
        metrics = data.execute('v2-data-dev', 'notes-api',
            "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8000/metrics').read().decode(),end='')")
        lab.namespace_guard('v2-observability')
        lab.refuse_foreign('Deployment', 'prometheus', 'v2-observability')
        lab.k('-n', 'v2-observability', 'exec', '-i', 'deployment/prometheus', '-c', 'prometheus-server',
              '--', 'promtool', 'check', 'metrics', stdin=metrics)
        identity = 'admin:' + (lab.LOCAL / 'grafana-password').read_text().strip()
        auth = {'Authorization': 'Basic ' + base64.b64encode(identity.encode()).decode()}
        deadline = time.monotonic() + 180
        while True:
            try:
                dashboard = http_json('http://127.0.0.1:8083/api/dashboards/uid/v2-notes-api', auth)['dashboard']
                break
            except urllib.error.HTTPError as error:
                if error.code != 404 or time.monotonic() >= deadline:
                    raise
                time.sleep(5)
        assert len(dashboard['panels']) == 8
        assert http_json('http://127.0.0.1:8083/api/datasources/uid/v2-prometheus/health', auth)['status'] == 'OK'
        # 새 시계열의 rate/분위수 계산에 필요한 두 scrape까지 준비 시간을 별도로 둠.
        deadline = time.monotonic() + 100
        while True:
            assert verify_data.api('v2-data-dev', path='/notes')['status'] == 200
            try:
                targets = http_json('http://127.0.0.1:8084/api/v1/targets')['data']['activeTargets']
                if (len(targets) == 27 and all(t['health'] == 'up' for t in targets)
                        and numeric('v2_notes_api_requests_total{job="notes-api"}') >= 3
                        and numeric('sum(rate(v2_notes_api_duration_seconds_count{job="notes-api"}[2m]))') > 0):
                    break
            except RuntimeError:
                pass
            if time.monotonic() >= deadline:
                raise RuntimeError('새 메모 지표 준비 시간 초과')
            time.sleep(5)
        stable_pods = workload_health()
        started = time.monotonic()
        while True:
            targets = http_json('http://127.0.0.1:8084/api/v1/targets')['data']['activeTargets']
            assert len(targets) == 27 and all(t['health'] == 'up' for t in targets)
            assert numeric('up{job="notes-api"}') == 1
            assert numeric('v2_notes_api_client_errors_total{job="notes-api"}') >= 2
            probes = query('probe_success{job="notes-http"}')
            assert {r['metric']['endpoint'] for r in probes if r['value'][1] == '1'} == {'health', 'ready'}
            apps = json.loads(lab.k('-n', 'argocd', 'get', 'applications', '-o', 'json'))['items']
            assert len(apps) == 18 and all(a['status']['sync']['status'] == 'Synced' and a['status']['health']['status'] == 'Healthy' for a in apps)
            assert workload_health() == stable_pods, '안정화 중 Pod 교체/재시작'
            assert data.owned('v2-data-restore', 'deployment', 'notes-api')['spec']['replicas'] == 0
            for path, auth_value, status in [('/ready', False, 200), ('/notes', True, 200), ('/notes', False, 401)]:
                assert verify_data.api('v2-data-dev', path=path, auth=auth_value)['status'] == status
            expressions = [target['expr'] for panel in dashboard['panels'] for target in panel.get('targets', [])]
            for expression in expressions:
                rows = query(expression)
                assert rows and all(math.isfinite(float(row['value'][1])) for row in rows)
            p95 = numeric('histogram_quantile(0.95, sum by (le) (rate(v2_notes_api_duration_seconds_bucket{job="notes-api"}[2m])))')
            errors = numeric('v2_notes_api_errors_total{job="notes-api"}')
            assert errors == 0, '정상 요청 중 5xx 관측'
            elapsed = time.monotonic() - started
            report['samples'].append({'elapsed_seconds': round(elapsed, 3), 'targets_up': len(targets),
                'applications_healthy': len(apps), 'p95_seconds': p95, 'api_5xx_total': errors})
            print('안정화 표본', len(report['samples']), 'PASS', round(elapsed), '초', flush=True)
            if elapsed >= soak_seconds:
                break
            time.sleep(min(15, soak_seconds - elapsed))
        after = snapshot()
        for key in ('cluster_uid', 'preserved', 'resources', 'rows'):
            assert after[key] == before[key], '원본 보존 기준 불일치: ' + key
        report['grafana_backend_queries'] = grafana_panels(dashboard, auth)
        report.update({'result': 'PASS', 'soak_seconds': round(time.monotonic() - started, 3),
            'data_rows': {k:v['count'] for k,v in after['rows'].items()}, 'preserved_resources': len(after['resources']),
            'existing_service_resources': after['preserved'], 'image': lock['api']['image'], 'dashboard_uid': dashboard['uid'],
            'dashboard_panels': len(dashboard['panels']), 'restore_api_replicas': 0, 'promtool_metrics': 'PASS'})
    finally:
        private_json(REPORT, report)
    print('V2 메모 관측·정상 상태 유지·데이터 보존 PASS')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', action='store_true', help='배포 전 보존 기준을 새로 기록함, 기존 기준 덮어쓰기 거부')
    parser.add_argument('--soak-seconds', type=int, default=180)
    args = parser.parse_args()
    if not 60 <= args.soak_seconds <= 600:
        parser.error('안정화 관측은 60~600초 범위 필요')
    if args.baseline:
        if BASELINE.exists():
            raise RuntimeError('기존 baseline 보존 필요, 자동 덮어쓰기 거부')
        private_json(BASELINE, snapshot())
    else:
        verify(args.soak_seconds)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('V2 메모 관측 검증 실패. 비밀값 보호로 상세 비출력, 로컬 결과와 현재 상태 확인 필요') from None
