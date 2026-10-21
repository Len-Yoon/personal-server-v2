#!/usr/bin/env python3
"""V2 실제 지표·Grafana provisioning·선택적 가용성 장애 회귀 검증."""
import argparse
import base64
import json
from pathlib import Path
import time
from types import SimpleNamespace
import urllib.parse
import urllib.request
import lab


def get_json(url, headers=None):
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}), timeout=15) as response:
        return json.load(response)


def query(expression):
    response = get_json('http://127.0.0.1:8084/api/v1/query?' + urllib.parse.urlencode({'query': expression}))
    if response.get('status') != 'success':
        raise RuntimeError('PromQL 오류')
    return response['data']['result']


def wait_for(predicate, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(5)
    raise RuntimeError('관측 기대 상태 시간 초과')


def verify(run_fault=False):
    state = lab.guard()
    lab.namespace_guard('v2-observability')
    report = {'cluster_uid': state['cluster_uid'], 'source_commit': lab.run(['git', 'rev-parse', 'HEAD']).strip(),
              'scope': 'V2 automated metrics verification, not user diagnosis'}
    def healthy_targets():
        targets = get_json('http://127.0.0.1:8084/api/v1/targets')['data']['activeTargets']
        report['targets'] = [{'job': target['labels']['job'], 'health': target['health'], 'lastError': target.get('lastError', '')} for target in targets]
        return len(targets) >= 13 and all(target['health'] == 'up' for target in targets)
    try:
        wait_for(healthy_targets)
        probes = query('probe_success{job="book-http"}')
        assert {r['metric']['environment'] for r in probes if r['value'][1] == '1'} == {'dev', 'verify'}
        wait_for(lambda: len(query('container_memory_working_set_bytes{namespace=~"v2-(dev|verify)",container="book"}')) >= 2)
        assert query('kube_deployment_status_replicas_available{namespace="v2-dev",deployment="book"}')[0]['value'][1] == '1'
        assert query('argocd_app_info')
        report['book_probes'] = 'dev/verify success1'
        report['pod_memory_metrics'] = 'both Book environments present'
        report['kube_state_metrics'] = 'Book available replica1'
        report['argocd_metrics'] = 'application info present'
        identity = 'admin:' + (lab.LOCAL / 'grafana-password').read_text().strip()
        auth = {'Authorization': 'Basic ' + base64.b64encode(identity.encode()).decode()}
        assert get_json('http://127.0.0.1:8083/api/health')['database'] == 'ok'
        dashboard = get_json('http://127.0.0.1:8083/api/dashboards/uid/v2-platform-lab', auth)['dashboard']
        assert len(dashboard['panels']) >= 8
        assert get_json('http://127.0.0.1:8083/api/datasources/uid/v2-prometheus/health', auth)['status'] == 'OK'
        report['grafana'] = {'dashboard_uid': dashboard['uid'], 'panels': len(dashboard['panels']), 'datasource_health': 'OK'}
        checks = {}
        for resource in ('nodes/metrics', 'nodes/proxy', 'secrets'):
            kind, _, subresource = resource.partition('/')
            args = ['auth', 'can-i', 'get', kind, '--as=system:serviceaccount:v2-observability:v2-prometheus']
            if subresource:
                args.append('--subresource=' + subresource)
            checks[resource] = lab.k(*args, check=False).strip()
        assert checks == {'nodes/metrics': 'yes', 'nodes/proxy': 'no', 'secrets': 'no'}, checks
        report['rbac'] = checks
        if run_fault:
            if (lab.LOCAL / 'exercise.json').exists():
                raise RuntimeError('기존 장애 실습을 먼저 복구해야 함')
            lab.exercise(SimpleNamespace(fault='probe'))
            try:
                wait_for(lambda: any(r['value'][1] == '0' for r in query('probe_success{job="book-http",environment="verify"}')))
                wait_for(lambda: bool(query('ALERTS{alertname="V2BookUnavailable",alertstate="firing",environment="verify"}')))
                report['fault'] = 'verify readiness failure → probe_success0 → V2BookUnavailable firing'
            finally:
                lab.restore(None)
            wait_for(lambda: any(r['value'][1] == '1' for r in query('probe_success{job="book-http",environment="verify"}')))
            wait_for(lambda: not query('ALERTS{alertname="V2BookUnavailable",alertstate="firing",environment="verify"}'))
            report['recovery'] = 'Book rollout → probe_success1 → firing cleared'
        report['result'] = 'PASS'
        print('지표 수집·Book 가용성·Grafana·RBAC' + ('·실패 감지/복구' if run_fault else '') + ' PASS')
    finally:
        (lab.LOCAL / 'observability-verification.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')


if __name__ == '__main__':
    import os
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-fault', action='store_true', help='V2 검증 Book readiness 장애·복구 및 alert firing/해제 검증')
    verify(parser.parse_args().run_fault)
