#!/usr/bin/env python3
"""명시적으로 실행하는 V2 자동 장애 회귀 검증. 사람의 진단 실습과 구분함."""
import argparse
import json
from pathlib import Path
import time
from types import SimpleNamespace
import lab


def wait_for(predicate, timeout=100):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(2)
    raise RuntimeError('예상 증상 관찰 시간 초과')


def data_count(namespace):
    code = "import sqlite3,os; c=sqlite3.connect(os.environ['BOOK_MEMO_DB_PATH']); print(c.execute(\"select count(*) from books where isbn='v2-lab-001'\").fetchone()[0])"
    return int(lab.k('-n', namespace, 'exec', 'deployment/book', '--', 'python', '-c', code).strip())


def symptom(fault):
    if fault == 'worker':
        node = json.loads(lab.k('get', 'node', 'k3d-ps-v2-agent-0', '-o', 'json'))
        condition = next(c for c in node['status']['conditions'] if c['type'] == 'Ready')
        return condition['status'] if condition['status'] != 'True' else None
    pods = json.loads(lab.k('-n', 'v2-verify', 'get', 'pods', '-l', 'app.kubernetes.io/name=book', '-o', 'json'))['items']
    for pod in pods:
        if pod['metadata'].get('deletionTimestamp'):
            continue
        if fault == 'pending':
            for condition in pod['status'].get('conditions', []):
                if condition['type'] == 'PodScheduled' and condition['status'] == 'False':
                    return condition.get('reason')
        for status in pod['status'].get('containerStatuses', []):
            waiting = status.get('state', {}).get('waiting', {}).get('reason')
            if fault == 'image' and waiting in {'ErrImagePull', 'ImagePullBackOff'}:
                return waiting
            terminated = status.get('lastState', {}).get('terminated', {})
            if fault == 'oom' and terminated.get('reason') == 'OOMKilled':
                return 'OOMKilled'
            if fault == 'probe' and status.get('state', {}).get('running') and not status.get('ready'):
                # 이벤트의 HTTP404까지 확인해 단순 startup 대기를 오판하지 않음.
                events = json.loads(lab.k('-n', 'v2-verify', 'get', 'events', '--field-selector', 'involvedObject.uid=' + pod['metadata']['uid'], '-o', 'json'))
                if any('Readiness probe failed' in e.get('message', '') and '404' in e.get('message', '') for e in events['items']):
                    return 'Readiness HTTP 404'
    return None


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-faults', action='store_true', required=True, help='V2 worker0 일시 정지·샘플 앱 장애를 명시 승인')
    parser.parse_args()
    state = lab.guard()
    if (lab.LOCAL / 'exercise.json').exists():
        raise RuntimeError('기존 실습 snapshot을 먼저 복구해야 함')
    before = {ns: data_count(ns) for ns in lab.ENVIRONMENTS.values()}
    assert all(count == 1 for count in before.values()), 'seed 데이터 필요'
    results = []
    try:
        # 서버 admission에서 정책 거부를 확인하며 실제 Pod는 만들지 않음.
        deployment = json.loads(lab.k('-n', 'v2-verify', 'get', 'deployment', 'book', '-o', 'json'))
        pod = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': 'v2-budget-negative', 'namespace': 'v2-verify'}, 'spec': deployment['spec']['template']['spec']}
        pod['spec']['containers'][0]['resources'] = {'requests': {'cpu': '100m', 'memory': '2Gi'}, 'limits': {'cpu': '500m', 'memory': '2Gi'}}
        try:
            lab.k('create', '--dry-run=server', '-f', '-', stdin=json.dumps(pod))
        except RuntimeError as error:
            if 'maximum memory usage' not in str(error) and 'exceeded quota' not in str(error):
                raise
            results.append({'case': 'resource-policy', 'observed': 'admission rejected over-budget memory', 'result': 'PASS'})
        else:
            raise RuntimeError('자원 정책이 과다 요청을 거부하지 않음')
        for fault in ('image', 'pending', 'probe', 'oom', 'worker'):
            start = time.monotonic()
            lab.exercise(SimpleNamespace(fault=fault))
            try:
                observed = wait_for(lambda: symptom(fault))
                events = json.loads(lab.k('-n', 'v2-verify', 'get', 'events', '-o', 'json'))
                reasons = sorted({e.get('reason', '') for e in events['items']})
            finally:
                lab.restore(None)
            after = {ns: data_count(ns) for ns in lab.ENVIRONMENTS.values()}
            if after != before:
                raise RuntimeError('복구 후 샘플 데이터 불일치')
            results.append({'case': fault, 'observed': observed, 'event_reasons': reasons, 'sample_counts': after,
                            'seconds': round(time.monotonic() - start, 2), 'result': 'PASS'})
            print(f'{fault}: {observed} → 복구·샘플 데이터 PASS', flush=True)
    finally:
        report = {'scope': 'V2 local automated regression, not user diagnosis', 'cluster_uid': state['cluster_uid'],
                  'image': json.loads((lab.LOCAL / 'image.json').read_text())['image'], 'cases': results}
        (lab.LOCAL / 'runtime-verification.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    lab.check(None)


if __name__ == '__main__':
    import os
    os.umask(0o077)
    run()
