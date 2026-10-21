#!/usr/bin/env python3
"""V2 Portal·YouTube 연계 자동 검증. 운영 데이터·자격 증명은 사용하지 않음."""
import argparse
import base64
import json
import os
import time
import urllib.parse
import urllib.request
import lab


SERVICES = {'portal': 8000, 'youtube': 8002}


def owned_pod(namespace, service):
    lab.guard()
    lab.namespace_guard(namespace)
    deployment = json.loads(lab.k('-n', namespace, 'get', 'deployment', service, '-o', 'json'))
    if deployment['metadata'].get('labels', {}).get(lab.OWNER) != lab.VALUE:
        raise RuntimeError('검증 대상 Deployment 소유 불일치')
    sets = json.loads(lab.k('-n', namespace, 'get', 'replicasets', '-o', 'json'))['items']
    set_uids = {item['metadata']['uid'] for item in sets if any(ref.get('uid') == deployment['metadata']['uid'] for ref in item['metadata'].get('ownerReferences', []))}
    pods = json.loads(lab.k('-n', namespace, 'get', 'pods', '-l', 'app.kubernetes.io/name=' + service, '-o', 'json'))['items']
    candidates = [pod for pod in pods if not pod['metadata'].get('deletionTimestamp') and pod['metadata'].get('labels', {}).get(lab.OWNER) == lab.VALUE
                  and any(ref.get('uid') in set_uids for ref in pod['metadata'].get('ownerReferences', []))
                  and any(condition.get('type') == 'Ready' and condition.get('status') == 'True' for condition in pod.get('status', {}).get('conditions', []))]
    if len(candidates) != 1:
        raise RuntimeError(f'{namespace}/{service}: Ready 소유 Pod 1개 필요')
    return candidates[0]


def execute(namespace, service, code):
    pod = owned_pod(namespace, service)
    output = lab.k('-n', namespace, 'exec', pod['metadata']['name'], '--', 'python', '-c', code)
    return json.loads(output.strip())


def http_health(namespace, service):
    code = r"""import json,urllib.request
result={}
for endpoint in ('health','ready'):
 with urllib.request.urlopen('http://127.0.0.1:PORT/'+endpoint, timeout=10) as response:
  payload=json.load(response)
  assert response.status == 200
  result[endpoint]={'http':response.status,'status':payload['status']}
print(json.dumps(result))
""".replace('PORT', str(SERVICES[service]))
    return execute(namespace, service, code)


def book_snapshot(namespace):
    code = "import os,sqlite3,json; c=sqlite3.connect(os.environ['BOOK_MEMO_DB_PATH']); print(json.dumps({t:c.execute('SELECT COUNT(*) FROM '+t).fetchone()[0] for t in ('books','book_chapters','book_memos')}))"
    return execute(namespace, 'book', code)


def seed_samples(namespace):
    portal = execute(namespace, 'portal', r"""import io,json
from types import SimpleNamespace
from app.services import file_store
name='v2-pvc-verification.txt'
content=b'V2 Portal PVC sample; no production data.\n'
file_store.ensure_storage()
destination=file_store.STORAGE_PATH/name
if not destination.exists():
 file_store.save_upload('', SimpleNamespace(filename=name,file=io.BytesIO(content),content_type='text/plain'))
assert file_store.get_download_item_path(name).read_bytes()==content
assert any(item['name']==name for item in file_store.get_directory('')['files'])
print(json.dumps({'file':name,'bytes':len(content),'stored':True}))
""")
    youtube = execute(namespace, 'youtube', r"""import json
from app.services import memo_service as service
video=service.create_or_get_video('https://www.youtube.com/watch?v=V2LAB000001',title_fetcher=lambda *_:'V2 통합 검색 영상')
memo=service.create_memo(video['id'],'V2 통합 검증 메모','실제 외부 영상 요청 없이 생성한 V2 샘플 데이터입니다.',tags='V2 실습',request_id='94fdd920fc8a41d8a152e3e6466f8322')
assert service.get_video(video['id'])['title']=='V2 통합 검색 영상'
assert any(item['id']==memo['id'] for item in service.list_memos(video['id']))
print(json.dumps({'video_id':video['id'],'memo_id':memo['id'],'sample_title':'V2 통합 검색 영상','stored':True},ensure_ascii=False))
""")
    return {'portal': portal, 'youtube': youtube}


def persisted_samples(namespace):
    return {
        'portal': execute(namespace, 'portal', r"""import json
from app.services import file_store
p=file_store.get_download_item_path('v2-pvc-verification.txt')
assert p.read_bytes()==b'V2 Portal PVC sample; no production data.\n'
print(json.dumps({'stored':True}))
"""),
        'youtube': execute(namespace, 'youtube', r"""import json,sqlite3
from app.services import memo_service as service
connection=sqlite3.connect(service.DB_PATH)
video=connection.execute("SELECT id FROM videos WHERE youtube_id='V2LAB000001'").fetchone()
assert video
assert any(item['title']=='V2 통합 검증 메모' for item in service.list_memos(video[0]))
print(json.dumps({'stored':True}))
""")}


def integrated_search(namespace):
    return execute(namespace, 'portal', r"""import asyncio,json,os,urllib.request,urllib.parse
from urllib.parse import urlsplit
from app.services.global_search import search_all
assert os.getenv('DEMO_MODE','').lower() not in {'1','true','yes','on'}
assert os.environ['BOOKS_SEARCH_URL']=='http://book:8003/api/search'
assert os.environ['YOUTUBE_SEARCH_URL']=='http://youtube:8002/api/search'
assert urlsplit(os.environ['NEWS_SEARCH_URL']).hostname in {'localhost','127.0.0.1'}
result=asyncio.run(search_all('V2'))
assert result['books']['status']=='ok' and result['books']['items']
assert result['youtube']['status']=='ok' and any('V2 통합 검색 영상' in str(item) for item in result['youtube']['items'])
with urllib.request.urlopen('http://127.0.0.1:8000/?'+urllib.parse.urlencode({'q':'V2'}),timeout=10) as response:
 html=response.read().decode()
 assert response.status==200 and 'V2 통합 검색 영상' in html
print(json.dumps({'books':result['books']['status'],'youtube':result['youtube']['status'],'news':result['news']['status'],'portal_search_http':200}))
""")


def restart_sample(namespace, service):
    pod = owned_pod(namespace, service)
    # UID 전제조건으로 같은 이름의 다른 Pod 삭제를 차단함.
    path = f'/api/v1/namespaces/{namespace}/pods/' + pod['metadata']['name']
    body = {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': pod['metadata']['uid']}}
    lab.k('delete', '--raw', path, '-f', '-', stdin=json.dumps(body))
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            current = owned_pod(namespace, service)
            if current['metadata']['uid'] != pod['metadata']['uid']:
                return {'old_uid': pod['metadata']['uid'], 'new_uid': current['metadata']['uid']}
        except RuntimeError:
            pass
        time.sleep(2)
    raise RuntimeError('샘플 Pod 재생성 시간 초과')


def get_json(url, headers=None):
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}), timeout=15) as response:
        return json.load(response)


def observe_services():
    deadline = time.monotonic() + 180
    expected = {(service, environment, endpoint) for service in SERVICES for environment in lab.ENVIRONMENTS for endpoint in ('health', 'ready')}
    while time.monotonic() < deadline:
        query = 'probe_success{job=~"portal-http|youtube-http"}'
        result = get_json('http://127.0.0.1:8084/api/v1/query?' + urllib.parse.urlencode({'query': query}))
        observed = {(sample['metric']['service'], sample['metric']['environment'], sample['metric']['endpoint']) for sample in result['data']['result'] if sample['value'][1] == '1'}
        if observed == expected:
            break
        time.sleep(5)
    else:
        raise RuntimeError('Portal/YouTube 8개 HTTP probe 성공 대기 시간 초과')
    credentials = 'admin:' + (lab.LOCAL / 'grafana-password').read_text().strip()
    headers = {'Authorization': 'Basic ' + base64.b64encode(credentials.encode()).decode()}
    dashboard = get_json('http://127.0.0.1:8083/api/dashboards/uid/v2-platform-lab', headers)['dashboard']
    expressions = [target.get('expr', '') for panel in dashboard['panels'] for target in panel.get('targets', [])]
    if not all(any(service + '-http' in expression for expression in expressions) for service in SERVICES):
        raise RuntimeError('Grafana 서비스 가용성 패널 누락')
    return {'success_targets': len(observed), 'dashboard_uid': dashboard['uid'], 'panels': len(dashboard['panels'])}


def verify(restart=False, observe=True):
    state = lab.guard()
    if (lab.LOCAL / 'exercise.json').exists():
        raise RuntimeError('기존 장애 실습을 먼저 복구해야 함')
    report = {'scope': 'V2 automated Portal/YouTube integration; not user diagnosis', 'cluster_uid': state['cluster_uid'],
              'source_commit': lab.run(['git', 'rev-parse', 'HEAD']).strip(), 'environments': {}}
    book_before = {namespace: book_snapshot(namespace) for namespace in lab.ENVIRONMENTS.values()}
    try:
        for environment, namespace in lab.ENVIRONMENTS.items():
            result = {'health': {service: http_health(namespace, service) for service in SERVICES}, 'samples': seed_samples(namespace)}
            result['search'] = integrated_search(namespace)
            if restart:
                result['recreated_pods'] = {service: restart_sample(namespace, service) for service in SERVICES}
                result['health_after_restart'] = {service: http_health(namespace, service) for service in SERVICES}
            result['pvc_readback'] = persisted_samples(namespace)
            report['environments'][environment] = result
        after = {namespace: book_snapshot(namespace) for namespace in lab.ENVIRONMENTS.values()}
        if after != book_before:
            raise RuntimeError('기존 Book 테이블 행 수 변경 감지')
        report['book_preserved'] = after
        if observe:
            report['observability'] = observe_services()
        report['result'] = 'PASS'
        print('Portal·YouTube health/ready·샘플 저장·통합 검색·Book 보존' + ('·Pod 재생성 후 PVC 읽기' if restart else '') + ('·관측' if observe else '') + ' PASS')
    finally:
        (lab.LOCAL / 'services-verification.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--restart-samples', action='store_true', help='V2 Portal/YouTube Pod만 재생성하여 PVC 데이터 유지를 확인함')
    parser.add_argument('--skip-observability', action='store_true', help='관측 sync 전 서비스 기능만 검증함')
    args = parser.parse_args()
    verify(args.restart_samples, not args.skip_observability)
