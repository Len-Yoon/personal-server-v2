"""메모 API 경계·CRUD 계약 자기 검증. 실제 PostgreSQL 복원은 별도 로컬 검증함."""
import copy
import importlib.util
import os
import asyncio
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import unittest
from unittest.mock import patch
from uuid import UUID

from fastapi.testclient import TestClient

path = Path(__file__).resolve().parents[1] / 'apps/notes-api/app.py'
spec = importlib.util.spec_from_file_location('v2_notes_api', path)
notes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(notes)


class MemoryDatabase:
    """SQL 문자열/인자를 기록하며 transaction commit/rollback을 구분하는 fixture."""
    def __init__(self):
        self.rows = {}
        self.queries = []
        self.commits = 0
        self.rollbacks = 0
        self.unavailable = False

    def connect(self):
        if self.unavailable:
            raise RuntimeError('password=should-never-escape')
        database = self
        class Connection:
            def __enter__(self):
                self.before = copy.deepcopy(database.rows)
                return self
            def __exit__(self, kind, value, traceback):
                if kind:
                    database.rows = self.before
                    database.rollbacks += 1
                else:
                    database.commits += 1
            def cursor(self):
                return Cursor()
        class Cursor:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def execute(self, query, params=None):
                database.queries.append((query, params))
                self.result = None
                if query.startswith('SELECT id FROM'):
                    return
                if query.startswith('INSERT INTO public.notes'):
                    identity, title, body = params
                    self.result = dict(id=str(identity), title=title, body=body,
                        created_at='2026-10-22T00:00:00Z', updated_at='2026-10-22T00:00:00Z')
                    database.rows[str(identity)] = self.result
                elif query.startswith('SELECT id,') and 'WHERE' in query:
                    self.result = database.rows.get(str(params[0]))
                elif query.startswith('SELECT id,'):
                    limit, offset = params
                    self.result = sorted(database.rows.values(), key=lambda row:row['id'])[offset:offset+limit]
                elif query.startswith('UPDATE'):
                    title, body, identity = params
                    row = database.rows.get(str(identity))
                    if row:
                        row = {**row, 'title':title, 'body':body, 'updated_at':'2026-10-22T00:00:01Z'}
                        database.rows[str(identity)] = row
                        self.result = row
                elif query.startswith('DELETE'):
                    row = database.rows.pop(str(params[0]), None)
                    self.result = {'id':row['id']} if row else None
                else:
                    raise AssertionError('예상하지 않은 SQL')
            def fetchone(self): return copy.deepcopy(self.result)
            def fetchall(self): return copy.deepcopy(self.result)
        return Connection()


class NotesAPITest(unittest.TestCase):
    def setUp(self):
        self.db = MemoryDatabase()
        self.client = TestClient(notes.create_app(self.db.connect))
        self.environment = patch.dict(os.environ, {'NOTES_API_TOKEN':'unit-test-only-token'}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.headers = {'Authorization':'Bearer unit-test-only-token'}

    def test_crud_parameterized_and_transactional(self):
        text = "'); DROP TABLE notes; --"
        response = self.client.post('/notes', headers=self.headers, json={'title':text,'body':'본문'})
        self.assertEqual(response.status_code,201)
        identity = response.json()['id']
        UUID(identity)
        self.assertEqual(self.client.get('/notes/'+identity, headers=self.headers).json()['title'],text)
        updated = self.client.put('/notes/'+identity, headers=self.headers, json={'title':'수정','body':'변경'})
        self.assertEqual(updated.json()['body'],'변경')
        self.assertEqual(len(self.client.get('/notes',headers=self.headers).json()),1)
        self.assertEqual(self.client.delete('/notes/'+identity,headers=self.headers).status_code,204)
        self.assertEqual(self.client.get('/notes/'+identity,headers=self.headers).status_code,404)
        self.assertGreaterEqual(self.db.commits,5)
        self.assertEqual(self.db.rollbacks,1)
        self.assertFalse(any(text in query for query,_ in self.db.queries))
        self.assertEqual(self.db.queries[0][1][1],text)

    def test_auth_fail_closed_without_db_contact(self):
        self.assertEqual(self.client.get('/notes').status_code,401)
        self.assertEqual(self.client.post('/notes',headers={'Authorization':'Bearer wrong'},json={'title':'x'}).status_code,401)
        self.assertEqual(self.db.queries,[])
        with patch.dict(os.environ,{'NOTES_API_TOKEN':''}):
            self.assertEqual(self.client.get('/notes',headers=self.headers).status_code,503)
        with patch.dict(os.environ,{'NOTES_API_TOKEN_FILE':'/missing-v2-test-secret'}):
            self.assertEqual(self.client.get('/notes',headers=self.headers).status_code,503)

    def test_public_version_survives_database_and_auth_unavailability(self):
        self.db.unavailable = True
        with patch.dict(os.environ, {'NOTES_API_TOKEN_FILE':'/missing-v2-test-secret'}):
            response = self.client.get('/version')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'service':'v2-notes-api', 'version':'1.2.0'})
        self.assertEqual(self.db.queries, [])
        self.assertEqual(self.client.get('/notes').status_code, 401)

    def test_database_failure_is_sanitized_and_liveness_survives(self):
        self.db.unavailable = True
        self.assertEqual(self.client.get('/health').status_code,200)
        for path in ('/ready','/notes'):
            response = self.client.get(path,headers=self.headers)
            self.assertEqual(response.status_code,503)
            self.assertEqual(response.json(),{'detail':'database unavailable'})
        metrics = self.client.get('/metrics')
        self.assertIn('v2_notes_errors_total 2', metrics.text)
        self.assertNotIn('password',metrics.text)

    def test_validation_pagination_unknown_fields_and_size(self):
        for value in ({'title':' '},{'title':'x'*201},{'title':'x','body':'y'*10001},{'title':'x','admin':True}):
            self.assertEqual(self.client.post('/notes',headers=self.headers,json=value).status_code,422)
        for query in ('?limit=0','?limit=101','?offset=-1','?offset=100001'):
            self.assertEqual(self.client.get('/notes'+query,headers=self.headers).status_code,422)
        self.assertEqual(self.client.get('/notes/not-a-uuid',headers=self.headers).status_code,422)
        response = self.client.post('/notes',headers={**self.headers,'Content-Type':'application/json'},content='x'*(notes.MAX_BODY+1))
        self.assertEqual(response.status_code,413)
        self.assertEqual(self.db.queries,[])

    def test_business_histogram_excludes_probes_and_records_failures(self):
        ticks = iter([0.0, 0.02, 1.0, 1.07, 2.0, 2.8, 3.0, 3.001])
        client = TestClient(notes.create_app(self.db.connect, clock=lambda:next(ticks)))
        self.assertEqual(client.get('/health').status_code,200)
        self.assertEqual(client.get('/notes?token=private-query').status_code,401)
        self.assertEqual(client.get('/notes?limit=0',headers=self.headers).status_code,422)
        self.db.unavailable = True
        self.assertEqual(client.get('/notes',headers=self.headers).status_code,503)
        metrics = client.get('/metrics').text
        self.assertIn('v2_notes_api_requests_total 3\n',metrics)
        self.assertIn('v2_notes_api_errors_total 1\n',metrics)
        self.assertIn('v2_notes_api_client_errors_total 2\n',metrics)
        self.assertIn('v2_notes_api_duration_seconds_bucket{le="0.05"} 1\n',metrics)
        self.assertIn('v2_notes_api_duration_seconds_bucket{le="0.1"} 2\n',metrics)
        self.assertIn('v2_notes_api_duration_seconds_bucket{le="+Inf"} 3\n',metrics)
        self.assertIn('v2_notes_api_duration_seconds_count 3\n',metrics)
        self.assertIn('v2_notes_api_duration_seconds_sum 0.871000000\n',metrics)
        self.assertNotIn('private-query',metrics)
        self.assertIn('\nv2_notes_api_requests_total 3\n',client.get('/metrics').text)

    def test_unhandled_exception_and_body_limit_are_counted(self):
        api = notes.create_app(self.db.connect)
        @api.get('/notes/fault-test/raise')
        def fault():
            raise RuntimeError('private-error')
        client = TestClient(api, raise_server_exceptions=False)
        self.assertEqual(client.get('/notes/fault-test/raise').status_code,500)
        self.assertEqual(client.post('/notes',content='x'*(notes.MAX_BODY+1)).status_code,413)
        text = client.get('/metrics').text
        self.assertIn('v2_notes_api_requests_total 2\n',text)
        self.assertIn('v2_notes_api_errors_total 1\n',text)
        self.assertIn('v2_notes_api_client_errors_total 1\n',text)
        self.assertNotIn('private-error',text)

    def test_metrics_concurrent_requests_keep_counts_and_buckets_consistent(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            statuses = list(pool.map(lambda _:self.client.get('/notes').status_code,range(40)))
        self.assertEqual(statuses,[401]*40)
        text = self.client.get('/metrics').text
        self.assertIn('v2_notes_api_requests_total 40\n',text)
        self.assertIn('v2_notes_api_client_errors_total 40\n',text)
        self.assertIn('v2_notes_api_duration_seconds_count 40\n',text)
        counts = [int(line.rsplit(' ',1)[1]) for line in text.splitlines() if line.startswith('v2_notes_api_duration_seconds_bucket')]
        self.assertEqual(counts,sorted(counts))
        self.assertEqual(counts[-1],40)

    def test_measurement_covers_response_body_completion_and_private_paths(self):
        seen=[]
        async def streaming(scope,receive,send):
            await send({'type':'http.response.start','status':200,'headers':[]})
            await send({'type':'http.response.body','body':b'x','more_body':False})
        ticks=iter([1.0,1.25])
        middleware=notes.RequestMetrics(streaming,lambda *args:seen.append(args),lambda:next(ticks))
        async def send(message):pass
        async def receive():return {'type':'http.request'}
        asyncio.run(middleware({'type':'http','path':'/notes/private-uuid'},receive,send))
        self.assertEqual(seen,[(200,0.25,True)])

    def test_metrics_no_unbounded_or_private_labels(self):
        self.client.get('/notes',headers=self.headers)
        response = self.client.get('/metrics')
        self.assertEqual(response.status_code,200)
        self.assertIn('v2_notes_requests_total 1',response.text)
        self.assertNotIn('unit-test-only-token',response.text)
        self.assertNotIn('/notes',response.text)
        self.assertEqual(self.client.get('/docs').status_code,404)


if __name__ == '__main__':
    unittest.main()
