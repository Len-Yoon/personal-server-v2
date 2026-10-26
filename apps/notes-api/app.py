"""V2 메모 CRUD 실습 API. 초기화는 별도 migrate 명령으로만 수행함."""
import argparse
from contextlib import contextmanager
import hmac
import os
from pathlib import Path
import threading
import time
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

MAX_BODY = 65536
APP_VERSION = '1.2.0'
LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10)


def private_setting(name):
    """파일이 지정되면 파일 실패를 환경변수 fallback으로 숨기지 않음."""
    filename = os.environ.get(name + '_FILE')
    if filename:
        return Path(filename).read_text().strip()
    return os.environ.get(name, '')


def connect_database():
    import psycopg
    from psycopg.rows import dict_row
    password = private_setting('PGPASSWORD')
    if not password:
        raise RuntimeError('DB 인증 정보가 필요함')
    return psycopg.connect(host=os.environ.get('PGHOST', 'postgres'),
        port=int(os.environ.get('PGPORT', '5432')),
        dbname=os.environ.get('PGDATABASE', 'notes'),
        user=os.environ.get('PGUSER', 'notes_app'), password=password,
        connect_timeout=3, options='-c statement_timeout=5000 -c lock_timeout=3000',
        row_factory=dict_row)


@contextmanager
def transaction(connector):
    try:
        with connector() as connection:
            with connection.cursor() as cursor:
                yield cursor
    except HTTPException:
        raise
    except Exception:
        # 드라이버 오류에 SQL/호스트/인증값이 포함될 수 있어 그대로 기록하지 않음.
        raise HTTPException(status_code=503, detail='database unavailable') from None


class NoteInput(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    title: str = Field(min_length=1, max_length=200)
    body: str = Field(default='', max_length=10000)


class BodyLimit:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or scope['method'] not in ('POST', 'PUT', 'PATCH'):
            await self.app(scope, receive, send)
            return
        chunks = []
        size = 0
        while True:
            event = await receive()
            if event['type'] == 'http.disconnect':
                return
            size += len(event.get('body', b''))
            if size > MAX_BODY:
                await JSONResponse({'detail': 'request body too large'}, status_code=413)(scope, receive, send)
                return
            chunks.append(event)
            if not event.get('more_body', False):
                break
        async def replay():
            return chunks.pop(0) if chunks else await receive()
        await self.app(scope, replay, send)


class RequestMetrics:
    """응답 본문 전송까지 측정하며 URL·본문·인증값을 저장하지 않음."""
    def __init__(self, app, record, clock):
        self.app, self.record, self.clock = app, record, clock

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or scope['path'] == '/metrics':
            await self.app(scope, receive, send)
            return
        started = self.clock()
        status = 500
        async def measured_send(message):
            nonlocal status
            if message['type'] == 'http.response.start':
                status = message['status']
            await send(message)
        try:
            await self.app(scope, receive, measured_send)
        finally:
            business = scope['path'] == '/notes' or scope['path'].startswith('/notes/')
            self.record(status, max(0.0, self.clock() - started), business)


def create_app(connector=connect_database, clock=time.perf_counter):
    api = FastAPI(title='V2 메모 실습 API', docs_url=None, redoc_url=None, openapi_url=None)
    api.add_middleware(BodyLimit)
    counters = {'requests': 0, 'errors': 0, 'api_requests': 0, 'api_errors': 0,
                'api_client_errors': 0, 'duration_sum': 0.0}
    buckets = [0 for _ in LATENCY_BUCKETS]
    counter_lock = threading.Lock()
    started = time.monotonic()

    def record(status, elapsed, business):
        with counter_lock:
            counters['requests'] += 1
            counters['errors'] += int(status >= 500)
            if business:
                counters['api_requests'] += 1
                counters['api_errors'] += int(status >= 500)
                counters['api_client_errors'] += int(400 <= status < 500)
                counters['duration_sum'] += elapsed
                for index, boundary in enumerate(LATENCY_BUCKETS):
                    buckets[index] += int(elapsed <= boundary)

    api.add_middleware(RequestMetrics, record=record, clock=clock)

    def authenticate(authorization: str | None = Header(default=None)):
        try:
            token = private_setting('NOTES_API_TOKEN')
        except (OSError, ValueError):
            token = ''
        if not token:
            raise HTTPException(status_code=503, detail='authentication unavailable')
        expected = 'Bearer ' + token
        if authorization is None or not hmac.compare_digest(authorization.encode(), expected.encode()):
            raise HTTPException(status_code=401, detail='unauthorized', headers={'WWW-Authenticate': 'Bearer'})

    @api.get('/health')
    def health():
        return {'status': 'ok'}

    @api.get('/version')
    def version():
        """인증값·환경 정보를 노출하지 않고 배포된 앱 버전을 확인함."""
        return {'service': 'v2-notes-api', 'version': APP_VERSION}

    @api.get('/ready')
    def ready():
        with transaction(connector) as cursor:
            cursor.execute('SELECT id FROM public.notes LIMIT 0')
        return {'status': 'ready'}

    @api.get('/metrics', response_class=Response)
    def metrics():
        with counter_lock:
            values = dict(counters)
            counts = list(buckets)
        histogram = ''.join(f'v2_notes_api_duration_seconds_bucket{{le="{boundary}"}} {count}\n'
                            for boundary, count in zip(LATENCY_BUCKETS, counts))
        return Response('# HELP v2_notes_requests_total All HTTP requests excluding metrics scrapes.\n'
            '# TYPE v2_notes_requests_total counter\n'
            f'v2_notes_requests_total {values["requests"]}\n'
            '# HELP v2_notes_errors_total All HTTP server failures excluding metrics scrapes.\n'
            '# TYPE v2_notes_errors_total counter\n'
            f'v2_notes_errors_total {values["errors"]}\n'
            '# HELP v2_notes_uptime_seconds Time since API process started.\n'
            '# TYPE v2_notes_uptime_seconds gauge\n'
            f'v2_notes_uptime_seconds {time.monotonic() - started:.3f}\n'
            '# HELP v2_notes_api_requests_total Requests to notes paths, excluding probes and scrapes.\n'
            '# TYPE v2_notes_api_requests_total counter\n'
            f'v2_notes_api_requests_total {values["api_requests"]}\n'
            '# HELP v2_notes_api_errors_total Notes HTTP server failures.\n'
            '# TYPE v2_notes_api_errors_total counter\n'
            f'v2_notes_api_errors_total {values["api_errors"]}\n'
            '# HELP v2_notes_api_client_errors_total Notes HTTP client errors including authentication failures.\n'
            '# TYPE v2_notes_api_client_errors_total counter\n'
            f'v2_notes_api_client_errors_total {values["api_client_errors"]}\n'
            '# HELP v2_notes_api_duration_seconds Notes response completion duration including failures.\n'
            '# TYPE v2_notes_api_duration_seconds histogram\n'
            + histogram + f'v2_notes_api_duration_seconds_bucket{{le="+Inf"}} {values["api_requests"]}\n'
            f'v2_notes_api_duration_seconds_count {values["api_requests"]}\n'
            f'v2_notes_api_duration_seconds_sum {values["duration_sum"]:.9f}\n',
            media_type='text/plain; version=0.0.4')

    @api.get('/notes', dependencies=[Depends(authenticate)])
    def list_notes(limit: int = 100, offset: int = 0):
        if not 1 <= limit <= 100 or not 0 <= offset <= 100000:
            raise HTTPException(status_code=422, detail='invalid pagination')
        with transaction(connector) as cursor:
            cursor.execute('SELECT id, title, body, created_at, updated_at FROM public.notes ORDER BY id LIMIT %s OFFSET %s', (limit, offset))
            return cursor.fetchall()

    @api.post('/notes', status_code=201, dependencies=[Depends(authenticate)])
    def create_note(value: NoteInput):
        with transaction(connector) as cursor:
            cursor.execute('INSERT INTO public.notes (id, title, body) VALUES (%s, %s, %s) RETURNING id, title, body, created_at, updated_at',
                (uuid4(), value.title, value.body))
            return cursor.fetchone()

    @api.get('/notes/{note_id}', dependencies=[Depends(authenticate)])
    def get_note(note_id: UUID):
        with transaction(connector) as cursor:
            cursor.execute('SELECT id, title, body, created_at, updated_at FROM public.notes WHERE id = %s', (note_id,))
            result = cursor.fetchone()
            if result is None:
                raise HTTPException(status_code=404, detail='note not found')
            return result

    @api.put('/notes/{note_id}', dependencies=[Depends(authenticate)])
    def update_note(note_id: UUID, value: NoteInput):
        with transaction(connector) as cursor:
            cursor.execute('UPDATE public.notes SET title = %s, body = %s, updated_at = clock_timestamp() WHERE id = %s RETURNING id, title, body, created_at, updated_at',
                (value.title, value.body, note_id))
            result = cursor.fetchone()
            if result is None:
                raise HTTPException(status_code=404, detail='note not found')
            return result

    @api.delete('/notes/{note_id}', status_code=204, dependencies=[Depends(authenticate)])
    def delete_note(note_id: UUID):
        with transaction(connector) as cursor:
            cursor.execute('DELETE FROM public.notes WHERE id = %s RETURNING id', (note_id,))
            if cursor.fetchone() is None:
                raise HTTPException(status_code=404, detail='note not found')
        return Response(status_code=204)

    return api


def migrate(connector=connect_database):
    """DB 소유자 계정 전용. 앱 실행 시 DDL을 자동 수행하지 않음."""
    with connector() as connection:
        with connection.cursor() as cursor:
            cursor.execute('SELECT pg_advisory_xact_lock(2606220601)')
            cursor.execute('CREATE TABLE IF NOT EXISTS public.schema_version (version integer PRIMARY KEY CHECK (version > 0))')
            cursor.execute('SELECT version FROM public.schema_version ORDER BY version DESC LIMIT 1')
            row = cursor.fetchone()
            if row and row['version'] != 1:
                raise RuntimeError('지원하지 않는 스키마 버전')
            if row is None:
                cursor.execute('CREATE TABLE public.notes (id uuid PRIMARY KEY, title varchar(200) NOT NULL CHECK (length(btrim(title)) > 0), body text NOT NULL DEFAULT \'\' CHECK (length(body) <= 10000), created_at timestamptz NOT NULL DEFAULT clock_timestamp(), updated_at timestamptz NOT NULL DEFAULT clock_timestamp())')
                cursor.execute('INSERT INTO public.schema_version (version) VALUES (1)')
            cursor.execute('GRANT SELECT, INSERT, UPDATE, DELETE ON public.notes TO notes_app')


app = create_app()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=('serve', 'migrate'))
    args = parser.parse_args()
    if args.command == 'migrate':
        try:
            migrate()
        except Exception:
            raise SystemExit('V2 스키마 초기화 실패: DB 연결·소유자 권한·버전을 확인해야 함') from None
        print('V2 메모 스키마 버전1 확인 완료')
    else:
        import uvicorn
        uvicorn.run(app, host='0.0.0.0', port=8000, access_log=False)
