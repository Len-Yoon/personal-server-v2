"""V2 명시 계측의 전송 경계와 실제 비동기 HTTP 부모/자식 계약 검증."""
import asyncio
import logging
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
try:
    import httpx
    from fastapi import APIRouter, FastAPI
    from starlette.responses import StreamingResponse
    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor, SpanExporter, SpanExportResult
    from opentelemetry.trace import Link, SpanContext, TraceFlags, TraceState, Status, StatusCode
    from telemetry import v2_telemetry as otel
    import uvicorn
except ImportError as exc:
    raise unittest.SkipTest('tools/telemetry/requirements.txt와 HTTP 테스트 의존성 설치 필요') from exc
from v2_source_patch import apply_telemetry


class Capture(SpanExporter):
    def __init__(self):
        self.spans = []
    def export(self, spans):
        self.spans.extend(spans)
        return SpanExportResult.SUCCESS


def provider(service, routes):
    collector = Capture()
    sdk = TracerProvider(resource=Resource({'arbitrary': 'resource-secret'}), shutdown_on_exit=False)
    sdk.add_span_processor(SimpleSpanProcessor(collector))
    return sdk, sdk.get_tracer('sensitive-scope', attributes={'token': 'scope-secret'}), collector


class PrivacyTests(unittest.TestCase):
    def test_patched_constructor_blocks_native_exporters_during_real_lifespan_in_subprocess(self):
        with tempfile.TemporaryDirectory() as directory:
            context = Path(directory)
            (context / 'app').mkdir()
            (context / 'app/__init__.py').write_text('')
            (context / 'app/main.py').write_text('from fastapi import FastAPI\napp = FastAPI(title="V2 fixture")\n'
                '@app.get("/health")\nasync def health(): return {"ok": True}\n'
                '@app.get("/search")\nasync def search(): return {"ok": True}\n')
            (context / 'app/v2_telemetry.py').write_bytes((ROOT / 'tools/telemetry/v2_telemetry.py').read_bytes())
            apply_telemetry(context)
            script = textwrap.dedent('''
                from unittest.mock import patch
                from types import SimpleNamespace
                from starlette.testclient import TestClient
                from fastapi.telemetry import _runtime
                from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest
                import app.v2_telemetry as telemetry
                providers, payloads = [], []
                original_provider = telemetry.TracerProvider
                def make_provider(*args, **kwargs):
                    provider = original_provider(*args, **kwargs)
                    providers.append(provider)
                    return provider
                def post(session, url, **kwargs):
                    assert url == telemetry.ENDPOINT + '/v1/traces'
                    request = ExportTraceServiceRequest.FromString(kwargs['data'])
                    payloads.append(request)
                    return SimpleNamespace(status_code=200)
                original_configure = _runtime._configure_from_environment
                seen = []
                def inspect_config(config):
                    seen.append(config)
                    assert all(config[key] is False for key in ('auto_configure', 'tracing', 'metrics', 'logs', 'operation_spans'))
                    return original_configure(config)
                with patch.object(telemetry, 'TracerProvider', side_effect=make_provider), \\
                     patch('requests.Session.post', new=post), \\
                     patch.object(_runtime, '_configure_from_environment', side_effect=inspect_config), \\
                     patch('opentelemetry.exporter.otlp.proto.http.trace_exporter.OTLPSpanExporter') as native_trace, \\
                     patch('opentelemetry.exporter.otlp.proto.http.metric_exporter.OTLPMetricExporter') as native_metrics, \\
                     patch('opentelemetry.exporter.otlp.proto.http._log_exporter.OTLPLogExporter') as native_logs:
                    from app.main import app
                    with TestClient(app) as client:
                        assert client.get('/health').status_code == 200
                        assert client.get('/search?q=synthetic-query&token=synthetic-token', headers={'Authorization': 'synthetic-header'}).status_code == 200
                    assert len(seen) == 1
                    assert len(providers) == 1
                    providers[0].force_flush()
                    native_trace.assert_not_called()
                    native_metrics.assert_not_called()
                    native_logs.assert_not_called()
                    spans = [span for payload in payloads for resource in payload.resource_spans for scope in resource.scope_spans for span in scope.spans]
                    assert len(spans) == 1
                    assert spans[0].name == 'HTTP server GET /search'
                    assert all(value not in payload.SerializeToString() for payload in payloads for value in (b'synthetic-query', b'synthetic-token', b'synthetic-header', b'/health'))
                    providers[0].shutdown()
                print('native exporters disabled; private-only lifespan export verified')
            ''')
            env = dict(os.environ, OTEL_SERVICE_NAME='portal', V2_ENVIRONMENT='dev', OTEL_EXPORTER_OTLP_ENDPOINT=otel.ENDPOINT)
            result = subprocess.run([sys.executable, '-c', script], cwd=context, env=env,
                                    capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('private-only lifespan export verified', result.stdout)

    def test_included_and_nested_router_templates_are_exported_without_user_values(self):
        app, router, nested = FastAPI(), APIRouter(), APIRouter()
        @router.get('/')
        async def home():
            return {'ok': True}
        @nested.get('/search')
        async def search():
            return {'ok': True}
        @nested.get('/items/{id}')
        async def item(id: str):
            return {'ok': True}
        router.include_router(nested, prefix='/api')
        app.include_router(router)
        captured = []
        def collect(exporter, spans):
            captured.append(exporter.payload(spans))
            return SpanExportResult.SUCCESS
        env = {'OTEL_SERVICE_NAME': 'portal', 'V2_ENVIRONMENT': 'dev', 'OTEL_EXPORTER_OTLP_ENDPOINT': otel.ENDPOINT}
        with patch.dict(os.environ, env, clear=True), patch.object(otel.PrivateExporter, 'export', collect):
            sdk = otel.configure(app)
            try:
                async def run():
                    async with httpx.AsyncClient(transport=httpx.ASGITransport(app)) as client:
                        for path in ('/', '/api/search?q=synthetic-search-secret', '/api/items/synthetic-user-secret'):
                            self.assertEqual((await client.get('http://portal' + path)).status_code, 200)
                asyncio.run(run())
                self.assertTrue(sdk.force_flush())
                spans = [span for request in captured for resource in request.resource_spans for scope in resource.scope_spans for span in scope.spans]
                names = {span.name for span in spans}
                self.assertEqual(names, {'HTTP server GET /', 'HTTP server GET /api/search', 'HTTP server GET /api/items/{id}'})
                route_values = {attribute.value.string_value for span in spans for attribute in span.attributes if attribute.key == 'http.route'}
                self.assertEqual(route_values, {'/', '/api/search', '/api/items/{id}'})
                for payload in captured:
                    self.assertNotIn(b'synthetic-search-secret', payload.SerializeToString())
                    self.assertNotIn(b'synthetic-user-secret', payload.SerializeToString())
            finally:
                sdk.shutdown()

    def test_payload_is_rebuilt_and_never_copies_arbitrary_data(self):
        sdk, tracer, capture = provider('portal', {'/item/{item_id}'})
        secret = 'v2-synthetic-privacy-secret'
        context = SpanContext(1, 2, False, TraceFlags(1), TraceState([('token', secret)]))
        with tracer.start_as_current_span(secret, kind=trace.SpanKind.SERVER,
                links=[Link(context, {'token': secret})]) as span:
            for key in ('http.url', 'url.query', 'db.statement', 'http.request.header.authorization', 'body'):
                span.set_attribute(key, secret)
            span.set_attribute('http.request.method', secret)
            span.set_attribute('http.route', '/item/' + secret)
            span.set_attribute('http.response.status_code', 500)
            span.add_event(secret, {'exception.stacktrace': secret})
            span.set_status(Status(StatusCode.ERROR, secret))
        exporter = otel.PrivateExporter('portal', 'dev', {'/item/{item_id}'})
        payload = exporter.payload(capture.spans)
        binary = payload.SerializeToString()
        for denied in (secret, 'resource-secret', 'scope-secret', 'sensitive-scope', 'db.statement', 'exception', 'body', 'token'):
            self.assertNotIn(denied.encode(), binary)
        exported = payload.resource_spans[0].scope_spans[0].spans[0]
        self.assertEqual(exported.name, 'HTTP server OTHER unmatched')
        self.assertEqual(exported.kind, 2)
        self.assertEqual(len(exported.events), 0)
        self.assertEqual(len(exported.links), 0)
        self.assertEqual(exported.status.message, '')
        self.assertEqual(exported.trace_state, '')
        self.assertEqual(len(payload.resource_spans[0].resource.attributes), 2)
        self.assertEqual(len(payload.resource_spans[0].scope_spans[0].scope.attributes), 0)
        sdk.shutdown()

    def test_export_transport_is_fixed_no_env_headers_redirects_or_error_logging(self):
        exporter = otel.PrivateExporter('book', 'verify', set())
        self.assertFalse(exporter.session.trust_env)
        with patch.object(exporter.session, 'post', side_effect=RuntimeError('token=synthetic-secret')) as post:
            with patch('logging.Logger.error') as logger:
                self.assertEqual(exporter.export([]), SpanExportResult.FAILURE)
                logger.assert_not_called()
            self.assertEqual(post.call_args.args[0], otel.ENDPOINT + '/v1/traces')
            self.assertEqual(post.call_args.kwargs['timeout'], 2)
            self.assertFalse(post.call_args.kwargs['allow_redirects'])
            self.assertEqual(post.call_args.kwargs['headers'], {'Content-Type': 'application/x-protobuf'})

    def test_config_fails_closed_and_ignores_resource_env(self):
        with patch.dict(os.environ, {'OTEL_SERVICE_NAME': 'portal', 'V2_ENVIRONMENT': 'dev',
                'OTEL_EXPORTER_OTLP_ENDPOINT': 'http://untrusted:4318'}, clear=True):
            with self.assertRaisesRegex(RuntimeError, 'endpoint invalid'):
                otel.configure(FastAPI())
        for service, env in [('other', 'dev'), ('book', 'production'), (None, None)]:
            with self.assertRaisesRegex(RuntimeError, 'identity invalid'):
                otel.PrivateExporter(service, env, set())

    def test_collector_outage_keeps_bounded_queue_and_never_blocks_requests(self):
        blocked, release = threading.Event(), threading.Event()
        def stalled_export(exporter, spans):
            blocked.set()
            release.wait(3)
            return SpanExportResult.FAILURE
        env = {'OTEL_SERVICE_NAME': 'portal', 'V2_ENVIRONMENT': 'verify',
               'OTEL_EXPORTER_OTLP_ENDPOINT': otel.ENDPOINT,
               'OTEL_RESOURCE_ATTRIBUTES': 'token=synthetic-resource-env',
               'OTEL_BSP_MAX_QUEUE_SIZE': '999999'}
        with patch.dict(os.environ, env, clear=True), patch.object(otel.PrivateExporter, 'export', stalled_export):
            app = FastAPI()
            @app.get('/search')
            async def search():
                return {'ok': True}
            sdk = otel.configure(app)
            try:
                self.assertEqual(dict(sdk.resource.attributes), {})
                tracer = sdk.get_tracer('test')
                for _ in range(32):
                    with tracer.start_as_current_span('fixed'):
                        pass
                self.assertTrue(blocked.wait(2))
                async def requests_during_outage():
                    async with httpx.AsyncClient(transport=httpx.ASGITransport(app)) as client:
                        for _ in range(200):
                            response = await client.get('http://portal/search')
                            self.assertEqual(response.status_code, 200)
                start = time.monotonic()
                asyncio.run(requests_during_outage())
                self.assertLess(time.monotonic() - start, 2)
                processor = sdk._active_span_processor._span_processors[0]._batch_processor
                self.assertEqual(processor._max_queue_size, 128)
                self.assertEqual(processor._max_export_batch_size, 32)
                self.assertLessEqual(len(processor._queue), 128)
            finally:
                release.set()
                sdk.shutdown()

    def test_log_id_is_prefix_and_only_valid_context_is_added(self):
        sdk, tracer, capture = provider('portal', set())
        with tracer.start_as_current_span('fixed') as span:
            record = logging.LogRecord('uvicorn.access', logging.INFO, '', 1, 'token=%s', ('synthetic',), None)
            otel.TraceLogFilter().filter(record)
            output = otel.TraceFormatter(logging.Formatter()).format(record)
            self.assertTrue(output.startswith(f'trace_id={span.get_span_context().trace_id:032x} span_id='))
            self.assertTrue(output.endswith('token=synthetic'))
            self.assertEqual(record.args, ('synthetic',))
        sdk.shutdown()

    def test_uvicorn_access_formatter_preserves_original_five_arguments(self):
        from uvicorn.logging import AccessFormatter
        sdk, tracer, _ = provider('portal', set())
        with tracer.start_as_current_span('fixed'):
            args = ('127.0.0.1:12345', 'GET', '/search?q=synthetic', '1.1', 200)
            record = logging.LogRecord('uvicorn.access', logging.INFO, '', 1, '%s - "%s %s HTTP/%s" %d', args, None)
            otel.TraceLogFilter().filter(record)
            formatter = AccessFormatter('%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s', use_colors=False)
            output = otel.TraceFormatter(formatter).format(record)
            self.assertTrue(output.startswith('trace_id='))
            self.assertIn('GET /search?q=synthetic HTTP/1.1', output)
            self.assertEqual(record.args, args)
        sdk.shutdown()

    def test_source_patch_is_explicit_and_requires_expected_context(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'app/services').mkdir(parents=True)
            (root / 'app/main.py').write_text('from fastapi import FastAPI\napp = FastAPI()\n')
            (root / 'app/services/global_search.py').write_text('import httpx\nclient = httpx.AsyncClient(timeout=SEARCH_BUDGET_SECONDS, follow_redirects=True)\n')
            apply_telemetry(root)
            self.assertTrue((root / 'app/main.py').read_text().endswith('configure_v2_telemetry(app)\n'))
            self.assertIn('transport=internal_transport()', (root / 'app/services/global_search.py').read_text())
            with self.assertRaises(RuntimeError):
                apply_telemetry(root)


class LivePropagationTests(unittest.TestCase):
    def test_intermediate_native_context_cannot_orphan_clients_or_mix_concurrent_requests(self):
        sdk, tracer, capture = provider('portal', {'/search'})
        app = FastAPI()
        propagated = []
        async def respond(request):
            await asyncio.sleep(0.001)
            propagated.append(otel.PROPAGATOR.extract(dict(request.headers)))
            return httpx.Response(200)
        @app.middleware('http')
        async def intermediate(request, call_next):
            # V1 BaseHTTPMiddleware/라이브러리가 생성하는, 전송에서 제외될 중간 span.
            with tracer.start_as_current_span('native intermediary', kind=trace.SpanKind.INTERNAL):
                await asyncio.sleep(0)
                return await call_next(request)
        @app.get('/search')
        async def fanout():
            with tracer.start_as_current_span('native route intermediary', kind=trace.SpanKind.INTERNAL):
                transport = otel.InternalTransport(tracer, httpx.MockTransport(respond))
                async with httpx.AsyncClient(transport=transport) as client:
                    await asyncio.gather(client.get('http://book:8003/api/search'), client.get('http://youtube:8002/api/search'))
                record = logging.LogRecord('uvicorn.access', logging.INFO, '', 1, 'fixed', (), None)
                otel.TraceLogFilter().filter(record)
                return {'prefix': record.v2_trace_prefix}
        app.add_middleware(otel.ServerMiddleware, tracer=tracer, routes={'/search'})
        async def run():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app)) as client:
                return await asyncio.gather(*(client.get('http://portal/search') for _ in range(12)))
        try:
            # 서버 요청 시작 전에도 ambient span이 있어도 새 서버 root에는 혼입하지 않음.
            with tracer.start_as_current_span('ambient outside request'):
                responses = asyncio.run(run())
            servers = [span for span in capture.spans if span.kind == trace.SpanKind.SERVER]
            clients = [span for span in capture.spans if span.kind == trace.SpanKind.CLIENT]
            self.assertEqual(len(servers), 12)
            self.assertEqual(len(clients), 24)
            self.assertEqual(len({span.context.trace_id for span in servers}), 12)
            for server in servers:
                self.assertIsNone(server.parent)
                descendants = [span for span in clients if span.context.trace_id == server.context.trace_id]
                self.assertEqual(len(descendants), 2)
                self.assertTrue(all(span.parent.span_id == server.context.span_id for span in descendants))
                self.assertTrue(any(response.json()['prefix'] == f'trace_id={server.context.trace_id:032x} span_id={server.context.span_id:016x} '
                                    for response in responses))
            self.assertEqual({trace.get_current_span(context).get_span_context().span_id for context in propagated},
                             {span.context.span_id for span in clients})
            self.assertIsNone(otel._request_context.get())
        finally:
            sdk.shutdown()

    def test_three_real_http_servers_async_fanout_exclusions_errors_and_log_prefix(self):
        servers, threads, sockets, sdks, captures, ports = [], [], [], [], {}, {}
        access = []
        class AccessHandler(logging.Handler):
            def emit(self, record):
                access.append(otel.TraceFormatter(logging.Formatter()).format(record))
        logger = logging.getLogger('uvicorn.access')
        handler, logfilter = AccessHandler(), otel.TraceLogFilter()
        logger.addHandler(handler)
        logger.addFilter(logfilter)
        error_logger = logging.getLogger('uvicorn.error')
        error_handlers = error_logger.handlers[:]
        error_propagate = error_logger.propagate
        error_logger.handlers = [handler]
        error_logger.propagate = False
        error_logger.addFilter(logfilter)
        old_level = logger.level
        logger.setLevel(logging.INFO)
        try:
            apps, tracers = {}, {}
            for service in ('book', 'youtube', 'portal'):
                app = FastAPI()
                sdk, tracer, capture = provider(service, {'/api/search', '/search', '/fail'})
                sdks.append(sdk)
                captures[service], tracers[service], apps[service] = capture, tracer, app
                if service != 'portal':
                    @app.get('/api/search')
                    async def search():
                        await asyncio.sleep(0.01)
                        return {'results': []}
                else:
                    class LoopbackTransport(httpx.AsyncBaseTransport):
                        def __init__(self):
                            self.inner = httpx.AsyncHTTPTransport()
                        async def handle_async_request(self, request):
                            request.url = request.url.copy_with(host='127.0.0.1', port=ports[request.url.host])
                            return await self.inner.handle_async_request(request)
                        async def aclose(self):
                            await self.inner.aclose()
                    @app.get('/search')
                    async def fanout():
                        transport = otel.InternalTransport(tracer=tracers['portal'], transport=LoopbackTransport())
                        async with httpx.AsyncClient(transport=transport) as client:
                            responses = await asyncio.gather(*[client.get(f'http://{s}:{p}/api/search?q=synthetic-query&token=synthetic-token')
                                for s, p in [('book', 8003), ('youtube', 8002)]])
                        return {'statuses': [response.status_code for response in responses]}
                    @app.get('/fail')
                    async def failure():
                        raise RuntimeError('synthetic-exception-secret')
                    @app.get('/stream')
                    async def stream():
                        async def chunks():
                            yield b'first'
                            await asyncio.sleep(0.01)
                            yield b'second'
                        return StreamingResponse(chunks())
                @app.get('/ready')
                async def ready():
                    return {'ok': True}
                app.add_middleware(otel.ServerMiddleware, tracer=tracer, routes={'/api/search', '/search', '/fail', '/ready', '/stream'})
                sock = socket.socket()
                sock.bind(('127.0.0.1', 0))
                sock.listen(64)
                sockets.append(sock)
                ports[service] = sock.getsockname()[1]
                server = uvicorn.Server(uvicorn.Config(app, log_config=None, lifespan='off', access_log=True))
                servers.append(server)
                thread = threading.Thread(target=server.run, kwargs={'sockets': [sock]}, daemon=True)
                threads.append(thread)
                thread.start()
            deadline = time.monotonic() + 10
            while not all(server.started for server in servers):
                if time.monotonic() > deadline:
                    self.fail('local HTTP servers did not start')
                time.sleep(0.01)
            with httpx.Client(trust_env=False) as client:
                response = client.request('GET', f'http://127.0.0.1:{ports["portal"]}/search?q=synthetic-query', headers={'Authorization': 'synthetic-header'}, content=b'synthetic-body')
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()['statuses'], [200, 200])
                client.get(f'http://127.0.0.1:{ports["portal"]}/ready')
                client.get(f'http://127.0.0.1:{ports["portal"]}/unknown/synthetic-path')
                self.assertEqual(client.get(f'http://127.0.0.1:{ports["portal"]}/stream').text, 'firstsecond')
                self.assertEqual(client.get(f'http://127.0.0.1:{ports["portal"]}/fail').status_code, 500)
            deadline = time.monotonic() + 2
            while not any('Exception in ASGI' in line for line in access) and time.monotonic() < deadline:
                time.sleep(0.005)
            portal_server = next(span for span in captures['portal'].spans if span.attributes.get('http.route') == '/search')
            clients = [span for span in captures['portal'].spans if span.kind == trace.SpanKind.CLIENT]
            self.assertEqual(len(clients), 2)
            client_payload = otel.PrivateExporter('portal', 'dev', {'/api/search'}).payload(clients)
            self.assertTrue(all(span.kind == 3 for span in client_payload.resource_spans[0].scope_spans[0].spans))
            for service in ('book', 'youtube'):
                child = captures[service].spans[0]
                self.assertEqual(child.context.trace_id, portal_server.context.trace_id)
                parent = next(span for span in clients if span.context.span_id == child.parent.span_id)
                self.assertEqual(parent.parent.span_id, portal_server.context.span_id)
            self.assertFalse(any(span.attributes.get('http.route') == '/ready' for span in captures['portal'].spans))
            self.assertTrue(any(line.startswith(f'trace_id={portal_server.context.trace_id:032x} span_id=') and '/search?' in line for line in access))
            failed = next(span for span in captures['portal'].spans if span.attributes.get('http.response.status_code') == 500)
            self.assertTrue(any(line.startswith(f'trace_id={failed.context.trace_id:032x} span_id=') and 'Exception in ASGI' in line for line in access))
            self.assertTrue(any(span.attributes.get('http.route') == '/stream' for span in captures['portal'].spans))
            for service, capture in captures.items():
                data = otel.PrivateExporter(service, 'dev', {'/search', '/fail', '/api/search'}).payload(capture.spans).SerializeToString()
                for value in ('synthetic-query', 'synthetic-token', 'synthetic-header', 'synthetic-path', 'synthetic-body', 'synthetic-exception-secret'):
                    self.assertNotIn(value.encode(), data)
        finally:
            for server in servers:
                server.should_exit = True
            for thread in threads:
                thread.join(3)
            for sock in sockets:
                sock.close()
            for sdk in sdks:
                sdk.shutdown()
            logger.removeHandler(handler)
            logger.removeFilter(logfilter)
            logger.setLevel(old_level)
            error_logger.handlers = error_handlers
            error_logger.propagate = error_propagate
            error_logger.removeFilter(logfilter)

    def test_untrusted_http_target_is_neither_traced_nor_injected(self):
        sdk, tracer, capture = provider('portal', set())
        seen = []
        async def respond(request):
            seen.append(dict(request.headers))
            return httpx.Response(200)
        async def run():
            transport = otel.InternalTransport(tracer, httpx.MockTransport(respond))
            async with httpx.AsyncClient(transport=transport) as client:
                for url in ('http://127.0.0.1:9/api/search', 'https://book:8003/api/search', 'http://book:8003/other'):
                    await client.get(url)
        asyncio.run(run())
        self.assertEqual(capture.spans, [])
        self.assertTrue(all('traceparent' not in headers for headers in seen))
        sdk.shutdown()

    def test_redirect_cannot_forward_context_to_external_target(self):
        sdk, tracer, capture = provider('portal', set())
        seen = []
        async def respond(request):
            seen.append((request.url.host, dict(request.headers)))
            if request.url.host == 'book':
                return httpx.Response(302, headers={'Location': 'http://external.invalid/collect'})
            return httpx.Response(200)
        async def run():
            transport = otel.InternalTransport(tracer, httpx.MockTransport(respond))
            async with httpx.AsyncClient(transport=transport, follow_redirects=True) as client:
                await client.get('http://book:8003/api/search', headers={'baggage': 'token=synthetic', 'tracestate': 'token=synthetic'})
        asyncio.run(run())
        self.assertIn('traceparent', seen[0][1])
        self.assertTrue(all(key not in seen[0][1] for key in ('baggage', 'tracestate')))
        self.assertTrue(all(key not in seen[1][1] for key in ('traceparent', 'baggage', 'tracestate')))
        self.assertEqual(len(capture.spans), 1)
        sdk.shutdown()


if __name__ == '__main__':
    unittest.main()
