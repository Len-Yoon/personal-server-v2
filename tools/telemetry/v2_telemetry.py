"""V2 전용 명시 HTTP 계측. 전송 protobuf는 허용한 값으로만 새로 구성함."""
import atexit
from contextvars import ContextVar
import logging
import os

import httpx
import requests
from starlette.routing import compile_path
from opentelemetry import trace
from opentelemetry.context import Context
from opentelemetry.propagators.textmap import DefaultGetter
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SpanExporter, SpanExportResult
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest
from opentelemetry.proto.trace.v1.trace_pb2 import Span as ProtoSpan, Status

ENDPOINT = 'http://alloy.v2-observability.svc.cluster.local:4318'
METHODS = frozenset(('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'))
PROPAGATOR = TraceContextTextMapPropagator()  # baggage는 읽거나 전달하지 않음.
_tracer = None
_service = None
_error_context = ContextVar('v2_error_trace', default=None)
_request_context = ContextVar('v2_http_server_context', default=None)


def method_name(value):
    return value if isinstance(value, str) and value in METHODS else 'OTHER'


class PrivateExporter(SpanExporter):
    """SDK의 임의 값은 복사하지 않음. exporter 자체도 env 헤더/proxy를 읽지 않음."""
    def __init__(self, service, environment, routes):
        if service not in {'portal', 'book', 'youtube'} or environment not in {'dev', 'verify'}:
            raise RuntimeError('V2 telemetry identity invalid')
        self.service, self.environment, self.routes = service, environment, frozenset(routes)
        self.session = requests.Session()
        self.session.trust_env = False

    def payload(self, spans):
        request = ExportTraceServiceRequest()
        resource = request.resource_spans.add()
        for key, value in (('service.name', self.service), ('deployment.environment.name', self.environment)):
            item = resource.resource.attributes.add(key=key)
            item.value.string_value = value
        scope = resource.scope_spans.add()
        scope.scope.name = 'v2.http'
        scope.scope.version = '1'
        for span in spans:
            if span.kind not in (trace.SpanKind.SERVER, trace.SpanKind.CLIENT):
                continue
            attributes = span.attributes or {}
            route = attributes.get('http.route')
            if not isinstance(route, str) or route not in self.routes:
                route = 'unmatched'
            method = method_name(attributes.get('http.request.method'))
            item = scope.spans.add()
            item.trace_id = span.context.trace_id.to_bytes(16, 'big')
            item.span_id = span.context.span_id.to_bytes(8, 'big')
            if span.parent and span.parent.is_valid:
                item.parent_span_id = span.parent.span_id.to_bytes(8, 'big')
            item.name = ('HTTP server ' if span.kind == trace.SpanKind.SERVER else 'HTTP client ') + method + ' ' + route
            item.kind = ProtoSpan.SPAN_KIND_SERVER if span.kind == trace.SpanKind.SERVER else ProtoSpan.SPAN_KIND_CLIENT
            item.start_time_unix_nano = span.start_time
            item.end_time_unix_nano = span.end_time
            item.flags = int(span.context.trace_flags) & 1
            for key, value in (('http.request.method', method), ('http.route', route)):
                item.attributes.add(key=key).value.string_value = value
            status = attributes.get('http.response.status_code')
            if type(status) is int and 100 <= status <= 599:
                item.attributes.add(key='http.response.status_code').value.int_value = status
                item.status.code = Status.STATUS_CODE_ERROR if status >= 500 else Status.STATUS_CODE_UNSET
            # events, links, trace_state, descriptions, resource/scope attrs는 복사하지 않음.
        return request

    def export(self, spans):
        try:
            data = self.payload(spans).SerializeToString()
            response = self.session.post(ENDPOINT + '/v1/traces', data=data,
                headers={'Content-Type': 'application/x-protobuf'}, timeout=2, allow_redirects=False)
            return SpanExportResult.SUCCESS if response.status_code == 200 else SpanExportResult.FAILURE
        except Exception:
            # 오류 객체/URL/응답 본문을 로그에 남기지 않음. 요청 경로와 분리된 batch worker임.
            return SpanExportResult.FAILURE

    def shutdown(self):
        self.session.close()


class TraceLogFilter(logging.Filter):
    def filter(self, record):
        context = trace.get_current_span().get_span_context()
        request_context = _request_context.get()
        if request_context is not None:
            context = trace.get_current_span(request_context).get_span_context()
        if not context.is_valid:
            context = _error_context.get() or context
        record.v2_trace_prefix = (f'trace_id={context.trace_id:032x} span_id={context.span_id:016x} '
                                  if context.is_valid and context.trace_flags.sampled else '')
        return True


class TraceFormatter(logging.Formatter):
    """Uvicorn AccessFormatter의 원래 msg/5개 args를 그대로 보존함."""
    def __init__(self, delegate):
        super().__init__()
        self.delegate = delegate or logging.Formatter()

    def format(self, record):
        return getattr(record, 'v2_trace_prefix', '') + self.delegate.format(record)


class ServerMiddleware:
    def __init__(self, app, tracer, routes):
        self.app, self.tracer, self.routes = app, tracer, routes
        self.route_patterns = [(route, compile_path(route)[0]) for route in routes]

    async def __call__(self, scope, receive, send):
        path = scope.get('path', '')
        if scope['type'] == 'http':
            _error_context.set(None)
        if scope['type'] != 'http' or path in {'/health', '/ready', '/metrics', '/internal/metrics'} or path == '/static' or path.startswith('/static/'):
            return await self.app(scope, receive, send)
        method = method_name(scope.get('method'))
        headers = {key.decode('latin1'): value.decode('latin1') for key, value in scope.get('headers', ()) if key.lower() == b'traceparent'}
        parent = PROPAGATOR.extract(headers, context=Context(), getter=DefaultGetter())
        with self.tracer.start_as_current_span('HTTP server', context=parent, kind=trace.SpanKind.SERVER,
                attributes={'http.request.method': method}, record_exception=False, set_status_on_exception=False) as span:
            token = _request_context.set(trace.set_span_in_context(span, Context()))
            async def traced_send(message):
                if message['type'] == 'http.response.start':
                    span.set_attribute('http.response.status_code', message['status'])
                    route = getattr(scope.get('route'), 'path', None)
                    if route is not None:
                        # 지연 include_router의 scope.route는 prefix 없는 원본 APIRoute임.
                        # 원본 요청값은 등록된 템플릿 선택에만 쓰며 속성으로 복사하지 않음.
                        route = next((template for template, pattern in self.route_patterns
                                      if pattern.fullmatch(scope.get('path', ''))), None)
                    if route in self.routes:
                        span.set_attribute('http.route', route)
                await send(message)
            try:
                return await self.app(scope, receive, traced_send)
            except Exception:
                span.set_attribute('http.response.status_code', 500)
                # Uvicorn은 ASGI 예외가 반환된 뒤 로깅함. 현재 요청 task에만 ID를 유지함.
                _error_context.set(span.get_span_context())
                raise
            finally:
                _request_context.reset(token)


class InternalTransport(httpx.AsyncBaseTransport):
    def __init__(self, tracer=None, transport=None):
        self.tracer = tracer or _tracer
        self.transport = transport or httpx.AsyncHTTPTransport()

    async def handle_async_request(self, request):
        # HTTPX redirect가 내부 요청 헤더를 외부 대상으로 복사해도 전파하지 않음.
        for header in ('traceparent', 'tracestate', 'baggage'):
            request.headers.pop(header, None)
        url = request.url
        allowed = (url.scheme == 'http' and not url.userinfo and url.path == '/api/search'
                   and (url.host, url.port) in {('book', 8003), ('youtube', 8002)})
        if not allowed or self.tracer is None:
            return await self.transport.handle_async_request(request)
        with self.tracer.start_as_current_span('HTTP client', context=_request_context.get() or Context(), kind=trace.SpanKind.CLIENT,
                attributes={'http.request.method': method_name(request.method), 'http.route': '/api/search'},
                record_exception=False, set_status_on_exception=False) as span:
            PROPAGATOR.inject(request.headers)
            try:
                response = await self.transport.handle_async_request(request)
                span.set_attribute('http.response.status_code', response.status_code)
                return response
            except Exception:
                span.set_attribute('http.response.status_code', 503)
                raise

    async def aclose(self):
        await self.transport.aclose()


def internal_transport():
    if _service != 'portal':
        raise RuntimeError('V2 internal client instrumentation requires portal')
    return InternalTransport()


def configure(app):
    global _tracer, _service
    service, environment = os.getenv('OTEL_SERVICE_NAME'), os.getenv('V2_ENVIRONMENT')
    if os.getenv('OTEL_EXPORTER_OTLP_ENDPOINT') != ENDPOINT:
        raise RuntimeError('V2 telemetry endpoint invalid')
    # FastAPI 0.142의 include_router는 app.routes에 지연 _IncludedRouter로 남음.
    # 공식 OpenAPI 생성 결과에서 prefix/nested router가 반영된 정적 템플릿을 얻음.
    routes = list(app.openapi().get('paths', {}))
    routes.extend(route.path for route in app.routes if hasattr(route, 'path') and route.path not in routes)
    exporter = PrivateExporter(service, environment, set(routes) | {'/api/search'})
    # Resource.create / global provider / 자동 detector는 환경 속성을 병합하므로 사용하지 않음.
    provider = TracerProvider(resource=Resource({}), shutdown_on_exit=False)
    provider.add_span_processor(BatchSpanProcessor(exporter, max_queue_size=128,
        max_export_batch_size=32, schedule_delay_millis=1000, export_timeout_millis=2000))
    _tracer, _service = provider.get_tracer('v2.http', '1'), service
    app.add_middleware(ServerMiddleware, tracer=_tracer, routes=routes)
    for name in ('uvicorn.access', 'uvicorn.error'):
        logger = logging.getLogger(name)
        if not any(isinstance(f, TraceLogFilter) for f in logger.filters):
            logger.addFilter(TraceLogFilter())
        current = logger
        while current is not None:
            for handler in current.handlers:
                if not isinstance(handler.formatter, TraceFormatter):
                    handler.setFormatter(TraceFormatter(handler.formatter))
            current = current.parent if current.propagate else None
    atexit.register(provider.shutdown)
    return provider
