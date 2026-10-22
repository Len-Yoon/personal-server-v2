"""실제 trace 증거의 서비스 관계와 개인정보 허용 목록 판정 검증."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
spec = importlib.util.spec_from_file_location('verify_tracing', ROOT / 'tools/verify_tracing.py')
verification = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verification)


def value(key, text):
    return {'key': key, 'value': {'stringValue': text}}


def fixture():
    trace = 'a' * 32
    payload = {'batches': []}
    for service, ids in [('portal', [('1', '', 2), ('2', '1', 3), ('3', '1', 3)]), ('book', [('4', '2', 2)]), ('youtube', [('5', '3', 2)])]:
        spans = []
        for span, parent, kind in ids:
            spans.append({'traceId': trace, 'spanId': span * 16, 'parentSpanId': parent * 16, 'kind': kind,
                'name': 'HTTP ' + ('server' if kind == 2 else 'client') + ' GET ' + ('/' if service == 'portal' and kind == 2 else '/api/search'), 'attributes': [value('http.request.method', 'GET'),
                value('http.route', '/' if service == 'portal' and kind == 2 else '/api/search'), {'key': 'http.response.status_code', 'value': {'intValue': 200}}]})
        payload['batches'].append({'resource': {'attributes': [value('service.name', service),
            value('deployment.environment.name', 'dev')]}, 'scopeSpans': [{'scope': {'name': 'v2.http', 'version': '1'}, 'spans': spans}]})
    return payload, trace


class TraceEvidenceTests(unittest.TestCase):
    def test_cross_service_parent_relationship_is_required(self):
        payload, trace = fixture()
        self.assertEqual(len(verification.inspect_trace(payload, trace, 'dev')['spans']), 5)
        payload['batches'][1]['scopeSpans'][0]['spans'][0]['parentSpanId'] = 'f' * 16
        with self.assertRaisesRegex(RuntimeError, '부모/자식'):
            verification.inspect_trace(payload, trace, 'dev')

    def test_stored_sensitive_attributes_events_and_status_are_rejected(self):
        for field in ('attribute', 'event', 'status', 'synthetic', 'resource', 'scope', 'tracestate', 'name', 'method', 'route'):
            payload, trace = fixture()
            span = payload['batches'][0]['scopeSpans'][0]['spans'][0]
            if field == 'attribute':
                span['attributes'].append(value('url.full', 'private'))
            elif field == 'event':
                span['events'] = [{'name': 'exception'}]
            elif field == 'status':
                span['status'] = {'message': 'private'}
            elif field == 'synthetic':
                span['name'] = verification.SYNTHETIC
            elif field == 'scope':
                payload['batches'][0]['scopeSpans'][0]['scope']['attributes'] = [value('private', 'other')]
            elif field == 'tracestate':
                span['traceState'] = 'private=other'
            elif field == 'name':
                span['name'] = 'private-other'
            elif field in ('method', 'route'):
                span['attributes'][0 if field == 'method' else 1]['value']['stringValue'] = 'private-other'
            else:
                payload['batches'][0]['resource']['attributes'].append(value('host.name', 'private'))
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                verification.inspect_trace(payload, trace, 'dev')


if __name__ == '__main__':
    unittest.main()
