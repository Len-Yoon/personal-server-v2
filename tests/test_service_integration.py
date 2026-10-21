"""Portal·YouTube 로컬 연계·격리·관측·소스 패치 계약의 정적 검증."""
import importlib.util
import json
import os
import sys
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import yaml

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


source_patch = module('v2_source_patch_test', ROOT / 'tools/v2_source_patch.py')
sys.path.insert(0, str(ROOT / 'tools'))
services_verification = module('services_verification_test', ROOT / 'tools/verify_services.py')


def render(service, environment):
    output = subprocess.check_output(['kubectl', 'kustomize', str(ROOT / 'apps' / service / 'overlays' / environment)], text=True)
    return [obj for obj in yaml.safe_load_all(output) if obj]


class ServiceManifestTests(unittest.TestCase):
    def test_services_persist_samples_without_host_credentials(self):
        for service, port in [('portal', 8000), ('youtube', 8002)]:
            for environment in ('dev', 'verify'):
                objects = render(service, environment)
                for obj in objects:
                    self.assertEqual(obj['metadata']['namespace'], 'v2-' + environment)
                    self.assertEqual(obj['metadata']['labels']['lab.personal-server-v2/owner'], 'personal-server-v2')
                    self.assertNotEqual(obj['kind'], 'Secret')
                deployment = next(obj for obj in objects if obj['kind'] == 'Deployment')
                self.assertEqual(deployment['spec']['replicas'], 1)
                self.assertEqual(deployment['spec']['strategy']['type'], 'Recreate')
                pod = deployment['spec']['template']['spec']
                self.assertFalse(pod['automountServiceAccountToken'])
                self.assertFalse(any('hostPath' in item for item in pod['volumes']))
                self.assertEqual(sum('persistentVolumeClaim' in item for item in pod['volumes']), 1)
                container = pod['containers'][0]
                self.assertRegex(container['image'], rf'^localhost:5001/v2-{service}@sha256:[0-9a-f]{{64}}$')
                self.assertEqual(container['readinessProbe']['httpGet']['path'], '/ready')
                self.assertEqual(container['livenessProbe']['httpGet']['path'], '/health')
                self.assertTrue(container['securityContext']['readOnlyRootFilesystem'])
                self.assertFalse(container['securityContext']['allowPrivilegeEscalation'])
                self.assertEqual(container['ports'][0]['containerPort'], port)
                values = {value['name']: value.get('value') for value in container['env']}
                self.assertEqual(values['V2_COOKIE_PREFIX'], 'v2_' + environment + '_')
                self.assertEqual(values['PORTAL_HOME_URL'], 'http://127.0.0.1:' + ('8000' if environment == 'dev' else '8090'))
                if service == 'portal':
                    self.assertEqual(values['DEMO_MODE'], 'false')
                    self.assertEqual(values['BOOKS_SEARCH_URL'], 'http://book:8003/api/search')
                    self.assertEqual(values['YOUTUBE_SEARCH_URL'], 'http://youtube:8002/api/search')
                    self.assertEqual(values['NEWS_SEARCH_URL'], 'http://127.0.0.1:9')
                    self.assertEqual(values['HOMEOPS_EXECUTOR_URL'], 'http://127.0.0.1:9')
                pvc = next(obj for obj in objects if obj['kind'] == 'PersistentVolumeClaim')
                self.assertEqual(pvc['metadata']['annotations']['argocd.argoproj.io/sync-options'], 'Prune=false,Delete=false')

    def test_observability_preserves_book_and_adds_all_service_endpoints(self):
        values = yaml.safe_load((ROOT / 'platforms/observability/prometheus/values.yaml').read_text())['prometheus']
        jobs = {job['job_name']: job for job in yaml.safe_load(values['extraScrapeConfigs'])}
        self.assertEqual(sum(len(row['targets']) for row in jobs['book-http']['static_configs']), 2)
        for service, port in [('portal', 8000), ('youtube', 8002)]:
            rows = jobs[service + '-http']['static_configs']
            actual = {(row['labels']['environment'], row['labels']['endpoint'], target) for row in rows for target in row['targets']}
            expected = {(environment, endpoint, f'http://{service}.v2-{environment}.svc.cluster.local:{port}/{endpoint}')
                        for environment in ('dev', 'verify') for endpoint in ('health', 'ready')}
            self.assertEqual(actual, expected)
        alerts = {rule['alert'] for group in values['serverFiles']['alerting_rules.yml']['groups'] for rule in group['rules']}
        self.assertTrue({'V2BookUnavailable', 'V2PortalUnavailable', 'V2YoutubeUnavailable'} <= alerts)
        dashboard = json.loads((ROOT / 'platforms/observability/grafana/chart/files/v2-platform-lab.json').read_text())
        self.assertEqual(len(dashboard['panels']), 12)
        expressions = [target.get('expr', '') for panel in dashboard['panels'] for target in panel.get('targets', [])]
        for service in ('book', 'portal', 'youtube'):
            self.assertTrue(any(f'probe_success{{job="{service}-http"}}' == expr for expr in expressions))

    def test_network_policies_limit_service_links_to_v2(self):
        for service in ('portal', 'youtube'):
            objects = render(service, 'verify')
            policy = next(obj for obj in objects if obj['kind'] == 'NetworkPolicy')
            self.assertIn('Egress', policy['spec']['policyTypes'])
            for rule in policy['spec']['egress']:
                self.assertTrue(rule.get('to'))
                self.assertFalse(any('ipBlock' in peer for peer in rule['to']))
                self.assertTrue(rule.get('ports'))
            if service == 'youtube':
                peers = [peer for rule in policy['spec']['ingress'] for peer in rule.get('from', [])]
                self.assertTrue(any(peer.get('namespaceSelector', {}).get('matchLabels', {}).get('kubernetes.io/metadata.name') == 'v2-observability'
                                    and peer.get('podSelector', {}).get('matchLabels', {}).get('app.kubernetes.io/name') == 'blackbox' for peer in peers))


class SourcePatchTests(unittest.TestCase):
    def fixture(self, directory):
        context = Path(directory)
        path = context / 'app/services/host_urls.py'
        path.parent.mkdir(parents=True)
        path.write_text('''import os
LOCAL = {"NEWS_SERVICE_URL": "http://127.0.0.1:8001", "YOUTUBE_MEMO_URL": "http://127.0.0.1:8002", "BOOK_MEMO_URL": "http://127.0.0.1:8003"}
def portal_home_url():
    return "http://127.0.0.1:8000/"
''')
        (context / 'app/main.py').write_text('import os\nWRITE_AUTH_COOKIE = "youtube_memo_write_session"\n')
        return context

    def test_v2_addresses_and_cookie_namespace_differ_by_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            context = self.fixture(directory)
            result = source_patch.apply(context)
            self.assertIn('app/services/host_urls.py', result['files'])
            self.assertIn('app/main.py', result['files'])
            cookies = set()
            for environment, portal, youtube, book in [('dev', 8000, 8002, 8003), ('verify', 8090, 8092, 8081)]:
                env = {'PORTAL_HOME_URL': f'http://127.0.0.1:{portal}', 'YOUTUBE_MEMO_URL': f'http://127.0.0.1:{youtube}',
                       'BOOK_MEMO_URL': f'http://127.0.0.1:{book}', 'V2_COOKIE_PREFIX': 'v2_' + environment + '_'}
                with patch.dict(os.environ, env, clear=True):
                    hosts, main = {}, {}
                    exec((context / 'app/services/host_urls.py').read_text(), hosts)
                    exec((context / 'app/main.py').read_text(), main)
                    self.assertEqual(hosts['portal_home_url'](), f'http://127.0.0.1:{portal}/')
                    self.assertEqual(hosts['LOCAL']['YOUTUBE_MEMO_URL'], f'http://127.0.0.1:{youtube}')
                    self.assertEqual(hosts['LOCAL']['BOOK_MEMO_URL'], f'http://127.0.0.1:{book}')
                    cookies.add(main['WRITE_AUTH_COOKIE'])
            self.assertEqual(cookies, {'v2_dev_youtube_memo_write_session', 'v2_verify_youtube_memo_write_session'})

    def test_unrecognized_source_contract_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            context = self.fixture(directory)
            (context / 'app/services/host_urls.py').write_text('import os\ndef unrelated(): return "changed upstream"\n')
            with self.assertRaisesRegex(RuntimeError, '계약 불일치'):
                source_patch.apply(context)


class RuntimeVerifierTests(unittest.TestCase):
    def test_all_generated_remote_python_compiles(self):
        sources = []
        def validate(namespace, service, code):
            compile(code, '<remote-' + service + '>', 'exec')
            sources.append(code)
            return {}
        with patch.object(services_verification, 'execute', side_effect=validate):
            services_verification.http_health('v2-verify', 'portal')
            services_verification.http_health('v2-verify', 'youtube')
            services_verification.book_snapshot('v2-verify')
            services_verification.seed_samples('v2-verify')
            services_verification.persisted_samples('v2-verify')
            services_verification.integrated_search('v2-verify')
        self.assertEqual(len(sources), 8)

    def test_pod_recreation_uses_uid_delete_precondition(self):
        calls = []
        def request(*args, **kwargs):
            calls.append((args, kwargs))
            return ''
        original = {'metadata': {'name': 'youtube-test', 'uid': 'original'}}
        replacement = {'metadata': {'name': 'youtube-new', 'uid': 'replacement'}}
        with patch.object(services_verification, 'owned_pod', side_effect=[original, replacement]), patch.object(services_verification.lab, 'k', side_effect=request):
            result = services_verification.restart_sample('v2-verify', 'youtube')
        self.assertEqual(result, {'old_uid': 'original', 'new_uid': 'replacement'})
        self.assertEqual(calls[0][0][:3], ('delete', '--raw', '/api/v1/namespaces/v2-verify/pods/youtube-test'))
        self.assertEqual(json.loads(calls[0][1]['stdin'])['preconditions']['uid'], 'original')


if __name__ == '__main__':
    unittest.main()
