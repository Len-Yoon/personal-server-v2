"""로그 수집의 범위·권한·원본 비밀값 차단·합성 검증 도구 계약."""
import importlib.util
from contextlib import contextmanager
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import yaml

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'platforms/observability/logging'
sys.path.insert(0, str(ROOT / 'tools'))
spec = importlib.util.spec_from_file_location('logging_verification_test', ROOT / 'tools/verify_logging.py')
verification = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verification)


def render(name):
    output = subprocess.check_output(['kubectl', 'kustomize', str(BASE / name)], text=True)
    return [obj for obj in yaml.safe_load_all(output) if obj]


class LoggingManifestTests(unittest.TestCase):
    def test_observability_memory_and_log_query_budgets(self):
        def mib(value):
            return int(value[:-2]) * (1024 if value.endswith('Gi') else 1)
        objects = render('alloy') + render('loki')
        objects += [obj for obj in yaml.safe_load_all(subprocess.check_output(['kubectl', 'kustomize', str(ROOT / 'platforms/observability/tracing/tempo')], text=True)) if obj]
        for name in ('prometheus', 'grafana'):
            base = ROOT / 'platforms/observability' / name
            rendered = subprocess.check_output(['helm', 'template', name, str(base / 'chart'), '-n', 'v2-observability', '-f', str(base / 'values.yaml')], text=True)
            objects += [obj for obj in yaml.safe_load_all(rendered) if obj]
        objects += [obj for obj in yaml.safe_load_all(subprocess.check_output(['kubectl', 'kustomize', str(ROOT / 'platforms/observability/blackbox')], text=True)) if obj]
        total = sum(mib(container['resources']['limits']['memory']) for obj in objects if obj['kind'] in ('Deployment', 'StatefulSet') for container in obj['spec']['template']['spec']['containers'])
        quota = next(obj for obj in objects if obj['kind'] == 'ResourceQuota')
        self.assertLessEqual(total, mib(quota['spec']['hard']['limits.memory']))
        grafana = yaml.safe_load((ROOT / 'platforms/observability/grafana/values.yaml').read_text())['grafana']
        self.assertLess(int(grafana['env']['GOMEMLIMIT'].removesuffix('MiB')), mib(grafana['resources']['limits']['memory']))
        datasource = next(row for row in grafana['datasources']['datasources.yaml']['datasources'] if row['uid'] == 'v2-loki')
        dashboard = json.loads((ROOT / 'platforms/observability/grafana/chart/files/v2-logs.json').read_text())
        for panel in dashboard['panels']:
            if panel['type'] == 'logs':
                for target in panel['targets']:
                    self.assertGreater(target['maxLines'], 0)
                    self.assertLessEqual(target['maxLines'], datasource['jsonData']['maxLines'])

    def test_workloads_have_digest_limits_and_no_host_or_secret_files(self):
        kinds = set()
        for name in ('alloy', 'loki'):
            objects = render(name)
            self.assertFalse(any(obj['kind'] in ('ClusterRole', 'ClusterRoleBinding', 'Secret') for obj in objects))
            for obj in objects:
                self.assertEqual(obj['metadata']['labels']['lab.personal-server-v2/owner'], 'personal-server-v2')
                if obj['kind'] == 'Service':
                    self.assertEqual(obj['spec']['type'], 'ClusterIP')
                if obj['kind'] not in ('Deployment', 'StatefulSet'):
                    continue
                kinds.add(obj['kind'])
                pod = obj['spec']['template']['spec']
                self.assertFalse(pod.get('hostPID', False))
                self.assertFalse(pod.get('hostNetwork', False))
                self.assertFalse(any('hostPath' in volume or 'secret' in volume for volume in pod['volumes']))
                self.assertTrue(pod['securityContext']['runAsNonRoot'])
                for container in pod['containers']:
                    self.assertRegex(container['image'], r'@sha256:[0-9a-f]{64}$')
                    self.assertTrue(container['resources']['limits']['memory'])
                    self.assertFalse(container['securityContext']['allowPrivilegeEscalation'])
                    self.assertTrue(container['securityContext']['readOnlyRootFilesystem'])
                    self.assertEqual(container['securityContext']['capabilities']['drop'], ['ALL'])
                    self.assertFalse(any('--stability.level=experimental' == arg for arg in container.get('args', [])))
                if name == 'alloy':
                    self.assertEqual(pod['serviceAccountName'], 'v2-alloy')
                    self.assertTrue(pod['automountServiceAccountToken'])
                else:
                    self.assertFalse(pod['automountServiceAccountToken'])
        self.assertEqual(kinds, {'Deployment', 'StatefulSet'})

    def test_alloy_rbac_is_only_pod_metadata_and_logs_in_four_namespaces(self):
        objects = render('alloy')
        roles = [obj for obj in objects if obj['kind'] == 'Role']
        bindings = [obj for obj in objects if obj['kind'] == 'RoleBinding']
        self.assertEqual({obj['metadata']['namespace'] for obj in roles}, set(verification.NAMESPACES))
        self.assertEqual(len(roles), 4)
        self.assertEqual(len(bindings), 4)
        for role in roles:
            self.assertEqual(role['metadata']['name'], 'v2-alloy-logs')
            allowed = {(tuple(rule['apiGroups']), resource, verb) for rule in role['rules']
                       for resource in rule['resources'] for verb in rule['verbs']}
            self.assertEqual(allowed, {(('',), 'pods', verb) for verb in ('get', 'list', 'watch')} | {(('',), 'pods/log', 'get')})
        for binding in bindings:
            self.assertEqual(binding['roleRef'], {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'Role', 'name': 'v2-alloy-logs'})
            self.assertEqual(binding['subjects'], [{'kind': 'ServiceAccount', 'name': 'v2-alloy', 'namespace': 'v2-observability'}])

    def test_source_uses_owner_and_namespace_filters_without_host_log_sources(self):
        source = (BASE / 'alloy/config.alloy').read_text()
        self.assertIn('loki.source.kubernetes', source)
        for forbidden in ('loki.source.file', 'local.file_match', '/var/log', '/var/lib/docker', '/run/secrets'):
            self.assertNotIn(forbidden, source)
        self.assertIn('label = "lab.personal-server-v2/owner=personal-server-v2"', re.sub(r'\s+=\s+', ' = ', source))
        self.assertIn('__meta_kubernetes_pod_label_lab_personal_server_v2_owner', source)
        names_block = re.search(r'namespaces\s*\{(.*?)\}', source, re.S).group(1)
        namespaces = re.findall(r'"(v2-dev|v2-verify|argocd|v2-observability)"', names_block)
        self.assertEqual(set(namespaces), set(verification.NAMESPACES))
        self.assertIn('regex', source)
        for label in ('cluster', 'namespace', 'environment', 'service', 'container', 'pod'):
            self.assertIn('"' + label + '"', source)
        self.assertIn('http://loki.v2-observability.svc.cluster.local:3100/loki/api/v1/push', source)

    def test_redaction_pattern_retains_marker_and_removes_only_synthetic_values(self):
        source = (BASE / 'alloy/config.alloy').read_text()
        literal = re.search(r'^\s*expression\s*=\s*("(?:\\.|[^"\\])*")', source, re.M).group(1)
        pattern = re.compile(json.loads(literal))
        self.assertEqual(pattern.groups, 1)
        for key in ('password', 'token', 'authorization', 'secret', 'private_key', 'PRIVATE-KEY'):
            line = 'GET /v2-log-canary-' + 'a' * 32 + '?' + key + '=' + verification.SYNTHETIC_VALUE + ' HTTP/1.1 404'
            match = pattern.search(line)
            self.assertIsNotNone(match)
            masked = line[:match.start(1)] + '[REDACTED]' + line[match.end(1):]
            self.assertNotIn(verification.SYNTHETIC_VALUE, masked)
            self.assertIn('v2-log-canary-' + 'a' * 32, masked)
            self.assertIn('[REDACTED]', masked)

    def test_loki_wal_and_chunks_use_preserved_local_pvc(self):
        config = yaml.safe_load((BASE / 'loki/config.yaml').read_text())
        self.assertEqual(config['common']['replication_factor'], 1)
        self.assertTrue(config['ingester']['wal']['enabled'])
        self.assertEqual(config['ingester']['wal']['dir'], '/loki/wal')
        self.assertEqual(config['common']['storage']['filesystem']['chunks_directory'], '/loki/chunks')
        self.assertEqual(config['limits_config']['retention_period'], '24h')
        objects = render('loki')
        pvc = next(obj for obj in objects if obj['kind'] == 'PersistentVolumeClaim')
        self.assertEqual(pvc['metadata']['name'], verification.LOKI_PVC)
        self.assertEqual(pvc['spec']['resources']['requests']['storage'], '2Gi')
        self.assertEqual(pvc['metadata']['annotations']['argocd.argoproj.io/sync-options'], 'Prune=false,Delete=false')
        workload = next(obj for obj in objects if obj['kind'] == 'StatefulSet')
        pod = workload['spec']['template']['spec']
        storage = next(volume for volume in pod['volumes'] if 'persistentVolumeClaim' in volume)
        self.assertEqual(storage['persistentVolumeClaim']['claimName'], verification.LOKI_PVC)
        self.assertTrue(any(mount['name'] == storage['name'] and mount['mountPath'] == '/loki' for mount in pod['containers'][0]['volumeMounts']))

    def test_network_policies_and_grafana_datasource_have_local_scope(self):
        for name in ('alloy', 'loki'):
            policy = next(obj for obj in render(name) if obj['kind'] == 'NetworkPolicy')
            self.assertEqual(set(policy['spec']['policyTypes']), {'Ingress', 'Egress'})
            self.assertTrue(policy['spec']['podSelector']['matchLabels'])
            for direction in ('ingress', 'egress'):
                for rule in policy['spec'].get(direction, []):
                    self.assertTrue(rule.get('ports'))
                    if not rule.get('from' if direction == 'ingress' else 'to'):
                        # API Service DNAT 주소가 재생성마다 달라지는 로컬 실습 예외임.
                        self.assertEqual((name, direction), ('alloy', 'egress'))
                        self.assertEqual({(port['protocol'], port['port']) for port in rule['ports']}, {('TCP', 443), ('TCP', 6443)})
                    for peer in rule.get('from' if direction == 'ingress' else 'to', []):
                        self.assertNotEqual(peer.get('ipBlock', {}).get('cidr'), '0.0.0.0/0')
        values = yaml.safe_load((ROOT / 'platforms/observability/grafana/values.yaml').read_text())['grafana']
        datasources = values['datasources']['datasources.yaml']['datasources']
        self.assertTrue(any(item.get('uid') == 'v2-prometheus' for item in datasources))
        loki = next(item for item in datasources if item.get('uid') == 'v2-loki')
        self.assertEqual(loki['url'], 'http://loki.v2-observability.svc.cluster.local:3100')
        self.assertEqual(loki['access'], 'proxy')
        dashboards = list((ROOT / 'platforms/observability/grafana/chart/files').glob('*.json'))
        logs = next(json.loads(path.read_text()) for path in dashboards if json.loads(path.read_text()).get('uid') == 'v2-logs')
        expressions = [target.get('expr', '') for panel in logs['panels'] for target in panel.get('targets', [])]
        self.assertTrue(any('cluster=' in expression and 'namespace' in expression and 'service' in expression for expression in expressions))


class LoggingVerifierTests(unittest.TestCase):
    def test_retention_reads_previous_markers_only_while_collector_is_paused(self):
        calls = []
        canaries = [{'marker': 'v2-log-canary-' + 'a' * 32}]
        @contextmanager
        def pause():
            calls.append('pause')
            try:
                yield {'deployment_uid': 'alloy'}
            finally:
                calls.append('restore')
        def stopped(_):
            calls.append('assert-paused')
            return True
        def read(*_):
            calls.append('read-existing')
            return canaries
        with patch.object(verification, 'paused_collector', pause), patch.object(verification, 'collector_is_paused', side_effect=stopped), patch.object(verification, 'recreate_loki', side_effect=lambda: calls.append('recreate-loki') or {'pvc_uid': 'pvc'}), patch.object(verification, 'observe_canaries', side_effect=read), patch.object(verification, 'create_canaries', side_effect=AssertionError('새 요청 금지')):
            result = verification.verify_retention(canaries, 1)
        self.assertEqual(calls, ['pause', 'recreate-loki', 'assert-paused', 'read-existing', 'assert-paused', 'restore'])
        self.assertTrue(result['collector_paused_during_readback'])

    def test_real_pause_context_restores_even_if_readback_raises(self):
        deployment = {'metadata': {'uid': 'alloy-uid'}, 'spec': {'replicas': 1}}
        with tempfile.TemporaryDirectory() as directory:
            snapshot = Path(directory) / 'pause.json'
            with patch.object(verification, 'PAUSE', snapshot), patch.object(verification.lab, 'guard', return_value={'cluster_uid': 'cluster'}), patch.object(verification.lab, 'application_guard', return_value={'spec': {}}), patch.object(verification, 'owned_object', return_value=deployment), patch.object(verification, 'collector_is_paused', return_value=True), patch.object(verification.lab, 'k', return_value='') as request, patch.object(verification, 'restore_collector') as restore:
                with self.assertRaisesRegex(RuntimeError, 'read failed'):
                    with verification.paused_collector():
                        self.assertEqual(json.loads(snapshot.read_text()), {'cluster_uid': 'cluster', 'deployment_uid': 'alloy-uid', 'replicas': 1})
                        raise RuntimeError('read failed')
                operations = json.loads(request.call_args.args[-1])
                self.assertEqual(operations[0], {'op': 'test', 'path': '/metadata/uid', 'value': 'alloy-uid'})
                self.assertEqual(operations[1], {'op': 'test', 'path': '/spec/replicas', 'value': 1})
                restore.assert_called_once()

    def test_restore_refuses_replaced_collector_without_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            snapshot = Path(directory) / 'pause.json'
            snapshot.write_text(json.dumps({'cluster_uid': 'cluster', 'deployment_uid': 'original', 'replicas': 1}))
            with patch.object(verification, 'PAUSE', snapshot), patch.object(verification.lab, 'guard', return_value={'cluster_uid': 'cluster'}), patch.object(verification, 'owned_object', return_value={'metadata': {'uid': 'replaced'}}), patch.object(verification.lab, 'k') as request:
                with self.assertRaisesRegex(RuntimeError, 'Deployment UID'):
                    verification.restore_collector()
                request.assert_not_called()
                self.assertTrue(snapshot.exists())

    def test_synthetic_request_code_compiles_for_six_app_sources(self):
        with patch.object(verification, 'execute', return_value={'http': 404}) as execute:
            canaries = verification.create_canaries()
        self.assertEqual(len(canaries), 6)
        self.assertEqual({(item['namespace'], item['service']) for item in canaries},
                         {(namespace, service) for namespace in ('v2-dev', 'v2-verify') for service in verification.SERVICES})
        self.assertEqual(len({item['marker'] for item in canaries}), 6)
        for call in execute.call_args_list:
            code = call.args[2]
            compile(code, '<synthetic-log-request>', 'exec')
            self.assertIn(verification.SYNTHETIC_VALUE, code)
            self.assertIn('http://127.0.0.1:', code)

    def test_unmasked_synthetic_token_fails_before_raw_log_is_recorded(self):
        canary = {'namespace': 'v2-dev', 'service': 'book', 'environment': 'dev', 'marker': 'v2-log-canary-' + 'a' * 32}
        with patch.object(verification, 'query_lines', return_value=[({}, 'raw ' + verification.SYNTHETIC_VALUE)]):
            with self.assertRaisesRegex(RuntimeError, '마스킹 없이'):
                verification.observe_canaries([canary], 1)

    def test_secret_body_not_read_if_owner_metadata_is_foreign(self):
        with patch.object(verification.lab, 'namespace_guard'), patch.object(verification.lab, 'k', return_value='uid\nforeign') as request:
            with self.assertRaisesRegex(RuntimeError, '소유 표식'):
                verification.owned_object('v2-dev', 'secret', 'book-auth')
        self.assertEqual(request.call_count, 1)

    def test_loki_delete_requires_uid_and_keeps_pvc_uid(self):
        before = {'metadata': {'name': 'loki-0', 'uid': 'old'}}
        after = {'metadata': {'name': 'loki-0', 'uid': 'new'}}
        pvc = {'metadata': {'uid': 'pvc'}, 'status': {'phase': 'Bound'}}
        with patch.object(verification.lab, 'guard'), patch.object(verification, 'loki_pod', side_effect=[before, after]), patch.object(verification, 'owned_object', return_value=pvc), patch.object(verification.lab, 'k', return_value='') as request:
            result = verification.recreate_loki()
        args, kwargs = request.call_args
        self.assertEqual(args[:3], ('delete', '--raw', '/api/v1/namespaces/v2-observability/pods/loki-0'))
        self.assertEqual(json.loads(kwargs['stdin'])['preconditions']['uid'], 'old')
        self.assertEqual(result['pvc_uid'], 'pvc')


if __name__ == '__main__':
    unittest.main()
