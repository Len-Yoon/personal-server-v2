"""관측 chart를 렌더해 실제 권한·공개 범위·비밀값·자원 예산을 확인함."""
import hashlib
import json
from pathlib import Path
import subprocess
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'platforms/observability'


def render(name):
    if name == 'blackbox':
        output = subprocess.check_output(['kubectl', 'kustomize', str(BASE / name)], text=True)
    else:
        output = subprocess.check_output(['helm', 'template', name, str(BASE / name / 'chart'), '-n', 'v2-observability', '-f', str(BASE / name / 'values.yaml')], text=True)
    return [o for o in yaml.safe_load_all(output) if o]


class ObservabilityTests(unittest.TestCase):
    def test_vendor_integrity(self):
        lock = json.loads((BASE / 'dependencies.json').read_text())
        for name in ('prometheus', 'grafana'):
            self.assertEqual(hashlib.sha256((BASE / lock[name]['file']).read_bytes()).hexdigest(), lock[name]['sha256'])

    def test_resource_and_security_contracts(self):
        memory_mib = 0
        declarations = list(yaml.safe_load_all((BASE / 'applications.yaml').read_text()))
        project = next(obj for obj in declarations if obj['kind'] == 'AppProject')
        allowed = {r['kind'] for key in ('namespaceResourceWhitelist', 'clusterResourceWhitelist') for r in project['spec'][key]}
        for name in ('prometheus', 'grafana', 'blackbox'):
            for obj in render(name):
                self.assertIn(obj['kind'], allowed)
                self.assertNotEqual(obj['kind'], 'Secret')
                self.assertEqual(obj['metadata']['labels']['lab.personal-server-v2/owner'], 'personal-server-v2')
                if obj['kind'] == 'Service':
                    self.assertEqual(obj['spec'].get('type', 'ClusterIP'), 'ClusterIP')
                if obj['kind'] in ('Role', 'ClusterRole'):
                    for rule in obj.get('rules', []):
                        self.assertNotIn('nodes/proxy', rule.get('resources', []))
                        self.assertNotIn('secrets', rule.get('resources', []))
                        self.assertNotIn('*', rule.get('resources', []))
                        self.assertTrue(set(rule['verbs']) <= {'get', 'list', 'watch'})
                if obj['kind'] == 'Deployment':
                    pod = obj['spec']['template']['spec']
                    self.assertFalse(pod.get('hostNetwork', False))
                    self.assertFalse(pod.get('hostPID', False))
                    self.assertFalse(any('hostPath' in volume for volume in pod.get('volumes', [])))
                    for container in pod['containers']:
                        memory = container['resources']['limits']['memory']
                        memory_mib += int(memory[:-2]) * (1024 if memory.endswith('Gi') else 1)
                        self.assertFalse(container.get('securityContext', {}).get('allowPrivilegeEscalation', False))
        self.assertLessEqual(memory_mib, 2048)

    def test_metrics_collection_has_tls_and_limited_scope(self):
        configs = [obj for obj in render('prometheus') if obj['kind'] == 'ConfigMap' and 'prometheus.yml' in obj.get('data', {})]
        config = yaml.safe_load(configs[0]['data']['prometheus.yml'])
        jobs = {job['job_name']: job for job in config['scrape_configs']}
        self.assertNotIn('prometheus-pushgateway', jobs)
        self.assertEqual(sum(len(config['targets']) for config in jobs['book-http']['static_configs']), 2)
        for name, job in jobs.items():
            self.assertFalse(job.get('tls_config', {}).get('insecure_skip_verify', False))
            for rule in job.get('relabel_configs', []):
                self.assertNotIn('/proxy/', rule.get('replacement', ''))
        config = yaml.safe_load((BASE / 'grafana/values.yaml').read_text())['grafana']
        self.assertFalse(config['automountServiceAccountToken'])
        self.assertEqual(config['admin']['existingSecret'], 'grafana-admin')
        self.assertFalse(config['grafana.ini']['auth.anonymous']['enabled'])


if __name__ == '__main__':
    unittest.main()
