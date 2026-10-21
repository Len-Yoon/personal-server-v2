"""GitOps 전환 시 기존 계약·공급 chart·관리 경계를 직접 렌더 대조함."""
import hashlib
import json
from pathlib import Path
import subprocess
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
OWNER = 'lab.personal-server-v2/owner'


def helm(chart, values, *extras):
    return list(yaml.safe_load_all(subprocess.check_output(['helm', 'template', 'argocd', str(chart), '-n', 'argocd', '-f', str(values), *extras], text=True)))


class PlatformTests(unittest.TestCase):
    def test_argo_vendor_and_runtime_secret_boundary(self):
        lock = json.loads((ROOT / 'dependencies.json').read_text())
        archive = ROOT / 'platforms/argocd/chart/charts' / lock['argocd_chart_file']
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), lock['argocd_chart_sha256'])
        objects = helm(ROOT / 'platforms/argocd/chart', ROOT / 'platforms/argocd/values.yaml')
        self.assertNotIn('Secret', {obj['kind'] for obj in objects})
        self.assertNotIn('Job', {obj['kind'] for obj in objects})
        for obj in objects:
            self.assertEqual(obj['metadata']['labels'][OWNER], 'personal-server-v2')
            self.assertNotIn('argocd.argoproj.io/hook', obj['metadata'].get('annotations', {}))
        # 초기 bootstrap에서만 인증 Secret과 init hook이 존재함.
        bootstrap = helm(ROOT / 'platforms/argocd/chart', ROOT / 'platforms/argocd/values.yaml',
                         '--set', 'argo-cd.configs.secret.createSecret=true', '--set', 'argo-cd.redisSecretInit.enabled=true')
        self.assertIn('Secret', {obj['kind'] for obj in bootstrap})
        self.assertIn('Job', {obj['kind'] for obj in bootstrap})

    def test_app_projects_match_rendered_permissions(self):
        declarations = list(yaml.safe_load_all((ROOT / 'platforms/argocd/self.yaml').read_text()))
        project = next(obj for obj in declarations if obj['kind'] == 'AppProject')
        allowed = {row['kind'] for key in ('clusterResourceWhitelist', 'namespaceResourceWhitelist') for row in project['spec'][key]}
        for obj in helm(ROOT / 'platforms/argocd/chart', ROOT / 'platforms/argocd/values.yaml'):
            self.assertIn(obj['kind'], allowed)
        app = next(obj for obj in declarations if obj['kind'] == 'Application')
        self.assertEqual(app['spec']['source']['helm'], {'releaseName': 'argocd', 'valueFiles': ['../values.yaml']})
        self.assertNotIn('automated', app['spec']['syncPolicy'])
        self.assertNotIn('finalizers', app['metadata'])

    def test_root_contains_only_owned_declarations(self):
        rendered = subprocess.check_output(['kubectl', 'kustomize', str(ROOT / 'platforms/gitops/root')], text=True)
        objects = list(yaml.safe_load_all(rendered))
        namespaces = set()
        apps = set()
        for obj in objects:
            self.assertIn(obj['kind'], {'Namespace', 'Application', 'AppProject'})
            self.assertEqual(obj['metadata']['labels'][OWNER], 'personal-server-v2')
            if obj['kind'] == 'Namespace':
                namespaces.add(obj['metadata']['name'])
                annotations = obj['metadata'].get('annotations', {})
                self.assertIn('Prune=false', annotations['argocd.argoproj.io/sync-options'])
                self.assertIn('Delete=false', annotations['argocd.argoproj.io/sync-options'])
            if obj['kind'] == 'Application':
                apps.add(obj['metadata']['name'])
                self.assertEqual(obj['spec']['source']['repoURL'], 'ssh://git@github.com/Len-Yoon/personal-server-v2.git')
                self.assertEqual(obj['spec']['destination']['server'], 'https://kubernetes.default.svc')
                self.assertNotIn('automated', obj['spec'].get('syncPolicy', {}))
                self.assertNotIn('finalizers', obj['metadata'])
        self.assertEqual(namespaces, {'argocd', 'v2-dev', 'v2-verify', 'v2-observability'})
        self.assertEqual(apps, {'argocd-self', 'book-dev', 'book-verify', 'prometheus', 'grafana', 'blackbox', 'portal-dev', 'portal-verify', 'youtube-dev', 'youtube-verify'})


if __name__ == '__main__':
    unittest.main()
