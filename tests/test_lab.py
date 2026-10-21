"""운영 접근 거부와 GitOps 배포 계약 검증. 실제 클러스터 접근 없음."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('lab', ROOT / 'tools/lab.py')
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


class GuardTests(unittest.TestCase):
    def test_multi_resource_json_accepts_list_and_stream(self):
        objects = [{'kind': 'Namespace', 'metadata': {'name': 'v2-dev'}}, {'kind': 'Application', 'metadata': {'name': 'book-dev'}}]
        self.assertEqual(lab.decode_objects('\n'.join(json.dumps(o) for o in objects)), objects)
        self.assertEqual(lab.decode_objects(json.dumps({'kind': 'List', 'items': objects})), objects)
    def config(self):
        return {'contexts': [{'name': lab.CONTEXT, 'context': {'cluster': 'v2', 'user': 'v2'}}],
                'clusters': [{'name': 'v2', 'cluster': {'server': 'https://127.0.0.1:6550', 'certificate-authority-data': 'v2-ca'}}],
                'users': [{'name': 'v2', 'user': {'client-certificate-data': 'cert', 'client-key-data': 'key'}}]}

    def test_only_pinned_loopback_certificate_config_allowed(self):
        self.assertTrue(lab.kube_config_valid(self.config()))
        for endpoint in ('https://production:6443', 'https://127.0.0.1:6443', 'http://127.0.0.1:6550'):
            config = self.config()
            config['clusters'][0]['cluster']['server'] = endpoint
            self.assertFalse(lab.kube_config_valid(config))
        for key, value in [('exec', {'command': 'malicious'}), ('auth-provider', {}), ('tokenFile', '/secret')]:
            config = self.config()
            config['users'][0]['user'][key] = value
            self.assertFalse(lab.kube_config_valid(config))
        config = self.config()
        config['clusters'][0]['cluster']['proxy-url'] = 'https://production'
        self.assertFalse(lab.kube_config_valid(config))

    def test_tampered_kubeconfig_refused_before_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            state, kube = Path(tmp) / 'state', Path(tmp) / 'config'
            state.write_text(json.dumps({'owner': lab.VALUE, 'kube_sha256': 'incorrect'}))
            kube.write_text('changed')
            with patch.object(lab, 'STATE', state), patch.object(lab, 'KUBE', kube), patch.object(lab, 'k') as k:
                with self.assertRaisesRegex(RuntimeError, '불일치'):
                    lab.guard()
                k.assert_not_called()

    def test_replaced_container_refused_before_cluster_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            kube, state = Path(tmp) / 'kube', Path(tmp) / 'state'
            kube.write_text('v2')
            state.write_text(json.dumps({'owner': lab.VALUE, 'kube_sha256': hashlib.sha256(b'v2').hexdigest(),
                                         'containers': {'ps-v2-registry': 'original'}, 'cluster_uid': 'v2'}))
            with patch.object(lab, 'KUBE', kube), patch.object(lab, 'STATE', state), patch.object(lab, 'k', return_value=json.dumps(self.config())) as k, patch.object(lab, 'container_owned', return_value={'Id': 'replacement'}):
                with self.assertRaisesRegex(RuntimeError, 'ID 불일치'):
                    lab.guard()
                self.assertEqual(k.call_count, 1)  # config view만 실행

    def test_remote_docker_refused(self):
        with patch.object(lab, 'run', return_value='ssh://production') as run:
            with self.assertRaisesRegex(RuntimeError, '소켓 불일치'):
                lab.docker('rm', '-f', 'anything')
            self.assertEqual(run.call_count, 1)

    def test_foreign_namespace_refused(self):
        with patch.object(lab, 'k', return_value=json.dumps({'metadata': {'labels': {}}})):
            with self.assertRaisesRegex(RuntimeError, '소유 표식'):
                lab.namespace_guard('v2-verify')

    def test_cleanup_refuses_shared_network_before_delete(self):
        data = {'containers': {'ps-v2-registry': 'our-id'}, 'network': 'our-net', 'volumes': {}}
        def docker(*args, **kwargs):
            if args[:2] == ('ps', '-a'):
                return 'ps-v2-registry\n'
            if args[:2] == ('network', 'ls'):
                return 'ps-v2\n'
            if args[:2] == ('network', 'inspect'):
                return json.dumps([{'Id': 'our-net', 'Containers': {'our-id': {}, 'foreign-id': {}}}])
            raise AssertionError('예상하지 않은 mutation: ' + repr(args))
        with patch.object(lab, 'docker', side_effect=docker), patch.object(lab, 'container_owned', return_value={'Id': 'our-id'}):
            with self.assertRaisesRegex(RuntimeError, '타 소유'):
                lab.cleanup_resources(data)

    def test_application_destination_tamper_refused(self):
        obj = {'metadata': {'labels': {lab.OWNER: lab.VALUE}}, 'spec': {'project': 'book-verify',
               'destination': {'server': 'https://production:6443', 'namespace': 'v2-verify'},
               'source': {'repoURL': lab.REPO, 'path': 'apps/book/overlays/verify'}}}
        with patch.object(lab, 'k', return_value=json.dumps(obj)):
            with self.assertRaisesRegex(RuntimeError, '불일치'):
                lab.application_guard('verify')

    def test_sync_ignores_old_failure_and_waits_for_own_operation(self):
        revision = 'a' * 40
        old = {'status': {'operationState': {'phase': 'Failed', 'message': 'old attempt',
               'operation': {'sync': {'revision': revision}, 'info': [{'name': 'v2-request', 'value': 'old'}]}}}}
        new = {'status': {'operationState': {'phase': 'Succeeded',
               'operation': {'sync': {'revision': revision}, 'info': [{'name': 'v2-request', 'value': 'new'}]}}}}
        responses = iter(['patched', 'rolled out'])
        with patch.object(lab, 'guard'), patch.object(lab, 'application_guard', side_effect=[old, old, new]) as get_app, patch.object(lab.secrets, 'token_hex', return_value='new'), patch.object(lab.time, 'sleep'), patch.object(lab, 'k', side_effect=lambda *a, **kw: next(responses)) as k:
            lab.sync(SimpleNamespace(environment='verify', revision=revision))
            self.assertEqual(k.call_count, 2)
            self.assertEqual(get_app.call_count, 3)

    def test_deploy_uses_argo_and_not_workload_apply(self):
        with patch.object(lab, 'credentials'), patch.object(lab, 'sync') as sync, patch.object(lab, 'k') as k:
            lab.deploy(SimpleNamespace(revision='a' * 40))
            self.assertEqual([c.args[0].environment for c in sync.call_args_list], ['dev', 'verify'])
            k.assert_not_called()

    def test_existing_argo_bootstrap_never_calls_helm(self):
        def k(*args, **kwargs):
            if 'deployment' in args:
                return '{"metadata":{"name":"argocd-server"}}'
            if 'secrets' in args:
                return 'secret/sh.helm.release.v1.argocd.v1'
            return ''
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(lab, 'LOCAL', Path(tmp)), patch.object(lab, 'guard'), patch.object(lab, 'namespace_guard'), patch.object(lab, 'refuse_foreign'), patch.object(lab, 'k', side_effect=k), patch.object(lab, 'run') as run:
                lab.argocd(None)
                run.assert_not_called()

    def test_cleanup_can_resume_with_missing_container(self):
        data = {'containers': {'deleted': 'gone-id', 'remaining': 'our-id'}, 'network': None, 'volumes': {}}
        calls = []
        def docker(*args, **kwargs):
            calls.append(args)
            if args[:2] == ('ps', '-a'):
                return 'remaining\n'
            return ''
        with patch.object(lab, 'docker', side_effect=docker), patch.object(lab, 'container_owned', return_value={'Id': 'our-id'}):
            lab.cleanup_resources(data)
        self.assertIn(('rm', '-f', 'our-id'), calls)
        self.assertNotIn(('rm', '-f', 'gone-id'), calls)


class ManifestTests(unittest.TestCase):
    def test_book_contract(self):
        import yaml
        for env in ('dev', 'verify'):
            rendered = subprocess.check_output(['kubectl', 'kustomize', str(ROOT / 'apps/book/overlays' / env)], text=True)
            objects = list(yaml.safe_load_all(rendered))
            self.assertEqual({o['kind'] for o in objects}, {'Deployment', 'Service', 'PersistentVolumeClaim', 'ResourceQuota', 'LimitRange'})
            for obj in objects:
                self.assertEqual(obj['metadata']['namespace'], 'v2-' + env)
                self.assertEqual(obj['metadata']['labels'][lab.OWNER], lab.VALUE)
            deployment = next(o for o in objects if o['kind'] == 'Deployment')
            self.assertEqual(deployment['spec']['replicas'], 1)
            self.assertEqual(deployment['spec']['strategy']['type'], 'Recreate')
            pod = deployment['spec']['template']['spec']
            self.assertFalse(pod['automountServiceAccountToken'])
            c = pod['containers'][0]
            self.assertRegex(c['image'], r'^localhost:5001/v2-book@sha256:[0-9a-f]{64}$')
            self.assertTrue(c['securityContext']['readOnlyRootFilesystem'])
            self.assertEqual(c['readinessProbe']['httpGet']['path'], '/ready')
            self.assertFalse(any('hostPath' in v for v in pod['volumes']))

    def test_k3d_and_gitops_boundaries(self):
        import yaml
        config = yaml.safe_load((ROOT / 'platforms/k3d/cluster.yaml').read_text())
        self.assertEqual(config['kubeAPI']['hostIP'], '127.0.0.1')
        self.assertFalse(config['options']['kubeconfig']['updateDefaultKubeconfig'])
        self.assertFalse(config['options']['kubeconfig']['switchCurrentContext'])
        self.assertFalse(config.get('volumes'))
        for obj in yaml.safe_load_all((ROOT / 'platforms/argocd/applications.yaml').read_text()):
            if obj['kind'] == 'Application':
                self.assertNotIn('automated', obj['spec']['syncPolicy'])
                self.assertEqual(obj['spec']['destination']['server'], 'https://kubernetes.default.svc')
            else:
                self.assertEqual(obj['spec']['clusterResourceWhitelist'], [])
                self.assertNotIn('Secret', {r['kind'] for r in obj['spec']['namespaceResourceWhitelist']})


if __name__ == '__main__':
    unittest.main()
