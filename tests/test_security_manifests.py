"""렌더된 보안 경계의 정적 회귀 검사. 실제 CEL 집행·CNI 패킷 증거와 구분함."""
import ipaddress
import json
from pathlib import Path
import subprocess
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
OWNER = 'lab.personal-server-v2/owner'
VALUE = 'personal-server-v2'
NAMESPACES = ('v2-dev', 'v2-verify')


def render(path):
    raw = subprocess.check_output(['kubectl', 'kustomize', str(ROOT / path)], text=True)
    return [obj for obj in yaml.safe_load_all(raw) if obj]


def selector_matches(selector, labels):
    if not all(labels.get(key) == value for key, value in selector.get('matchLabels', {}).items()):
        return False
    for expression in selector.get('matchExpressions', []):
        key, operator = expression['key'], expression['operator']
        values = expression.get('values', [])
        if operator == 'In' and labels.get(key) not in values:
            return False
        if operator == 'NotIn' and labels.get(key) in values:
            return False
        if operator == 'Exists' and key not in labels:
            return False
        if operator == 'DoesNotExist' and key in labels:
            return False
    return True


def actor(app, namespace, address='10.42.0.10', owned=True):
    labels = {'app.kubernetes.io/name': app}
    if owned:
        labels[OWNER] = VALUE
    return {'namespace': namespace, 'labels': labels, 'ip': address}


def peer_matches(peer, endpoint, policy_namespace):
    if 'ipBlock' in peer:
        ip = ipaddress.ip_address(endpoint['ip'])
        block = peer['ipBlock']
        return ip in ipaddress.ip_network(block['cidr']) and not any(ip in ipaddress.ip_network(item) for item in block.get('except', []))
    if 'namespaceSelector' in peer:
        namespace_labels = {'kubernetes.io/metadata.name': endpoint['namespace']}
        if not selector_matches(peer['namespaceSelector'], namespace_labels):
            return False
    elif 'podSelector' in peer and endpoint['namespace'] != policy_namespace:
        return False
    return selector_matches(peer.get('podSelector', {}), endpoint['labels'])


def direction_allowed(policies, subject, other, direction, port, protocol):
    selected = [obj for obj in policies
                if obj['metadata']['namespace'] == subject['namespace']
                and direction in obj['spec']['policyTypes']
                and selector_matches(obj['spec']['podSelector'], subject['labels'])]
    if not selected:
        return True
    peer_key = 'from' if direction == 'Ingress' else 'to'
    for policy in selected:
        for rule in policy['spec'].get(direction.lower(), []):
            ports = rule.get('ports', [])
            if ports and not any(item.get('protocol', 'TCP') == protocol and item['port'] == port for item in ports):
                continue
            peers = rule.get(peer_key, [])
            if not peers or any(peer_matches(peer, other, subject['namespace']) for peer in peers):
                return True
    return False


def permits(policies, source, target, port, protocol='TCP'):
    return (direction_allowed(policies, source, target, 'Egress', port, protocol)
            and direction_allowed(policies, target, source, 'Ingress', port, protocol))


class SecurityManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.security = render('platforms/security/policies')
        cls.apps = {(app, namespace): render(f'apps/{app}/overlays/{namespace.removeprefix("v2-")}')
                    for app in ('book', 'portal', 'youtube') for namespace in NAMESPACES}
        cls.policies = [obj for obj in cls.security if obj['kind'] == 'NetworkPolicy']
        for objects in cls.apps.values():
            cls.policies.extend(obj for obj in objects if obj['kind'] == 'NetworkPolicy')
        cls.policies.extend(obj for obj in render('platforms/observability/logging/alloy') if obj['kind'] == 'NetworkPolicy')

    def test_app_serviceaccounts_are_explicit_and_never_bind_roles(self):
        for (app, namespace), objects in self.apps.items():
            with self.subTest(app=app, namespace=namespace):
                deployment = next(obj for obj in objects if obj['kind'] == 'Deployment')
                pod = deployment['spec']['template']['spec']
                serviceaccount = next(obj for obj in objects if obj['kind'] == 'ServiceAccount')
                self.assertEqual(pod['serviceAccountName'], 'v2-' + app)
                self.assertIs(pod['automountServiceAccountToken'], False)
                self.assertIs(serviceaccount['automountServiceAccountToken'], False)
                self.assertEqual(serviceaccount['metadata']['name'], 'v2-' + app)
                self.assertEqual(serviceaccount['metadata']['namespace'], namespace)
                self.assertEqual(serviceaccount['metadata']['labels'][OWNER], VALUE)
                self.assertFalse(any(obj['kind'] in ('RoleBinding', 'ClusterRoleBinding') for obj in objects))
        for obj in self.security:
            if obj['kind'] == 'RoleBinding':
                self.assertEqual(obj['subjects'], [{'kind': 'ServiceAccount', 'name': 'v2-diagnostics', 'namespace': obj['metadata']['namespace']}])

    def test_diagnostic_rbac_has_no_write_secret_exec_or_token_access(self):
        expected = {('', 'pods', verb) for verb in ('get', 'list', 'watch')}
        expected |= {('', 'events', verb) for verb in ('get', 'list', 'watch')}
        expected |= {('events.k8s.io', 'events', verb) for verb in ('get', 'list', 'watch')}
        expected.add(('', 'pods/log', 'get'))
        roles = [obj for obj in self.security if obj['kind'] == 'Role']
        self.assertEqual({obj['metadata']['namespace'] for obj in roles}, set(NAMESPACES))
        for role in roles:
            actual = {(group, resource, verb) for rule in role['rules'] for group in rule['apiGroups']
                      for resource in rule['resources'] for verb in rule['verbs']}
            self.assertEqual(actual, expected)
        for obj in self.security:
            if obj['kind'] == 'ServiceAccount':
                self.assertEqual(obj['metadata']['name'], 'v2-diagnostics')
                self.assertIs(obj['automountServiceAccountToken'], False)
        self.assertFalse(any(obj['kind'] in ('ClusterRole', 'ClusterRoleBinding', 'Secret') for obj in self.security))

    def test_admission_scope_cannot_be_bypassed_by_owner_or_namespace_labels(self):
        policy = next(obj for obj in self.security if obj['kind'] == 'ValidatingAdmissionPolicy')
        binding = next(obj for obj in self.security if obj['kind'] == 'ValidatingAdmissionPolicyBinding')
        spec = policy['spec']
        self.assertEqual(spec['failurePolicy'], 'Fail')
        self.assertEqual(spec['matchConditions'], [{'name': 'v2-app-namespaces', 'expression': "request.namespace in ['v2-dev', 'v2-verify']"}])
        for data in (spec['matchConstraints'], binding['spec'].get('matchResources', {})):
            self.assertNotIn('objectSelector', data)
            self.assertNotIn('namespaceSelector', data)
        self.assertEqual(binding['spec'], {'policyName': 'v2-app-workloads', 'validationActions': ['Deny']})
        rules = spec['matchConstraints']['resourceRules']
        self.assertEqual({resource for rule in rules for resource in rule['resources']}, {'pods', 'pods/ephemeralcontainers', 'deployments'})
        self.assertTrue(all(rule['operations'] == ['CREATE', 'UPDATE'] and rule['apiVersions'] == ['v1'] for rule in rules))
        variables = {variable['name']: variable['expression'] for variable in spec['variables']}
        expressions = '\n'.join(item['expression'] for item in spec['validations'])
        self.assertIn('initContainers', variables['containers'])
        self.assertIn('ephemeralContainers', expressions)
        self.assertIn('has(s.serviceAccountToken)', expressions)
        self.assertIn('variables.expectedSA', expressions)
        self.assertIn('automountServiceAccountToken == false', expressions)
        self.assertIn('object.metadata.labels', expressions)
        self.assertIn('variables.podMetadata.labels', expressions)
        self.assertIn('localhost:5001/v2-', expressions)
        self.assertIn('@sha256:[a-f0-9]{64}$', expressions)
        self.assertIn('v2-security-probe', variables['expectedSA'])
        self.assertIn('v2-diagnostics', variables['expectedSA'])
        self.assertIn("quantity('1Gi')", expressions)

    def test_security_project_and_gitops_root_do_not_expand_cluster_kinds(self):
        declarations = list(yaml.safe_load_all((ROOT / 'platforms/security/applications.yaml').read_text()))
        project = next(obj for obj in declarations if obj['kind'] == 'AppProject')
        self.assertEqual(project['spec']['clusterResourceWhitelist'], [
            {'group': 'admissionregistration.k8s.io', 'kind': 'ValidatingAdmissionPolicy'},
            {'group': 'admissionregistration.k8s.io', 'kind': 'ValidatingAdmissionPolicyBinding'}])
        self.assertEqual({item['namespace'] for item in project['spec']['destinations']}, set(NAMESPACES))
        allowed = {(item['group'], item['kind']) for item in project['spec']['namespaceResourceWhitelist']}
        self.assertEqual(allowed, {('', 'ServiceAccount'), ('rbac.authorization.k8s.io', 'Role'),
                                   ('rbac.authorization.k8s.io', 'RoleBinding'), ('networking.k8s.io', 'NetworkPolicy')})
        app = next(obj for obj in declarations if obj['kind'] == 'Application')
        self.assertEqual(app['spec']['source']['path'], 'platforms/security/policies')
        self.assertEqual(app['spec']['destination']['namespace'], 'v2-dev')
        self.assertNotIn('automated', app['spec']['syncPolicy'])
        root = render('platforms/gitops/root')
        self.assertTrue(any(obj['kind'] == 'Application' and obj['metadata']['name'] == 'security' for obj in root))
        self.assertTrue(all(obj['kind'] in ('Application', 'AppProject', 'Namespace') for obj in root))

    def test_namespace_deny_and_app_allowed_traffic_matrix(self):
        deny = [obj for obj in self.security if obj['kind'] == 'NetworkPolicy']
        self.assertEqual({obj['metadata']['namespace'] for obj in deny}, set(NAMESPACES))
        self.assertTrue(all(obj['spec'] == {'podSelector': {}, 'policyTypes': ['Ingress', 'Egress'], 'ingress': [], 'egress': []} for obj in deny))
        for namespace in NAMESPACES:
            portal = actor('portal', namespace)
            book = actor('book', namespace, '10.42.0.11')
            youtube = actor('youtube', namespace, '10.42.0.12')
            probe = actor('v2-security-probe', namespace, '10.42.0.13')
            self.assertTrue(permits(self.policies, portal, book, 8003))
            self.assertTrue(permits(self.policies, portal, youtube, 8002))
            self.assertFalse(permits(self.policies, book, portal, 8000))
            self.assertFalse(permits(self.policies, youtube, portal, 8000))
            for app, port in ((portal, 8000), (book, 8003), (youtube, 8002)):
                self.assertFalse(permits(self.policies, probe, app, port))
                for client in ('blackbox', 'prometheus'):
                    self.assertTrue(permits(self.policies, actor(client, 'v2-observability'), app, port))
                self.assertTrue(permits(self.policies, app, actor('alloy', 'v2-observability'), 4318))
                self.assertFalse(permits(self.policies, app, actor('alloy', 'v2-observability'), 12345))
                for protocol in ('TCP', 'UDP'):
                    self.assertTrue(permits(self.policies, app, {'namespace': 'kube-system', 'labels': {'k8s-app': 'kube-dns'}, 'ip': '10.42.1.2'}, 53, protocol))
        for app, port in (('book', 8003), ('portal', 8000), ('youtube', 8002)):
            self.assertFalse(permits(self.policies, actor('portal', 'v2-dev'), actor(app, 'v2-verify'), port))
            self.assertFalse(permits(self.policies, actor('portal', 'v2-verify'), actor(app, 'v2-dev'), port))

    def test_book_public_https_exception_covers_nonpublic_ranges(self):
        canonical = json.loads((ROOT / 'platforms/security/public_https_exclusions.json').read_text())['ipv4_https_excluded_cidrs']
        networks = [ipaddress.ip_network(item) for item in canonical]
        self.assertEqual(len(networks), len(set(networks)))
        denied = ('0.1.2.3', '10.42.0.1', '100.64.1.1', '127.0.0.1', '169.254.169.254', '172.16.1.1',
                  '192.0.0.1', '192.0.2.1', '192.88.99.1', '192.168.1.1', '198.18.1.1', '198.51.100.1',
                  '203.0.113.1', '224.0.0.1', '240.0.0.1', '255.255.255.255')
        for namespace in NAMESPACES:
            policy = next(obj for obj in self.policies if obj['metadata']['namespace'] == namespace and obj['metadata']['name'] == 'book-isolation')
            exceptions = [peer['ipBlock'] for rule in policy['spec']['egress'] for peer in rule.get('to', []) if 'ipBlock' in peer]
            self.assertEqual(exceptions, [{'cidr': '0.0.0.0/0', 'except': canonical}])
            for address in denied:
                with self.subTest(namespace=namespace, address=address):
                    self.assertTrue(any(ipaddress.ip_address(address) in network for network in networks))
                    self.assertFalse(permits(self.policies, actor('book', namespace), actor('outside', 'external', address), 443))
            for address in ('8.8.8.8', '1.1.1.1'):
                self.assertTrue(permits(self.policies, actor('book', namespace), actor('outside', 'external', address), 443))
                self.assertFalse(permits(self.policies, actor('book', namespace), actor('outside', 'external', address), 80))

    def test_argo_only_unneeded_mounts_disabled_and_management_roles_preserved(self):
        raw = subprocess.check_output(['helm', 'template', 'argocd', str(ROOT / 'platforms/argocd/chart'),
                                       '-n', 'argocd', '-f', str(ROOT / 'platforms/argocd/values.yaml')], text=True)
        objects = [obj for obj in yaml.safe_load_all(raw) if obj]
        for name in ('argocd-repo-server', 'argocd-redis'):
            pod = next(obj for obj in objects if obj['kind'] == 'Deployment' and obj['metadata']['name'] == name)['spec']['template']['spec']
            self.assertIs(pod['automountServiceAccountToken'], False)
            accounts = [obj for obj in objects if obj['kind'] == 'ServiceAccount' and obj['metadata']['name'] == pod['serviceAccountName']]
            for account in accounts:
                self.assertIs(account['automountServiceAccountToken'], False)
            # Redis chart는 별도 SA를 생성하지 않아도 Pod-level false로 차단함.
            if not accounts:
                self.assertEqual(pod['serviceAccountName'], 'default')
        for name in ('argocd-application-controller', 'argocd-server'):
            self.assertTrue(any(obj['kind'] == 'ClusterRoleBinding' and obj['metadata']['name'] == name for obj in objects))


if __name__ == '__main__':
    unittest.main()
