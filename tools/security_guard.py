"""V2 내장 admission 정책의 고정 namespace·소유 경계. 일반 context 사용 금지."""
import json
import lab

NAME = 'v2-app-workloads'
NS = frozenset(lab.ENVIRONMENTS.values())
POLICY = 'ValidatingAdmissionPolicy'
BINDING = 'ValidatingAdmissionPolicyBinding'
SCOPE = [{'name': 'v2-app-namespaces', 'expression': "request.namespace in ['v2-dev', 'v2-verify']"}]


def validate(objects):
    expected = {(POLICY, None, NAME), (BINDING, None, NAME)}
    for namespace in NS:
        expected |= {(kind, namespace, 'v2-diagnostics') for kind in ('ServiceAccount', 'Role', 'RoleBinding')}
        expected.add(('NetworkPolicy', namespace, 'v2-default-deny'))
    actual = set()
    for obj in objects:
        kind, meta = obj['kind'], obj['metadata']
        key = (kind, meta.get('namespace'), meta['name'])
        if key not in expected or key in actual or meta.get('labels', {}).get(lab.OWNER) != lab.VALUE:
            raise RuntimeError('보안 선언 종류/이름/namespace/소유 불일치')
        actual.add(key)
        if kind == POLICY:
            spec = obj['spec']
            if (spec.get('matchConditions') != SCOPE or spec.get('failurePolicy') != 'Fail'
                    or spec.get('paramKind') or spec.get('matchConstraints', {}).get('objectSelector')):
                raise RuntimeError('보안 정책의 고정 적용 범위 불일치')
        if kind == BINDING and (obj['spec'].get('policyName') != NAME
                               or obj['spec'].get('validationActions') != ['Deny']
                               or obj['spec'].get('paramRef')):
            raise RuntimeError('보안 Binding 계약 불일치')
    if actual != expected:
        raise RuntimeError('보안 선언 누락')
    return objects


def preflight(revision):
    path = 'platforms/security'
    if lab.run(['git', 'rev-parse', 'HEAD']).strip() != revision or lab.run(['git', 'status', '--porcelain', '--', path]).strip():
        raise RuntimeError('보안 정책은 checkout된 커밋의 명세로만 적용함')
    rendered = lab.k('kustomize', 'platforms/security/policies')
    objects = validate(lab.decode_objects(lab.k('create', '--dry-run=client', '--validate=false', '-f', '-', '-o', 'json', stdin=rendered)))
    for obj in objects:
        ns = obj['metadata'].get('namespace')
        if ns:
            lab.namespace_guard(ns)
        lab.refuse_foreign(obj['kind'], obj['metadata']['name'], ns)
    return objects


def owned_cluster(kind):
    lab.guard()
    obj = json.loads(lab.k('get', kind, NAME, '-o', 'json'))
    if obj['metadata'].get('labels', {}).get(lab.OWNER) != lab.VALUE:
        raise RuntimeError('보안 cluster 자원 소유 불일치')
    if kind == POLICY and (obj['spec'].get('matchConditions') != SCOPE or obj['spec'].get('failurePolicy') != 'Fail'):
        raise RuntimeError('실제 보안 정책의 namespace 범위 불일치')
    if kind == BINDING and obj['spec'].get('policyName') != NAME:
        raise RuntimeError('보안 Binding 정책 이름 불일치')
    return obj
