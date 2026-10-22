"""보안 CLI의 적용 범위·실습 격리·실패 시 Secret 보존 경계."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import lab
import security_guard as guard
import verify_security as verify


class SecurityToolTests(unittest.TestCase):
    def objects(self):
        import yaml, subprocess
        return [o for o in yaml.safe_load_all(subprocess.check_output(['kubectl','kustomize',str(ROOT/'platforms/security/policies')],text=True)) if o]

    def test_scope_label_removal_cannot_expand_cluster_policy(self):
        objects = self.objects();guard.validate(objects)
        for change in ('scope', 'objectSelector', 'binding', 'foreign-kind'):
            modified = copy.deepcopy(objects)
            policy = next(o for o in modified if o['kind'] == guard.POLICY)
            binding = next(o for o in modified if o['kind'] == guard.BINDING)
            if change == 'scope': policy['spec']['matchConditions'] = []
            elif change == 'objectSelector': policy['spec']['matchConstraints']['objectSelector'] = {'matchLabels': {lab.OWNER: lab.VALUE}}
            elif change == 'binding': binding['spec']['validationActions'] = ['Warn']
            else: modified.append({'kind':'Secret','metadata':{'name':'v2-diagnostics','namespace':'v2-verify','labels':{lab.OWNER:lab.VALUE}}})
            with self.subTest(change=change), self.assertRaises(RuntimeError): guard.validate(modified)

    def test_preflight_foreign_source_stops_before_cluster_mutation(self):
        with patch.object(lab,'run',side_effect=['a'*40,'changed']), patch.object(lab,'k') as k:
            with self.assertRaises(RuntimeError):guard.preflight('a'*40)
            k.assert_not_called()

    def test_probe_never_uses_existing_service_identity_or_api_token(self):
        obj=verify.pod_spec('v2-security-probe-fixture')
        self.assertEqual(obj['metadata']['labels']['app.kubernetes.io/name'],'v2-security-probe')
        self.assertEqual(obj['spec']['serviceAccountName'],'v2-diagnostics')
        self.assertFalse(obj['spec']['automountServiceAccountToken'])
        self.assertRegex(obj['spec']['containers'][0]['image'],r'@sha256:[a-f0-9]{64}$')

    def test_dryrun_acceptance_or_unrelated_errors_do_not_count_as_rejection(self):
        with patch.object(lab,'k',return_value='{}'):
            with self.assertRaisesRegex(RuntimeError,'허용됨'):verify.dry_run({},guard.NAME)
        with patch.object(lab,'k',side_effect=RuntimeError('immutable field')):
            with self.assertRaisesRegex(RuntimeError,'예상한 정책'):verify.dry_run({},guard.NAME)

    def test_cleanup_refuses_replaced_uid_without_delete(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'journal'
            path.write_text(json.dumps({'cluster_uid':'cluster','items':[{'namespace':'v2-verify','kind':'Pod','name':'v2-security-test','uid':'original'}]}))
            with patch.object(verify,'JOURNAL',path),patch.object(lab,'guard',return_value={'cluster_uid':'cluster'}),patch.object(lab,'k',return_value='pod/v2-security-test') as k,patch.object(verify,'owned_object',return_value={'metadata':{'uid':'other'}}):
                with self.assertRaisesRegex(RuntimeError,'UID 변경'):verify.cleanup()
                self.assertEqual(k.call_count,1)
                self.assertTrue(path.exists())

    def test_credentials_preflight_failure_does_not_apply_or_commit_files(self):
        with patch.object(lab,'guard'),patch.object(lab,'refuse_foreign'),patch.object(lab,'k',return_value='namespace'),patch.object(lab,'credential_secret',return_value={'data':{}}),patch('secret_files.preflight_password',side_effect=RuntimeError('mismatch')),patch('secret_files.commit_password') as commit:
            with self.assertRaisesRegex(RuntimeError,'mismatch'):lab.credentials(None)
            commit.assert_not_called()

    def test_foreign_secret_body_is_not_read(self):
        with patch.object(lab,'k',return_value='uid\nforeign') as k:
            with self.assertRaisesRegex(RuntimeError,'소유 불일치'):lab.credential_secret('v2-dev','book-auth')
            self.assertEqual(k.call_count,1)

    def test_binding_restore_refuses_cluster_uid_mismatch_before_patch(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'journal';path.write_text(json.dumps({'cluster_uid':'wrong','binding_uid':'b','policy_uid':'p'}))
            with patch.object(verify,'BREAKGLASS',path),patch.object(lab,'guard',return_value={'cluster_uid':'cluster'}),patch.object(lab,'application_guard',return_value={'spec':{}}),patch.object(guard,'owned_cluster',side_effect=[{'metadata':{'uid':'b'},'spec':{'validationActions':['Warn','Audit']}},{'metadata':{'uid':'p'}}]),patch.object(lab,'k') as k:
                with self.assertRaisesRegex(RuntimeError,'UID 불일치'):verify.binding_recovery(restore=True)
                k.assert_not_called()

if __name__=='__main__':unittest.main()
