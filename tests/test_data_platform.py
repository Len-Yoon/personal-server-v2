"""데이터 실습의 파괴 방지·namespace·자격 증명·배포 계약."""
import copy,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import yaml
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import lab,data_lab
ROOT=lab.ROOT
class DataTests(unittest.TestCase):
 def objects(self,env):return list(yaml.safe_load_all(subprocess.check_output(['kubectl','kustomize',str(ROOT/'platforms/data'/env)],text=True)))
 def test_pvc_deletion_protection_role_mounts_and_restore_stopped(self):
  for env in ('dev','restore'):
   objects=self.objects(env)
   for o in objects:
    self.assertEqual(o['metadata']['namespace'],'v2-data-'+env)
    self.assertEqual(o['metadata']['labels'][lab.OWNER],lab.VALUE)
    if o['kind']=='PersistentVolumeClaim':
     self.assertIn('Delete=false',o['metadata']['annotations']['argocd.argoproj.io/sync-options'])
    if o['kind'] in ('Deployment','StatefulSet'):
     p=o['spec']['template']['spec'];self.assertFalse(p['automountServiceAccountToken'])
     for c in p['containers']+p.get('initContainers',[]):
      self.assertRegex(c['image'],r'@sha256:[0-9a-f]{64}$');self.assertFalse(c['securityContext']['allowPrivilegeEscalation'])
   api=next(o for o in objects if o['kind']=='Deployment' and o['metadata']['name']=='notes-api')
   self.assertEqual(api['spec']['replicas'],1 if env=='dev' else 0)
   if env=='restore':self.assertNotIn('initContainers',api['spec']['template']['spec'])
   db=next(o for o in objects if o['kind']=='StatefulSet')
   self.assertEqual(db['spec']['replicas'],1)
 def test_schedule_and_default_deny(self):
  objects=self.objects('dev');cron=next(o for o in objects if o['kind']=='CronJob')['spec']
  self.assertEqual(cron['schedule'],'0 * * * *');self.assertEqual(cron['concurrencyPolicy'],'Forbid')
  for env in ('dev','restore'):
   n=next(o for o in self.objects(env) if o['metadata']['name']=='data-default-deny')
   self.assertEqual(n['spec'],{'podSelector':{},'policyTypes':['Ingress','Egress']})
 def test_uncommitted_preflight_no_cluster_mutation(self):
  with patch.object(lab,'run',side_effect=['a'*40,'changed']),patch.object(lab,'k') as k:
   with self.assertRaises(RuntimeError):data_lab.preflight('data-dev','a'*40)
   k.assert_not_called()
 def test_restore_invalid_id_refuses_before_job_creation(self):
  with patch.object(lab,'guard'),patch.object(data_lab,'owned',return_value={'spec':{'jobTemplate':{'spec':{'template':{'spec':{}}}}}}),patch.object(lab,'k') as k:
   with self.assertRaises(RuntimeError):data_lab.run_job('restore','../../foreign')
   k.assert_not_called()
 def test_credentials_failure_preserves_all_existing(self):
  with patch.object(lab,'guard'),patch.object(lab,'namespace_guard'),patch.object(lab,'credential_secret',return_value=None),patch.object(data_lab,'preflight_password',side_effect=RuntimeError('mismatch')),patch.object(data_lab,'commit_password') as commit,patch.object(lab,'k') as k:
   with self.assertRaises(RuntimeError):data_lab.credentials()
   commit.assert_not_called();k.assert_not_called()
 def test_foreign_namespace_never_read(self):
  with patch.object(lab,'k') as k:
   with self.assertRaises(RuntimeError):data_lab.owned('v2-dev','pvc','book-data')
   k.assert_not_called()
