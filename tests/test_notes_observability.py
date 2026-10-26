"""실제 chart 렌더·수집 범위·대시보드 쿼리·통신 허용 경계 검증."""
import json
from pathlib import Path
import subprocess
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'platforms/observability'


def rendered(name):
    output = subprocess.check_output(['helm','template',name,str(BASE/name/'chart'),
        '-n','v2-observability','-f',str(BASE/name/'values.yaml')],text=True)
    return [o for o in yaml.safe_load_all(output) if o]


class NotesObservabilityTests(unittest.TestCase):
    def test_real_prometheus_config_scrapes_only_active_api_and_separates_probes(self):
        configs=[o for o in rendered('prometheus') if o['kind']=='ConfigMap' and 'prometheus.yml' in o.get('data',{})]
        config=yaml.safe_load(configs[0]['data']['prometheus.yml'])
        jobs={j['job_name']:j for j in config['scrape_configs']}
        job=jobs['notes-api']
        self.assertEqual(job['metrics_path'],'/metrics')
        self.assertEqual(job['sample_limit'],64)
        self.assertEqual(job['static_configs'],[{'targets':['notes-api.v2-data-dev.svc.cluster.local:8000'],
            'labels':{'environment':'dev','service':'notes-api'}}])
        self.assertNotIn('authorization',job)
        self.assertNotIn('bearer_token',job)
        self.assertEqual(job['metric_relabel_configs'][0]['action'],'keep')
        probes=jobs['notes-http']
        self.assertEqual(probes['metrics_path'],'/probe')
        self.assertEqual({r['labels']['endpoint'] for r in probes['static_configs']},{'health','ready'})
        self.assertTrue(all('v2-data-dev' in r['targets'][0] for r in probes['static_configs']))

    def test_provisioned_dashboard_queries_business_metrics(self):
        cm=next(o for o in rendered('grafana') if o['kind']=='ConfigMap' and o['metadata']['name']=='grafana-v2-lab-dashboard')
        dashboard=json.loads(cm['data']['v2-notes-api.json'])
        self.assertEqual(dashboard['uid'],'v2-notes-api')
        self.assertEqual(len(dashboard['panels']),8)
        for panel in dashboard['panels']:
            self.assertEqual(panel['datasource']['uid'],'v2-prometheus')
        expressions=' '.join(t['expr']for p in dashboard['panels']for t in p['targets'])
        for metric in ('v2_notes_api_requests_total','v2_notes_api_errors_total',
                       'v2_notes_api_client_errors_total','v2_notes_api_duration_seconds_bucket'):
            self.assertIn(metric,expressions)
        self.assertIn('histogram_quantile(0.95',expressions)
        self.assertNotIn('v2_notes_requests_total',expressions)
        for key in ('v2-platform-lab.json','v2-logs.json','v2-traces.json'):
            self.assertIn(key,cm['data'])

    def test_scrape_ingress_is_scoped_to_owned_prometheus_and_blackbox(self):
        objects=list(yaml.safe_load_all((ROOT/'platforms/data/dev/resources.yaml').read_text()))
        policy=next(o for o in objects if o['metadata']['name']=='data-clients')
        ingress=policy['spec']['ingress']
        self.assertEqual(len(ingress),1)
        self.assertEqual(ingress[0]['ports'],[{'protocol':'TCP','port':8000}])
        self.assertEqual(len(ingress[0]['from']),1)
        peer=ingress[0]['from'][0]
        self.assertEqual(peer['namespaceSelector']['matchLabels'],{'kubernetes.io/metadata.name':'v2-observability'})
        self.assertEqual(peer['podSelector']['matchLabels'],{'lab.personal-server-v2/owner':'personal-server-v2'})
        self.assertEqual(peer['podSelector']['matchExpressions'],[{'key':'app.kubernetes.io/name','operator':'In','values':['prometheus','blackbox']}])


if __name__=='__main__':unittest.main()
