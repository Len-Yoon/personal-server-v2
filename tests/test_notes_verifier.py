"""관측 검증기의 인증 목적지·리디렉션·빈 패널 결과 거부 검증."""
import io
import sys
from pathlib import Path
import unittest
from unittest.mock import patch
import urllib.request

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import verify_notes_observability as verify


class NotesVerifierTests(unittest.TestCase):
    def test_foreign_url_and_credentials_to_prometheus_fail_before_network(self):
        with patch.object(urllib.request,'build_opener') as opener:
            for url,headers in [('https://127.0.0.1:8083/',None),('http://evil.test/',{'Authorization':'private'}),
                    ('http://127.0.0.1:8083@evil.test/',{'Authorization':'private'}),
                    ('http://127.0.0.1:8084/',{'Authorization':'private'})]:
                with self.subTest(url=url),self.assertRaises(RuntimeError):verify.http_json(url,headers)
            opener.assert_not_called()

    def test_proxy_environment_is_disabled_and_redirect_cannot_forward_auth(self):
        with patch.dict('os.environ',{'HTTP_PROXY':'http://foreign.test:9999'}),patch.object(urllib.request,'build_opener') as build:
            build.return_value.open.return_value.__enter__.return_value=io.BytesIO(b'{"ok":true}')
            self.assertEqual(verify.http_json('http://127.0.0.1:8083/api/health',{'Authorization':'private'}),{'ok':True})
            proxy,redirect=build.call_args.args
            self.assertEqual(proxy.proxies,{})
            request=build.return_value.open.call_args.args[0]
            self.assertIsNone(redirect.redirect_request(request,None,302,'',{},'http://foreign.test/'))

    def test_backend_error_and_empty_numeric_frames_are_rejected(self):
        dashboard={'panels':[{'id':1,'datasource':{'uid':'v2-prometheus'},'targets':[{'expr':'up'}]}]}
        for value in ({'results':{}},{'results':{'1':{'error':'failed'}}},
                {'results':{'1':{'frames':[{'schema':{'fields':[{'type':'time'}]},'data':{'values':[[123]]}}]}}}):
            with patch.object(verify,'http_json',return_value=value),self.assertRaises(RuntimeError):
                verify.grafana_panels(dashboard,{})
        value={'results':{'1':{'frames':[{'schema':{'fields':[{'type':'number'}]},'data':{'values':[[1.0]]}}]}}}
        with patch.object(verify,'http_json',return_value=value):
            self.assertEqual(verify.grafana_panels(dashboard,{}),1)


if __name__=='__main__':unittest.main()
