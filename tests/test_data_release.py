"""배포 준비의 실패 시 명세 보존·재실행·소스 추적 경계를 자기 검증함."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import build_data as release
import prepare_data_release as prepare
import lab


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for target, value in [('ROOT', self.root), ('LOCAL', self.root / '.local')]:
            p = patch.object(lab, target, value)
            p.start()
            self.addCleanup(p.stop)
        self.previous = {}
        for kind, directories in release.SOURCES.items():
            for directory in directories:
                path = self.root / directory / 'source.txt'
                path.parent.mkdir(parents=True)
                path.write_text('source ' + kind)
            self.previous[kind] = {'image':'localhost:5001/' + release.REPOSITORIES[kind] + '@sha256:' + ('1' if kind == 'api' else '2') * 64,
                'base':release.BASES[kind], 'architecture':'arm64', 'source_sha256':release.source_hash(kind)}
        for environment in ('dev', 'restore', 'policies'):
            path = self.root / 'platforms/data' / environment / 'resources.yaml'
            path.parent.mkdir(parents=True)
            path.write_text(' '.join(x['image'] for x in self.previous.values()))
        self.lock = self.root / 'platforms/data/images.lock.json'
        self.lock.write_text(json.dumps(self.previous, indent=2) + '\n')
        self.paths = [*(self.root / 'platforms/data' / e / 'resources.yaml' for e in ('dev','restore','policies')), self.lock]
        self.before = {p:p.read_bytes() for p in self.paths}
        p = patch.object(lab, 'guard')
        self.guard = p.start()
        self.addCleanup(p.stop)

    def assert_preserved(self):
        self.assertEqual({p:p.read_bytes() for p in self.paths}, self.before)

    def changed_images(self):
        result = copy.deepcopy(self.previous)
        result['api']['image'] = result['api']['image'].split('@')[0] + '@sha256:' + '3' * 64
        return result

    def test_tests_fail_before_build_or_writes(self):
        with patch.object(release, 'build_images') as build:
            with self.assertRaises(RuntimeError):
                release.prepare(run_tests=lambda: (_ for _ in ()).throw(RuntimeError('failed')))
        self.guard.assert_called_once()
        build.assert_not_called()
        self.assert_preserved()

    def test_build_push_or_digest_failure_preserves_all_files(self):
        (self.root/'apps/notes-api/source.txt').write_text('updated API')
        new_image=self.changed_images()['api']['image']
        for failure in ('build', 'push', 'digest'):
            calls=[]
            def docker(*args, **kwargs):
                calls.append(args[0])
                if args[0]==failure:raise RuntimeError(failure)
                if args[0]=='image':return json.dumps([{'RepoDigests':[new_image]}])
                return 0
            with self.subTest(failure=failure), patch.object(lab,'docker',side_effect=docker), patch.object(release,'verify_image',side_effect=RuntimeError('digest') if failure=='digest' else None):
                with self.assertRaises(RuntimeError):release.prepare()
                self.assertEqual(calls[:1], ['build'])
                if failure!='build':self.assertIn('push',calls)
                self.assert_preserved()

    def test_unchanged_sources_verify_registry_and_do_not_build(self):
        with patch.object(release, 'verify_image') as verify, patch.object(lab, 'docker') as docker:
            release.prepare()
            release.prepare()
        self.assertEqual(verify.call_count,4)
        docker.assert_not_called()
        self.assert_preserved()

    def test_success_updates_all_files_and_repeat_is_noop(self):
        updated = self.changed_images()
        with patch.object(release, 'build_images', return_value=updated):
            release.prepare()
            after = {p:p.read_bytes() for p in self.paths}
            release.prepare()
        self.assertEqual(after, {p:p.read_bytes() for p in self.paths})
        for p in self.paths:self.assertIn(updated['api']['image'], p.read_text())

    def test_source_change_during_tests_stops_before_build(self):
        def mutate():(self.root/'apps/notes-api/source.txt').write_text('changed')
        with patch.object(release,'build_images') as build, self.assertRaisesRegex(RuntimeError,'테스트 중'):
            release.prepare(run_tests=mutate)
        build.assert_not_called()
        self.assert_preserved()

    def test_source_change_during_build_never_updates_manifests(self):
        def mutate(*args):
            (self.root/'apps/notes-api/source.txt').write_text('changed')
            return self.changed_images()
        with patch.object(release,'build_images',side_effect=mutate), self.assertRaisesRegex(RuntimeError,'빌드 중'):
            release.prepare()
        self.assert_preserved()

    def test_manifest_concurrent_change_is_not_overwritten(self):
        def mutate(*args):
            self.paths[0].write_text('concurrent editor')
            return self.changed_images()
        with patch.object(release,'build_images',side_effect=mutate), self.assertRaises(RuntimeError):release.prepare()
        self.assertEqual(self.paths[0].read_text(),'concurrent editor')
        for p in self.paths[1:]:self.assertEqual(p.read_bytes(),self.before[p])

    def test_second_file_replace_failure_rolls_back_first_file_and_lock(self):
        real_replace = release.os.replace
        calls = []
        def replace(source,destination):
            calls.append(destination)
            if len(calls)==2:raise OSError('simulated disk failure')
            return real_replace(source,destination)
        with patch.object(release,'build_images',return_value=self.changed_images()), patch.object(release.os,'replace',side_effect=replace), self.assertRaises(OSError):
            release.prepare()
        self.assert_preserved()
        self.assertEqual(list(self.root.rglob('.v2-release-*')),[])

    def test_parallel_release_is_refused(self):
        with release.release_lock(), self.assertRaisesRegex(RuntimeError,'실행 중'):release.prepare()
        self.assert_preserved()

    def test_registry_bytes_and_architecture_are_checked(self):
        payload=b'{"schemaVersion":2}'
        image='localhost:5001/v2-notes-api@sha256:'+hashlib.sha256(payload).hexdigest()
        inspected=[{'Architecture':'arm64','Os':'linux','RepoDigests':[image]}]
        with patch.object(lab,'docker',return_value=json.dumps(inspected)), patch.object(release.urllib.request,'build_opener') as opener:
            response=opener.return_value.open.return_value.__enter__.return_value
            response.read.return_value=payload
            release.verify_image('api',image)
            response.read.return_value=b'damaged'
            with self.assertRaisesRegex(RuntimeError,'digest'):release.verify_image('api',image)
        inspected[0]['Architecture']='amd64'
        with patch.object(lab,'docker',return_value=json.dumps(inspected)), self.assertRaisesRegex(RuntimeError,'ARM64'):
            release.verify_image('api',image)

    def test_foreign_image_is_rejected_before_docker_or_network(self):
        with patch.object(lab,'docker') as docker, self.assertRaises(RuntimeError):
            release.verify_image('api','example.com/v2-notes-api@sha256:'+'3'*64)
        docker.assert_not_called()

    def test_test_skips_and_empty_suite_are_not_release_success(self):
        for count,skipped in ((0,[]),(1,[('x','missing deps')])):
            with patch.object(prepare.unittest.defaultTestLoader,'discover'), patch.object(prepare.unittest,'TextTestRunner') as runner:
                result=runner.return_value.run.return_value
                result.wasSuccessful.return_value=True
                result.testsRun=count
                result.skipped=skipped
                with self.assertRaises(RuntimeError):prepare.run_tests()


if __name__=='__main__':unittest.main()
