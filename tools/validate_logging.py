#!/usr/bin/env python3
"""고정 Loki·Alloy·Tempo 바이너리로 설정 검증. 클러스터 데이터에 접근하지 않음."""
import argparse
import json
import os
import re
import subprocess
import lab


def validate(ci=False):
    if ci and os.environ.get('GITHUB_ACTIONS') != 'true':
        raise RuntimeError('--ci는 GitHub Actions 환경에서만 허용함')
    lock = json.loads((lab.ROOT / 'platforms/observability/dependencies.json').read_text())
    for name, uid, filename, arguments in [
        ('loki', 10001, 'config.yaml', ['-config.file=/etc/v2-config', '-verify-config=true']),
        ('alloy', 473, 'config.alloy', ['validate', '/etc/v2-config']),
        ('tempo', 10001, 'config.yaml', ['-config.file=/etc/v2-config', '-config.verify=true']),
    ]:
        image = lock[name]['image']
        if not re.fullmatch(r'grafana/' + name + r':[^@]+@sha256:[0-9a-f]{64}', image):
            raise RuntimeError('고정 공식 이미지 digest 계약 불일치')
        folder = 'tracing' if name == 'tempo' else 'logging'
        config = lab.ROOT / 'platforms/observability' / folder / name / filename
        command = ['run', '--rm', '--network', 'none', '--read-only', '--user', f'{uid}:{uid}',
                   '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--memory', '512m', '--cpus', '1',
                   '--tmpfs', f'/tmp:rw,noexec,nosuid,size=64m,uid={uid},gid={uid}',
                   '--tmpfs', f'/loki:rw,noexec,nosuid,size=64m,uid={uid},gid={uid}',
                   '--mount', f'type=bind,src={config},dst=/etc/v2-config,readonly', image, *arguments]
        if ci:
            subprocess.run(['docker', *command], check=True, cwd=lab.ROOT)
        else:
            lab.docker(*command, capture=False)
        print(name + ' 고정 바이너리 설정 검증 PASS', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ci', action='store_true', help='GitHub Actions 전용 Docker 환경')
    validate(parser.parse_args().ci)
