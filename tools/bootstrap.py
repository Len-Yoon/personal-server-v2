#!/usr/bin/env python3
"""맥북 ARM64 전용 도구 설치. 시스템 도구/기본 kubeconfig는 변경하지 않음."""
import hashlib
import json
import os
from pathlib import Path
import platform
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
LOCK = json.loads((ROOT / 'dependencies.json').read_text())


def download(url, destination, digest):
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not destination.exists():
        with urllib.request.urlopen(url, timeout=90) as response:
            data = response.read()
        if hashlib.sha256(data).hexdigest() != digest:
            raise RuntimeError(f'체크섬 불일치: {destination.name}')
        destination.write_bytes(data)
    if hashlib.sha256(destination.read_bytes()).hexdigest() != digest:
        raise RuntimeError(f'체크섬 불일치: {destination.name}')


def main():
    if platform.system() != 'Darwin' or platform.machine() != 'arm64':
        raise RuntimeError('이 bootstrap은 macOS ARM64만 지원함. CI는 별도 검증 workflow 사용')
    os.umask(0o077)
    (ROOT / '.local').mkdir(exist_ok=True, mode=0o700)
    (ROOT / '.local').chmod(0o700)
    download(f'https://github.com/k3d-io/k3d/releases/download/{LOCK["k3d"]}/k3d-darwin-arm64', ROOT / '.tools/bin/k3d', LOCK['k3d_darwin_arm64_sha256'])
    download(f'https://dl.k8s.io/release/{LOCK["kubectl"]}/bin/darwin/arm64/kubectl', ROOT / '.tools/bin/kubectl', LOCK['kubectl_darwin_arm64_sha256'])
    download(f'https://github.com/argoproj/argo-helm/releases/download/argo-cd-10.10.5/{LOCK["argocd_chart_file"]}', ROOT / '.local/cache' / LOCK['argocd_chart_file'], LOCK['argocd_chart_sha256'])
    for name in ('k3d', 'kubectl'):
        (ROOT / '.tools/bin' / name).chmod(0o755)
    print('공식 배포 도구/checksum 검증 PASS. 추가 필요: Python3, Docker/OrbStack, Helm')


if __name__ == '__main__':
    main()
