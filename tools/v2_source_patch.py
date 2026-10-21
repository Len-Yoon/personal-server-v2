"""고정 V1 소스의 V2 주소·쿠키 격리 패치. 운영 저장소는 수정하지 않음."""
import hashlib
from pathlib import Path
import re


def apply(context: Path):
    path = context / 'app/services/host_urls.py'
    original = path.read_text()
    content = original.replace(
        'return "http://127.0.0.1:8000/"',
        'return os.getenv("PORTAL_HOME_URL", "http://127.0.0.1:8000").rstrip("/") + "/"')
    for key, port in [('NEWS_SERVICE_URL', 8001), ('YOUTUBE_MEMO_URL', 8002), ('BOOK_MEMO_URL', 8003)]:
        content = content.replace(f'"{key}": "http://127.0.0.1:{port}"',
                                  f'"{key}": os.getenv("{key}", "http://127.0.0.1:{port}")')
    if content == original or 'return "http://127.0.0.1:8000/"' in content:
        raise RuntimeError('고정 소스 주소 패치 계약 불일치')
    path.write_text(content)
    changed = [str(path.relative_to(context))]
    # localhost는 포트별로 쿠키를 격리하지 않으므로 개발/검증 prefix를 부여함.
    for path in (context / 'app').rglob('*.py'):
        original = path.read_text()
        content = re.sub(r'^(\w*COOKIE) = ("[^"\n]+")$',
                         r'\1 = os.getenv("V2_COOKIE_PREFIX", "v2_") + \2', original, flags=re.M)
        if path.name == 'admin.py':
            content = content.replace('"homeops_admin_session"',
                                      '(os.getenv("V2_COOKIE_PREFIX", "v2_") + "homeops_admin_session")')
        if content != original:
            if not re.search(r'^import os\b', content, re.M):
                raise RuntimeError('쿠키 패치 대상의 os import 없음')
            path.write_text(content)
            changed.append(str(path.relative_to(context)))
    return {'patch_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'files': changed}
