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
    dashboard = context / 'app/routers/dashboard.py'
    if dashboard.exists():
        original = dashboard.read_text()
        anchor = '    return templates.TemplateResponse(\n        request=request, name="dashboard.html",'
        if original.count(anchor) != 1:
            raise RuntimeError('V2 서비스 목록 패치 계약 불일치')
        dashboard.write_text(original.replace(anchor,
            '    services = [item for item in services if item["icon"] not in {"N", "T"}]\n\n' + anchor))
        changed.append(str(dashboard.relative_to(context)))
        template = context / 'app/templates/dashboard.html'
        content = template.read_text().replace('PERSONAL SERVER{% if demo_mode %}', 'V2 LOCAL LAB{% if demo_mode %}')
        content = content.replace('뉴스 수집, 유튜브 메모, 자동매매 기록을 관리하는\n        개인용 서비스 허브입니다.',
                                  '책과 유튜브 학습 메모, 파일을 관리하는 로컬 실습 서비스입니다.')
        content = content.replace('저장 뉴스, 유튜브 메모, 책 메모를 한 번에 찾습니다.', '유튜브 메모와 책 메모를 한 번에 찾습니다.')
        content = content.replace('<option value="news"{% if search_source == "news" %} selected{% endif %}>뉴스</option>', '')
        content = content.replace('{% for group, payload in search_results.items() %}',
                                  '{% for group, payload in search_results.items() if group != "news" %}')
        template.write_text(content)
        changed.append(str(template.relative_to(context)))
    return {'patch_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'files': changed}
