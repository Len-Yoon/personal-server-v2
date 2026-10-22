"""고정 V1 소스의 V2 주소·쿠키 격리 패치. 운영 저장소는 수정하지 않음."""
import hashlib
from pathlib import Path
import re


def apply_telemetry(context: Path):
    """고정 소스의 build context에만 명시 bootstrap/내부 전송 계층을 연결함."""
    main = context / 'app/main.py'
    content = main.read_text()
    if content.count('app = FastAPI(') != 1 or 'v2_telemetry' in content:
        raise RuntimeError('V2 telemetry main patch contract mismatch')
    # FastAPI 0.142는 lifespan에서 env endpoint를 보고 별도 native exporter를 만듦.
    # 자체 PrivateExporter 외의 trace/metric/log 전송 경로를 생성자에서 차단함.
    content = content.replace('app = FastAPI(',
        'app = FastAPI(telemetry={"auto_configure": False, "tracing": False, '
        '"metrics": False, "logs": False, "operation_spans": False}, ', 1)
    content += '\n# V2 전용 명시 HTTP 계측 (모든 라우트 등록 이후 초기화)\nfrom app.v2_telemetry import configure as configure_v2_telemetry\nconfigure_v2_telemetry(app)\n'
    changed = ['app/main.py']
    search = context / 'app/services/global_search.py'
    if search.exists():
        original = search.read_text()
        anchor = 'httpx.AsyncClient(timeout=SEARCH_BUDGET_SECONDS, follow_redirects=True)'
        if original.count(anchor) != 1:
            raise RuntimeError('V2 telemetry HTTPX patch contract mismatch')
        patched = original.replace('import httpx\n', 'import httpx\nfrom app.v2_telemetry import internal_transport\n', 1)
        patched = patched.replace(anchor, 'httpx.AsyncClient(timeout=SEARCH_BUDGET_SECONDS, follow_redirects=True, transport=internal_transport())')
        search.write_text(patched)
        changed.append(str(search.relative_to(context)))
    main.write_text(content)
    return changed


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
