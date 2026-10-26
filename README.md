# Personal Server V2 · Kubernetes Platform Lab

**현재 상태:** [메모 API 관측·배포 준비 고도화와 안정화 검증](docs/20261026_V2_관측배포_고도화검증.md)을 완료함. [직접 학습 계획](docs/20261026_V2_고도화학습계획.md)은 고도화·안정화 후 재개하며 사용자 직접1주차는 미시작임.

V1의 Portal·Book·YouTube 고정 소스를 재사용하고, 맥북에 GitOps·지표·로그·요청 추적·보안 정책·PostgreSQL 백업 복원 실습을 구성한 프로젝트임.

**[V1을 기준으로 V2에 무엇을 붙였는지 보기](docs/20261022_V1대비_V2_구축정리.md)** — 재사용한 기능·추가한 구성·검증 결과·보류 범위를 한 문서로 정리함.

| 구분 | 범위 | 비고 |
|---|---|---|
| V1 | [personal-server](https://github.com/Len-Yoon/personal-server)의 실제 서비스 운영·유지보수 | 기존 저장소·운영 구성 보존 |
| V2 | 맥북 로컬 Kubernetes 운영 실습 | V1 전체 복제·즉시 대체 아님 |
| 현재 상태 | 세 앱 연계·GitOps·지표·로그·trace·보안·별도 PostgreSQL 백업 복원 검증 완료 | 2026-10-26 검증18개 Argo 앱·27개 관측 대상 정상 |
| 최근 배포 | 메모 API1.2.0 관측 연결·안전한 배포 준비 자동화·정상 상태 유지·보존 검증 완료 | [고도화 검증 결과](docs/20261026_V2_관측배포_고도화검증.md), 사용자 직접 실행과 구분 |
| 현재 우선순위 | 승인한 고도화·안정화 완료, 사용자 요청 시 직접 학습 재개 | 폐쇄망 보류, SBOM·서명 검증 미구현 |
| 운영 보호 | N100 접속·동기화·이미지 반입·배포·운영 데이터 사용 제외 | 별도 명시 승인 전 금지 |

## 개발 방향

V1에도 K3s·Prometheus·Grafana·CI·백업 구성이 있음. V2에서는 이 기반을 맥북 전용 k3d 환경에 재구성하고, Argo CD 배포 관리·Loki 로그 수집·OpenTelemetry/Tempo 요청 추적·권한/통신/배포 정책을 연결함.

기존 세 앱은 고정 V1 소스에 V2 주소·쿠키·계측 패치를 적용해 ARM64 이미지로 빌드함. 신규 메모 API는 V2에서 작성하고 PostgreSQL과 연결해 별도 데이터·백업·복원을 실습함. 기존 앱의 SQLite나 V1 운영 데이터를 이전하지 않음.

[개발 계획](docs/20261021_V2_개발계획.md) · [로컬 실습 가이드](docs/20261021_V2_로컬실습_운영가이드.md) · [검증 기록](docs/20261021_V2_검증기록.md) · [GitOps·관측 기록](docs/20261021_V2_GitOps전환_지표관측_검증기록.md) · [에이전트 작업 기준](AGENTS.md)

## localhost 접속

```sh
python3 tools/lab.py serve
```

| 대상 | 주소 | 비고 |
|---|---|---|
| Portal 개발 / 검증 | http://127.0.0.1:8000 / http://127.0.0.1:8090 | 파일함·Book·YouTube 연결 |
| YouTube 개발 / 검증 | http://127.0.0.1:8002 / http://127.0.0.1:8092 | 별도 PVC·쓰기 인증 |
| Book 개발 | http://localhost:8080 | 쓰기 비밀번호 .local/dev-password |
| Book 검증 | http://localhost:8081 | 쓰기 비밀번호 .local/verify-password |
| Argo CD | https://localhost:8082 | admin / .local/argocd-password, 자체 서명 인증서 |
| Grafana | http://localhost:8083/d/v2-platform-lab | admin / .local/grafana-password |
| Grafana 로그 | http://localhost:8083/d/v2-logs | 환경·서비스별 Loki 로그 검색 |
| Prometheus | http://localhost:8084 | 지표·targets·내부 alert 조회 |
| Grafana 요청 추적 | http://localhost:8083/d/v2-traces/v2-traces | Portal→Book/YouTube 요청과 로그 연계 |
| 메모 API 버전 | http://localhost:8086/version | 서비스명·앱 버전1.2.0 확인, 인증 불필요 |
| Grafana 메모 API | http://localhost:8083/d/v2-notes-api | 업무 요청·오류·지연 및 health/ready 관측 |
| 별도 메모 API | http://localhost:8086/health / http://localhost:8086/ready | 프로세스·DB 접근 상태, 메모 API는 Bearer 인증 |

현재 CI는 테스트·설정을 검사함. 로컬에서 `.local/otel-venv/bin/python tools/prepare_data_release.py`를 실행하면 전체 테스트·변경 이미지 빌드·등록·digest 검증·명세 갱신을 일괄 수행함. 전체 테스트 의존성이 설치된 Python 실행기를 사용하며, 자동 commit·push·배포는 수행하지 않음. PR·CI·main 병합 후 Argo 수동 Sync로 배포함. [고도화 배포·검증 기록](docs/20261026_V2_관측배포_고도화검증.md)에 현재 순서와 결과를 기록함.

정상 배포는 `lab.py gitops` 또는 `lab.py sync`로 수행함. 기존 Argo에 Helm upgrade를 반복하지 않음. 최초 설치·이미지 빌드·배포는 로컬 실습 가이드에 따름. 포워딩 프로세스를 유지해야 접속 가능하며 localhost 주소만 입력해서 클러스터가 자동 시작되지는 않음. 비밀번호 파일 내용은 Git·로그에 기록하지 않음.

## 검증과 현재 한계

정적 안전 경계 검증과 실제 로컬 실행 증거를 구분해 검증 기록에 보관함. 자동 장애 회귀와 별도 DB 복원을 확인했으며, 사용자의 직접 진단 경험·물리 HA·다른 물리 호스트의 재해복구와 구분함. GitHub 저장·병합·CI와 로컬 수동 GitOps 동기화·N100 운영 배포를 구분함.

Portal·YouTube 통합 범위와 제한은 [서비스 통합 기록](docs/20261021_V2_서비스통합_검증기록.md)에 정리함. 로그인 정보는 Git 제외 `.local/V2_로그인정보.md`에만 저장됨.

[Loki·Alloy 로그 수집 기록](docs/20261021_V2_로그수집_검증기록.md) · 표준 Pod 로그만 수집하며, 보안 이벤트 파일·호스트 로그는 포함하지 않음.

[요청 추적 기록](docs/20261022_V2_요청추적_검증기록.md) · [보안 검증](docs/20261022_V2_보안강화_검증기록.md) · [PostgreSQL 백업·복원](docs/20261022_V2_데이터백업복구_검증기록.md)
